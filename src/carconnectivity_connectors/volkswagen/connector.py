"""Module implements the connector to interact with the Skoda API."""
from __future__ import annotations
from typing import TYPE_CHECKING

import os
import logging
import netrc
from datetime import datetime, timedelta
import requests

from carconnectivity.garage import Garage
from carconnectivity.errors import AuthenticationError, TooManyRequestsError, RetrievalError, APIError
from carconnectivity.util import robust_time_parse, log_extra_keys
from carconnectivity.units import Length
from carconnectivity.vehicle import GenericVehicle
from carconnectivity.doors import Doors
from carconnectivity_connectors.base.connector import BaseConnector
from carconnectivity_connectors.volkswagen.auth.session_manager import SessionManager, SessionUser, Service
from carconnectivity_connectors.volkswagen.vehicle import VolkswagenVehicle, VolkswagenElectricVehicle, VolkswagenCombustionVehicle, VolkswagenHybridVehicle
from carconnectivity_connectors.volkswagen.capability import Capability


if TYPE_CHECKING:
    from typing import Dict, List, Optional, Any

    from requests import Session

    from carconnectivity.carconnectivity import CarConnectivity

LOG: logging.Logger = logging.getLogger("carconnectivity-connector-volkswagen")
LOG_API_DEBUG: logging.Logger = logging.getLogger("carconnectivity-connector-volkswagen-api-debug")


class Connector(BaseConnector):
    """
    Connector class for Skoda API connectivity.
    Args:
        car_connectivity (CarConnectivity): An instance of CarConnectivity.
        config (Dict): Configuration dictionary containing connection details.
    Attributes:
        max_age (Optional[int]): Maximum age for cached data in seconds.
    """
    def __init__(self, car_connectivity: CarConnectivity, config: Dict) -> None:
        BaseConnector.__init__(self, car_connectivity, config)
        LOG.info("Loading skoda connector with config %s", self.config)

        username: Optional[str] = None
        password: Optional[str] = None
        if 'username' in self.config and 'password' in self.config:
            username = self.config['username']
            password = self.config['password']
        else:
            if 'netrc' in self.config:
                netrc_filename: str = self.config['netrc']
            else:
                netrc_filename = os.path.join(os.path.expanduser("~"), ".netrc")
            try:
                secrets = netrc.netrc(file=netrc_filename)
                secret: tuple[str, str, str] | None = secrets.authenticators("volkswagen")
                if secret is None:
                    raise AuthenticationError(f'Authentication using {netrc_filename} failed: volkswagen not found in netrc')
                username, _, password = secret
            except netrc.NetrcParseError as err:
                LOG.error('Authentification using %s failed: %s', netrc_filename, err)
                raise AuthenticationError(f'Authentication using {netrc_filename} failed: {err}') from err
            except TypeError as err:
                if 'username' not in self.config:
                    raise AuthenticationError(f'skoda.de entry was not found in {netrc_filename} netrc-file.'
                                              ' Create it or provide username and password in config') from err
            except FileNotFoundError as err:
                raise AuthenticationError(f'{netrc_filename} netrc-file was not found. Create it or provide username and password in config') from err

        self.max_age: Optional[int] = 300
        if 'maxAge' in self.config:
            self.max_age = self.config['maxAge']

        if username is None or password is None:
            raise AuthenticationError('Username or password not provided')

        self._manager: SessionManager = SessionManager(tokenstore=car_connectivity.get_tokenstore(), cache=car_connectivity.get_cache())
        self._session: Session = self._manager.get_session(Service.WE_CONNECT, SessionUser(username=username, password=password))

        self._elapsed: List[timedelta] = []

    def persist(self) -> None:
        """
        Persists the current state using the manager's persist method.

        This method calls the `persist` method of the `_manager` attribute to save the current state.
        """
        self._manager.persist()

    def shutdown(self) -> None:
        """
        Shuts down the connector by persisting current state, closing the session,
        and cleaning up resources.

        This method performs the following actions:
        1. Persists the current state.
        2. Closes the session.
        3. Sets the session and manager to None.
        4. Calls the shutdown method of the base connector.

        Returns:
            None
        """
        self.persist()
        self._session.close()
        BaseConnector.shutdown(self)

    def fetch_all(self) -> None:
        """
        Fetches all necessary data for the connector.

        This method calls the `fetch_vehicles` method to retrieve vehicle data.
        """
        self.fetch_vehicles()

    def fetch_vehicles(self) -> None:
        """
        Fetches the list of vehicles from the Skoda Connect API and updates the garage with new vehicles.
        This method sends a request to the Skoda Connect API to retrieve the list of vehicles associated with the user's account.
        If new vehicles are found in the response, they are added to the garage.

        Returns:
            None
        """
        garage: Garage = self.car_connectivity.garage
        url = 'https://emea.bff.cariad.digital/vehicle/v1/vehicles'
        data: Dict[str, Any] | None = self._fetch_data(url, session=self._session)
        print(data)

        seen_vehicle_vins: set[str] = set()
        if data is not None:
            if 'data' in data and data['data'] is not None:
                for vehicle_dict in data['data']:
                    if 'vin' in vehicle_dict and vehicle_dict['vin'] is not None:
                        seen_vehicle_vins.add(vehicle_dict['vin'])
                        vehicle: Optional[VolkswagenVehicle] = garage.get_vehicle(vehicle_dict['vin'])  # pyright: ignore[reportAssignmentType]
                        if vehicle is None:
                            vehicle = VolkswagenVehicle(vin=vehicle_dict['vin'], garage=garage)
                            garage.add_vehicle(vehicle_dict['vin'], vehicle)

                        if 'nickname' in vehicle_dict and vehicle_dict['nickname'] is not None:
                            vehicle.name._set_value(vehicle_dict['nickname'])  # pylint: disable=protected-access

                        if 'model' in vehicle_dict and vehicle_dict['model'] is not None:
                            vehicle.model._set_value(vehicle_dict['model'])  # pylint: disable=protected-access

                        if 'capabilities' in vehicle_dict and vehicle_dict['capabilities'] is not None:
                            found_capabilities = set()
                            for capability_dict in vehicle_dict['capabilities']:
                                if 'id' in capability_dict and capability_dict['id'] is not None:
                                    capability_id = capability_dict['id']
                                    found_capabilities.add(capability_id)
                                    if capability_id in vehicle.capabilities:
                                        capability: Capability = vehicle.capabilities[capability_id]
                                    else:
                                        capability = Capability(capability_id=capability_id, vehicle=vehicle)
                                        vehicle.capabilities[capability_id] = capability
                                    if 'expirationDate' in capability_dict and capability_dict['expirationDate'] is not None:
                                        expiration_date: datetime = robust_time_parse(capability_dict['expirationDate'])
                                        capability.expiration_date._set_value(expiration_date)  # pylint: disable=protected-access
                                    if 'userDisablingAllowed' in capability_dict and capability_dict['userDisablingAllowed'] is not None:
                                        # pylint: disable-next=protected-access
                                        capability.user_disabling_allowed._set_value(capability_dict['userDisablingAllowed'])
                            for capability_id in vehicle.capabilities.keys() - found_capabilities:
                                vehicle.capabilities[capability_id].enabled = False
                                vehicle.capabilities.pop(capability_id)

                        self.fetch_vehicle_status(vehicle)
        for vin in set(garage.list_vehicle_vins()) - seen_vehicle_vins:
            vehicle_to_remove = garage.get_vehicle(vin)
            if vehicle_to_remove is not None and vehicle_to_remove.is_managed_by_connector(self):
                garage.remove_vehicle(vin)

    def fetch_vehicle_status(self, vehicle: VolkswagenVehicle) -> None:
        """
        Fetches the status of a vehicle from the Volkswagen API.

        Args:
            vehicle (GenericVehicle): The vehicle object containing the VIN.

        Returns:
            None
        """
        vin = vehicle.vin.value
        known_capabilities: list[str] = ['access',
                                         'activeventilation',
                                         'automation',
                                         'auxiliaryheating',
                                         'userCapabilities'
                                         'charging',
                                         'chargingProfiles',
                                         'batteryChargingCare',
                                         'climatisation',
                                         'climatisationTimers'
                                         'departureTimers',
                                         'fuelStatus',
                                         'vehicleLights',
                                         'lvBattery',
                                         'readiness',
                                         'vehicleHealthInspection',
                                         'vehicleHealthWarnings',
                                         'oilLevel',
                                         'measurements',
                                         'batterySupport']
        jobs: list[str] = []
        for capability_id in known_capabilities:
            if capability_id in vehicle.capabilities.keys() and vehicle.capabilities[capability_id].enabled:
                jobs.append(capability_id)

        url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/selectivestatus?jobs=' + ','.join(jobs)
        data: Dict[str, Any] | None = self._fetch_data(url, self._session)
        if data is not None:
            if 'measurements' in data and data['measurements'] is not None:
                if 'fuelLevelStatus' in data['measurements'] and data['measurements']['fuelLevelStatus'] is not None:
                    if 'value' in data['measurements']['fuelLevelStatus'] and data['measurements']['fuelLevelStatus']['value'] is not None:
                        fuel_level_status = data['measurements']['fuelLevelStatus']['value']
                        captured_at: datetime = robust_time_parse(fuel_level_status['carCapturedTimestamp'])
                        # Check vehicle type and if it does not match the current vehicle type, create a new vehicle object using copy constructor
                        if 'carType' in fuel_level_status and fuel_level_status['carType'] is not None:
                            try:
                                car_type = GenericVehicle.Type(fuel_level_status['carType'])
                                if car_type == GenericVehicle.Type.ELECTRIC and not isinstance(vehicle, VolkswagenElectricVehicle):
                                    vehicle = VolkswagenElectricVehicle(origin=vehicle)
                                elif car_type in [GenericVehicle.Type.FUEL,
                                                  GenericVehicle.Type.GASOLINE,
                                                  GenericVehicle.Type.PETROL,
                                                  GenericVehicle.Type.DIESEL,
                                                  GenericVehicle.Type.CNG,
                                                  GenericVehicle.Type.LPG] \
                                        and not isinstance(vehicle, VolkswagenCombustionVehicle):
                                    vehicle = VolkswagenCombustionVehicle(origin=vehicle)
                                elif car_type == GenericVehicle.Type.HYBRID and not isinstance(vehicle, VolkswagenHybridVehicle):
                                    vehicle = VolkswagenHybridVehicle(origin=vehicle)
                                vehicle.type._set_value(car_type)  # pylint: disable=protected-access
                            except ValueError:
                                LOG_API_DEBUG.warning('Unknown car type %s', fuel_level_status['carType'])
                        log_extra_keys(LOG_API_DEBUG, 'fuelLevelStatus', data['measurements']['fuelLevelStatus'], {'carCapturedTimestamp', 'carType'})
                if 'rangeStatus' in data['measurements'] and data['measurements']['rangeStatus'] is not None:
                    if 'value' in data['measurements']['rangeStatus'] and data['measurements']['rangeStatus']['value'] is not None:
                        range_status = data['measurements']['rangeStatus']['value']
                        # TODO: Implement the rangeStatus
                        log_extra_keys(LOG_API_DEBUG, 'rangeStatus', range_status, set())
                if 'odometerStatus' in data['measurements'] and data['measurements']['odometerStatus'] is not None:
                    if 'value' in data['measurements']['odometerStatus'] and data['measurements']['odometerStatus']['value'] is not None:
                        odometer_status = data['measurements']['odometerStatus']['value']
                        if 'carCapturedTimestamp' not in odometer_status or odometer_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(odometer_status['carCapturedTimestamp'])
                        if 'odometer' in odometer_status and odometer_status['odometer'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.odometer._set_value(value=odometer_status['odometer'], measured=captured_at, unit=Length.KM)
                        log_extra_keys(LOG_API_DEBUG, 'odometerStatus', odometer_status, {'carCapturedTimestamp', 'odometer'})
                log_extra_keys(LOG_API_DEBUG, 'measurements', data['measurements'], {'fuelLevelStatus', 'rangeStatus', 'odometerStatus'})
            if 'access' in data and data['access'] is not None:
                if 'accessStatus' in data['access'] and data['access']['accessStatus'] is not None:
                    if 'value' in data['access']['accessStatus'] and data['access']['accessStatus']['value'] is not None:
                        access_status = data['access']['accessStatus']['value']
                        if 'carCapturedTimestamp' not in access_status or access_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(access_status['carCapturedTimestamp'])
                        if 'doors' in access_status and access_status['doors'] is not None:
                            seen_door_ids: set[str] = set()
                            all_doors_closed = True
                            for door_status in access_status['doors']:
                                door_id = door_status['name']
                                seen_door_ids.add(door_id)
                                if door_id in vehicle.doors.doors:
                                    door: Doors.Door = vehicle.doors.doors[door_id]
                                else:
                                    door = Doors.Door(door_id=door_id, doors=vehicle.doors)
                                    vehicle.doors.doors[door_id] = door
                                if 'status' in door_status and door_status['status'] is not None:
                                    if 'locked' in door_status['status']:
                                        door.lock_state._set_value(Doors.LockState.LOCKED, measured=captured_at)  # pylint: disable=protected-access
                                    elif 'unlocked' in door_status['status']:
                                        door.lock_state._set_value(Doors.LockState.UNLOCKED, measured=captured_at)  # pylint: disable=protected-access
                                    else:
                                        door.lock_state._set_value(Doors.LockState.UNKNOWN, measured=captured_at)  # pylint: disable=protected-access
                                    if 'open' in door_status['status']:
                                        all_doors_closed = False
                                        door.open_state._set_value(Doors.OpenState.OPEN, measured=captured_at)  # pylint: disable=protected-access
                                    elif 'closed' in door_status['status']:
                                        door.open_state._set_value(Doors.OpenState.CLOSED, measured=captured_at)  # pylint: disable=protected-access
                                    elif 'unsupported' in door_status['status']:
                                        door.open_state._set_value(Doors.OpenState.UNSUPPORTED, measured=captured_at)  # pylint: disable=protected-access
                                    else:
                                        door.open_state._set_value(Doors.OpenState.UNKNOWN, measured=captured_at)  # pylint: disable=protected-access
                                        LOG_API_DEBUG.warning('Unknown door status %s', door_status['status'])
                                log_extra_keys(LOG_API_DEBUG, 'doors', door_status, {'name', 'status'})
                            if all_doors_closed:
                                vehicle.doors.open_state._set_value(Doors.OpenState.CLOSED, measured=captured_at)  # pylint: disable=protected-access
                            else:
                                vehicle.doors.open_state._set_value(Doors.OpenState.OPEN, measured=captured_at)  # pylint: disable=protected-access
                            for door_id in vehicle.doors.doors.keys() - seen_door_ids:
                                vehicle.doors.doors[door_id].enabled = False
                                vehicle.doors.doors.pop(door_id)
                        if 'overallStatus' in access_status and access_status['overallStatus'] is not None:
                            if access_status['overallStatus'] == 'safe':
                                vehicle.doors.lock_state._set_value(Doors.LockState.LOCKED, measured=captured_at)  # pylint: disable=protected-access
                            elif access_status['overallStatus'] == 'unsafe':
                                vehicle.doors.lock_state._set_value(Doors.LockState.UNLOCKED, measured=captured_at)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API_DEBUG, 'accessStatus', access_status, {'carCapturedTimestamp', 'doors', 'overallStatus'})
                log_extra_keys(LOG_API_DEBUG, 'access', data['access'], {'accessStatus'})
            log_extra_keys(LOG_API_DEBUG, 'selectivestatus', data, {'measurements', 'access'})

        print(data)

    def _record_elapsed(self, elapsed: timedelta) -> None:
        """
        Records the elapsed time.

        Args:
            elapsed (timedelta): The elapsed time to record.
        """
        self._elapsed.append(elapsed)

    def _fetch_data(self, url, session, force=False, allow_empty=False, allow_http_error=False, allowed_errors=None) -> Optional[Dict[str, Any]]:  # noqa: C901
        data: Optional[Dict[str, Any]] = None
        cache_date: Optional[datetime] = None
        if not force and (self.max_age is not None and session.cache is not None and url in session.cache):
            data, cache_date_string = session.cache[url]
            cache_date = datetime.fromisoformat(cache_date_string)
        if data is None or self.max_age is None \
                or (cache_date is not None and cache_date < (datetime.utcnow() - timedelta(seconds=self.max_age))):
            try:
                status_response: requests.Response = session.get(url, allow_redirects=False)
                self._record_elapsed(status_response.elapsed)
                if status_response.status_code in (requests.codes['ok'], requests.codes['multiple_status']):
                    data = status_response.json()
                    if session.cache is not None:
                        session.cache[url] = (data, str(datetime.utcnow()))
                elif status_response.status_code == requests.codes['too_many_requests']:
                    raise TooManyRequestsError('Could not fetch data due to too many requests from your account. '
                                               f'Status Code was: {status_response.status_code}')
                elif status_response.status_code == requests.codes['unauthorized']:
                    LOG.info('Server asks for new authorization')
                    session.login()
                    status_response = session.get(url, allow_redirects=False)

                    if status_response.status_code in (requests.codes['ok'], requests.codes['multiple_status']):
                        data = status_response.json()
                        if session.cache is not None:
                            session.cache[url] = (data, str(datetime.utcnow()))
                    elif not allow_http_error or (allowed_errors is not None and status_response.status_code not in allowed_errors):
                        raise RetrievalError(f'Could not fetch data even after re-authorization. Status Code was: {status_response.status_code}')
                elif not allow_http_error or (allowed_errors is not None and status_response.status_code not in allowed_errors):
                    raise RetrievalError(f'Could not fetch data. Status Code was: {status_response.status_code}')
            except requests.exceptions.ConnectionError as connection_error:
                raise RetrievalError from connection_error
            except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
                raise RetrievalError from chunked_encoding_error
            except requests.exceptions.ReadTimeout as timeout_error:
                raise RetrievalError from timeout_error
            except requests.exceptions.RetryError as retry_error:
                raise RetrievalError from retry_error
            except requests.exceptions.JSONDecodeError as json_error:
                if allow_empty:
                    data = None
                else:
                    raise RetrievalError from json_error
        return data
