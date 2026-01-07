"""Module implements the connector to interact with the Volskwagen API."""
from __future__ import annotations
from typing import TYPE_CHECKING

import threading

import json
import os
import traceback
import logging
import netrc
from datetime import datetime, timezone, timedelta
import requests

from carconnectivity.garage import Garage
from carconnectivity.errors import AuthenticationError, TooManyRequestsError, RetrievalError, APIError, APICompatibilityError, \
    TemporaryAuthenticationError, SetterError, CommandError
from carconnectivity.util import robust_time_parse, log_extra_keys, config_remove_credentials
from carconnectivity.units import Length, Power, Speed
from carconnectivity.vehicle import GenericVehicle
from carconnectivity.doors import Doors
from carconnectivity.windows import Windows
from carconnectivity.lights import Lights
from carconnectivity.drive import GenericDrive, ElectricDrive, CombustionDrive, DieselDrive
from carconnectivity.battery import Battery
from carconnectivity.attributes import BooleanAttribute, DurationAttribute, GenericAttribute, TemperatureAttribute, EnumAttribute, LevelAttribute, \
    CurrentAttribute
from carconnectivity.units import Temperature
from carconnectivity.command_impl import ClimatizationStartStopCommand, WakeSleepCommand, HonkAndFlashCommand, LockUnlockCommand, ChargingStartStopCommand, \
    WindowHeatingStartStopCommand
from carconnectivity.climatization import Climatization
from carconnectivity.commands import Commands
from carconnectivity.charging import Charging
from carconnectivity.charging_connector import ChargingConnector
from carconnectivity.position import Position
from carconnectivity.enums import ConnectionState
from carconnectivity.window_heating import WindowHeatings

from carconnectivity_connectors.base.connector import BaseConnector
from carconnectivity_connectors.volkswagen.auth.session_manager import SessionManager, SessionUser, Service
from carconnectivity_connectors.volkswagen.auth.we_connect_session import WeConnectSession
from carconnectivity_connectors.volkswagen.vehicle import VolkswagenVehicle, VolkswagenElectricVehicle, VolkswagenCombustionVehicle, \
    VolkswagenHybridVehicle
from carconnectivity_connectors.volkswagen.climatization import VolkswagenClimatization
from carconnectivity_connectors.volkswagen.capability import Capability
from carconnectivity_connectors.volkswagen._version import __version__
from carconnectivity_connectors.volkswagen.command_impl import SpinCommand
from carconnectivity_connectors.volkswagen.charging import VolkswagenCharging, mapping_volskwagen_charging_state


SUPPORT_IMAGES = False
SUPPORT_IMAGES_STR: str = ""
try:
    from PIL import Image
    import base64
    import io
    SUPPORT_IMAGES = True
    from carconnectivity.attributes import ImageAttribute
except ImportError as exc:
    if str(exc) == "No module named 'PIL'":
        SUPPORT_IMAGES_STR = str(exc) + " (cannot find pillow library)"
    else:
        SUPPORT_IMAGES_STR = str(exc)  # pylint: disable=invalid-name

if TYPE_CHECKING:
    from typing import Dict, List, Optional, Any, Union

    from carconnectivity.carconnectivity import CarConnectivity

LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen")
LOG_API: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen-api-debug")


# pylint: disable=too-many-lines
class Connector(BaseConnector):
    """
    Connector class for Volkswagen API connectivity.
    Args:
        car_connectivity (CarConnectivity): An instance of CarConnectivity.
        config (Dict): Configuration dictionary containing connection details.
    Attributes:
        max_age (Optional[int]): Maximum age for cached data in seconds.
    """
    def __init__(self, connector_id: str, car_connectivity: CarConnectivity, config: Dict, initialization: Optional[Dict] = None) -> None:
        BaseConnector.__init__(self, connector_id=connector_id, car_connectivity=car_connectivity, config=config, log=LOG, api_log=LOG_API,
                               initialization=initialization)

        self._background_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.connection_state: EnumAttribute[ConnectionState] = EnumAttribute(name="connection_state", parent=self, value_type=ConnectionState,
                                                                              value=ConnectionState.DISCONNECTED, tags={'connector_custom'})
        self.interval: DurationAttribute = DurationAttribute(name="interval", parent=self, tags={'connector_custom'})
        self.interval.minimum = timedelta(seconds=180)
        self.interval._is_changeable = True  # pylint: disable=protected-access

        self.commands: Commands = Commands(parent=self)

        LOG.info("Loading volkswagen connector with config %s", config_remove_credentials(config))

        if 'spin' in config and config['spin'] is not None:
            self.active_config['spin'] = config['spin']
        else:
            self.active_config['spin'] = None

        self.active_config['username'] = None
        self.active_config['password'] = None
        if 'username' in config and 'password' in config:
            self.active_config['username'] = config['username']
            self.active_config['password'] = config['password']
        else:
            if 'netrc' in config:
                self.active_config['netrc'] = config['netrc']
            else:
                self.active_config['netrc'] = os.path.join(os.path.expanduser("~"), ".netrc")
            try:
                secrets = netrc.netrc(file=self.active_config['netrc'])
                secret: tuple[str, str, str] | None = secrets.authenticators("volkswagen")
                if secret is None:
                    raise AuthenticationError(f'Authentication using {self.active_config["netrc"]} failed: volkswagen not found in netrc')
                self.active_config['username'], account, self.active_config['password'] = secret

                if self.active_config['spin'] is None and account is not None:
                    try:
                        self.active_config['spin'] = account
                    except ValueError as err:
                        LOG.error('Could not parse spin from netrc: %s', err)
            except netrc.NetrcParseError as err:
                LOG.error('Authentification using %s failed: %s', self.active_config['netrc'], err)
                raise AuthenticationError(f'Authentication using {self.active_config["netrc"]} failed: {err}') from err
            except TypeError as err:
                if 'username' not in config:
                    raise AuthenticationError(f'"volkswagen" entry was not found in {self.active_config["netrc"]} netrc-file.'
                                              ' Create it or provide username and password in config') from err
            except FileNotFoundError as err:
                raise AuthenticationError(f'{self.active_config["netrc"]} netrc-file was not found. Create it or provide username and password in config') \
                                          from err

        self.active_config['interval'] = 300
        if 'interval' in config:
            self.active_config['interval'] = config['interval']
            if self.active_config['interval'] < 180:
                raise ValueError('Intervall must be at least 180 seconds')
        self.active_config['max_age'] = self.active_config['interval'] - 1
        if 'max_age' in config:
            self.active_config['max_age'] = config['max_age']
        self.interval._set_value(timedelta(seconds=self.active_config['interval']))  # pylint: disable=protected-access
        self.active_config['online_timeout'] = self.active_config['interval'] + 60
        if 'online_timeout' in config:
            self.active_config['online_timeout'] = config['online_timeout']
        self.online_timeout: timedelta = timedelta(seconds=self.active_config['online_timeout'])


        self.active_config['force_enable_access'] = False
        if 'force_enable_access' in config:
            self.active_config['force_enable_access'] = config['force_enable_access']

        if self.active_config['username'] is None or self.active_config['password'] is None:
            raise AuthenticationError('Username or password not provided')

        self._manager: SessionManager = SessionManager(tokenstore=car_connectivity.get_tokenstore(), cache=car_connectivity.get_cache())
        session: requests.Session = self._manager.get_session(Service.WE_CONNECT, SessionUser(username=self.active_config['username'],
                                                                                              password=self.active_config['password']))
        if not isinstance(session, WeConnectSession):
            raise AuthenticationError('Could not create session')
        self.session: WeConnectSession = session
        self.session.retries = 3
        self.session.timeout = 180
        # Check if tokens exist before attempting to refresh
        if self.session.token is not None and self.session.refresh_token is not None:
            LOG.debug("Existing tokens found, refreshing session")
            self.session.refresh()
        else:
            LOG.debug("No existing tokens found, performing initial login")
            self.session.login()

        self._elapsed: List[timedelta] = []

    def startup(self) -> None:
        self._background_thread = threading.Thread(target=self._background_loop, daemon=False)
        self._background_thread.name = 'carconnectivity.connectors.volkswagen-background'
        self._background_thread.start()
        self.healthy._set_value(value=True)  # pylint: disable=protected-access

    def _background_loop(self) -> None:
        self._stop_event.clear()
        fetch: bool = True
        self.connection_state._set_value(value=ConnectionState.CONNECTING)  # pylint: disable=protected-access
        while not self._stop_event.is_set():
            interval = 300
            try:
                try:
                    if fetch:
                        self.fetch_all()
                        fetch = False
                    else:
                        self.update_vehicles()
                    self.last_update._set_value(value=datetime.now(tz=timezone.utc))  # pylint: disable=protected-access
                    if self.interval.value is not None:
                        interval: float = self.interval.value.total_seconds()
                except Exception:
                    self.connection_state._set_value(value=ConnectionState.ERROR)  # pylint: disable=protected-access
                    if self.interval.value is not None:
                        interval: float = self.interval.value.total_seconds()
                    raise
            except TooManyRequestsError as err:
                LOG.error('Retrieval error during update. Too many requests from your account (%s). Will try again after 15 minutes', str(err))
                self.connection_state._set_value(value=ConnectionState.ERROR)  # pylint: disable=protected-access
                self._stop_event.wait(900)
            except RetrievalError as err:
                LOG.error('Retrieval error during update (%s). Will try again after configured interval of %ss', str(err), interval)
                self.connection_state._set_value(value=ConnectionState.ERROR)  # pylint: disable=protected-access
                self._stop_event.wait(interval)
            except APICompatibilityError as err:
                LOG.error('API compatability error during update (%s). Will try again after configured interval of %ss', str(err), interval)
                self.connection_state._set_value(value=ConnectionState.ERROR)  # pylint: disable=protected-access
                self._stop_event.wait(interval)
            except TemporaryAuthenticationError as err:
                LOG.error('Temporary authentification error during update (%s). Will try again after configured interval of %ss', str(err), interval)
                self.connection_state._set_value(value=ConnectionState.ERROR)  # pylint: disable=protected-access
                self._stop_event.wait(interval)
            except Exception as err:
                LOG.critical('Critical error during update: %s', traceback.format_exc())
                self.healthy._set_value(value=False)  # pylint: disable=protected-access
                self.connection_state._set_value(value=ConnectionState.ERROR)  # pylint: disable=protected-access
                raise err
            else:
                self.connection_state._set_value(value=ConnectionState.CONNECTED)  # pylint: disable=protected-access
                self._stop_event.wait(interval)
        # When leaving the loop, set the connection state to disconnected
        self.connection_state._set_value(value=ConnectionState.DISCONNECTED)  # pylint: disable=protected-access

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
        # Disable and remove all vehicles managed soley by this connector
        for vehicle in self.car_connectivity.garage.list_vehicles():
            if len(vehicle.managing_connectors) == 1 and self in vehicle.managing_connectors:
                self.car_connectivity.garage.remove_vehicle(vehicle.id)
                vehicle.enabled = False
        self._stop_event.set()
        self.session.close()
        if self._background_thread is not None:
            self._background_thread.join()
        self.persist()
        BaseConnector.shutdown(self)

    def fetch_all(self) -> None:
        """
        Fetches all necessary data for the connector.

        This method calls the `fetch_vehicles` method to retrieve vehicle data.
        """
        # Add spin command
        if self.commands is not None and not self.commands.contains_command('spin'):
            spin_command = SpinCommand(parent=self.commands)
            spin_command._add_on_set_hook(self.__on_spin)  # pylint: disable=protected-access
            spin_command.enabled = True
            self.commands.add_command(spin_command)
        self.fetch_vehicles()

    def update_vehicles(self) -> None:
        """
        Updates the status of all vehicles in the garage managed by this connector.

        This method iterates through all vehicle VINs in the garage, and for each vehicle that is
        managed by this connector and is an instance of VolkswagenVehicle, it updates the vehicle's status
        by fetching data from various APIs. If the vehicle is an instance of VolkswagenElectricVehicle,
        it also fetches charging information.

        Returns:
            None
        """
        garage: Garage = self.car_connectivity.garage
        for vin in set(garage.list_vehicle_vins()):
            vehicle_to_update: Optional[GenericVehicle] = garage.get_vehicle(vin)
            if vehicle_to_update is not None and isinstance(vehicle_to_update, VolkswagenVehicle) and vehicle_to_update.is_managed_by_connector(self):
                self.fetch_vehicle_status(vehicle_to_update)

                capability_parking_position: Optional[Capability] = vehicle_to_update.capabilities.get_capability('parkingPosition')
                if capability_parking_position is not None and capability_parking_position.enabled and len(capability_parking_position.status.value) == 0:
                    self.fetch_parking_position(vehicle_to_update)
                self.decide_state(vehicle_to_update)
        self.car_connectivity.transaction_end()

    def fetch_vehicles(self) -> None:
        """
        Fetches the list of vehicles from the Volkswagen Connect API and updates the garage with new vehicles.
        This method sends a request to the Volkswagen Connect API to retrieve the list of vehicles associated with the user's account.
        If new vehicles are found in the response, they are added to the garage.

        Returns:
            None
        """
        garage: Garage = self.car_connectivity.garage
        url = 'https://emea.bff.cariad.digital/vehicle/v1/vehicles'
        data: Dict[str, Any] | None = self._fetch_data(url, session=self.session)

        seen_vehicle_vins: set[str] = set()
        if data is not None:
            if 'data' in data and data['data'] is not None:
                for vehicle_dict in data['data']:
                    if 'vin' in vehicle_dict and vehicle_dict['vin'] is not None:
                        if vehicle_dict['vin'] in self.active_config['hide_vins']:
                            LOG.info('Vehicle %s filtered out due to configuration', vehicle_dict['vin'])
                            continue
                        seen_vehicle_vins.add(vehicle_dict['vin'])
                        vehicle: Optional[VolkswagenVehicle] = garage.get_vehicle(vehicle_dict['vin'])  # pyright: ignore[reportAssignmentType]
                        if vehicle is None:
                            vehicle = VolkswagenVehicle(vin=vehicle_dict['vin'], garage=garage, managing_connector=self,
                                                        initialization=garage.get_initialization(vehicle_dict['vin']))
                            garage.add_vehicle(vehicle_dict['vin'], vehicle)

                        if 'nickname' in vehicle_dict and vehicle_dict['nickname'] is not None:
                            vehicle.name._set_value(vehicle_dict['nickname'])  # pylint: disable=protected-access
                        else:
                            vehicle.name._set_value(None)  # pylint: disable=protected-access

                        if 'model' in vehicle_dict and vehicle_dict['model'] is not None:
                            vehicle.model._set_value(vehicle_dict['model'])  # pylint: disable=protected-access
                        else:
                            vehicle.model._set_value(None)  # pylint: disable=protected-access

                        if 'capabilities' in vehicle_dict and vehicle_dict['capabilities'] is not None:
                            found_capabilities = set()
                            for capability_dict in vehicle_dict['capabilities']:
                                if 'id' in capability_dict and capability_dict['id'] is not None:
                                    capability_id = capability_dict['id']
                                    found_capabilities.add(capability_id)
                                    if vehicle.capabilities.has_capability(capability_id):
                                        capability: Capability = vehicle.capabilities.get_capability(capability_id)  # pyright: ignore[reportAssignmentType]
                                    else:
                                        capability = Capability(capability_id=capability_id, capabilities=vehicle.capabilities,
                                                                initialization=vehicle.capabilities.get_initialization(capability_id))
                                        vehicle.capabilities.add_capability(capability_id, capability)
                                    if 'expirationDate' in capability_dict and capability_dict['expirationDate'] is not None:
                                        expiration_date: datetime = robust_time_parse(capability_dict['expirationDate'])
                                        capability.expiration_date._set_value(expiration_date)  # pylint: disable=protected-access
                                    else:
                                        capability.expiration_date._set_value(None)  # pylint: disable=protected-access
                                    if 'userDisablingAllowed' in capability_dict and capability_dict['userDisablingAllowed'] is not None:
                                        # pylint: disable-next=protected-access
                                        capability.user_disabling_allowed._set_value(capability_dict['userDisablingAllowed'])
                                    else:
                                        capability.user_disabling_allowed._set_value(None)  # pylint: disable=protected-access
                                    if 'status' in capability_dict and capability_dict['status'] is not None:
                                        statuses = capability_dict['status']
                                        if isinstance(statuses, list):
                                            for status in statuses:
                                                if status in [item.value for item in Capability.Status]:
                                                    capability.status.value.append(Capability.Status(status))
                                                else:
                                                    LOG_API.warning('Capability status unkown %s', status)
                                                    capability.status.value.append(Capability.Status.UNKNOWN)
                                        else:
                                            LOG_API.warning('Capability status not a list in %s', statuses)
                                    else:
                                        capability.status.value.clear()
                                    log_extra_keys(LOG_API, 'capability', capability_dict, {'id', 'expirationDate', 'userDisablingAllowed', 'status'})
                                else:
                                    raise APIError('Could not fetch capabilities, capability ID missing')
                            for capability_id in vehicle.capabilities.capabilities.keys() - found_capabilities:
                                vehicle.capabilities.remove_capability(capability_id)
                        else:
                            vehicle.capabilities.clear_capabilities()

                        capability_wakeup: Optional[Capability] = vehicle.capabilities.get_capability('vehicleWakeUpTrigger')
                        if capability_wakeup is not None and capability_wakeup.enabled and len(capability_wakeup.status.value) == 0:
                            if vehicle.commands is not None and vehicle.commands.commands is not None \
                                    and not vehicle.commands.contains_command('wake-sleep'):
                                wake_sleep_command = WakeSleepCommand(parent=vehicle.commands)
                                wake_sleep_command._add_on_set_hook(self.__on_wake_sleep)  # pylint: disable=protected-access
                                wake_sleep_command.enabled = True
                                vehicle.commands.add_command(wake_sleep_command)

                        # Add honkAndFlash command if necessary capabilities are available
                        capability_honk_and_flash: Optional[Capability] = vehicle.capabilities.get_capability('honkAndFlash')
                        if capability_honk_and_flash is not None and capability_honk_and_flash.enabled and len(capability_honk_and_flash.status.value) == 0:
                            if vehicle.commands is not None and vehicle.commands.commands is not None \
                                    and not vehicle.commands.contains_command('honk-flash'):
                                honk_flash_command = HonkAndFlashCommand(parent=vehicle.commands, with_duration=True)
                                honk_flash_command._add_on_set_hook(self.__on_honk_flash)  # pylint: disable=protected-access
                                honk_flash_command.enabled = True
                                vehicle.commands.add_command(honk_flash_command)

                        # Add lock and unlock command
                        capability_access: Optional[Capability] = vehicle.capabilities.get_capability('access')
                        if capability_access is not None and capability_access.enabled and len(capability_access.status.value) == 0:
                            if vehicle.doors is not None and vehicle.doors.commands is not None and vehicle.doors.commands.commands is not None \
                                    and not vehicle.doors.commands.contains_command('lock-unlock'):
                                lock_unlock_command = LockUnlockCommand(parent=vehicle.doors.commands)
                                lock_unlock_command._add_on_set_hook(self.__on_lock_unlock)  # pylint: disable=protected-access
                                lock_unlock_command.enabled = True
                                vehicle.doors.commands.add_command(lock_unlock_command)

                        if SUPPORT_IMAGES:
                            # fetch vehcile images
                            url: str = f'https://emea.bff.cariad.digital/media/v2/vehicle-images/{vehicle_dict["vin"]}?resolution=2x'
                            data = self._fetch_data(url, session=self.session, allow_http_error=True)
                            if data is not None and 'data' in data:  # pylint: disable=too-many-nested-blocks
                                for image in data['data']:
                                    img = None
                                    cache_date = None
                                    imageurl: str = image['url']
                                    if self.active_config['max_age'] is not None and self.session.cache is not None and imageurl in self.session.cache:
                                        img, cache_date_string = self.session.cache[imageurl]
                                        img = base64.b64decode(img)  # pyright: ignore[reportPossiblyUnboundVariable]
                                        img = Image.open(io.BytesIO(img))  # pyright: ignore[reportPossiblyUnboundVariable]
                                        cache_date = datetime.fromisoformat(cache_date_string)
                                    if img is None or self.active_config['max_age'] is None \
                                            or (cache_date is not None and cache_date < (datetime.utcnow() - timedelta(seconds=self.active_config['max_age']))):
                                        try:
                                            image_download_response = self.session.get(imageurl, stream=True)
                                            if image_download_response.status_code == requests.codes['ok']:
                                                img = Image.open(image_download_response.raw)  # pyright: ignore[reportPossiblyUnboundVariable]
                                                if self.session.cache is not None:
                                                    buffered = io.BytesIO()  # pyright: ignore[reportPossiblyUnboundVariable]
                                                    img.save(buffered, format="PNG")
                                                    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")  # pyright: ignore[reportPossiblyUnboundVariable]
                                                    self.session.cache[imageurl] = (img_str, str(datetime.utcnow()))
                                            elif image_download_response.status_code == requests.codes['unauthorized']:
                                                LOG.info('Server asks for new authorization')
                                                self.session.login()
                                                image_download_response = self.session.get(imageurl, stream=True)
                                                if image_download_response.status_code == requests.codes['ok']:
                                                    img = Image.open(image_download_response.raw)  # pyright: ignore[reportPossiblyUnboundVariable]
                                                    if self.session.cache is not None:
                                                        buffered = io.BytesIO()  # pyright: ignore[reportPossiblyUnboundVariable]
                                                        img.save(buffered, format="PNG")
                                                        img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")  # pyright: ignore[reportPossiblyUnboundVariable]
                                                        self.session.cache[imageurl] = (img_str, str(datetime.utcnow()))
                                        except requests.exceptions.ConnectionError as connection_error:
                                            raise RetrievalError(f'Connection error: {connection_error}') from connection_error
                                        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
                                            raise RetrievalError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
                                        except requests.exceptions.ReadTimeout as timeout_error:
                                            raise RetrievalError(f'Timeout during read: {timeout_error}') from timeout_error
                                        except requests.exceptions.RetryError as retry_error:
                                            raise RetrievalError(f'Retrying failed: {retry_error}') from retry_error
                                    if img is not None:
                                        vehicle._car_images[image['id']] = img  # pylint: disable=protected-access
                                        if image['id'] == 'car_34view':
                                            if 'car_picture' in vehicle.images.images:
                                                vehicle.images.images['car_picture']._set_value(img)  # pylint: disable=protected-access
                                            else:
                                                vehicle.images.images['car_picture'] = ImageAttribute(name="car_picture", parent=vehicle.images,
                                                                                                      value=img, tags={'carconnectivity'})
                    else:
                        raise APIError('Could not fetch vehicle data, VIN missing')
        for vin in set(garage.list_vehicle_vins()) - seen_vehicle_vins:
            vehicle_to_remove = garage.get_vehicle(vin)
            if vehicle_to_remove is not None and vehicle_to_remove.is_managed_by_connector(self):
                garage.remove_vehicle(vin)
        self.update_vehicles()

    def decide_state(self, vehicle: VolkswagenVehicle) -> None:
        """
        Decides the state of the vehicle based on the current data.

        Args:
            vehicle (VolkswagenVehicle): The Volkswagen vehicle object.
        """
        if vehicle is not None:
            if vehicle.connection_state is not None and vehicle.connection_state.enabled \
                    and vehicle.connection_state.value == GenericVehicle.ConnectionState.OFFLINE:
                vehicle.state._set_value(GenericVehicle.State.OFFLINE, measured=vehicle.connection_state.last_updated)  # pylint: disable=protected-access
            elif vehicle.is_active is not None and vehicle.is_active.enabled and vehicle.is_active.value:
                vehicle.state._set_value(GenericVehicle.State.IGNITION_ON, measured=vehicle.is_active.last_updated)  # pylint: disable=protected-access
            elif vehicle.position is not None and vehicle.position.enabled and vehicle.position.position_type is not None \
                    and vehicle.position.position_type.enabled and vehicle.position.position_type.value == Position.PositionType.PARKING:
                vehicle.state._set_value(GenericVehicle.State.PARKED, measured=vehicle.position.position_type.last_updated)  # pylint: disable=protected-access
            else:
                vehicle.state._set_value(GenericVehicle.State.UNKNOWN)  # pylint: disable=protected-access

    def fetch_vehicle_status(self, vehicle: VolkswagenVehicle) -> None:
        """
        Fetches the status of a vehicle from the Volkswagen API.

        Args:
            vehicle (GenericVehicle): The vehicle object containing the VIN.

        Returns:
            None
        """
        vin = vehicle.vin.value
        if vin is None:
            raise ValueError('vehicle.vin cannot be None')
        known_capabilities: list[str] = ['access',
                                         'activeventilation',
                                         'automation',
                                         'auxiliaryheating',
                                         'userCapabilities',
                                         'charging',
                                         'chargingProfiles',
                                         'batteryChargingCare',
                                         'climatisation',
                                         'climatisationTimers',
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
            capability: Optional[Capability] = vehicle.capabilities.get_capability(capability_id)
            if capability is not None and capability.enabled and len(capability.status.value) == 0:
                jobs.append(capability_id)
        if len(jobs) == 0:
            LOG.warning('No capabilities enabled for vehicle %s', vin)
            return

        if 'access' not in jobs and 'access' in known_capabilities and self.active_config['force_enable_access']:
            LOG_API.debug('Adding "access" capability to API request despite not being in vehicle capabilities (VW API)')
            jobs.append('access')
            LOG_API.debug('Updated jobs list: %s', jobs)

        url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/selectivestatus?jobs=' + ','.join(jobs)
        data: Dict[str, Any] | None = self._fetch_data(url, self.session)
        if data is not None:
            if 'fuelStatus' in data and data['fuelStatus'] is not None:
                if 'rangeStatus' in data['fuelStatus'] and data['fuelStatus']['rangeStatus'] is not None:
                    if 'value' in data['fuelStatus']['rangeStatus'] and data['fuelStatus']['rangeStatus']['value'] is not None:
                        range_status = data['fuelStatus']['rangeStatus']['value']
                        if 'carCapturedTimestamp' not in range_status or range_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(range_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'carType' in range_status and range_status['carType'] is not None:
                            try:
                                car_type = GenericVehicle.Type(range_status['carType'])
                                if car_type == GenericVehicle.Type.ELECTRIC and not isinstance(vehicle, VolkswagenElectricVehicle):
                                    LOG.debug('Promoting %s to VolkswagenElectricVehicle object for %s', vehicle.__class__.__name__, vin)
                                    vehicle = VolkswagenElectricVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                    self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                elif car_type in [GenericVehicle.Type.FUEL,
                                                  GenericVehicle.Type.GASOLINE,
                                                  GenericVehicle.Type.PETROL,
                                                  GenericVehicle.Type.DIESEL,
                                                  GenericVehicle.Type.CNG,
                                                  GenericVehicle.Type.LPG] \
                                        and not isinstance(vehicle, VolkswagenCombustionVehicle):
                                    # try to work around bug in API that shows hybrid cars as combustion cars
                                    if car_type == GenericVehicle.Type.GASOLINE and vehicle.capabilities.has_capability('charging'):
                                        car_type = GenericVehicle.Type.HYBRID
                                        if not isinstance(vehicle, VolkswagenHybridVehicle):
                                            LOG.debug('Promoting %s to VolkswagenHybridVehicle object for %s', vehicle.__class__.__name__, vin)
                                            vehicle = VolkswagenHybridVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                            self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                    else:
                                        LOG.debug('Promoting %s to VolkswagenCombustionVehicle object for %s', vehicle.__class__.__name__, vin)
                                        vehicle = VolkswagenCombustionVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                        self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                elif car_type == GenericVehicle.Type.HYBRID and not isinstance(vehicle, VolkswagenHybridVehicle):
                                    LOG.debug('Promoting %s to VolkswagenHybridVehicle object for %s', vehicle.__class__.__name__, vin)
                                    vehicle = VolkswagenHybridVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                    self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                vehicle.type._set_value(car_type)  # pylint: disable=protected-access
                            except ValueError:
                                LOG_API.warning('Unknown car type %s', range_status['carType'])
                        drive_ids: set[str] = {'primary', 'secondary'}
                        total_range: float = 0
                        for drive_id in drive_ids:
                            if f'{drive_id}Engine' in range_status and range_status[f'{drive_id}Engine'] is not None:
                                try:
                                    engine_type: GenericDrive.Type = GenericDrive.Type(range_status[f'{drive_id}Engine']['type'])
                                except ValueError:
                                    LOG_API.warning('Unknown engine_type type %s', range_status[f'{drive_id}Engine']['type'])
                                    engine_type: GenericDrive.Type = GenericDrive.Type.UNKNOWN

                                if drive_id in vehicle.drives.drives:
                                    drive: GenericDrive = vehicle.drives.drives[drive_id]
                                else:
                                    if engine_type == GenericDrive.Type.ELECTRIC:
                                        drive = ElectricDrive(drive_id=drive_id, drives=vehicle.drives,
                                                              initialization=vehicle.drives.get_initialization(drive_id))
                                    elif engine_type == GenericDrive.Type.DIESEL:
                                        drive = DieselDrive(drive_id=drive_id, drives=vehicle.drives,
                                                            initialization=vehicle.drives.get_initialization(drive_id))
                                    elif engine_type in [GenericDrive.Type.FUEL,
                                                         GenericDrive.Type.GASOLINE,
                                                         GenericDrive.Type.PETROL,
                                                         GenericDrive.Type.CNG,
                                                         GenericDrive.Type.LPG]:
                                        drive = CombustionDrive(drive_id=drive_id, drives=vehicle.drives,
                                                                initialization=vehicle.drives.get_initialization(drive_id))
                                    else:
                                        drive = GenericDrive(drive_id=drive_id, drives=vehicle.drives,
                                                             initialization=vehicle.drives.get_initialization(drive_id))
                                    drive.type._set_value(engine_type)  # pylint: disable=protected-access
                                    vehicle.drives.add_drive(drive)
                                if 'currentSOC_pct' in range_status[f'{drive_id}Engine'] \
                                        and range_status[f'{drive_id}Engine']['currentSOC_pct'] is not None:
                                    # pylint: disable-next=protected-access
                                    drive.level._set_value(value=range_status[f'{drive_id}Engine']['currentSOC_pct'], measured=captured_at)
                                    drive.level.precision = 1
                                elif 'currentFuelLevel_pct' in range_status[f'{drive_id}Engine'] \
                                        and range_status[f'{drive_id}Engine']['currentFuelLevel_pct'] is not None:
                                    # pylint: disable-next=protected-access
                                    drive.level._set_value(value=range_status[f'{drive_id}Engine']['currentFuelLevel_pct'], measured=captured_at)
                                    drive.level.precision = 1
                                else:
                                    drive.level._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                                if 'remainingRange_km' in range_status[f'{drive_id}Engine'] \
                                        and range_status[f'{drive_id}Engine']['remainingRange_km'] is not None:
                                    # pylint: disable-next=protected-access
                                    drive.range._set_value(value=range_status[f'{drive_id}Engine']['remainingRange_km'], measured=captured_at, unit=Length.KM)
                                    drive.range.precision = 1
                                    total_range += range_status[f'{drive_id}Engine']['remainingRange_km']
                                else:
                                    drive.range._set_value(None, measured=captured_at, unit=Length.KM)  # pylint: disable=protected-access

                                log_extra_keys(LOG_API, f'{drive_id}Engine', range_status[f'{drive_id}Engine'], {'type',
                                                                                                                 'currentSOC_pct',
                                                                                                                 'currentFuelLevel_pct'
                                                                                                                 'remainingRange_km'})
                        if 'totalRange_km' in range_status and range_status['totalRange_km'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.drives.total_range._set_value(value=range_status['totalRange_km'], measured=captured_at, unit=Length.KM)
                            vehicle.drives.total_range.precision = 1
                        else:
                            if total_range > 0:
                                # pylint: disable-next=protected-access
                                vehicle.drives.total_range._set_value(value=total_range, measured=captured_at, unit=Length.KM)
                            else:
                                vehicle.drives.total_range._set_value(None)  # pylint: disable=protected-access
                        if 'adBlueRange' in range_status and range_status['adBlueRange'] is not None:
                            for drive in vehicle.drives.drives.values():
                                if isinstance(drive, DieselDrive):
                                    # pylint: disable-next=protected-access
                                    drive.adblue_range._set_value(value=range_status['adBlueRange'], measured=captured_at, unit=Length.KM)
                                    drive.adblue_range.precision = 1
                        log_extra_keys(LOG_API, 'rangeStatus', range_status, {'carCapturedTimestamp', 'carType', 'primaryEngine', 'secondaryEngine',
                                                                              'totalRange_km', 'adBlueRange', 'dieselRange'})
                    else:
                        vehicle.drives.enabled = False
                else:
                    vehicle.drives.enabled = False
            else:
                vehicle.drives.enabled = False

            if 'measurements' in data and data['measurements'] is not None:
                if 'fuelLevelStatus' in data['measurements'] and data['measurements']['fuelLevelStatus'] is not None:
                    if 'value' in data['measurements']['fuelLevelStatus'] and data['measurements']['fuelLevelStatus']['value'] is not None:
                        fuel_level_status = data['measurements']['fuelLevelStatus']['value']
                        captured_at: datetime = robust_time_parse(fuel_level_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        # Check vehicle type and if it does not match the current vehicle type, create a new vehicle object using copy constructor
                        if 'carType' in fuel_level_status and fuel_level_status['carType'] is not None:
                            try:
                                car_type = GenericVehicle.Type(fuel_level_status['carType'])
                                if car_type == GenericVehicle.Type.ELECTRIC and not isinstance(vehicle, VolkswagenElectricVehicle):
                                    LOG.debug('Promoting %s to VolkswagenElectricVehicle object for %s', vehicle.__class__.__name__, vin)
                                    vehicle = VolkswagenElectricVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                    self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                elif car_type in [GenericVehicle.Type.FUEL,
                                                  GenericVehicle.Type.GASOLINE,
                                                  GenericVehicle.Type.PETROL,
                                                  GenericVehicle.Type.DIESEL,
                                                  GenericVehicle.Type.CNG,
                                                  GenericVehicle.Type.LPG] \
                                        and not isinstance(vehicle, VolkswagenCombustionVehicle):
                                    # try to work around bug in API that shows hybrid cars as combustion cars
                                    if car_type == GenericVehicle.Type.GASOLINE and vehicle.capabilities.has_capability('charging'):
                                        car_type = GenericVehicle.Type.HYBRID
                                        if not isinstance(vehicle, VolkswagenHybridVehicle):
                                            LOG.debug('Promoting %s to VolkswagenHybridVehicle object for %s', vehicle.__class__.__name__, vin)
                                            vehicle = VolkswagenHybridVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                            self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                    else:
                                        LOG.debug('Promoting %s to VolkswagenCombustionVehicle object for %s', vehicle.__class__.__name__, vin)
                                        vehicle = VolkswagenCombustionVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                        self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                elif car_type == GenericVehicle.Type.HYBRID and not isinstance(vehicle, VolkswagenHybridVehicle):
                                    LOG.debug('Promoting %s to VolkswagenHybridVehicle object for %s', vehicle.__class__.__name__, vin)
                                    vehicle = VolkswagenHybridVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                                    self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                                vehicle.type._set_value(car_type)  # pylint: disable=protected-access
                            except ValueError:
                                LOG_API.warning('Unknown car type %s', fuel_level_status['carType'])
                        drive_ids: set[str] = {'primary', 'secondary'}
                        for drive_id in drive_ids:
                            if f'{drive_id}EngineType' in fuel_level_status and fuel_level_status[f'{drive_id}EngineType'] is not None:
                                try:
                                    engine_type: GenericDrive.Type = GenericDrive.Type(fuel_level_status[f'{drive_id}EngineType'])
                                except ValueError:
                                    LOG_API.warning('Unknown engine_type type %s', fuel_level_status[f'{drive_id}EngineType'])
                                    engine_type: GenericDrive.Type = GenericDrive.Type.UNKNOWN

                                if drive_id in vehicle.drives.drives:
                                    drive: GenericDrive = vehicle.drives.drives[drive_id]
                                else:
                                    if engine_type == GenericDrive.Type.ELECTRIC:
                                        drive = ElectricDrive(drive_id=drive_id, drives=vehicle.drives,
                                                              initialization=vehicle.drives.get_initialization(drive_id))
                                    elif engine_type == GenericDrive.Type.DIESEL:
                                        drive = DieselDrive(drive_id=drive_id, drives=vehicle.drives,
                                                            initialization=vehicle.drives.get_initialization(drive_id))
                                    elif engine_type in [GenericDrive.Type.FUEL,
                                                         GenericDrive.Type.GASOLINE,
                                                         GenericDrive.Type.PETROL,
                                                         GenericDrive.Type.CNG,
                                                         GenericDrive.Type.LPG]:
                                        drive = CombustionDrive(drive_id=drive_id, drives=vehicle.drives,
                                                                initialization=vehicle.drives.get_initialization(drive_id))
                                    else:
                                        drive = GenericDrive(drive_id=drive_id, drives=vehicle.drives,
                                                             initialization=vehicle.drives.get_initialization(drive_id))
                                    drive.type._set_value(engine_type)  # pylint: disable=protected-access
                                    vehicle.drives.add_drive(drive)
                        if 'currentSOC_pct' in fuel_level_status and fuel_level_status['currentSOC_pct'] is not None \
                                and isinstance(vehicle, VolkswagenElectricVehicle):
                            electric_drive: Optional[ElectricDrive] = vehicle.get_electric_drive()
                            if electric_drive is not None:
                                # pylint: disable-next=protected-access
                                electric_drive.level._set_value(value=fuel_level_status['currentSOC_pct'], measured=captured_at)
                                electric_drive.level.precision = 1
                        if 'currentFuelLevel_pct' in fuel_level_status and fuel_level_status['currentFuelLevel_pct'] is not None \
                                and isinstance(vehicle, VolkswagenCombustionVehicle):
                            combustion_drive: Optional[CombustionDrive] = vehicle.get_combustion_drive()
                            if combustion_drive is not None:
                                # pylint: disable-next=protected-access
                                combustion_drive.level._set_value(value=fuel_level_status['currentFuelLevel_pct'], measured=captured_at)
                                combustion_drive.level.precision = 1
                        log_extra_keys(LOG_API, 'fuelLevelStatus', fuel_level_status, {'carCapturedTimestamp', 'carType', 'currentSOC_pct',
                                                                                       'currentFuelLevel_pct', 'primaryEngineType', 'secondaryEngineType'})
                if 'rangeStatus' in data['measurements'] and data['measurements']['rangeStatus'] is not None:
                    if 'value' in data['measurements']['rangeStatus'] and data['measurements']['rangeStatus']['value'] is not None:
                        range_status = data['measurements']['rangeStatus']['value']
                        if 'carCapturedTimestamp' not in range_status or range_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(range_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'electricRange' in range_status and range_status['electricRange'] is not None:
                            if isinstance(vehicle, VolkswagenElectricVehicle):
                                electric_drive: Optional[ElectricDrive] = vehicle.get_electric_drive()
                                if electric_drive is not None:
                                    # pylint: disable-next=protected-access
                                    electric_drive.range._set_value(value=range_status['electricRange'], measured=captured_at, unit=Length.KM)
                                    electric_drive.range.precision = 1
                        if 'gasolineRange' in range_status and range_status['gasolineRange'] is not None:
                            if isinstance(vehicle, VolkswagenCombustionVehicle):
                                combustion_drive: Optional[CombustionDrive] = vehicle.get_combustion_drive()
                                if combustion_drive is not None:
                                    # pylint: disable-next=protected-access
                                    combustion_drive.range._set_value(value=range_status['gasolineRange'], measured=captured_at, unit=Length.KM)
                                    combustion_drive.range.precision = 1
                        if 'totalRange_km' in range_status and range_status['totalRange_km'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.drives.total_range._set_value(value=range_status['totalRange_km'], measured=captured_at, unit=Length.KM)
                            vehicle.drives.total_range.precision = 1
                        log_extra_keys(LOG_API, 'rangeStatus', range_status, {'carCapturedTimestamp', 'electricRange', 'gasolineRange', 'totalRange_km'})
                if 'odometerStatus' in data['measurements'] and data['measurements']['odometerStatus'] is not None:
                    if 'value' in data['measurements']['odometerStatus'] and data['measurements']['odometerStatus']['value'] is not None:
                        odometer_status = data['measurements']['odometerStatus']['value']
                        if 'carCapturedTimestamp' not in odometer_status or odometer_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(odometer_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'odometer' in odometer_status and odometer_status['odometer'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.odometer._set_value(value=odometer_status['odometer'], measured=captured_at, unit=Length.KM)
                            vehicle.odometer.precision = 1
                        else:
                            vehicle.odometer._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API, 'odometerStatus', odometer_status, {'carCapturedTimestamp', 'odometer'})
                else:
                    vehicle.odometer._set_value(None)  # pylint: disable=protected-access
                if 'temperatureOutsideStatus' in data['measurements'] and data['measurements']['temperatureOutsideStatus'] is not None:
                    if 'value' in data['measurements']['temperatureOutsideStatus'] and data['measurements']['temperatureOutsideStatus']['value'] is not None:
                        temperature_outside_status = data['measurements']['temperatureOutsideStatus']['value']
                        if 'carCapturedTimestamp' not in temperature_outside_status or temperature_outside_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(temperature_outside_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'temperatureOutside_K' in temperature_outside_status and temperature_outside_status['temperatureOutside_K'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.outside_temperature._set_value(value=temperature_outside_status['temperatureOutside_K'], measured=captured_at,
                                                                   unit=Temperature.K)
                        else:
                            vehicle.outside_temperature._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                if 'temperatureBatteryStatus' in data['measurements'] and data['measurements']['temperatureBatteryStatus'] is not None:
                    if 'value' in data['measurements']['temperatureBatteryStatus'] and data['measurements']['temperatureBatteryStatus']['value'] is not None:
                        temperature_battery_status = data['measurements']['temperatureBatteryStatus']['value']
                        if isinstance(vehicle, VolkswagenElectricVehicle):
                            electric_drive: Optional[ElectricDrive] = vehicle.get_electric_drive()
                            if electric_drive is not None:
                                battery: Battery = electric_drive.battery
                                if 'carCapturedTimestamp' not in temperature_battery_status or temperature_battery_status['carCapturedTimestamp'] is None:
                                    raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                                captured_at: datetime = robust_time_parse(temperature_battery_status['carCapturedTimestamp'])
                                self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                                if 'temperatureHvBatteryMin_K' in temperature_battery_status \
                                        and temperature_battery_status['temperatureHvBatteryMin_K'] is not None:
                                    # pylint: disable-next=protected-access
                                    battery.temperature_min._set_value(value=temperature_battery_status['temperatureHvBatteryMin_K'], measured=captured_at,
                                                                       unit=Temperature.K)
                                else:
                                    battery.temperature_min._set_value(None)  # pylint: disable=protected-access
                                if 'temperatureHvBatteryMax_K' in temperature_battery_status \
                                        and temperature_battery_status['temperatureHvBatteryMax_K'] is not None:
                                    # pylint: disable-next=protected-access
                                    battery.temperature_max._set_value(value=temperature_battery_status['temperatureHvBatteryMax_K'], measured=captured_at,
                                                                       unit=Temperature.K)
                                else:
                                    battery.temperature_max._set_value(None)  # pylint: disable=protected-access
                                if battery.temperature_min.enabled and battery.temperature_min.value is not None \
                                        and battery.temperature_max.enabled and battery.temperature_max.value is not None:
                                    # pylint: disable-next=protected-access
                                    battery.temperature._set_value(value=(battery.temperature_min.value + battery.temperature_max.value) / 2,
                                                                   measured=captured_at, unit=Temperature.K)
                                else:
                                    battery.temperature._set_value(None)  # pylint: disable=protected-access
                                log_extra_keys(LOG_API, 'temperatureBatteryStatus', temperature_battery_status, {'carCapturedTimestamp',
                                                                                                                 'temperatureHvBatteryMin_K',
                                                                                                                 'temperatureHvBatteryMax_K'})
                log_extra_keys(LOG_API, 'measurements', data['measurements'], {'fuelLevelStatus', 'odometerStatus', 'temperatureOutsideStatus',
                                                                               'temperatureBatteryStatus', 'rangeStatus'})
            else:
                vehicle.odometer._set_value(None)  # pylint: disable=protected-access

            if 'access' in data and data['access'] is not None:
                if 'accessStatus' in data['access'] and data['access']['accessStatus'] is not None:
                    if 'value' in data['access']['accessStatus'] and data['access']['accessStatus']['value'] is not None:
                        access_status = data['access']['accessStatus']['value']
                        if 'carCapturedTimestamp' not in access_status or access_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(access_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        seen_door_ids: set[str] = set()
                        if 'doors' in access_status and access_status['doors'] is not None:
                            all_doors_closed = True
                            for door_status in access_status['doors']:
                                if 'name' in door_status and door_status['name'] is not None:
                                    door_id = door_status['name']
                                    seen_door_ids.add(door_id)
                                    if door_id in vehicle.doors.doors:
                                        door: Doors.Door = vehicle.doors.doors[door_id]
                                    else:
                                        door = Doors.Door(door_id=door_id, doors=vehicle.doors, initialization=vehicle.doors.get_initialization(door_id))
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
                                            LOG_API.info('Unknown door status %s', door_status['status'])
                                    else:
                                        door.open_state._set_value(None)  # pylint: disable=protected-access
                                        door.lock_state._set_value(None)  # pylint: disable=protected-access
                                else:
                                    raise APIError('Could not fetch door status, door ID missing')
                                log_extra_keys(LOG_API, 'doors', door_status, {'name', 'status'})
                            if all_doors_closed:
                                vehicle.doors.open_state._set_value(Doors.OpenState.CLOSED, measured=captured_at)  # pylint: disable=protected-access
                            else:
                                vehicle.doors.open_state._set_value(Doors.OpenState.OPEN, measured=captured_at)  # pylint: disable=protected-access
                            if 'doorLockStatus' in access_status and access_status['doorLockStatus'] is not None:
                                if access_status['doorLockStatus'] == 'locked':
                                    vehicle.doors.lock_state._set_value(Doors.LockState.LOCKED, measured=captured_at)  # pylint: disable=protected-access
                                elif access_status['doorLockStatus'] == 'unlocked':
                                    vehicle.doors.lock_state._set_value(Doors.LockState.UNLOCKED, measured=captured_at)  # pylint: disable=protected-access
                                elif access_status['doorLockStatus'] == 'invalid':
                                    vehicle.doors.lock_state._set_value(Doors.LockState.INVALID, measured=captured_at)  # pylint: disable=protected-access
                                else:
                                    LOG_API.info('Unknown door lock status %s', access_status['doorLockStatus'])
                                    vehicle.doors.lock_state._set_value(Doors.LockState.UNKNOWN, measured=captured_at)  # pylint: disable=protected-access
                            else:
                                vehicle.doors.lock_state._set_value(None, measured=captured_at)  # pylint: disable=protected-access

                        else:
                            vehicle.doors.open_state._set_value(None)  # pylint: disable=protected-access
                        for door_id in vehicle.doors.doors.keys() - seen_door_ids:
                            vehicle.doors.doors[door_id].enabled = False
                        if 'overallStatus' in access_status and access_status['overallStatus'] is not None:
                            if access_status['overallStatus'] == 'safe':
                                vehicle.doors.lock_state._set_value(Doors.LockState.LOCKED, measured=captured_at)  # pylint: disable=protected-access
                            elif access_status['overallStatus'] == 'unsafe':
                                vehicle.doors.lock_state._set_value(Doors.LockState.UNLOCKED, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.doors.lock_state._set_value(None)  # pylint: disable=protected-access
                        seen_window_ids: set[str] = set()
                        if 'windows' in access_status and access_status['windows'] is not None:
                            all_windows_closed = True
                            for window_status in access_status['windows']:
                                if 'name' in window_status and window_status['name'] is not None:
                                    window_id = window_status['name']
                                    seen_window_ids.add(window_id)
                                    if window_id in vehicle.windows.windows:
                                        window: Windows.Window = vehicle.windows.windows[window_id]
                                    else:
                                        window = Windows.Window(window_id=window_id, windows=vehicle.windows, initialization=vehicle.windows.get_initialization(window_id))
                                        vehicle.windows.windows[window_id] = window
                                    if 'status' in window_status and window_status['status'] is not None:
                                        if 'closed' in window_status['status']:
                                            window.open_state._set_value(Windows.OpenState.CLOSED, measured=captured_at)  # pylint: disable=protected-access
                                        elif 'open' in window_status['status']:
                                            all_windows_closed = False
                                            window.open_state._set_value(Windows.OpenState.OPEN, measured=captured_at)  # pylint: disable=protected-access
                                        elif 'unsupported' in window_status['status']:
                                            # pylint: disable-next=protected-access
                                            window.open_state._set_value(Windows.OpenState.UNSUPPORTED, measured=captured_at)
                                        elif 'invalid' in window_status['status']:
                                            window.open_state._set_value(Windows.OpenState.INVALID, measured=captured_at)  # pylint: disable=protected-access
                                        else:
                                            window.open_state._set_value(Windows.OpenState.UNKNOWN, measured=captured_at)  # pylint: disable=protected-access
                                            LOG_API.info('Unknown window status %s', window_status['status'])
                                    else:
                                        window.open_state._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                                else:
                                    raise APIError('Could not fetch window status, window ID missing')
                            if all_windows_closed:
                                vehicle.windows.open_state._set_value(Windows.OpenState.CLOSED, measured=captured_at)  # pylint: disable=protected-access
                            else:
                                vehicle.windows.open_state._set_value(Windows.OpenState.OPEN, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.windows.open_state._set_value(None)  # pylint: disable=protected-access
                        for window_id in vehicle.windows.windows.keys() - seen_window_ids:
                            vehicle.windows.windows[window_id].enabled = False
                        log_extra_keys(LOG_API, 'accessStatus', access_status, {'carCapturedTimestamp',
                                                                                'doors',
                                                                                'overallStatus',
                                                                                'doorLockStatus',
                                                                                'windows'})
                log_extra_keys(LOG_API, 'access', data['access'], {'accessStatus'})
            else:
                vehicle.doors.lock_state._set_value(None)  # pylint: disable=protected-access
                vehicle.doors.open_state._set_value(None)  # pylint: disable=protected-access
                vehicle.doors.enabled = False
            if 'vehicleLights' in data and data['vehicleLights'] is not None:
                if 'lightsStatus' in data['vehicleLights'] and data['vehicleLights']['lightsStatus'] is not None:
                    lights_status = data['vehicleLights']['lightsStatus']
                    seen_light_ids: set[str] = set()
                    if 'value' in lights_status and lights_status['value'] is not None:
                        lights_status = lights_status['value']
                        if 'carCapturedTimestamp' not in lights_status or lights_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(lights_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'lights' in lights_status and lights_status['lights'] is not None:
                            all_lights_off = True
                            for light_status in lights_status['lights']:
                                if 'name' in light_status and light_status['name'] is not None:
                                    light_id = light_status['name']
                                    seen_light_ids.add(light_id)
                                    if light_id in vehicle.lights.lights:
                                        light: Lights.Light = vehicle.lights.lights[light_id]
                                    else:
                                        light: Lights.Light = Lights.Light(light_id=light_id, lights=vehicle.lights,
                                                                           initialization=vehicle.lights.get_initialization(light_id))
                                        vehicle.lights.lights[light_id] = light
                                    if 'status' in light_status and light_status['status'] is not None:
                                        if light_status['status'] == 'on':
                                            all_lights_off = False
                                            light.light_state._set_value(Lights.LightState.ON, measured=captured_at)  # pylint: disable=protected-access
                                        elif light_status['status'] == 'off':
                                            light.light_state._set_value(Lights.LightState.OFF, measured=captured_at)  # pylint: disable=protected-access
                                        elif light_status['status'] == 'invalid':
                                            light.light_state._set_value(Lights.LightState.INVALID, measured=captured_at)  # pylint: disable=protected-access
                                        else:
                                            light.light_state._set_value(Lights.LightState.UNKNOWN, measured=captured_at)  # pylint: disable=protected-access
                                            LOG_API.info('Unknown light status %s', light_status['status'])
                                    else:
                                        light.light_state._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                                else:
                                    raise APIError('Could not fetch light status, light ID missing')
                                log_extra_keys(LOG_API, 'lights', light_status, {'name', 'status'})
                            if all_lights_off:
                                vehicle.lights.light_state._set_value(Lights.LightState.OFF, measured=captured_at)  # pylint: disable=protected-access
                            else:
                                vehicle.lights.light_state._set_value(Lights.LightState.ON, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.lights.light_state._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API, 'lights', lights_status, {'carCapturedTimestamp', 'lights'})
                    for light_id in vehicle.lights.lights.keys() - seen_light_ids:
                        vehicle.lights.lights[light_id].enabled = False
                else:
                    vehicle.lights.light_state._set_value(None)  # pylint: disable=protected-access
                    vehicle.lights.enabled = False
            else:
                vehicle.lights.light_state._set_value(None)  # pylint: disable=protected-access
                vehicle.lights.enabled = False
            if 'climatisation' in data and data['climatisation'] is not None:
                if not isinstance(vehicle.climatization, VolkswagenClimatization):
                    vehicle.climatization = VolkswagenClimatization(origin=vehicle.climatization)
                assert isinstance(vehicle.climatization.settings, VolkswagenClimatization.Settings)
                if vehicle.climatization is not None and vehicle.climatization.commands is not None \
                        and not vehicle.climatization.commands.contains_command('start-stop'):
                    start_stop_command = ClimatizationStartStopCommand(parent=vehicle.climatization.commands)
                    start_stop_command._add_on_set_hook(self.__on_air_conditioning_start_stop)  # pylint: disable=protected-access
                    start_stop_command.enabled = True
                    vehicle.climatization.commands.add_command(start_stop_command)
                if 'climatisationStatus' in data['climatisation'] and data['climatisation']['climatisationStatus'] is not None:
                    climatisation_status = data['climatisation']['climatisationStatus']
                    if 'value' in climatisation_status and climatisation_status['value'] is not None:
                        climatisation_status = climatisation_status['value']
                        if 'carCapturedTimestamp' not in climatisation_status or climatisation_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(climatisation_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'climatisationState' in climatisation_status and climatisation_status['climatisationState'] is not None:
                            if climatisation_status['climatisationState'] in [item.value for item in VolkswagenClimatization.ClimatizationState]:
                                climatization_state: VolkswagenClimatization.ClimatizationState = \
                                    VolkswagenClimatization.ClimatizationState(climatisation_status['climatisationState'])
                            else:
                                LOG_API.info('Unknown climatization state %s not in %s', climatisation_status['climatisationState'],
                                             str(VolkswagenClimatization.ClimatizationState))
                                climatization_state = VolkswagenClimatization.ClimatizationState.UNKNOWN
                            vehicle.climatization.state._set_value(value=climatization_state, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.climatization.state._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'remainingClimatisationTime_min' in climatisation_status and climatisation_status['remainingClimatisationTime_min'] is not None:
                            remaining_duration: timedelta = timedelta(minutes=climatisation_status['remainingClimatisationTime_min'])
                            estimated_date_reached: datetime = captured_at + remaining_duration
                            estimated_date_reached = estimated_date_reached.replace(second=0, microsecond=0)
                            # pylint: disable-next=protected-access
                            vehicle.climatization.estimated_date_reached._set_value(value=estimated_date_reached, measured=captured_at)
                        else:
                            vehicle.climatization.estimated_date_reached._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API, 'climatisationStatus', climatisation_status, {'carCapturedTimestamp', 'climatisationState',
                                                                                              'remainingClimatisationTime_min'})
                else:
                    vehicle.climatization.state._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.estimated_date_reached._set_value(None)  # pylint: disable=protected-access
                if 'climatisationSettings' in data['climatisation'] and data['climatisation']['climatisationSettings'] is not None:
                    climatisation_settings = data['climatisation']['climatisationSettings']
                    if 'value' in climatisation_settings and climatisation_settings['value'] is not None:
                        climatisation_settings = climatisation_settings['value']
                        if 'carCapturedTimestamp' not in climatisation_settings or climatisation_settings['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(climatisation_settings['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        preferred_unit: Temperature = Temperature.C
                        precision: float = 0.5
                        if 'unitInCar' in climatisation_settings and climatisation_settings['unitInCar'] is not None:
                            if climatisation_settings['unitInCar'] == 'farenheit':
                                preferred_unit = Temperature.F
                                vehicle.climatization.settings.unit_in_car = Temperature.F
                            elif climatisation_settings['unitInCar'] == 'celsius':
                                preferred_unit = Temperature.C
                                vehicle.climatization.settings.unit_in_car = Temperature.C
                            else:
                                LOG_API.info('Unknown unitInCar %s', climatisation_settings['unitInCar'])
                        if preferred_unit == Temperature.C and 'targetTemperature_C' in climatisation_settings:
                            target_temperature: Optional[float] = climatisation_settings['targetTemperature_C']
                            actual_unit: Optional[Temperature] = Temperature.C
                            min_temperature: Optional[float] = 16
                            max_temperature: Optional[float] = 29.5
                        elif preferred_unit == Temperature.F and 'targetTemperature_F' in climatisation_settings:
                            target_temperature = climatisation_settings['targetTemperature_F']
                            actual_unit = Temperature.F
                            min_temperature: Optional[float] = 61
                            max_temperature: Optional[float] = 85
                        elif 'targetTemperature_C' in climatisation_settings:
                            target_temperature = climatisation_settings['targetTemperature_C']
                            actual_unit = Temperature.C
                            min_temperature: Optional[float] = 16
                            max_temperature: Optional[float] = 29.5
                        elif 'targetTemperature_F' in climatisation_settings:
                            target_temperature = climatisation_settings['targetTemperature_F']
                            actual_unit = Temperature.F
                            min_temperature: Optional[float] = 61
                            max_temperature: Optional[float] = 85
                        else:
                            target_temperature = None
                            actual_unit = None
                            min_temperature: Optional[float] = None
                            max_temperature: Optional[float] = None
                        vehicle.climatization.settings.target_temperature._set_value(value=target_temperature,  # pylint: disable=protected-access
                                                                                     measured=captured_at,
                                                                                     unit=actual_unit)
                        vehicle.climatization.settings.target_temperature.minimum = min_temperature
                        vehicle.climatization.settings.target_temperature.maximum = max_temperature
                        vehicle.climatization.settings.target_temperature.precision = precision
                        # pylint: disable-next=protected-access
                        vehicle.climatization.settings.target_temperature._add_on_set_hook(self.__on_air_conditioning_settings_change)
                        vehicle.climatization.settings.target_temperature._is_changeable = True  # pylint: disable=protected-access
                        if 'climatisationWithoutExternalPower' in climatisation_settings \
                                and climatisation_settings['climatisationWithoutExternalPower'] is not None:
                            vehicle.climatization.settings.climatization_without_external_power._set_value(  # pylint: disable=protected-access
                                climatisation_settings['climatisationWithoutExternalPower'], measured=captured_at)
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.climatization_without_external_power._add_on_set_hook(self.__on_air_conditioning_settings_change)
                            vehicle.climatization.settings.climatization_without_external_power._is_changeable = True  # pylint: disable=protected-access
                        else:
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.climatization_without_external_power._set_value(None, measured=captured_at)
                        if 'climatizationAtUnlock' in climatisation_settings and climatisation_settings['climatizationAtUnlock'] is not None:
                            vehicle.climatization.settings.climatization_at_unlock._set_value(  # pylint: disable=protected-access
                                climatisation_settings['climatizationAtUnlock'], measured=captured_at)
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.climatization_at_unlock._add_on_set_hook(self.__on_air_conditioning_settings_change)
                            vehicle.climatization.settings.climatization_at_unlock._is_changeable = True  # pylint: disable=protected-access
                        else:
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.climatization_at_unlock._set_value(None, measured=captured_at)
                        if 'windowHeatingEnabled' in climatisation_settings and climatisation_settings['windowHeatingEnabled'] is not None:
                            vehicle.climatization.settings.window_heating._set_value(  # pylint: disable=protected-access
                                climatisation_settings['windowHeatingEnabled'], measured=captured_at)
                        # pylint: disable-next=protected-access
                            vehicle.climatization.settings.window_heating._add_on_set_hook(self.__on_air_conditioning_settings_change)
                            vehicle.climatization.settings.window_heating._is_changeable = True  # pylint: disable=protected-access
                        else:
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.window_heating._set_value(None, measured=captured_at)
                        if 'zoneFrontLeftEnabled' in climatisation_settings and climatisation_settings['zoneFrontLeftEnabled'] is not None:
                            vehicle.climatization.settings.front_zone_left_enabled._set_value(  # pylint: disable=protected-access
                                climatisation_settings['zoneFrontLeftEnabled'], measured=captured_at)
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.front_zone_left_enabled._add_on_set_hook(self.__on_air_conditioning_settings_change)
                            vehicle.climatization.settings.front_zone_left_enabled._is_changeable = True  # pylint: disable=protected-access
                        else:
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.front_zone_left_enabled._set_value(None, measured=captured_at)
                        if 'zoneFrontRightEnabled' in climatisation_settings and climatisation_settings['zoneFrontRightEnabled'] is not None:
                            vehicle.climatization.settings.front_zone_right_enabled._set_value(  # pylint: disable=protected-access
                                climatisation_settings['zoneFrontRightEnabled'], measured=captured_at)
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.front_zone_right_enabled._add_on_set_hook(self.__on_air_conditioning_settings_change)
                            vehicle.climatization.settings.front_zone_right_enabled._is_changeable = True  # pylint: disable=protected-access
                        else:
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.front_zone_right_enabled._set_value(None, measured=captured_at)
                        if 'zoneRearLeftEnabled' in climatisation_settings and climatisation_settings['zoneRearLeftEnabled'] is not None:
                            vehicle.climatization.settings.rear_zone_left_enabled._set_value(  # pylint: disable=protected-access
                                climatisation_settings['zoneRearLeftEnabled'], measured=captured_at)
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.rear_zone_left_enabled._add_on_set_hook(self.__on_air_conditioning_settings_change)
                            vehicle.climatization.settings.rear_zone_left_enabled._is_changeable = True  # pylint: disable=protected-access
                        else:
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.rear_zone_left_enabled._set_value(None, measured=captured_at)
                        if 'zoneRearRightEnabled' in climatisation_settings and climatisation_settings['zoneRearRightEnabled'] is not None:
                            vehicle.climatization.settings.rear_zone_right_enabled._set_value(  # pylint: disable=protected-access
                                climatisation_settings['zoneRearRightEnabled'], measured=captured_at)
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.rear_zone_right_enabled._add_on_set_hook(self.__on_air_conditioning_settings_change)
                            vehicle.climatization.settings.rear_zone_right_enabled._is_changeable = True  # pylint: disable=protected-access
                        else:
                            # pylint: disable-next=protected-access
                            vehicle.climatization.settings.rear_zone_right_enabled._set_value(None, measured=captured_at)
                        if vehicle.climatization.settings.front_zone_left_enabled.enabled \
                                or vehicle.climatization.settings.front_zone_right_enabled.enabled \
                                or vehicle.climatization.settings.rear_zone_left_enabled.enabled \
                                or vehicle.climatization.settings.rear_zone_right_enabled.enabled:
                            if vehicle.climatization.settings.front_zone_left_enabled.value \
                                    or vehicle.climatization.settings.front_zone_right_enabled.value \
                                    or vehicle.climatization.settings.rear_zone_left_enabled.value \
                                    or vehicle.climatization.settings.rear_zone_right_enabled.value:
                                vehicle.climatization.settings.seat_heating._set_value(True, measured=captured_at)  # pylint: disable=protected-access
                            else:
                                vehicle.climatization.settings.seat_heating._set_value(False, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.climatization.settings.seat_heating._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'heaterSource' in climatisation_settings and climatisation_settings['heaterSource'] is not None:
                            if climatisation_settings['heaterSource'] in [item.value for item in Climatization.Settings.HeaterSource]:
                                vehicle.climatization.settings.heater_source._set_value(  # pylint: disable=protected-access
                                    Climatization.Settings.HeaterSource(climatisation_settings['heaterSource']), measured=captured_at)
                            else:
                                LOG_API.info('Unknown heater source %s', climatisation_settings['heaterSource'])
                                # pylint: disable-next=protected-access
                                vehicle.climatization.settings.heater_source._set_value(Climatization.Settings.HeaterSource.UNKNOWN, measured=captured_at)
                        else:
                            vehicle.climatization.settings.heater_source._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API, 'climatisationSettings', climatisation_settings, {'carCapturedTimestamp',
                                                                                                  'unitInCar',
                                                                                                  'targetTemperature_C',
                                                                                                  'targetTemperature_F',
                                                                                                  'climatisationWithoutExternalPower',
                                                                                                  'climatizationAtUnlock',
                                                                                                  'windowHeatingEnabled',
                                                                                                  'zoneRearLeftEnabled',
                                                                                                  'zoneRearRightEnabled',
                                                                                                  'heaterSource'})
                else:
                    vehicle.climatization.settings.target_temperature._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.climatization_without_external_power._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.climatization_at_unlock._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.window_heating._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.front_zone_left_enabled._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.front_zone_right_enabled._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.rear_zone_left_enabled._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.rear_zone_right_enabled._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.seat_heating._set_value(None)  # pylint: disable=protected-access
                    vehicle.climatization.settings.heater_source._set_value(None)  # pylint: disable=protected-access
                
                if 'windowHeatingStatus' in data['climatisation'] and data['climatisation']['windowHeatingStatus'] is not None:
                    if 'value' in data['climatisation']['windowHeatingStatus'] and data['climatisation']['windowHeatingStatus']['value'] is not None:
                        window_heating_status = data['climatisation']['windowHeatingStatus']['value']
                        if 'carCapturedTimestamp' not in window_heating_status or window_heating_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(window_heating_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'windowHeatingStatus' in window_heating_status and window_heating_status['windowHeatingStatus'] is not None:
                            heating_on: bool = False
                            all_heating_invalid: bool = True
                            for window_heating in window_heating_status['windowHeatingStatus']:
                                if 'windowLocation' in window_heating and window_heating['windowLocation'] is not None:
                                    window_id = window_heating['windowLocation']
                                    if window_id in vehicle.window_heatings.windows:
                                        window: WindowHeatings.WindowHeating = vehicle.window_heatings.windows[window_id]
                                    else:
                                        window = WindowHeatings.WindowHeating(window_id=window_id, window_heatings=vehicle.window_heatings,
                                                                              initialization=vehicle.window_heatings.get_initialization(window_id))
                                        vehicle.window_heatings.windows[window_id] = window
                                    if 'windowHeatingState' in window_heating and window_heating['windowHeatingState'] is not None:
                                        if window_heating['windowHeatingState'] in [item.value for item in WindowHeatings.HeatingState]:
                                            window_heating_state: WindowHeatings.HeatingState = WindowHeatings.HeatingState(window_heating['windowHeatingState'])
                                            if window_heating_state == WindowHeatings.HeatingState.ON:
                                                heating_on = True
                                            if window_heating_state in [WindowHeatings.HeatingState.ON,
                                                                        WindowHeatings.HeatingState.OFF]:
                                                all_heating_invalid = False
                                            window.heating_state._set_value(window_heating_state, measured=captured_at)  # pylint: disable=protected-access
                                        else:
                                            LOG_API.info('Unknown window heating state %s not in %s', window_heating['windowHeatingState'],
                                                         str(WindowHeatings.HeatingState))
                                            # pylint: disable-next=protected-access
                                            window.heating_state._set_value(WindowHeatings.HeatingState.UNKNOWN, measured=captured_at)
                                    else:
                                        window.heating_state._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                                log_extra_keys(LOG_API, 'windowHeatingStatus', window_heating, {'windowLocation', 'windowHeatingState'})
                            if all_heating_invalid:
                                # pylint: disable-next=protected-access
                                vehicle.window_heatings.heating_state._set_value(WindowHeatings.HeatingState.INVALID, measured=captured_at)
                            else:
                                if heating_on:
                                    # pylint: disable-next=protected-access
                                    vehicle.window_heatings.heating_state._set_value(WindowHeatings.HeatingState.ON, measured=captured_at)
                                else:
                                    # pylint: disable-next=protected-access
                                    vehicle.window_heatings.heating_state._set_value(WindowHeatings.HeatingState.OFF, measured=captured_at)
                        if vehicle.window_heatings is not None and vehicle.window_heatings.commands is not None \
                                and not vehicle.window_heatings.commands.contains_command('start-stop'):
                            start_stop_command = WindowHeatingStartStopCommand(parent=vehicle.window_heatings.commands)
                            start_stop_command._add_on_set_hook(self.__on_window_heating_start_stop)  # pylint: disable=protected-access
                            start_stop_command.enabled = True
                            vehicle.window_heatings.commands.add_command(start_stop_command)
                        log_extra_keys(LOG_API, 'windowHeatingStatus', window_heating_status, {'carCapturedTimestamp', 'windowHeatingStatus'})

                log_extra_keys(LOG_API, 'climatisation', data['climatisation'], {'climatisationStatus', 'climatisationSettings', 'windowHeatingStatus'})
            if 'charging' in data and data['charging'] is not None:
                if not isinstance(vehicle, VolkswagenElectricVehicle):
                    LOG.debug('Promoting %s to VolkswagenElectricVehicle object for %s', vehicle.__class__.__name__, vin)
                    vehicle = VolkswagenElectricVehicle(garage=self.car_connectivity.garage, origin=vehicle)
                    self.car_connectivity.garage.replace_vehicle(vin, vehicle)
                if vehicle.charging is not None and vehicle.charging.commands is not None \
                        and not vehicle.charging.commands.contains_command('start-stop'):
                    start_stop_command = ChargingStartStopCommand(parent=vehicle.charging.commands)
                    start_stop_command._add_on_set_hook(self.__on_charging_start_stop)  # pylint: disable=protected-access
                    start_stop_command.enabled = True
                    vehicle.charging.commands.add_command(start_stop_command)
                if 'chargingStatus' in data['charging'] and data['charging']['chargingStatus'] is not None:
                    if 'value' in data['charging']['chargingStatus'] and data['charging']['chargingStatus']['value'] is not None:
                        charging_status = data['charging']['chargingStatus']['value']
                        if 'carCapturedTimestamp' not in charging_status or charging_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(charging_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'chargingState' in charging_status and charging_status['chargingState'] is not None:
                            if charging_status['chargingState'] in [item.value for item in VolkswagenCharging.VolkswagenChargingState]:
                                volkswagen_charging_state = VolkswagenCharging.VolkswagenChargingState(charging_status['chargingState'])
                                charging_state: Charging.ChargingState = mapping_volskwagen_charging_state[volkswagen_charging_state]
                            else:
                                LOG_API.info('Unkown charging state %s not in %s', charging_status['chargingState'],
                                             str(VolkswagenCharging.VolkswagenChargingState))
                                charging_state = Charging.ChargingState.UNKNOWN

                            # pylint: disable-next=protected-access
                            vehicle.charging.state._set_value(value=charging_state, measured=captured_at)
                        else:
                            vehicle.charging.state._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'chargeType' in charging_status and charging_status['chargeType'] is not None:
                            if charging_status['chargeType'] in [item.value for item in Charging.ChargingType]:
                                vehicle.charging.type._set_value(value=Charging.ChargingType(charging_status['chargeType']),  # pylint: disable=protected-access
                                                                 measured=captured_at)
                            else:
                                LOG_API.info('Unknown charge type %s', charging_status['chargeType'])
                                vehicle.charging.type._set_value(Charging.ChargingType.UNKNOWN, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.charging.type._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'chargePower_kW' in charging_status and charging_status['chargePower_kW'] is not None:
                            vehicle.charging.power._set_value(value=charging_status['chargePower_kW'],  # pylint: disable=protected-access
                                                              measured=captured_at, unit=Power.KW)
                        else:
                            vehicle.charging.power._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'chargeRate_kmph' in charging_status and charging_status['chargeRate_kmph'] is not None:
                            vehicle.charging.rate._set_value(value=charging_status['chargeRate_kmph'],  # pylint: disable=protected-access
                                                             measured=captured_at, unit=Speed.KMH)
                        else:
                            vehicle.charging.rate._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'remainingChargingTimeToComplete_min' in charging_status and charging_status['remainingChargingTimeToComplete_min'] is not None:
                            remaining_duration: timedelta = timedelta(minutes=charging_status['remainingChargingTimeToComplete_min'])
                            estimated_date_reached: datetime = captured_at + remaining_duration
                            estimated_date_reached = estimated_date_reached.replace(second=0, microsecond=0)
                            vehicle.charging.estimated_date_reached._set_value(value=estimated_date_reached,  # pylint: disable=protected-access
                                                                               measured=captured_at)
                        else:
                            vehicle.charging.estimated_date_reached._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API, 'chargingStatus', charging_status, {'chargingStatus', 'carCapturedTimestamp',
                                                                                    'chargingState', 'chargePower_kW',
                                                                                    'chargeRate_kmph', 'remainingChargingTimeToComplete_min'})
                if 'chargingSettings' in data['charging'] and data['charging']['chargingSettings'] is not None:
                    if 'value' in data['charging']['chargingSettings'] and data['charging']['chargingSettings']['value'] is not None:
                        charging_settings = data['charging']['chargingSettings']['value']
                        if 'carCapturedTimestamp' not in charging_settings or charging_settings['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(charging_settings['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'maxChargeCurrentAC_A' in charging_settings and charging_settings['maxChargeCurrentAC_A'] is not None:
                            if isinstance(vehicle.charging.settings, VolkswagenCharging.Settings):
                                vehicle.charging.settings.max_current_in_ampere = True
                            else:
                                raise ValueError('Charging settings not of type VolkswagenCharging.Settings')
                            vehicle.charging.settings.maximum_current.minimum = 6.0
                            vehicle.charging.settings.maximum_current.maximum = 32.0
                            vehicle.charging.settings.maximum_current.precision = 1.0
                            # pylint: disable-next=protected-access
                            vehicle.charging.settings.maximum_current._add_on_set_hook(self.__on_charging_settings_change)
                            vehicle.charging.settings.maximum_current._is_changeable = True  # pylint: disable=protected-access
                            vehicle.charging.settings.maximum_current._set_value(charging_settings['maxChargeCurrentAC_A'],  # pylint: disable=protected-access
                                                                                 measured=captured_at)
                        elif 'maxChargeCurrentAC' in charging_settings and charging_settings['maxChargeCurrentAC'] is not None:
                            if isinstance(vehicle.charging.settings, VolkswagenCharging.Settings):
                                vehicle.charging.settings.max_current_in_ampere = False
                            else:
                                raise ValueError('Charging settings not of type VolkswagenCharging.Settings')
                            vehicle.charging.settings.maximum_current.minimum = 6.0
                            vehicle.charging.settings.maximum_current.maximum = 16.0
                            vehicle.charging.settings.maximum_current.precision = 1.0
                            # pylint: disable-next=protected-access
                            vehicle.charging.settings.maximum_current._add_on_set_hook(self.__on_charging_settings_change)
                            vehicle.charging.settings.maximum_current._is_changeable = True  # pylint: disable=protected-access
                            if charging_settings['maxChargeCurrentAC'] == 'maximum':
                                vehicle.charging.settings.maximum_current._set_value(16.0,  # pylint: disable=protected-access
                                                                                     measured=captured_at)
                            elif charging_settings['maxChargeCurrentAC'] == 'reduced':
                                vehicle.charging.settings.maximum_current._set_value(6.0,  # pylint: disable=protected-access
                                                                                     measured=captured_at)
                            else:
                                LOG_API.info('Unknown max charge current %s', charging_settings['maxChargeCurrentAC'])
                                vehicle.charging.settings.maximum_current._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.charging.settings.maximum_current._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'autoUnlockPlugWhenChargedAC' in charging_settings and charging_settings['autoUnlockPlugWhenChargedAC'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.charging.settings.auto_unlock._add_on_set_hook(self.__on_charging_settings_change)
                            vehicle.charging.settings.auto_unlock._is_changeable = True  # pylint: disable=protected-access
                            if charging_settings['autoUnlockPlugWhenChargedAC'] == 'on':
                                vehicle.charging.settings.auto_unlock._set_value(True,  # pylint: disable=protected-access
                                                                                 measured=captured_at)
                            elif charging_settings['autoUnlockPlugWhenChargedAC'] == 'off':
                                vehicle.charging.settings.auto_unlock._set_value(False,  # pylint: disable=protected-access
                                                                                 measured=captured_at)
                            else:
                                LOG_API.info('Unknown auto unlock plug when charged %s', charging_settings['autoUnlockPlugWhenChargedAC'])
                                vehicle.charging.settings.auto_unlock._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.charging.settings.auto_unlock._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        if 'targetSOC_pct' in charging_settings and charging_settings['targetSOC_pct'] is not None:
                            vehicle.charging.settings.target_level.minimum = 50.0
                            vehicle.charging.settings.target_level.maximum = 100.0
                            vehicle.charging.settings.target_level.precision = 10.0
                            # pylint: disable-next=protected-access
                            vehicle.charging.settings.target_level._add_on_set_hook(self.__on_charging_settings_change)
                            vehicle.charging.settings.target_level._is_changeable = True  # pylint: disable=protected-access
                            vehicle.charging.settings.target_level._set_value(charging_settings['targetSOC_pct'],  # pylint: disable=protected-access
                                                                              measured=captured_at)
                        else:
                            vehicle.charging.settings.target_level._set_value(None, measured=captured_at)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API, 'chargingSettings', charging_settings, {'carCapturedTimestamp', 'maxChargeCurrentAC_A', 'maxChargeCurrentAC',
                                                                                        'autoUnlockPlugWhenChargedAC', 'targetSOC_pct'})
                else:
                    vehicle.charging.settings.maximum_current._set_value(None)  # pylint: disable=protected-access
                    vehicle.charging.settings.auto_unlock._set_value(None)  # pylint: disable=protected-access
                    vehicle.charging.settings.target_level._set_value(None)  # pylint: disable=protected-access

                if 'plugStatus' in data['charging'] and data['charging']['plugStatus'] is not None:
                    if 'value' in data['charging']['plugStatus'] and data['charging']['plugStatus']['value'] is not None:
                        plug_status = data['charging']['plugStatus']['value']
                        if 'carCapturedTimestamp' not in plug_status or plug_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(plug_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'plugConnectionState' in plug_status and plug_status['plugConnectionState'] is not None:
                            if plug_status['plugConnectionState'] in [item.value for item in ChargingConnector.ChargingConnectorConnectionState]:
                                plug_state: ChargingConnector.ChargingConnectorConnectionState = \
                                    ChargingConnector.ChargingConnectorConnectionState(plug_status['plugConnectionState'])
                            else:
                                LOG_API.info('Unknown plug connection state %s not in %s', plug_status['plugConnectionState'],
                                             str(ChargingConnector.ChargingConnectorConnectionState))
                                plug_state = ChargingConnector.ChargingConnectorConnectionState.UNKNOWN
                            vehicle.charging.connector.connection_state._set_value(value=plug_state,  # pylint: disable=protected-access
                                                                                   measured=captured_at)
                        else:
                            vehicle.charging.connector.connection_state._set_value(None)  # pylint: disable=protected-access
                        if 'plugLockState' in plug_status and plug_status['plugLockState'] is not None:
                            if plug_status['plugLockState'] in [item.value for item in ChargingConnector.ChargingConnectorLockState]:
                                plug_lock_state: ChargingConnector.ChargingConnectorLockState = \
                                    ChargingConnector.ChargingConnectorLockState(plug_status['plugLockState'])
                            else:
                                LOG_API.info('Unknown plug lock state %s not in %s', plug_status['plugLockState'],
                                             str(ChargingConnector.ChargingConnectorLockState))
                                plug_lock_state = ChargingConnector.ChargingConnectorLockState.UNKNOWN
                            vehicle.charging.connector.lock_state._set_value(value=plug_lock_state,  # pylint: disable=protected-access
                                                                             measured=captured_at)
                        else:
                            vehicle.charging.connector.lock_state._set_value(None)  # pylint: disable=protected-access
                        if 'externalPower' in plug_status and plug_status['externalPower'] is not None:
                            if plug_status['externalPower'] in [item.value for item in ChargingConnector.ExternalPower]:
                                external_power: ChargingConnector.ExternalPower = \
                                    ChargingConnector.ExternalPower(plug_status['externalPower'])
                            else:
                                LOG_API.info('Unknown external power %s not in %s', plug_status['externalPower'],
                                             str(ChargingConnector.ExternalPower))
                                external_power = ChargingConnector.ExternalPower.UNKNOWN
                            vehicle.charging.connector.external_power._set_value(value=external_power,  # pylint: disable=protected-access
                                                                                 measured=captured_at)
                        else:
                            vehicle.charging.connector.external_power._set_value(None)  # pylint: disable=protected-access
                        log_extra_keys(LOG_API, 'plugStatus', plug_status, {'carCapturedTimestamp', 'plugConnectionState', 'plugLockState', 'externalPower'})
            if 'vehicleHealthInspection' in data and data['vehicleHealthInspection'] is not None:
                if 'maintenanceStatus' in data['vehicleHealthInspection'] and data['vehicleHealthInspection']['maintenanceStatus'] is not None:
                    if 'value' in data['vehicleHealthInspection']['maintenanceStatus'] \
                            and data['vehicleHealthInspection']['maintenanceStatus']['value'] is not None:
                        maintenance_status = data['vehicleHealthInspection']['maintenanceStatus']['value']
                        if 'carCapturedTimestamp' not in maintenance_status or maintenance_status['carCapturedTimestamp'] is None:
                            raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
                        captured_at: datetime = robust_time_parse(maintenance_status['carCapturedTimestamp'])
                        self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)
                        if 'inspectionDue_days' in maintenance_status and maintenance_status['inspectionDue_days'] is not None:
                            inspection_due: timedelta = timedelta(days=maintenance_status['inspectionDue_days'])
                            inspection_date: datetime = captured_at + inspection_due
                            inspection_date = inspection_date.replace(hour=0, minute=0, second=0, microsecond=0)
                            vehicle.maintenance.inspection_due_at._set_value(value=inspection_date, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.maintenance.inspection_due_at._set_value(None)  # pylint: disable=protected-access
                        if 'inspectionDue_km' in maintenance_status and maintenance_status['inspectionDue_km'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.maintenance.inspection_due_after._set_value(value=maintenance_status['inspectionDue_km'], measured=captured_at,
                                                                                unit=Length.KM)
                            vehicle.maintenance.inspection_due_after.precision = 1
                        else:
                            vehicle.maintenance.inspection_due_after._set_value(None)  # pylint: disable=protected-access
                        if 'oilServiceDue_days' in maintenance_status and maintenance_status['oilServiceDue_days'] is not None:
                            oil_service_due: timedelta = timedelta(days=maintenance_status['oilServiceDue_days'])
                            oil_service_date: datetime = captured_at + oil_service_due
                            oil_service_date = oil_service_date.replace(hour=0, minute=0, second=0, microsecond=0)
                            vehicle.maintenance.oil_service_due_at._set_value(value=oil_service_date, measured=captured_at)  # pylint: disable=protected-access
                        else:
                            vehicle.maintenance.oil_service_due_at._set_value(None)  # pylint: disable=protected-access
                        if 'oilServiceDue_km' in maintenance_status and maintenance_status['oilServiceDue_km'] is not None:
                            # pylint: disable-next=protected-access
                            vehicle.maintenance.oil_service_due_after._set_value(value=maintenance_status['oilServiceDue_km'], measured=captured_at,
                                                                                 unit=Length.KM)
                            vehicle.maintenance.oil_service_due_after.precision = 1
                        else:
                            vehicle.maintenance.oil_service_due_after._set_value(None)  # pylint: disable=protected-access
                        if 'mileage_km' in maintenance_status and maintenance_status['mileage_km'] is not None \
                                and not vehicle.odometer.enabled and vehicle.odometer is None:
                            # pylint: disable-next=protected-access
                            vehicle.odometer._set_value(value=maintenance_status['mileage_km'], measured=captured_at, unit=Length.KM)
                            vehicle.odometer.precision = 1

                        log_extra_keys(LOG_API, 'maintenanceStatus', maintenance_status, {'carCapturedTimestamp', 'inspectionDue_days', 'inspectionDue_km',
                                                                                          'oilServiceDue_days', 'oilServiceDue_km', 'mileage_km'})
                log_extra_keys(LOG_API, 'vehicleHealthInspection', data['vehicleHealthInspection'], {'maintenanceStatus'})
            if 'readiness' in data and data['readiness'] is not None:
                if 'readinessStatus' in data['readiness'] and data['readiness']['readinessStatus'] is not None:
                    readiness_status = data['readiness']['readinessStatus']
                    if 'value' in readiness_status and readiness_status['value'] is not None:
                        readiness_status = readiness_status['value']
                        if 'connectionState' in readiness_status and readiness_status['connectionState'] is not None:
                            if 'isOnline' in readiness_status['connectionState'] and readiness_status['connectionState']['isOnline'] is not None:
                                if readiness_status['connectionState']['isOnline'] is True:
                                    if vehicle.connection_state.value != GenericVehicle.ConnectionState.ONLINE:
                                        vehicle.connection_state._set_value(GenericVehicle.ConnectionState.REACHABLE)  # pylint: disable=protected-access
                                    vehicle.official_connection_state = GenericVehicle.ConnectionState.REACHABLE
                                else:
                                    vehicle.connection_state._set_value(GenericVehicle.ConnectionState.OFFLINE)  # pylint: disable=protected-access
                            else:
                                vehicle.connection_state._set_value(None)  # pylint: disable=protected-access
                            if 'isActive' in readiness_status['connectionState'] and readiness_status['connectionState']['isActive'] is not None:
                                vehicle.is_active._set_value(readiness_status['connectionState']['isActive'])  # pylint: disable=protected-access
                            else:
                                vehicle.is_active._set_value(None)  # pylint: disable=protected-access
                            log_extra_keys(LOG_API, 'connectionState', readiness_status['connectionState'], {'isOnline', 'isActive'})
                        log_extra_keys(LOG_API, 'readinessStatus', readiness_status, {'connectionState'})
            log_extra_keys(LOG_API, 'selectivestatus', data, {'measurements', 'access', 'vehicleLights', 'climatisation', 'vehicleHealthInspection',
                                                              'charging', 'readiness'})

    def fetch_parking_position(self, vehicle: VolkswagenVehicle) -> None:
        """
        Fetches the parking position of the given Volkswagen vehicle and updates the vehicle's position attributes.

        Args:
            vehicle (VolkswagenVehicle): The Volkswagen vehicle object whose parking position is to be fetched.

        Raises:
            ValueError: If the vehicle's VIN is None.
            APIError: If the fetched data does not contain 'carCapturedTimestamp' or it is None.

        Updates:
            vehicle.position.latitude: The latitude of the vehicle's parking position.
            vehicle.position.longitude: The longitude of the vehicle's parking position.
        """
        vin = vehicle.vin.value
        if vin is None:
            raise ValueError('vehicle.vin cannot be None')
        url: str = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/parkingposition'
        data: Dict[str, Any] | None = self._fetch_data(url, self.session, allow_empty=True, allow_http_error=True, 
                                                       allowed_errors=[requests.codes['not_found']])
        if data is not None and 'data' in data and data['data'] is not None:
            if 'carCapturedTimestamp' not in data['data'] or data['data']['carCapturedTimestamp'] is None:
                raise APIError('Could not fetch vehicle status, carCapturedTimestamp missing')
            captured_at: datetime = robust_time_parse(data['data']['carCapturedTimestamp'])
            self._update_online_tracking(vehicle=vehicle, last_measurement=captured_at)

            if 'lat' in data['data'] and data['data']['lat'] is not None and 'lon' in data['data'] and data['data']['lon'] is not None:
                vehicle.position.latitude._set_value(data['data']['lat'], measured=captured_at)  # pylint: disable=protected-access
                vehicle.position.latitude.precision = 0.000001
                vehicle.position.longitude._set_value(data['data']['lon'], measured=captured_at)  # pylint: disable=protected-access
                vehicle.position.longitude.precision = 0.000001
                vehicle.position.position_type._set_value(Position.PositionType.PARKING, measured=captured_at)  # pylint: disable=protected-access
            else:
                vehicle.position.latitude._set_value(None)  # pylint: disable=protected-access
                vehicle.position.longitude._set_value(None)  # pylint: disable=protected-access
                vehicle.position.position_type._set_value(None)  # pylint: disable=protected-access
        else:
            vehicle.position.latitude._set_value(None)  # pylint: disable=protected-access
            vehicle.position.longitude._set_value(None)  # pylint: disable=protected-access
            vehicle.position.position_type._set_value(None)  # pylint: disable=protected-access

    def _update_online_tracking(self, vehicle: VolkswagenVehicle, last_measurement: Optional[datetime]) -> None:
        with vehicle.online_timeout_timer_lock:
            if last_measurement is not None and (vehicle.last_measurement is None or last_measurement > vehicle.last_measurement):
                if (last_measurement + self.online_timeout) > datetime.now(tz=timezone.utc):
                    rest_timeout: timedelta = (last_measurement + self.online_timeout) - datetime.now(tz=timezone.utc)
                    # Only set to online if the timeout is greater than 60 seconds
                    if rest_timeout.total_seconds() > 60:
                        LOG.info('Vehicle %s is online', vehicle.vin.value)
                        vehicle.connection_state._set_value(GenericVehicle.ConnectionState.ONLINE)  # pylint: disable=protected-access
                        if vehicle.online_timeout_timer is not None:
                            vehicle.online_timeout_timer.cancel()
                        rest_timeout = (last_measurement + self.online_timeout) - datetime.now(tz=timezone.utc)
                        vehicle.online_timeout_timer = threading.Timer(rest_timeout.total_seconds(), self._set_vehicle_offline, args=[vehicle])
                        vehicle.online_timeout_timer.start()
                vehicle.last_measurement = last_measurement

    def _set_vehicle_offline(self, vehicle: VolkswagenVehicle) -> None:
        with vehicle.online_timeout_timer_lock:
            last_online_measurement: Optional[datetime] = vehicle.last_measurement
            # The car goes offline approximatly 2 minutes after the last measurement
            if last_online_measurement is not None:
                last_online_measurement += timedelta(seconds=120)
            vehicle.connection_state._set_value(vehicle.official_connection_state, measured=last_online_measurement)  # pylint: disable=protected-access
            vehicle.online_timeout_timer = None
            if vehicle.official_connection_state is not None:
                LOG.info('Vehicle %s went from online to %s', vehicle.vin.value, vehicle.official_connection_state.value)

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
        if not force and (self.active_config['max_age'] is not None and session.cache is not None and url in session.cache):
            data, cache_date_string = session.cache[url]
            cache_date = datetime.fromisoformat(cache_date_string)
        if data is None or self.active_config['max_age'] is None \
                or (cache_date is not None and cache_date < (datetime.utcnow() - timedelta(seconds=self.active_config['max_age']))):
            try:
                status_response: requests.Response = session.get(url, allow_redirects=False)
                self._record_elapsed(status_response.elapsed)
                if status_response.status_code in (requests.codes['ok'], requests.codes['multiple_status']):
                    data = status_response.json()
                    if session.cache is not None:
                        session.cache[url] = (data, str(datetime.utcnow()))
                elif status_response.status_code == requests.codes['no_content'] and allow_empty:
                    data = None
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
                    raise RetrievalError(f'Could not fetch data for {url}. Status Code was: {status_response.status_code}')
            except requests.exceptions.ConnectionError as connection_error:
                raise RetrievalError(f'Connection error: {connection_error}') from connection_error
            except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
                raise RetrievalError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
            except requests.exceptions.ReadTimeout as timeout_error:
                raise RetrievalError(f'Timeout during read: {timeout_error}') from timeout_error
            except requests.exceptions.RetryError as retry_error:
                raise RetrievalError(f'Retrying failed: {retry_error}') from retry_error
            except requests.exceptions.JSONDecodeError as json_error:
                if allow_empty:
                    data = None
                else:
                    raise RetrievalError(f'JSON decode error: {json_error}') from json_error
        return data

    def get_version(self) -> str:
        return __version__

    def get_features(self) -> dict[str, tuple[bool, str]]:
        features: dict[str, tuple[bool, str]] = {}
        features['Images'] = (SUPPORT_IMAGES, SUPPORT_IMAGES_STR)
        return features

    def get_type(self) -> str:
        return "carconnectivity-connector-volkswagen"

    def __on_air_conditioning_settings_change(self, attribute: GenericAttribute, value: Any) -> Any:
        """
        Callback for the climatization setting change.
        """
        if attribute.parent is None or not isinstance(attribute.parent, VolkswagenClimatization.Settings) \
                or attribute.parent.parent is None \
                or attribute.parent.parent.parent is None or not isinstance(attribute.parent.parent.parent, VolkswagenVehicle):
            raise SetterError('Object hierarchy is not as expected')
        settings: VolkswagenClimatization.Settings = attribute.parent
        vehicle: VolkswagenVehicle = attribute.parent.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise SetterError('VIN in object hierarchy missing')
        setting_dict = {}
        if settings.target_temperature.enabled and settings.target_temperature.value is not None:
            # Round target temperature to nearest 0.5
            # Check if the attribute changed is the target_temperature attribute
            precision: float = settings.target_temperature.precision if settings.target_temperature.precision is not None else 0.5
            if isinstance(attribute, TemperatureAttribute) and attribute.id == 'target_temperature':
                value = round(value / precision) * precision
                setting_dict['targetTemperature'] = value
            else:
                setting_dict['targetTemperature'] = round(settings.target_temperature.value / precision) * precision
            if settings.unit_in_car == Temperature.C:
                setting_dict['targetTemperatureUnit'] = 'celsius'
            elif settings.target_temperature.unit == Temperature.F:
                setting_dict['targetTemperatureUnit'] = 'farenheit'
            else:
                setting_dict['targetTemperatureUnit'] = 'celsius'
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'climatisation_without_external_power':
            setting_dict['climatisationWithoutExternalPower'] = value
        elif settings.climatization_without_external_power.enabled and settings.climatization_without_external_power.value is not None:
            setting_dict['climatisationWithoutExternalPower'] = settings.climatization_without_external_power.value
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'climatization_at_unlock':
            setting_dict['climatizationAtUnlock'] = value
        elif settings.climatization_at_unlock.enabled and settings.climatization_at_unlock.value is not None:
            setting_dict['climatizationAtUnlock'] = settings.climatization_at_unlock.value
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'window_heating':
            setting_dict['windowHeatingEnabled'] = value
        elif settings.window_heating.enabled and settings.window_heating.value is not None:
            setting_dict['windowHeatingEnabled'] = settings.window_heating.value
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'front_zone_left_enabled':
            setting_dict['zoneFrontLeftEnabled'] = value
        elif settings.front_zone_left_enabled.enabled and settings.front_zone_left_enabled.value is not None:
            setting_dict['zoneFrontLeftEnabled'] = settings.front_zone_left_enabled.value
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'front_zone_right_enabled':
            setting_dict['zoneFrontRightEnabled'] = value
        elif settings.front_zone_right_enabled.enabled and settings.front_zone_right_enabled.value is not None:
            setting_dict['zoneFrontRightEnabled'] = settings.front_zone_right_enabled.value
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'rear_zone_left_enabled':
            setting_dict['zoneRearLeftEnabled'] = value
        elif settings.rear_zone_left_enabled.enabled and settings.rear_zone_left_enabled.value is not None:
            setting_dict['zoneRearLeftEnabled'] = settings.rear_zone_left_enabled.value
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'rear_zone_right_enabled':
            setting_dict['zoneRearRightEnabled'] = value
        elif settings.rear_zone_right_enabled.enabled and settings.rear_zone_right_enabled.value is not None:
            setting_dict['zoneRearRightEnabled'] = settings.rear_zone_right_enabled.value

        url: str = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/climatisation/settings'
        try:
            settings_response: requests.Response = self.session.put(url, data=json.dumps(setting_dict), allow_redirects=True)
            if settings_response.status_code != requests.codes['ok']:
                LOG.error('Could not set climatization settings (%s)', settings_response.status_code)
                raise SetterError(f'Could not set value ({settings_response.status_code})')
        except requests.exceptions.ConnectionError as connection_error:
            raise SetterError(f'Connection error: {connection_error}.'
                              ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
            raise SetterError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
        except requests.exceptions.ReadTimeout as timeout_error:
            raise SetterError(f'Timeout during read: {timeout_error}') from timeout_error
        except requests.exceptions.RetryError as retry_error:
            raise SetterError(f'Retrying failed: {retry_error}') from retry_error
        return value

    def __on_air_conditioning_start_stop(self, start_stop_command: ClimatizationStartStopCommand, command_arguments: Union[str, Dict[str, Any]]) \
            -> Union[str, Dict[str, Any]]:
        if start_stop_command.parent is None or start_stop_command.parent.parent is None \
                or start_stop_command.parent.parent.parent is None or not isinstance(start_stop_command.parent.parent.parent, VolkswagenVehicle):
            raise CommandError('Object hierarchy is not as expected')
        if not isinstance(command_arguments, dict):
            raise CommandError('Command arguments are not a dictionary')
        vehicle: VolkswagenVehicle = start_stop_command.parent.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise CommandError('VIN in object hierarchy missing')
        if 'command' not in command_arguments:
            raise CommandError('Command argument missing')
        command_dict = {}
        command_str: Optional[str] = None
        if command_arguments['command'] == ClimatizationStartStopCommand.Command.START:
            command_str = 'start'
            if vehicle.climatization.settings is None:
                raise CommandError('Could not control climatisation, there are no climatisation settings for the vehicle available.')
            precision: float = 0.5
            if 'target_temperature' in command_arguments:
                # Round target temperature to nearest 0.5
                command_dict['targetTemperature'] = round(command_arguments['target_temperature'] / precision) * precision
            elif vehicle.climatization.settings.target_temperature is not None and vehicle.climatization.settings.target_temperature.enabled \
                    and vehicle.climatization.settings.target_temperature.value is not None:
                if vehicle.climatization.settings.target_temperature.precision is not None:
                    precision: float = vehicle.climatization.settings.target_temperature.precision
                if isinstance(vehicle.climatization.settings, VolkswagenClimatization.Settings) \
                        and vehicle.climatization.settings.unit_in_car is not None:
                    temperature_value: Optional[float] = vehicle.climatization.settings.target_temperature.temperature_in(
                        vehicle.climatization.settings.unit_in_car)
                else:
                    temperature_value = vehicle.climatization.settings.target_temperature.value
                if temperature_value is not None:
                    command_dict['targetTemperature'] = round(temperature_value / precision) * precision
            if 'target_temperature_unit' in command_arguments:
                if command_arguments['target_temperature_unit'] == Temperature.C:
                    command_dict['targetTemperatureUnit'] = 'celsius'
                elif command_arguments['target_temperature_unit'] == Temperature.F:
                    command_dict['targetTemperatureUnit'] = 'farenheit'
                else:
                    command_dict['targetTemperatureUnit'] = 'celsius'
            elif isinstance(vehicle.climatization.settings, VolkswagenClimatization.Settings) \
                    and vehicle.climatization.settings.unit_in_car == Temperature.C:
                command_dict['targetTemperatureUnit'] = 'celsius'
            elif isinstance(vehicle.climatization.settings, VolkswagenClimatization.Settings) \
                    and vehicle.climatization.settings.unit_in_car == Temperature.F:
                command_dict['targetTemperatureUnit'] = 'farenheit'
            else:
                command_dict['targetTemperatureUnit'] = 'celsius'

            if vehicle.climatization.settings.climatization_without_external_power is not None \
                    and vehicle.climatization.settings.climatization_without_external_power.enabled:
                command_dict['climatisationWithoutExternalPower'] = vehicle.climatization.settings.climatization_without_external_power.value
            if vehicle.climatization.settings.window_heating is not None and vehicle.climatization.settings.window_heating.enabled:
                command_dict['windowHeatingEnabled'] = vehicle.climatization.settings.window_heating.value
            if vehicle.climatization.settings.climatization_at_unlock is not None and vehicle.climatization.settings.climatization_at_unlock.enabled:
                command_dict['climatizationAtUnlock'] = vehicle.climatization.settings.climatization_at_unlock.value
            if isinstance(vehicle.climatization.settings, VolkswagenClimatization.Settings):
                if vehicle.climatization.settings.front_zone_left_enabled is not None and vehicle.climatization.settings.front_zone_left_enabled.enabled:
                    command_dict['zoneFrontLeftEnabled'] = vehicle.climatization.settings.front_zone_left_enabled.value
                if vehicle.climatization.settings.front_zone_right_enabled is not None and vehicle.climatization.settings.front_zone_right_enabled.enabled:
                    command_dict['zoneFrontRightEnabled'] = vehicle.climatization.settings.front_zone_right_enabled.value
                if vehicle.climatization.settings.rear_zone_left_enabled is not None and vehicle.climatization.settings.rear_zone_left_enabled.enabled:
                    command_dict['zoneRearLeftEnabled'] = vehicle.climatization.settings.rear_zone_left_enabled.value
                if vehicle.climatization.settings.rear_zone_right_enabled is not None and vehicle.climatization.settings.rear_zone_right_enabled.enabled:
                    command_dict['zoneRearRightEnabled'] = vehicle.climatization.settings.rear_zone_right_enabled.value
            if vehicle.climatization.settings.heater_source is not None and vehicle.climatization.settings.heater_source.enabled:
                command_dict['heaterSource'] = vehicle.climatization.settings.heater_source.value
        elif command_arguments['command'] == ClimatizationStartStopCommand.Command.STOP:
            command_str = 'stop'
        else:
            raise CommandError(f'Unknown command {command_arguments["command"]}')

        url: str = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/climatisation/{command_str}'
        try:
            command_response: requests.Response = self.session.post(url, data=json.dumps(command_dict), allow_redirects=True)
            if command_response.status_code != requests.codes['ok']:
                LOG.error('Could not start/stop air conditioning (%s: %s)', command_response.status_code, command_response.text)
                raise CommandError(f'Could not start/stop air conditioning ({command_response.status_code}: {command_response.text})')
        except requests.exceptions.ConnectionError as connection_error:
            raise CommandError(f'Connection error: {connection_error}.'
                               ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
            raise CommandError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
        except requests.exceptions.ReadTimeout as timeout_error:
            raise CommandError(f'Timeout during read: {timeout_error}') from timeout_error
        except requests.exceptions.RetryError as retry_error:
            raise CommandError(f'Retrying failed: {retry_error}') from retry_error
        return command_arguments

    def __on_wake_sleep(self, wake_sleep_command: WakeSleepCommand, command_arguments: Union[str, Dict[str, Any]]) \
            -> Union[str, Dict[str, Any]]:
        if wake_sleep_command.parent is None or wake_sleep_command.parent.parent is None \
                or not isinstance(wake_sleep_command.parent.parent, GenericVehicle):
            raise CommandError('Object hierarchy is not as expected')
        if not isinstance(command_arguments, dict):
            raise CommandError('Command arguments are not a dictionary')
        vehicle: GenericVehicle = wake_sleep_command.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise CommandError('VIN in object hierarchy missing')
        if 'command' not in command_arguments:
            raise CommandError('Command argument missing')
        if command_arguments['command'] == WakeSleepCommand.Command.WAKE:
            url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/vehiclewakeuptrigger'

            try:
                command_response: requests.Response = self.session.post(url, data='{}', allow_redirects=True)
                if command_response.status_code not in (requests.codes['ok'], requests.codes['no_content']):
                    LOG.error('Could not execute wake command (%s: %s)', command_response.status_code, command_response.text)
                    raise CommandError(f'Could not execute wake command ({command_response.status_code}: {command_response.text})')
            except requests.exceptions.ConnectionError as connection_error:
                raise CommandError(f'Connection error: {connection_error}.'
                                   ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
            except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
                raise CommandError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
            except requests.exceptions.ReadTimeout as timeout_error:
                raise CommandError(f'Timeout during read: {timeout_error}') from timeout_error
            except requests.exceptions.RetryError as retry_error:
                raise CommandError(f'Retrying failed: {retry_error}') from retry_error
        elif command_arguments['command'] == WakeSleepCommand.Command.SLEEP:
            raise CommandError('Sleep command not supported by vehicle. Vehicle will put itself to sleep')
        else:
            raise CommandError(f'Unknown command {command_arguments["command"]}')
        return command_arguments

    def __on_honk_flash(self, honk_flash_command: HonkAndFlashCommand, command_arguments: Union[str, Dict[str, Any]]) \
            -> Union[str, Dict[str, Any]]:
        if honk_flash_command.parent is None or honk_flash_command.parent.parent is None \
                or not isinstance(honk_flash_command.parent.parent, GenericVehicle):
            raise CommandError('Object hierarchy is not as expected')
        if not isinstance(command_arguments, dict):
            raise CommandError('Command arguments are not a dictionary')
        vehicle: GenericVehicle = honk_flash_command.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise CommandError('VIN in object hierarchy missing')
        if 'command' not in command_arguments:
            raise CommandError('Command argument missing')
        command_dict = {}
        if command_arguments['command'] in [HonkAndFlashCommand.Command.FLASH, HonkAndFlashCommand.Command.HONK_AND_FLASH]:
            if 'duration' in command_arguments:
                command_dict['duration_s'] = command_arguments['duration']
            else:
                command_dict['duration_s'] = 10
            command_dict['mode'] = command_arguments['command'].value
            command_dict['userPosition'] = {}
            if vehicle.position is None or vehicle.position.latitude is None or vehicle.position.longitude is None \
                    or vehicle.position.latitude.value is None or vehicle.position.longitude.value is None \
                    or not vehicle.position.latitude.enabled or not vehicle.position.longitude.enabled:
                raise CommandError('Can only execute honk and flash commands if vehicle position is known')
            command_dict['userPosition']['latitude'] = vehicle.position.latitude.value
            command_dict['userPosition']['longitude'] = vehicle.position.longitude.value

            url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/honkandflash'
            try:
                command_response: requests.Response = self.session.post(url, data=json.dumps(command_dict), allow_redirects=True)
                if command_response.status_code not in (requests.codes['ok'], requests.codes['no_content']):
                    LOG.error('Could not execute honk or flash command (%s: %s)', command_response.status_code, command_response.text)
                    raise CommandError(f'Could not execute honk or flash command ({command_response.status_code}: {command_response.text})')
            except requests.exceptions.ConnectionError as connection_error:
                raise CommandError(f'Connection error: {connection_error}.'
                                   ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
            except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
                raise CommandError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
            except requests.exceptions.ReadTimeout as timeout_error:
                raise CommandError(f'Timeout during read: {timeout_error}') from timeout_error
            except requests.exceptions.RetryError as retry_error:
                raise CommandError(f'Retrying failed: {retry_error}') from retry_error
            else:
                raise CommandError(f'Unknown command {command_arguments["command"]}')
        return command_arguments

    def __on_lock_unlock(self, lock_unlock_command: LockUnlockCommand, command_arguments: Union[str, Dict[str, Any]]) \
            -> Union[str, Dict[str, Any]]:
        if lock_unlock_command.parent is None or lock_unlock_command.parent.parent is None \
                or lock_unlock_command.parent.parent.parent is None or not isinstance(lock_unlock_command.parent.parent.parent, GenericVehicle):
            raise CommandError('Object hierarchy is not as expected')
        if not isinstance(command_arguments, dict):
            raise SetterError('Command arguments are not a dictionary')
        vehicle: GenericVehicle = lock_unlock_command.parent.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise CommandError('VIN in object hierarchy missing')
        if 'command' not in command_arguments:
            raise CommandError('Command argument missing')
        command_dict = {}
        if 'spin' in command_arguments:
            command_dict['spin'] = command_arguments['spin']
        else:
            if self.active_config['spin'] is None:
                raise CommandError('S-PIN is missing, please add S-PIN to your configuration or .netrc file')
            command_dict['spin'] = self.active_config['spin']
        if command_arguments['command'] == LockUnlockCommand.Command.LOCK:
            url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/access/lock'
        elif command_arguments['command'] == LockUnlockCommand.Command.UNLOCK:
            url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/access/unlock'
        else:
            raise CommandError(f'Unknown command {command_arguments["command"]}')
        try:
            command_response: requests.Response = self.session.post(url, data=json.dumps(command_dict), allow_redirects=True)
            if command_response.status_code != requests.codes['ok']:
                LOG.error('Could not execute locking command (%s: %s)', command_response.status_code, command_response.text)
                raise CommandError(f'Could not execute locking command ({command_response.status_code}: {command_response.text})')
        except requests.exceptions.ConnectionError as connection_error:
            raise CommandError(f'Connection error: {connection_error}.'
                               ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
            raise CommandError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
        except requests.exceptions.ReadTimeout as timeout_error:
            raise CommandError(f'Timeout during read: {timeout_error}') from timeout_error
        except requests.exceptions.RetryError as retry_error:
            raise CommandError(f'Retrying failed: {retry_error}') from retry_error
        return command_arguments

    def __on_spin(self, spin_command: SpinCommand, command_arguments: Union[str, Dict[str, Any]]) \
            -> Union[str, Dict[str, Any]]:
        del spin_command
        if not isinstance(command_arguments, dict):
            raise CommandError('Command arguments are not a dictionary')
        if 'command' not in command_arguments:
            raise CommandError('Command argument missing')
        command_dict = {}
        if self.active_config['spin'] is None:
            raise CommandError('S-PIN is missing, please add S-PIN to your configuration or .netrc file')
        if 'spin' in command_arguments:
            command_dict['spin'] = command_arguments['spin']
        else:
            if self.active_config['spin'] is None or self.active_config['spin'] == '':
                raise CommandError('S-PIN is missing, please add S-PIN to your configuration or .netrc file')
            command_dict['spin'] = self.active_config['spin']
        if command_arguments['command'] == SpinCommand.Command.VERIFY:
            url = 'https://emea.bff.cariad.digital/vehicle/v1/spin/verify'
        else:
            raise CommandError(f'Unknown command {command_arguments["command"]}')
        try:
            command_response: requests.Response = self.session.post(url, data=json.dumps(command_dict), allow_redirects=True)
            if command_response.status_code != requests.codes['no_content']:
                LOG.error('Could not execute spin command (%s: %s)', command_response.status_code, command_response.text)
                raise CommandError(f'Could not execute spin command ({command_response.status_code}: {command_response.text})')
            else:
                LOG.info('Spin verify command executed successfully')
        except requests.exceptions.ConnectionError as connection_error:
            raise CommandError(f'Connection error: {connection_error}.'
                               ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
            raise CommandError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
        except requests.exceptions.ReadTimeout as timeout_error:
            raise CommandError(f'Timeout during read: {timeout_error}') from timeout_error
        except requests.exceptions.RetryError as retry_error:
            raise CommandError(f'Retrying failed: {retry_error}') from retry_error
        return command_arguments

    def __on_charging_start_stop(self, start_stop_command: ChargingStartStopCommand, command_arguments: Union[str, Dict[str, Any]]) \
            -> Union[str, Dict[str, Any]]:
        if start_stop_command.parent is None or start_stop_command.parent.parent is None \
                or start_stop_command.parent.parent.parent is None or not isinstance(start_stop_command.parent.parent.parent, VolkswagenVehicle):
            raise CommandError('Object hierarchy is not as expected')
        if not isinstance(command_arguments, dict):
            raise CommandError('Command arguments are not a dictionary')
        vehicle: VolkswagenVehicle = start_stop_command.parent.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise CommandError('VIN in object hierarchy missing')
        if 'command' not in command_arguments:
            raise CommandError('Command argument missing')
        try:
            if command_arguments['command'] == ChargingStartStopCommand.Command.START:
                url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/charging/start'
                command_response: requests.Response = self.session.post(url, data='{}', allow_redirects=True)
            elif command_arguments['command'] == ChargingStartStopCommand.Command.STOP:
                url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/charging/stop'
                command_response: requests.Response = self.session.post(url, data='{}', allow_redirects=True)
            else:
                raise CommandError(f'Unknown command {command_arguments["command"]}')

            if command_response.status_code != requests.codes['ok']:
                LOG.error('Could not start/stop charging (%s: %s)', command_response.status_code, command_response.text)
                raise CommandError(f'Could not start/stop charging ({command_response.status_code}: {command_response.text})')
        except requests.exceptions.ConnectionError as connection_error:
            raise CommandError(f'Connection error: {connection_error}.'
                               ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
            raise CommandError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
        except requests.exceptions.ReadTimeout as timeout_error:
            raise CommandError(f'Timeout during read: {timeout_error}') from timeout_error
        except requests.exceptions.RetryError as retry_error:
            raise CommandError(f'Retrying failed: {retry_error}') from retry_error
        return command_arguments

    def __on_charging_settings_change(self, attribute: GenericAttribute, value: Any) -> Any:
        """
        Callback for the charging setting change.
        """
        if attribute.parent is None or not isinstance(attribute.parent, VolkswagenCharging.Settings) \
                or attribute.parent.parent is None \
                or attribute.parent.parent.parent is None or not isinstance(attribute.parent.parent.parent, VolkswagenVehicle):
            raise SetterError('Object hierarchy is not as expected')
        settings: VolkswagenCharging.Settings = attribute.parent
        vehicle: VolkswagenVehicle = attribute.parent.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise SetterError('VIN in object hierarchy missing')
        setting_dict = {}
        precision: float = settings.maximum_current.precision if settings.maximum_current.precision is not None else 1.0
        if isinstance(attribute, CurrentAttribute) and attribute.id == 'maximum_current':
            value = round(value / precision) * precision
            if settings.max_current_in_ampere:
                if value < 5.0:
                    raise SetterError('Maximum current must be greater than 5 amps')
                if value < 10.0:
                    setting_dict['maxChargeCurrentAC_A'] = 5
                    value = 5.0
                elif value < 13.0:
                    setting_dict['maxChargeCurrentAC_A'] = 10
                    value = 10.0
                elif value < 32.0:
                    setting_dict['maxChargeCurrentAC_A'] = 13
                    value = 13.0
                elif value == 32.0:
                    setting_dict['maxChargeCurrentAC_A'] = 32
                    value = 32.0
                else:
                    raise SetterError('Maximum current must be less than 32 amps')
            else:
                if value < 6:
                    raise SetterError('Maximum current must be greater than 6 amps')
                if value < 16:
                    setting_dict['maxChargeCurrentAC'] = 'reduced'
                    value = 6.0
                else:
                    setting_dict['maxChargeCurrentAC'] = 'maximum'
                    value = 16.0
        elif settings.maximum_current.enabled and settings.maximum_current.value is not None:
            if settings.max_current_in_ampere:
                setting_dict['maxChargeCurrentAC_A'] = round(settings.maximum_current.value / precision) * precision
            else:
                if settings.maximum_current.value < 6:
                    raise SetterError('Maximum current must be greater than 6 amps')
                if settings.maximum_current.value < 16:
                    setting_dict['maxChargeCurrentAC'] = 'reduced'
                    settings.maximum_current.value = 6.0
                else:
                    setting_dict['maxChargeCurrentAC'] = 'maximum'
                    settings.maximum_current.value = 16.0
        if isinstance(attribute, BooleanAttribute) and attribute.id == 'auto_unlock':
            setting_dict['autoUnlockPlugWhenChargedAC'] = 'on' if value else 'off'
        elif settings.auto_unlock.enabled and settings.auto_unlock.value is not None:
            setting_dict['autoUnlockPlugWhenChargedAC'] = 'on' if settings.auto_unlock.value else 'off'
        precision: float = settings.target_level.precision if settings.target_level.precision is not None else 10.0
        if isinstance(attribute, LevelAttribute) and attribute.id == 'target_level':
            value = round(value / precision) * precision
            setting_dict['targetSOC_pct'] = value
        elif settings.target_level.enabled and settings.target_level.value is not None:
            setting_dict['targetSOC_pct'] = round(settings.target_level.value / precision) * precision

        url: str = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/charging/settings'
        try:
            settings_response: requests.Response = self.session.put(url, data=json.dumps(setting_dict), allow_redirects=True)
            if settings_response.status_code != requests.codes['ok']:
                LOG.error('Could not set charging settings (%s)', settings_response.status_code)
                raise SetterError(f'Could not set value ({settings_response.status_code})')
        except requests.exceptions.ConnectionError as connection_error:
            raise SetterError(f'Connection error: {connection_error}.'
                              ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
            raise SetterError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
        except requests.exceptions.ReadTimeout as timeout_error:
            raise SetterError(f'Timeout during read: {timeout_error}') from timeout_error
        except requests.exceptions.RetryError as retry_error:
            raise SetterError(f'Retrying failed: {retry_error}') from retry_error
        return value

    def __on_window_heating_start_stop(self, start_stop_command: WindowHeatingStartStopCommand, command_arguments: Union[str, Dict[str, Any]]) \
            -> Union[str, Dict[str, Any]]:
        if start_stop_command.parent is None or start_stop_command.parent.parent is None \
                or start_stop_command.parent.parent.parent is None or not isinstance(start_stop_command.parent.parent.parent, VolkswagenVehicle):
            raise CommandError('Object hierarchy is not as expected')
        if not isinstance(command_arguments, dict):
            raise CommandError('Command arguments are not a dictionary')
        vehicle: VolkswagenVehicle = start_stop_command.parent.parent.parent
        vin: Optional[str] = vehicle.vin.value
        if vin is None:
            raise CommandError('VIN in object hierarchy missing')
        if 'command' not in command_arguments:
            raise CommandError('Command argument missing')
        try:
            if command_arguments['command'] == WindowHeatingStartStopCommand.Command.START:
                url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/windowheating/start'
                command_response: requests.Response = self.session.post(url, data='{}', allow_redirects=True)
            elif command_arguments['command'] == WindowHeatingStartStopCommand.Command.STOP:
                url = f'https://emea.bff.cariad.digital/vehicle/v1/vehicles/{vin}/windowheating/stop'
                command_response: requests.Response = self.session.post(url, data='{}', allow_redirects=True)
            else:
                raise CommandError(f'Unknown command {command_arguments["command"]}')

            if command_response.status_code != requests.codes['ok']:
                LOG.error('Could not start/stop window heating (%s: %s)', command_response.status_code, command_response.text)
                raise CommandError(f'Could not start/stop window heating ({command_response.status_code}: {command_response.text})')
        except requests.exceptions.ConnectionError as connection_error:
            raise CommandError(f'Connection error: {connection_error}.'
                               ' If this happens frequently, please check if other applications communicate with the Volkswagen server.') from connection_error
        except requests.exceptions.ChunkedEncodingError as chunked_encoding_error:
            raise CommandError(f'Error: {chunked_encoding_error}') from chunked_encoding_error
        except requests.exceptions.ReadTimeout as timeout_error:
            raise CommandError(f'Timeout during read: {timeout_error}') from timeout_error
        except requests.exceptions.RetryError as retry_error:
            raise CommandError(f'Retrying failed: {retry_error}') from retry_error
        return command_arguments

    def get_name(self) -> str:
        return "Volkswagen Connector"
