"""Module containing the OpenStreetMap location service."""
# pylint: disable=duplicate-code
from __future__ import annotations
from typing import TYPE_CHECKING, Dict

from carconnectivity_services.base.service import ServiceType
from carconnectivity_services.location.location_service import LocationService
from carconnectivity.charging_station import ChargingStation

if TYPE_CHECKING:
    from typing import Optional, Any

    import logging

    from carconnectivity.carconnectivity import CarConnectivity
    from carconnectivity_connectors.volkswagen.connector import Connector


class VolkswagenLocationService(LocationService):  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    """
    Service for retrieving charging station location data from Volkswagen's platform.
    This service extends the LocationService to provide Volkswagen-specific functionality
    for finding and retrieving information about charging stations based on geographic
    coordinates.
    Attributes:
        connector (Connector): The Volkswagen connector instance used to fetch data from
            the CARIAD API.
    Methods:
        get_types() -> list[tuple[ServiceType, int]]:
            Returns the service types supported by this service with their priorities.
        charging_station_from_lat_lon(latitude: float, longitude: float, radius: int,
            Retrieves the nearest charging station information from Volkswagen's API
            based on geographic coordinates and search radius. Populates a ChargingStation
            object with details including location, address, charging spots, power
            capabilities, and operator information.
    """

    def __init__(self, service_id: str, car_connectivity: CarConnectivity, log: logging.Logger, connector: Connector) -> None:
        super().__init__(service_id, car_connectivity, log)
        self.connector: Connector = connector

    def get_types(self) -> list[tuple[ServiceType, int]]:
        return [(ServiceType.LOCATION_CHARGING_STATION, 100)]

    def charging_station_from_lat_lon(self, latitude: float, longitude: float, radius: int,  # pylint: disable=too-many-branches,too-many-statements
                                      charging_station: Optional[ChargingStation] = None) -> Optional[ChargingStation]:
        """
        Retrieve charging station information based on latitude and longitude coordinates.
        This method queries the Volkswagen charging station API to find the nearest charging station
        within a specified radius from the given coordinates. If multiple stations are found, the
        closest one is returned.
        Args:
            latitude (float): The latitude coordinate to search from.
            longitude (float): The longitude coordinate to search from.
            radius (int): The search radius in meters.
            charging_station (Optional[ChargingStation], optional): An existing ChargingStation object
                to update with the retrieved data. If None, a new ChargingStation object will be created
                if data is found. Defaults to None.
        Returns:
            Optional[ChargingStation]: A ChargingStation object populated with data from the API response,
                including details such as:
                - uid: Unique identifier of the station
                - name: Station name
                - location: Latitude and longitude coordinates
                - address: Street address, city, postcode, and country
                - num_spots: Total number of charging spots/connectors
                - max_power: Maximum charging power available (in kW)
                - operator_id: Charging point operator ID
                - operator_name: Charging point operator name
                Returns None if no charging stations are found or if the API request fails.
        Note:
            - The method searches the Volkswagen EMEA charging station database
            - Results are sorted by distance, with the closest station processed first
            - Only the first (closest) station is returned
            - The source is automatically set to 'Volkswagen'
        """
        url: str = f'https://emea.bff.cariad.digital/poi/charging-stations/v2?latitude={latitude}&longitude={longitude}&searchRadius={radius}'
        if self.connector.session.user_id is not None:
            url += f'&userId={self.connector.session.user_id}'
        data: Dict[str, Any] | None = self.connector._fetch_data(url, session=self.connector.session, force=True)  # pylint: disable=protected-access
        if data is not None:
            if 'chargingStations' in data and data['chargingStations']:
                data['chargingStations'] = sorted(data['chargingStations'], key=lambda x: x.get('distance', float('inf')))
                for station_dict in data['chargingStations']:
                    if 'id' in station_dict:
                        if charging_station is None:
                            charging_station = ChargingStation(name=str(station_dict['id']), parent=None)
                        charging_station.uid._set_value(station_dict['id'])  # pylint: disable=protected-access
                        charging_station.source._set_value('Volkswagen')  # pylint: disable=protected-access
                        if 'name' in station_dict:
                            charging_station.name._set_value(station_dict['name'])  # pylint: disable=protected-access
                        if 'latitude' in station_dict and 'longitude' in station_dict:
                            charging_station.latitude._set_value(station_dict['latitude'])  # pylint: disable=protected-access
                            charging_station.longitude._set_value(station_dict['longitude'])  # pylint: disable=protected-access
                        if any(key in station_dict for key in ['street', 'city', 'postcode', 'country']):
                            address_parts: list[str] = []
                            if 'street' in station_dict:
                                address_parts.append(station_dict['street'])
                            if 'postcode' in station_dict:
                                address_parts.append(str(station_dict['postcode']))
                            if 'city' in station_dict:
                                address_parts.append(str(station_dict['city']))
                            if 'country' in station_dict:
                                address_parts.append(station_dict['country'])
                            charging_station.address._set_value(', '.join(address_parts))  # pylint: disable=protected-access
                        if 'chargingSpots' in station_dict and isinstance(station_dict['chargingSpots'], list):
                            total_spots: int = 0
                            max_power: float = 0.0
                            for spot in station_dict['chargingSpots']:
                                if 'connectors' in spot and isinstance(spot['connectors'], list):
                                    total_spots += len(spot['connectors'])
                                    for connector in spot['connectors']:
                                        if 'chargingPower' in connector:
                                            try:
                                                power: float = float(connector['chargingPower'])
                                                if power > max_power:
                                                    max_power = power
                                            except (ValueError, TypeError):
                                                self.log.debug(f"Invalid chargingPower value: {connector['chargingPower']}")
                            charging_station.num_spots._set_value(total_spots)  # pylint: disable=protected-access
                            charging_station.max_power._set_value(max_power)  # pylint: disable=protected-access
                        if 'cpoiOperatorInfo' in station_dict:
                            operator_info = station_dict['cpoiOperatorInfo']
                            if 'id' in operator_info:
                                charging_station.operator_id._set_value(operator_info['id'])  # pylint: disable=protected-access
                            if 'name' in operator_info:
                                charging_station.operator_name._set_value(operator_info['name'])  # pylint: disable=protected-access
                        return charging_station
        return None
