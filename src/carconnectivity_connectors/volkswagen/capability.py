"""Module for volkswagen vehicle capability class."""
from __future__ import annotations
from typing import TYPE_CHECKING

from enum import IntEnum

from carconnectivity.objects import GenericObject
from carconnectivity.attributes import StringAttribute, BooleanAttribute, DateAttribute, GenericAttribute

if TYPE_CHECKING:
    from typing import Dict, Optional
    from carconnectivity_connectors.volkswagen.vehicle import VolkswagenVehicle


class Capabilities(GenericObject):
    """
    Represents the capabilities of a Volkswagen vehicle.
    """
    def __init__(self, vehicle: VolkswagenVehicle) -> None:
        super().__init__(object_id='capabilities', parent=vehicle)
        self.__capabilities: Dict[str, Capability] = {}

    @property
    def capabilities(self) -> Dict[str, Capability]:
        """
        Retrieve the capabilities of the vehicle.

        Returns:
            Dict[str, Capability]: A dictionary of capabilities.
        """
        return self.__capabilities

    def add_capability(self, capability_id: str, capability: Capability) -> None:
        """
        Adds a capability to the Capabilities of the vehicle.

        Args:
            capability_id (str): The unique identifier of the capability.
            capability (Capability): The capability object to be added.

        Returns:
            None
        """
        self.__capabilities[capability_id] = capability

    def remove_capability(self, capability_id: str) -> None:
        """
        Remove a capability from the Capabilities by its capability ID.

        Args:
            capability_id (str): The ID of the capability to be removed.

        Returns:
            None
        """
        if capability_id in self.__capabilities:
            del self.__capabilities[capability_id]

    def clear_capabilities(self) -> None:
        """
        Remove all capabilities from the Capabilities.

        Returns:
            None
        """
        self.__capabilities.clear()

    def get_capability(self, capability_id: str) -> Optional[Capability]:
        """
        Retrieve a capability from the Capabilities by its capability ID.

        Args:
            capability_id (str): The unique identifier of the capability to retrieve.

        Returns:
            Capability: The capability object if found, otherwise None.
        """
        return self.__capabilities.get(capability_id)

    def has_capability(self, capability_id: str, check_status_ok=False) -> bool:
        """
        Check if the Capabilities contains a capability with the specified ID.

        Args:
            capability_id (str): The unique identifier of the capability to check.

        Returns:
            bool: True if the capability exists, otherwise False.
        """
        if check_status_ok:
            if capability_id in self.__capabilities and self.__capabilities[capability_id].enabled:
                capability: Capability = self.__capabilities[capability_id]
                if capability.status.enabled and capability.status.value is not None and len(capability.status.value) > 0:
                    return False
                return True
            return False
        return capability_id in self.__capabilities and self.__capabilities[capability_id].enabled


class Capability(GenericObject):
    """
    Represents a capability of a Volkswagen vehicle.
    """

    def __init__(self, capability_id: str, capabilities: Capabilities) -> None:
        if capabilities is None:
            raise ValueError('Cannot create capability without capabilities')
        if id is None:
            raise ValueError('Capability ID cannot be None')
        super().__init__(object_id=capability_id, parent=capabilities)
        self.delay_notifications = True
        self.capability_id = StringAttribute("id", self, capability_id, tags={'connector_custom'})
        self.expiration_date = DateAttribute("expiration_date", self, tags={'connector_custom'})
        self.user_disabling_allowed = BooleanAttribute("user_disabling_allowed", self, tags={'connector_custom'})
        self.status = GenericAttribute("status", self, value=[], tags={'connector_custom'})
        self.enabled = True
        self.delay_notifications = False

    class Status(IntEnum):
        """
        Enum for capability status.
        """
        UNKNOWN = 0
        DEACTIVATED = 1001
        INITIALLY_DISABLED = 1003
        DISABLED_BY_USER = 1004
        OFFLINE_MODE = 1005
        WORKSHOP_MODE = 1006
        MISSING_OPERATION = 1007
        MISSING_SERVICE = 1008
        PLAY_PROTECTION = 1009
        POWER_BUDGET_REACHED = 1010
        DEEP_SLEEP = 1011
        LOCATION_DATA_DISABLED = 1013
        DISABLED_FROM_VEHICLE = 1014
        DISABLED_BY_USER = 1018
        ONE_CONNECTED_INFOTAINMENT_AT_ANDROID = 1020
        DATA_SAVING_MODE = 1021
        LICENSE_INACTIVE = 2001
        LICENSE_EXPIRED = 2002
        MISSING_LICENSE = 2003
        USER_NOT_VERIFIED = 3001
        TERMS_AND_CONDITIONS_NOT_ACCEPTED = 3002
        INSUFFICIENT_RIGHTS = 3003
        CONSENT_MISSING = 3004
        LIMITED_FEATURE = 3005
        AUTH_APP_CERT_ERROR = 3006  #INSUFFICIENT_USER_ROLE 
        INSUFFICIENT_SECURITY_LEVEL = 3007
        STATUS_UNSUPPORTED = 4001
