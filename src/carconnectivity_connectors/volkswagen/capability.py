"""Module for volkswagen vehicle capability class."""
from __future__ import annotations
from typing import TYPE_CHECKING

from enum import IntEnum

from carconnectivity.objects import GenericObject
from carconnectivity.attributes import StringAttribute, BooleanAttribute, DateAttribute

if TYPE_CHECKING:
    from carconnectivity_connectors.volkswagen.vehicle import VolkswagenVehicle


class Capability(GenericObject):
    """
    Represents a capability of a Volkswagen vehicle.
    """

    def __init__(self, capability_id: str, vehicle: VolkswagenVehicle) -> None:
        if vehicle is None:
            raise ValueError('Cannot create capability without vehicle')
        if id is None:
            raise ValueError('Capability ID cannot be None')
        super().__init__(object_id=capability_id, parent=vehicle)
        self.capability_id = StringAttribute("id", self, capability_id)
        self.expiration_date = DateAttribute("expiration_date", self)
        self.user_disabling_allowed = BooleanAttribute("user_disabling_allowed", self)
        self.statuses = list[Capability.Status]
        self.enabled = True

    def __str__(self) -> str:
        return_string = f'{self.capability_id}'
        if self.expiration_date.enabled:
            return_string += f' expires: {self.expiration_date}'
        if self.user_disabling_allowed.enabled:
            return_string += f' user_disabling_allowed: {self.user_disabling_allowed}'
        return return_string

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
        LICENSE_INACTIVE = 2001
        LICENSE_EXPIRED = 2002
        MISSING_LICENSE = 2003
        USER_NOT_VERIFIED = 3001
        TERMS_AND_CONDITIONS_NOT_ACCEPTED = 3002
        INSUFFICIENT_RIGHTS = 3003
        CONSENT_MISSING = 3004
        LIMITED_FEATURE = 3005
        AUTH_APP_CERT_ERROR = 3006
        STATUS_UNSUPPORTED = 4001
