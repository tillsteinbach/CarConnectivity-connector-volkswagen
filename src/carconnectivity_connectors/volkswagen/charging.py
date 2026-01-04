"""
Module for charging for Volskwagen vehicles.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from enum import Enum

from carconnectivity.charging import Charging
from carconnectivity.vehicle import ElectricVehicle

if TYPE_CHECKING:
    from typing import Optional, Dict

    from carconnectivity.objects import GenericObject


class VolkswagenCharging(Charging):  # pylint: disable=too-many-instance-attributes
    """
    VolkswagenCharging class for handling Volkswagen vehicle charging information.

    This class extends the Charging class and includes an enumeration of various
    charging states specific to Volkswagen vehicles.
    """
    def __init__(self, vehicle: Optional[ElectricVehicle] = None, origin: Optional[Charging] = None, initialization: Optional[Dict] = None) -> None:
        if origin is not None:
            super().__init__(vehicle=vehicle, origin=origin, initialization=initialization)
            self.settings = VolkswagenCharging.Settings(parent=self, origin=origin.settings)
        else:
            super().__init__(vehicle=vehicle, initialization=initialization)
            self.settings = VolkswagenCharging.Settings(parent=self, initialization=self.get_initialization('settings'))

    class Settings(Charging.Settings):
        """
        This class represents the settings for car volkswagen car charging.
        """
        def __init__(self, parent: Optional[GenericObject] = None, origin: Optional[Charging.Settings] = None, initialization: Optional[Dict] = None) -> None:
            if origin is not None:
                super().__init__(parent=parent, origin=origin, initialization=initialization)
            else:
                super().__init__(parent=parent, initialization=initialization)
            self.max_current_in_ampere: Optional[bool] = None

    class VolkswagenChargingState(Enum,):
        """
        Enum representing the various charging states for a Volkswagen vehicle.
        """
        OFF = 'off'
        READY_FOR_CHARGING = 'readyForCharging'
        NOT_READY_FOR_CHARGING = 'notReadyForCharging'
        CONSERVATION = 'conservation'
        CHARGE_PURPOSE_REACHED_NOT_CONSERVATION_CHARGING = 'chargePurposeReachedAndNotConservationCharging'
        CHARGE_PURPOSE_REACHED_CONSERVATION = 'chargePurposeReachedAndConservation'
        CHARGING = 'charging'
        ERROR = 'error'
        UNSUPPORTED = 'unsupported'
        DISCHARGING = 'discharging'
        UNKNOWN = 'unknown charging state'

    class VolkswagenChargeMode(Enum,):
        """
        Enum class representing different Volkswagen charge modes.
        """
        MANUAL = 'manual'
        INVALID = 'invalid'
        OFF = 'off'
        TIMER = 'timer'
        ONLY_OWN_CURRENT = 'onlyOwnCurrent'
        PREFERRED_CHARGING_TIMES = 'preferredChargingTimes'
        TIMER_CHARGING_WITH_CLIMATISATION = 'timerChargingWithClimatisation'
        HOME_STORAGE_CHARGING = 'homeStorageCharging'
        IMMEDIATE_DISCHARGING = 'immediateDischarging'
        UNKNOWN = 'unknown charge mode'


# Mapping of Volkswagen charging states to generic charging states
mapping_volskwagen_charging_state: Dict[VolkswagenCharging.VolkswagenChargingState, Charging.ChargingState] = {
    VolkswagenCharging.VolkswagenChargingState.OFF: Charging.ChargingState.OFF,
    VolkswagenCharging.VolkswagenChargingState.NOT_READY_FOR_CHARGING: Charging.ChargingState.OFF,
    VolkswagenCharging.VolkswagenChargingState.READY_FOR_CHARGING: Charging.ChargingState.READY_FOR_CHARGING,
    VolkswagenCharging.VolkswagenChargingState.CONSERVATION: Charging.ChargingState.CONSERVATION,
    VolkswagenCharging.VolkswagenChargingState.CHARGE_PURPOSE_REACHED_NOT_CONSERVATION_CHARGING: Charging.ChargingState.READY_FOR_CHARGING,
    VolkswagenCharging.VolkswagenChargingState.CHARGE_PURPOSE_REACHED_CONSERVATION: Charging.ChargingState.CONSERVATION,
    VolkswagenCharging.VolkswagenChargingState.CHARGING: Charging.ChargingState.CHARGING,
    VolkswagenCharging.VolkswagenChargingState.ERROR: Charging.ChargingState.ERROR,
    VolkswagenCharging.VolkswagenChargingState.UNSUPPORTED: Charging.ChargingState.UNSUPPORTED,
    VolkswagenCharging.VolkswagenChargingState.DISCHARGING: Charging.ChargingState.DISCHARGING,
    VolkswagenCharging.VolkswagenChargingState.UNKNOWN: Charging.ChargingState.UNKNOWN
}
