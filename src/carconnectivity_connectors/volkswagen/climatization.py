"""
Module for climatization for volkswagen vehicles.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from carconnectivity.climatization import Climatization
from carconnectivity.objects import GenericObject
from carconnectivity.vehicle import GenericVehicle
from carconnectivity.attributes import BooleanAttribute
from carconnectivity.units import Temperature

if TYPE_CHECKING:
    from typing import Optional, Dict


class VolkswagenClimatization(Climatization):  # pylint: disable=too-many-instance-attributes
    """
    VolkswagenClimatization class for handling Volkswagen vehicle climatization information.

    This class extends the Climatization class and includes an enumeration of various
    climatization states specific to Volkswagen vehicles.
    """
    def __init__(self, vehicle: Optional[GenericVehicle] = None, origin: Optional[Climatization] = None, initialization: Optional[Dict] = None) -> None:
        if origin is not None:
            super().__init__(origin=origin, initialization=initialization)
            if not isinstance(self.settings, VolkswagenClimatization.Settings):
                self.settings: Climatization.Settings = VolkswagenClimatization.Settings(parent=self, origin=origin.settings, initialization=initialization)
        else:
            super().__init__(vehicle=vehicle, initialization=initialization)
            self.settings: Climatization.Settings = VolkswagenClimatization.Settings(parent=self, initialization=self.get_initialization('settings'))

    class Settings(Climatization.Settings):
        """
        This class represents the settings for a skoda car climatiation.
        """
        def __init__(self, parent: Optional[GenericObject] = None, origin: Optional[Climatization.Settings] = None,
                     initialization: Optional[Dict] = None) -> None:
            if origin is not None:
                super().__init__(parent=parent, origin=origin, initialization=initialization)
            else:
                super().__init__(parent=parent, initialization=initialization)
            self.unit_in_car: Optional[Temperature] = None
            self.front_zone_left_enabled: BooleanAttribute = BooleanAttribute(parent=self, name='front_zone_left_enabled', tags={'connector_custom'},
                                                                              initialization=self.get_initialization('front_zone_left_enabled'))
            self.front_zone_right_enabled: BooleanAttribute = BooleanAttribute(parent=self, name='front_zone_right_enabled', tags={'connector_custom'},
                                                                               initialization=self.get_initialization('front_zone_right_enabled'))
            self.rear_zone_left_enabled: BooleanAttribute = BooleanAttribute(parent=self, name='rear_zone_left_enabled', tags={'connector_custom'},
                                                                             initialization=self.get_initialization('rear_zone_left_enabled'))
            self.rear_zone_right_enabled: BooleanAttribute = BooleanAttribute(parent=self, name='rear_zone_right_enabled', tags={'connector_custom'},
                                                                              initialization=self.get_initialization('rear_zone_right_enabled'))
