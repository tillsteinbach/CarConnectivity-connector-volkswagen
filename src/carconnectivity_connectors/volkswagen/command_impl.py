"""This module defines the classes that represent attributes in the CarConnectivity system."""
from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Union

from enum import Enum
import argparse
import logging

from carconnectivity.commands import GenericCommand
from carconnectivity.objects import GenericObject
from carconnectivity.errors import SetterError
from carconnectivity.util import ThrowingArgumentParser

if TYPE_CHECKING:
    from carconnectivity.objects import Optional

LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen")


class SpinCommand(GenericCommand):
    """
    SpinCommand is a command class for verifying the spin

    """
    def __init__(self, name: str = 'spin', parent: Optional[GenericObject] = None, initialization: Optional[Dict] = None) -> None:
        super().__init__(name=name, parent=parent, initialization=initialization)

    @property
    def value(self) -> Optional[Union[str, Dict]]:
        return super().value

    @value.setter
    def value(self, new_value: Optional[Union[str, Dict]]) -> None:
        # Execute early hooks before parsing the value
        new_value = self._execute_on_set_hook(new_value, early_hook=True)
        if isinstance(new_value, SpinCommand.Command):
            newvalue_dict = {}
            newvalue_dict['command'] = new_value
            new_value = newvalue_dict
        elif isinstance(new_value, str):
            parser = ThrowingArgumentParser(prog='', add_help=False, exit_on_error=False)
            parser.add_argument('command', help='Command to execute', type=SpinCommand.Command,
                                choices=list(SpinCommand.Command))
            parser.add_argument('--spin', dest='spin', help='Spin to be used instead of spin from config or .netrc', type=str, required=False,
                                default=None)
            try:
                args = parser.parse_args(new_value.strip().split(sep=' '))
            except argparse.ArgumentError as e:
                raise SetterError(f'Invalid format for SpinCommand: {e.message} {parser.format_usage()}') from e

            newvalue_dict = {}
            newvalue_dict['command'] = args.command
            if args.spin is not None:
                newvalue_dict['spin'] = args.spin
            new_value = newvalue_dict
        elif isinstance(new_value, dict):
            if 'command' in new_value and isinstance(new_value['command'], str):
                if new_value['command'] in SpinCommand.Command:
                    new_value['command'] = SpinCommand.Command(new_value['command'])
                else:
                    raise ValueError('Invalid value for SpinCommand. '
                                     f'Command must be one of {SpinCommand.Command}')
        if self._is_changeable:
            # Execute late hooks before setting the value
            new_value = self._execute_on_set_hook(new_value, early_hook=False)
            self._set_value(new_value)
        else:
            raise TypeError('You cannot set this attribute. Attribute is not mutable.')

    class Command(Enum):
        """
        Enum class representing different commands for SPIN.

        """
        VERIFY = 'verify'

        def __str__(self) -> str:
            return self.value
