"""Shared fixtures and helpers for the test suite."""
from unittest.mock import MagicMock, patch
import pytest

from carconnectivity_connectors.volkswagen.auth.we_connect_session import WeConnectSession


def make_mock_car_connectivity():
    """Create a mock CarConnectivity instance with the minimal interface the Connector needs."""
    cc = MagicMock()
    cc.get_tokenstore.return_value = {}
    cc.get_cache.return_value = {}
    cc.garage = MagicMock()
    cc.garage.get_vehicle.return_value = None
    cc.garage.list_vehicle_vins.return_value = []
    cc.garage.get_initialization.return_value = None
    return cc


def make_connector(config=None, token=None, refresh_token=None):
    """
    Return a Connector with all network/IO dependencies patched.

    Parameters
    ----------
    config:
        Extra keys merged into the base config dict.
    token / refresh_token:
        When provided the mock session looks like it already has tokens,
        so ``session.refresh()`` is called instead of ``session.login_with_retry()``.
    """
    from carconnectivity_connectors.volkswagen.connector import Connector

    base_config = {'username': 'test@example.com', 'password': 'secret'}
    if config:
        base_config.update(config)

    mock_session = MagicMock(spec=WeConnectSession)
    mock_session.token = token
    mock_session.refresh_token = refresh_token
    mock_session.cache = {}

    mock_manager = MagicMock()
    mock_manager.get_session.return_value = mock_session

    mock_cc = make_mock_car_connectivity()

    with patch('carconnectivity_connectors.volkswagen.connector.SessionManager', return_value=mock_manager), \
         patch('carconnectivity_connectors.volkswagen.connector.VolkswagenLocationService') as mock_loc:
        mock_loc.return_value.get_types.return_value = []
        connector = Connector(
            connector_id='vw_test',
            car_connectivity=mock_cc,
            config=base_config,
        )

    connector._mock_session = mock_session
    connector._mock_manager = mock_manager
    connector._mock_cc = mock_cc
    return connector
