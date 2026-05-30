"""Tests for Connector authentication / initialisation logic."""
from unittest.mock import MagicMock, patch

import pytest

from carconnectivity.errors import AuthenticationError

from carconnectivity_connectors.volkswagen.connector import Connector
from carconnectivity_connectors.volkswagen.auth.we_connect_session import WeConnectSession
from conftest import make_mock_car_connectivity


def _build_connector(config, token=None, refresh_token=None):
    """Instantiate Connector with all external I/O patched out."""
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
        connector = Connector(connector_id='vw', car_connectivity=mock_cc, config=config)

    connector._mock_session = mock_session
    return connector


class TestConnectorLoginBehaviour:
    def test_login_with_retry_called_when_no_tokens(self):
        connector = _build_connector({'username': 'u@ex.com', 'password': 'pw'})
        connector._mock_session.login_with_retry.assert_called_once()
        connector._mock_session.refresh.assert_not_called()

    def test_refresh_called_when_tokens_exist(self):
        connector = _build_connector(
            {'username': 'u@ex.com', 'password': 'pw'},
            token={'access_token': 'abc'},
            refresh_token='refresh_xyz',
        )
        connector._mock_session.refresh.assert_called_once()
        connector._mock_session.login_with_retry.assert_not_called()


class TestConnectorConfigValidation:
    def test_missing_username_raises(self):
        mock_cc = make_mock_car_connectivity()
        with patch('carconnectivity_connectors.volkswagen.connector.SessionManager'), \
             patch('carconnectivity_connectors.volkswagen.connector.VolkswagenLocationService'), \
             pytest.raises(AuthenticationError):
            Connector(connector_id='vw', car_connectivity=mock_cc, config={'password': 'pw'})

    def test_missing_password_raises(self):
        mock_cc = make_mock_car_connectivity()
        with patch('carconnectivity_connectors.volkswagen.connector.SessionManager'), \
             patch('carconnectivity_connectors.volkswagen.connector.VolkswagenLocationService'), \
             pytest.raises(AuthenticationError):
            Connector(connector_id='vw', car_connectivity=mock_cc, config={'username': 'u@ex.com'})

    def test_interval_below_minimum_raises(self):
        mock_cc = make_mock_car_connectivity()
        with patch('carconnectivity_connectors.volkswagen.connector.SessionManager'), \
             patch('carconnectivity_connectors.volkswagen.connector.VolkswagenLocationService'), \
             pytest.raises(ValueError):
            Connector(
                connector_id='vw',
                car_connectivity=mock_cc,
                config={'username': 'u@ex.com', 'password': 'pw', 'interval': 60},
            )

    def test_default_interval_is_300(self):
        connector = _build_connector({'username': 'u@ex.com', 'password': 'pw'})
        assert connector.active_config['interval'] == 300

    def test_custom_interval_stored(self):
        connector = _build_connector({'username': 'u@ex.com', 'password': 'pw', 'interval': 600})
        assert connector.active_config['interval'] == 600

    def test_spin_stored_when_provided(self):
        connector = _build_connector({'username': 'u@ex.com', 'password': 'pw', 'spin': '1234'})
        assert connector.active_config['spin'] == '1234'

    def test_spin_none_when_not_provided(self):
        connector = _build_connector({'username': 'u@ex.com', 'password': 'pw'})
        assert connector.active_config['spin'] is None
