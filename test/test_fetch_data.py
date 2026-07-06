"""Tests for _fetch_data (HTTP layer) and fetch_vehicles (data parsing)."""
from datetime import datetime, timedelta
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from carconnectivity.errors import TooManyRequestsError, RetrievalError

from conftest import make_connector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(status_code: int, json_data=None):
    """Build a minimal mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.elapsed = timedelta(milliseconds=50)
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


VEHICLES_URL = 'https://emea.bff.cariad.digital/vehicle/v1/vehicles'

SINGLE_VEHICLE_RESPONSE = {
    'data': [
        {
            'vin': 'WVWZZZ1KZAW000001',
            'nickname': 'My Golf',
            'model': 'Golf 8',
            'capabilities': [
                {
                    'id': 'access',
                    'status': [],
                    'userDisablingAllowed': True,
                }
            ],
        }
    ]
}


# ---------------------------------------------------------------------------
# _fetch_data tests
# ---------------------------------------------------------------------------

class TestFetchData:
    def setup_method(self):
        self.connector = make_connector()
        self.session = self.connector._mock_session

    def test_returns_json_on_200(self):
        payload = {'key': 'value'}
        self.session.get.return_value = _mock_response(200, payload)

        result = self.connector._fetch_data('https://example.com/data', session=self.session)
        assert result == payload

    def test_returns_none_on_204_allow_empty(self):
        self.session.get.return_value = _mock_response(204)

        result = self.connector._fetch_data(
            'https://example.com/data', session=self.session, allow_empty=True
        )
        assert result is None

    def test_raises_too_many_requests_on_429(self):
        self.session.get.return_value = _mock_response(429)

        with pytest.raises(TooManyRequestsError):
            self.connector._fetch_data('https://example.com/data', session=self.session)

    def test_raises_retrieval_error_on_500(self):
        self.session.get.return_value = _mock_response(500)

        with pytest.raises(RetrievalError):
            self.connector._fetch_data('https://example.com/data', session=self.session)

    def test_401_triggers_refresh_then_retry(self):
        good_response = _mock_response(200, {'ok': True})
        self.session.get.side_effect = [_mock_response(401), good_response]

        result = self.connector._fetch_data('https://example.com/data', session=self.session)

        self.session.refresh.assert_called_once()
        assert result == {'ok': True}

    def test_401_falls_back_to_login_when_refresh_fails(self):
        self.session.refresh.side_effect = Exception('refresh failed')
        good_response = _mock_response(200, {'ok': True})
        self.session.get.side_effect = [_mock_response(401), good_response]

        result = self.connector._fetch_data('https://example.com/data', session=self.session)

        self.session.login_with_retry.assert_called()
        assert result == {'ok': True}

    def test_uses_cache_when_fresh(self):
        cached_data = {'cached': True}
        url = 'https://example.com/data'
        # Inject a cache entry that is still fresh (1 second old)
        self.session.cache[url] = (cached_data, str(datetime.utcnow() - timedelta(seconds=1)))
        # max_age defaults to 299, so 1 second old is still valid

        result = self.connector._fetch_data(url, session=self.session)

        self.session.get.assert_not_called()
        assert result == cached_data

    def test_bypasses_cache_when_force_true(self):
        url = 'https://example.com/data'
        fresh_data = {'fresh': True}
        self.session.cache[url] = ({'cached': True}, str(datetime.utcnow()))
        self.session.get.return_value = _mock_response(200, fresh_data)

        result = self.connector._fetch_data(url, session=self.session, force=True)

        self.session.get.assert_called_once()
        assert result == fresh_data

    def test_raises_retrieval_error_on_connection_error(self):
        self.session.get.side_effect = requests.exceptions.ConnectionError('no route')

        with pytest.raises(RetrievalError, match='Connection error'):
            self.connector._fetch_data('https://example.com/data', session=self.session)

    def test_raises_retrieval_error_on_timeout(self):
        self.session.get.side_effect = requests.exceptions.ReadTimeout('timed out')

        with pytest.raises(RetrievalError, match='Timeout'):
            self.connector._fetch_data('https://example.com/data', session=self.session)


# ---------------------------------------------------------------------------
# fetch_vehicles tests
# ---------------------------------------------------------------------------

class TestFetchVehicles:
    def setup_method(self):
        self.connector = make_connector()
        self.session = self.connector._mock_session
        self.garage = self.connector._mock_cc.garage

    def _patch_fetch_data(self, return_value):
        patcher = patch.object(self.connector, '_fetch_data', return_value=return_value)
        patcher.start()
        self.addCleanup = patcher.stop  # noqa: allow dynamic assignment

    def test_adds_vehicle_to_garage(self):
        with patch.object(self.connector, '_fetch_data', return_value=SINGLE_VEHICLE_RESPONSE), \
             patch.object(self.connector, 'update_vehicles'):
            self.connector.fetch_vehicles()

        self.garage.add_vehicle.assert_called_once()
        vin_arg = self.garage.add_vehicle.call_args[0][0]
        assert vin_arg == 'WVWZZZ1KZAW000001'

    def test_vehicle_nickname_and_model_set(self):
        added_vehicle = MagicMock()
        self.garage.get_vehicle.return_value = None

        with patch('carconnectivity_connectors.volkswagen.connector.VolkswagenVehicle',
                   return_value=added_vehicle) as mock_veh_cls, \
             patch.object(self.connector, '_fetch_data', return_value=SINGLE_VEHICLE_RESPONSE), \
             patch.object(self.connector, 'update_vehicles'):
            self.connector.fetch_vehicles()

        added_vehicle.name._set_value.assert_called_with('My Golf')
        added_vehicle.model._set_value.assert_called_with('Golf 8')

    def test_empty_data_does_not_add_vehicles(self):
        with patch.object(self.connector, '_fetch_data', return_value={'data': []}), \
             patch.object(self.connector, 'update_vehicles'):
            self.connector.fetch_vehicles()

        self.garage.add_vehicle.assert_not_called()

    def test_none_response_does_not_crash(self):
        with patch.object(self.connector, '_fetch_data', return_value=None), \
             patch.object(self.connector, 'update_vehicles'):
            self.connector.fetch_vehicles()  # should not raise

        self.garage.add_vehicle.assert_not_called()

    def test_vehicles_no_longer_in_response_are_removed(self):
        existing_vin = 'WVWOLD000000'
        self.garage.list_vehicle_vins.return_value = [existing_vin]
        existing_vehicle = MagicMock()
        existing_vehicle.is_managed_by_connector.return_value = True
        self.garage.get_vehicle.side_effect = lambda v: existing_vehicle if v == existing_vin else None

        with patch.object(self.connector, '_fetch_data', return_value={'data': []}), \
             patch.object(self.connector, 'update_vehicles'):
            self.connector.fetch_vehicles()

        self.garage.remove_vehicle.assert_called_with(existing_vin)

    def test_fetch_vehicles_uses_correct_url(self):
        with patch.object(self.connector, '_fetch_data', return_value=None) as mock_fetch, \
             patch.object(self.connector, 'update_vehicles'):
            self.connector.fetch_vehicles()

        called_url = mock_fetch.call_args[0][0]
        assert called_url == VEHICLES_URL
