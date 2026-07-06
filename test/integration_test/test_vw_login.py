"""
Integration tests — require real VW credentials and network access.

Run with:
    pytest -m integration -v

Credentials are loaded from test/integration_test/carConnectivity.json.
Tests are skipped automatically if the file is missing or credentials are absent.
"""
import json
import os
import pytest

_DIR = os.path.dirname(__file__)
# carConnectivity.local.json is gitignored and holds real credentials.
# carConnectivity.json is the placeholder template committed to the repo.
_LOCAL_FILE = os.path.join(_DIR, 'carConnectivity.local.json')
_TEMPLATE_FILE = os.path.join(_DIR, 'carConnectivity.json')
CREDENTIALS_FILE = _LOCAL_FILE if os.path.exists(_LOCAL_FILE) else _TEMPLATE_FILE

_PLACEHOLDER_VALUES = {'YOUR_EMAIL@example.com', 'YOUR_PASSWORD', '', None}


def _load_credentials():
    """
    Return (username, password) from carConnectivity.local.json (preferred) or
    carConnectivity.json. Returns (None, None) when neither file exists or when
    the file contains only placeholder values.
    """
    if not os.path.exists(CREDENTIALS_FILE):
        return None, None
    with open(CREDENTIALS_FILE) as f:
        cfg = json.load(f)
    try:
        connector_cfg = cfg['carConnectivity']['connectors'][0]['config']
        username = connector_cfg.get('username')
        password = connector_cfg.get('password')
        if username in _PLACEHOLDER_VALUES or password in _PLACEHOLDER_VALUES:
            return None, None
        return username, password
    except (KeyError, IndexError):
        return None, None


USERNAME, PASSWORD = _load_credentials()
_skip_if_no_creds = pytest.mark.skipif(
    not USERNAME or not PASSWORD,
    reason='VW credentials not found in test/integration_test/carConnectivity.json',
)


@pytest.fixture(scope='module')
def vw_connector():
    """Authenticated Connector instance, shared across all tests in this module."""
    from carconnectivity.carconnectivity import CarConnectivity
    from carconnectivity_connectors.volkswagen.connector import Connector

    config = {
        'carConnectivity': {
            'connectors': [{'type': 'volkswagen', 'config': {
                'username': USERNAME,
                'password': PASSWORD,
                'interval': 180,
            }}],
            'plugins': [],
        }
    }
    cc = CarConnectivity(config=config)
    connector = next(
        (c for c in cc.connectors.connectors.values() if isinstance(c, Connector)),
        None,
    )
    assert connector is not None, 'Volkswagen connector not found in CarConnectivity instance'
    # Attach cc so tests can access the garage
    connector._cc = cc
    return connector


@pytest.mark.integration
@_skip_if_no_creds
class TestVWLogin:
    def test_access_token_present(self, vw_connector):
        """Login must produce a non-empty access token."""
        assert vw_connector.session.access_token, 'access_token is missing after login'

    def test_access_token_is_string(self, vw_connector):
        assert isinstance(vw_connector.session.access_token, str)
        assert len(vw_connector.session.access_token) > 20

    def test_token_not_expired(self, vw_connector):
        assert not vw_connector.session.expired, 'token is already expired after login'

    def test_expires_in_positive(self, vw_connector):
        """Token should have a positive lifetime (VW issues 7200 s tokens)."""
        expires_in = vw_connector.session.expires_in
        assert expires_in is not None, 'expires_in not set'
        assert float(expires_in) > 0, f'expires_in is not positive: {expires_in}'

    def test_session_authorized(self, vw_connector):
        assert vw_connector.session.authorized


@pytest.mark.integration
@_skip_if_no_creds
class TestVWFetchVehicles:
    @pytest.fixture(autouse=True)
    def _fetch(self, vw_connector):
        vw_connector.fetch_vehicles()
        self.garage = vw_connector._cc.garage
        self.vins = list(self.garage.list_vehicle_vins())

    def test_at_least_one_vehicle(self):
        assert len(self.vins) > 0, 'No vehicles returned from VW API'

    def test_each_vehicle_has_vin(self):
        for vin in self.vins:
            assert vin and len(vin) == 17, f'Invalid VIN: {vin!r}'

    def test_each_vehicle_has_name_or_model(self):
        """Every vehicle must have at least a name or a model set."""
        for vin in self.vins:
            v = self.garage.get_vehicle(vin)
            has_name = v.name.value is not None
            has_model = v.model.value is not None
            assert has_name or has_model, f'Vehicle {vin} has neither name nor model'

    def test_vehicle_with_capabilities_has_at_least_one(self):
        """At least one vehicle in the account must expose capabilities."""
        totals = sum(
            len(self.garage.get_vehicle(vin).capabilities.capabilities)
            for vin in self.vins
        )
        assert totals > 0, 'No capabilities found across all vehicles'

    def test_most_capable_vehicle_has_many_capabilities(self):
        """The vehicle with the most capabilities should expose at least 10."""
        max_caps = max(
            len(self.garage.get_vehicle(vin).capabilities.capabilities)
            for vin in self.vins
        )
        assert max_caps >= 10, f'Expected ≥10 capabilities on at least one vehicle, got max={max_caps}'

    def test_most_capable_vehicle_has_key_capabilities(self):
        """The most capable vehicle should include common core capabilities."""
        most_capable_vin = max(
            self.vins,
            key=lambda v: len(self.garage.get_vehicle(v).capabilities.capabilities),
        )
        caps = set(self.garage.get_vehicle(most_capable_vin).capabilities.capabilities.keys())
        for expected in ('access', 'measurements', 'fuelStatus'):
            assert expected in caps, (
                f'Core capability {expected!r} missing from {most_capable_vin} '
                f'(available: {sorted(caps)})'
            )
