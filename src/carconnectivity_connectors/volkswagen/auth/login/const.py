"""Constants for VW identity device-flow login."""

# Device authorization flow endpoints (identity.vwgroup.io)
DEVICE_FLOW_CLIENT_ID = "650d46ca-2475-4384-85c2-6af3bf3d52f1@apps_vw-dilab_com"
DEVICE_FLOW_CLIENT_SCOPE = "openid profile badge cars dealers vin offline_access"
DEVICE_FLOW_BASE_URL = "https://identity.vwgroup.io"
DEVICE_FLOW_AUTHORIZATION_URL = DEVICE_FLOW_BASE_URL + "/oidc/v1/device_authorization"
DEVICE_FLOW_TOKEN_URL = DEVICE_FLOW_BASE_URL + "/oidc/v1/token"
DEVICE_FLOW_LOGIN_IDENTIFIER_URL = (
    DEVICE_FLOW_BASE_URL + "/signin-service/v1/{client_id}/login/identifier"
)
DEVICE_FLOW_LOGIN_AUTHENTICATE_URL = (
    DEVICE_FLOW_BASE_URL + "/signin-service/v1/{client_id}/login/authenticate"
)
DEVICE_FLOW_CODE_CONFIRMATION_URL = (
    DEVICE_FLOW_BASE_URL + "/signin-service/v1/device/{client_id}/{user_code}"
)
DEVICE_FLOW_BROWSER_HEADERS = {
    "User-Agent": (
        "carconnectivity-connector-volkswagen-auth/1.0"
        " (+https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
# Use this if VW blocks the library user-agent.
DEVICE_FLOW_BROWSER_HEADERS_FIREFOX = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) "
        "Gecko/20100101 Firefox/130.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
