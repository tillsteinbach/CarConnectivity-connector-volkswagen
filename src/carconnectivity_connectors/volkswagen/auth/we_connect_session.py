"""
Module implements the WeConnect Session handling.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

import json
import logging

from urllib.parse import parse_qs, urlparse, urlencode

from requests.models import CaseInsensitiveDict

from oauthlib.common import to_unicode

from carconnectivity.errors import AuthenticationError, TemporaryAuthenticationError

from carconnectivity_connectors.volkswagen.auth.openid_session import AccessType
from carconnectivity_connectors.volkswagen.auth.vw_web_session import VWWebSession

if TYPE_CHECKING:
    from typing import Dict


LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen.auth")


class WeConnectSession(VWWebSession):
    """
    WeConnectSession class handles the authentication and session management for Volkswagen's WeConnect service.
    """
    def __init__(self, session_user, **kwargs) -> None:
        super(WeConnectSession, self).__init__(client_id='a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
                                               refresh_url='https://identity.vwgroup.io/oidc/v1/token',
                                               scope='openid profile badge cars dealers vin offline_access',
                                               redirect_uri='weconnect://authenticated',
                                               state=None,
                                               session_user=session_user,
                                               **kwargs)

        self.headers = CaseInsensitiveDict({
            'accept': '*/*',
            'content-type': 'application/json',
            'content-version': '1',
            'x-newrelic-id': 'VgAEWV9QDRAEXFlRAAYPUA==',
            'user-agent': 'Volkswagen/3.61.0-android/14',
            'accept-language': 'de-de',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'x-android-package-name': 'com.volkswagen.weconnect'
        })

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        access_type=AccessType.ACCESS,
        token=None,
        timeout=None,
        **kwargs
    ):
        """Intercept all requests and add weconnect-trace-id header."""

        import secrets
        traceId = secrets.token_hex(16)
        we_connect_trace_id = (traceId[:8] + '-' + traceId[8:12] + '-' + traceId[12:16] + '-' + traceId[16:20] + '-' + traceId[20:]).upper()
        headers = headers or {}
        headers['weconnect-trace-id'] = we_connect_trace_id

        return super(WeConnectSession, self).request(
            method, url, headers=headers, data=data, withhold_token=withhold_token, access_type=access_type, token=token, timeout=timeout, **kwargs
        )

    def login(self):
        """Perform OIDC hybrid flow authentication.

        Uses response_type=code id_token token so identity.vwgroup.io (Auth0)
        delivers access_token and id_token directly in the callback URL.
        No server-side token exchange with the CARIAD BFF is needed.
        """
        super(WeConnectSession, self).login()
        # Build hybrid OIDC authorization URL directly on identity.vwgroup.io.
        # The parent class authorization_url() hardcodes response_type=code id_token token.
        auth_url: str = self.authorization_url(url='https://identity.vwgroup.io/oidc/v1/authorize')
        # Follow the web auth flow; tokens are returned in the callback URL
        callback_url = self.do_web_auth(auth_url)
        # Extract tokens directly from the hybrid callback (no BFF exchange)
        self.fetch_tokens(None, authorization_response=callback_url)
        if not self.access_token:
            raise AuthenticationError('Login failed: no access_token received in callback URL')

    def refresh(self) -> None:
        """Perform full re-login since OIDC hybrid flow does not issue refresh tokens.

        The hybrid flow (response_type=code id_token token) delivers tokens
        directly in the callback URL with no refresh_token for security
        reasons. When the access_token expires, a complete re-authentication
        is required.
        """
        LOG.info('No refresh token available (OIDC hybrid flow). Performing full re-login.')
        self.login()

    def clear_tokens(self) -> None:
        """
        Clear all stored tokens to force a fresh login.

        This method is useful when the server requests new authorization
        and we need to clear invalid/expired tokens.
        """
        LOG.info("Clearing all stored tokens")
        self.token = None
        LOG.debug("All tokens cleared successfully")

    def fetch_tokens(
        self,
        token_url,  # noqa: ARG002 — ignored: hybrid flow delivers tokens in callback URL
        authorization_response=None,
        **_
    ):
        """Extract tokens directly from the OIDC hybrid flow callback URL.

        With hybrid flow (response_type=code id_token token), the OAuth
        callback URL already contains access_token and id_token directly.
        No server-side token exchange with the CARIAD BFF is performed
        (that endpoint is closed / returns 401 access_denied).

        This follows the same approach as robinostlund/volkswagencarnet#333.
        """
        if authorization_response is None:
            LOG.error("fetch_tokens called without authorization_response")
            return None

        # Parse tokens from the hybrid OIDC callback URL.
        # Combines query-string params (code, state) with fragment params
        # (access_token, id_token) before delegating to the base parser.
        parsed = urlparse(authorization_response)
        all_params: Dict[str, str] = {}
        if parsed.query:
            all_params.update({k: v[0] for k, v in parse_qs(parsed.query).items()})
        if parsed.fragment:
            all_params.update({k: v[0] for k, v in parse_qs(parsed.fragment).items()})
        if all_params:
            authorization_response = 'https://egal?' + urlencode(all_params)

        self.parse_from_fragment(authorization_response)

        if self.token is None or 'access_token' not in self.token:
            LOG.error("No access_token found in callback URL")
            return None

        LOG.debug("Hybrid flow: access_token expires in %s seconds", self.token.get('expires_in', 'unknown'))
        LOG.debug("Refresh token available: %s", 'refresh_token' in self.token)

        # OIDC hybrid flow does not return refresh_token for security reasons.
        # Re-login will be required when the access_token expires.
        if 'refresh_token' not in self.token:
            LOG.debug('No refresh token in response (expected with hybrid flow)')

        return self.token

    def parse_from_body(self, token_response, state=None):
        """
            Fix strange token naming before parsing it with OAuthlib.
        """
        try:
            # Tokens are in body of response in json format
            token = json.loads(token_response)
        except json.decoder.JSONDecodeError as err:
            raise TemporaryAuthenticationError('Token could not be refreshed due to temporary WeConnect failure: json could not be decoded') from err
        # Fix token keys, we want access_token instead of accessToken
        if 'accessToken' in token:
            token['access_token'] = token.pop('accessToken')
        # Fix token keys, we want id_token instead of idToken
        if 'idToken' in token:
            token['id_token'] = token.pop('idToken')
        # Fix token keys, we want refresh_token instead of refreshToken
        if 'refreshToken' in token:
            token['refresh_token'] = token.pop('refreshToken')
        # generate json from fixed dict
        fixed_token_response = to_unicode(json.dumps(token)).encode("utf-8")
        # Let OAuthlib parse the token (this internally sets self.token)
        parsed_token = super(WeConnectSession, self).parse_from_body(token_response=fixed_token_response, state=state)
        return parsed_token

    def refresh_tokens(
        self,
        token_url,
        refresh_token=None,
        auth=None,
        timeout=None,
        headers=None,
        verify=True,
        proxies=None,
        **_
    ):
        """Token refresh is not available with OIDC hybrid flow.

        The hybrid flow does not return a refresh_token — Auth0 issues no
        refresh tokens for security reasons with response_type=code id_token
        token. When tokens expire, a full re-login is required.

        This method is preserved as a forward-compatibility placeholder
        in case VW restores a usable code exchange path on the BFF.
        """
        LOG.info('Token refresh not available (OIDC hybrid flow). Performing full re-login.')
        self.login()
        return self.token
