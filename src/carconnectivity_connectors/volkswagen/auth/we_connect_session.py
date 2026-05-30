"""
Module implements the WeConnect Session handling.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

import json
import logging
import secrets

from urllib.parse import parse_qs, urlparse, urlencode

import requests
from requests.models import CaseInsensitiveDict

from oauthlib.common import to_unicode
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import is_secure_transport

from carconnectivity.errors import AuthenticationError, RetrievalError, TemporaryAuthenticationError

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
        super(WeConnectSession, self).login()
        if hasattr(self, '_clear_connection_pools'):
            self._clear_connection_pools()
        # Build hybrid OIDC authorization URL directly on identity.vwgroup.io
        authorization_url_str: str = self.authorization_url(url='https://identity.vwgroup.io/oidc/v1/authorize')
        # Follow the web auth flow; tokens are returned in the callback URL
        callback_url = self.do_web_auth(authorization_url_str)
        # Extract tokens directly from the hybrid callback (no BFF exchange)
        self.fetch_tokens(None, authorization_response=callback_url)
        if not self.access_token:
            raise AuthenticationError('Login failed: no access_token received in callback URL')

    def refresh(self) -> None:
        # refresh tokens from updated CARIAD endpoint (moved May 2026)
        self.refresh_tokens(
            'https://emea.bff.cariad.digital/auth/v1/idk/oidc/token',
        )

    def clear_tokens(self) -> None:
        """
        Clear all stored tokens to force a fresh login.
        
        This method is useful when the server requests new authorization
        and we need to clear invalid/expired tokens.
        """
        LOG.info("Clearing all stored tokens")
        self.token = None
        LOG.debug("All tokens cleared successfully")

    def parse_from_fragment(self, authorization_response, state=None):
        """
        Parse tokens from a hybrid OIDC callback URL that may carry params in both
        the query string (code, state) and the fragment (access_token, id_token, …).
        Combines both before delegating to the base class parser.
        """
        if authorization_response:
            parsed = urlparse(authorization_response)
            all_params: Dict[str, str] = {}
            if parsed.query:
                all_params.update({k: v[0] for k, v in parse_qs(parsed.query).items()})
            if parsed.fragment:
                all_params.update({k: v[0] for k, v in parse_qs(parsed.fragment).items()})
            if all_params:
                authorization_response = 'https://egal?' + urlencode(all_params)
        return super().parse_from_fragment(authorization_response, state=state)

    def fetch_tokens(
        self,
        token_url,  # noqa: ARG002  — ignored: hybrid flow delivers tokens in callback URL
        authorization_response=None,
        **_
    ):
        """
        Extract tokens directly from the hybrid OIDC callback URL.
        No server-side exchange with the CARIAD BFF is performed (endpoint is closed).
        """
        if authorization_response is None:
            LOG.error("fetch_tokens called without authorization_response")
            return None
        self.parse_from_fragment(authorization_response)
        if self.token is None or 'access_token' not in self.token:
            LOG.error("No access_token found in callback URL")
            return None
        LOG.debug("Hybrid flow: access_token expires in %s seconds", self.token.get('expires_in', 'unknown'))
        LOG.debug("Refresh token available: %s", 'refresh_token' in self.token)
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
        """
        Refreshes the authentication tokens using the provided refresh token.
        Args:
            token_url (str): The URL to request new tokens from.
            refresh_token (str, optional): The refresh token to use. Defaults to None.
            auth (tuple, optional): Authentication credentials. Defaults to None.
            timeout (float or tuple, optional): How long to wait for the server to send data before giving up. Defaults to None.
            headers (dict, optional): Headers to include in the request. Defaults to None.
            verify (bool, optional): Whether to verify the server's TLS certificate. Defaults to True.
            proxies (dict, optional): Proxies to use for the request. Defaults to None.
            **_ (dict): Additional arguments.
        Raises:
            ValueError: If no token endpoint is set for auto_refresh.
            InsecureTransportError: If the token URL is not secure.
            AuthenticationError: If the server requests new authorization.
            TemporaryAuthenticationError: If the token could not be refreshed due to a temporary server failure.
            RetrievalError: If the status code from the server is not recognized.
        Returns:
            dict: The new tokens.
        """
        LOG.info('Refreshing tokens')
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        # Store old refresh token in case no new one is given
        # First try to get from the current token property, then fall back to stored token
        if refresh_token is None:
            refresh_token = self.refresh_token
            # If still None, try to get from the token dict directly
            if refresh_token is None and self.token is not None:
                refresh_token = self.token.get('refresh_token')
        
        if not refresh_token:
            raise AuthenticationError('No refresh token available. Please log in again.')

        # Close any idle connections to prevent reusing stale connections
        # This helps prevent "Remote end closed connection without response" errors
        # that occur when trying to reuse a connection that the server has closed
        try:
            # Get the HTTPAdapter and close idle connections in the pool
            adapter = self.get_adapter(token_url)
            if hasattr(adapter, 'poolmanager') and adapter.poolmanager is not None:
                # Clear idle connections from the pool
                adapter.poolmanager.clear()
                LOG.debug("Cleared connection pool before token refresh")
        except Exception as e:
            # If clearing fails, log but continue - not critical
            LOG.debug("Could not clear connection pool: %s", str(e))

        # Create headers matching the examples format
        tHeaders = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Volkswagen/3.61.0-android/14",
            "x-android-package-name": "com.volkswagen.weconnect",
        }

        # Create form data body matching the examples format
        body = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }

        # Use a shorter timeout for token refresh to prevent stale connection issues
        # Token endpoints should respond quickly; 30 seconds is more than enough
        # This prevents holding connections open for 180 seconds which can lead to
        # "Remote end closed connection without response" errors
        if timeout is None:
            timeout = 30

        # Request new tokens using POST with form data
        # CRITICAL: withhold_token=True prevents adding Bearer token to token refresh request
        # Token refresh uses refresh_token in the body, NOT Bearer token in headers
        token_response = self.post(
            token_url,
            data=body,
            headers=tHeaders,
            timeout=timeout,
            verify=verify,
            withhold_token=True,
            proxies=proxies,
        )
        
        if token_response.status_code == requests.codes['unauthorized']:
            LOG.error('Token refresh failed with 401 - server requests new authorization. Refresh token may be expired or invalid.')
            raise AuthenticationError('Refreshing tokens failed: Server requests new authorization. Please log in again.')
        elif token_response.status_code in (requests.codes['internal_server_error'], requests.codes['service_unavailable'], requests.codes['gateway_timeout']):
            raise TemporaryAuthenticationError(f'Token could not be refreshed due to temporary WeConnect failure: {token_response.status_code}')
        elif token_response.status_code == requests.codes['ok']:
            # parse new tokens from response (this internally sets self.token)
            new_token = self.parse_from_body(token_response.text)
            if new_token is not None and "refresh_token" not in new_token:
                LOG.debug("No new refresh token given. Re-using old.")
                new_token["refresh_token"] = refresh_token
                # Update the token property to include the refresh_token
                self.token = new_token
            LOG.debug("Successfully refreshed tokens")
            return new_token
        else:
            raise RetrievalError(f'Status Code from WeConnect while refreshing tokens was: {token_response.status_code}')
