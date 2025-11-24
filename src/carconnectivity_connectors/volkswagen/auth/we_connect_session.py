"""
Module implements the WeConnect Session handling.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

import json
import logging
import secrets

from urllib.parse import parse_qsl, urlparse

import requests
from requests.models import CaseInsensitiveDict

from oauthlib.common import add_params_to_uri, generate_nonce, to_unicode
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import is_secure_transport

from carconnectivity.errors import AuthenticationError, RetrievalError, TemporaryAuthenticationError

from carconnectivity_connectors.volkswagen.auth.openid_session import AccessType
from carconnectivity_connectors.volkswagen.auth.vw_web_session import VWWebSession

if TYPE_CHECKING:
    from typing import Tuple, Dict


LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen.auth")


class WeConnectSession(VWWebSession):
    """
    WeConnectSession class handles the authentication and session management for Volkswagen's WeConnect service.
    """
    def __init__(self, session_user, **kwargs) -> None:
        super(WeConnectSession, self).__init__(client_id='a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
                                               refresh_url='https://identity.vwgroup.io/oidc/v1/token',
                                               scope='openid profile badge cars dealers vin',
                                               redirect_uri='weconnect://authenticated',
                                               state=None,
                                               session_user=session_user,
                                               **kwargs)

        self.headers = CaseInsensitiveDict({
            'accept': '*/*',
            'content-type': 'application/json',
            'content-version': '1',
            'x-newrelic-id': 'VgAEWV9QDRAEXFlRAAYPUA==',
            'user-agent': 'WeConnect/3 CFNetwork/1331.0.7 Darwin/21.4.0',
            'accept-language': 'de-de',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
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
        # retrieve authorization URL
        authorization_url_str: str = self.authorization_url(url='https://identity.vwgroup.io/oidc/v1/authorize')
        # perform web authentication
        response = self.do_web_auth(authorization_url_str)
        # fetch tokens from web authentication response
        self.fetch_tokens('https://emea.bff.cariad.digital/login/v1/idk/token',
                          authorization_response=response)

    def refresh(self) -> None:
        # refresh tokens from refresh endpoint
        self.refresh_tokens(
            'https://emea.bff.cariad.digital/user-login/refresh/v1',
        )

    def authorization_url(self, url, state=None, **kwargs) -> str:
        if state is not None:
            raise AuthenticationError('Do not provide state')
        if self.redirect_uri is None:
            raise AuthenticationError('Redirect URI is not set')

        params: list[Tuple[str, str]] = [(('redirect_uri', self.redirect_uri)),
                                         (('nonce', generate_nonce()))]

        # add required parameters redirect_uri and nonce to the authorization URL
        auth_url: str = add_params_to_uri('https://emea.bff.cariad.digital/user-login/v1/authorize', params)
        try_login_response: requests.Response = self.get(auth_url, allow_redirects=False, access_type=AccessType.NONE)  # pyright: ignore reportCallIssue
        if try_login_response.status_code != requests.codes['see_other'] or 'Location' not in try_login_response.headers:
            raise AuthenticationError('Authorization URL could not be fetched due to WeConnect failure')
        # Redirect is URL to authorize
        redirect: str = try_login_response.headers['Location']
        query: str = urlparse(redirect).query
        query_params: Dict[str, str] = dict(parse_qsl(query))
        if 'state' in query_params:
            self.state = query_params['state']

        return redirect

    def fetch_tokens(
        self,
        token_url,
        authorization_response=None,
        **_
    ):
        """
        Fetches tokens using the given token URL using the tokens from authorization response.

        Args:
            token_url (str): The URL to request the tokens from.
            authorization_response (str, optional): The authorization response containing the tokens. Defaults to None.
            **_ : Additional keyword arguments.

        Returns:
            dict: A dictionary containing the fetched tokens if successful.
            None: If the tokens could not be fetched.

        Raises:
            TemporaryAuthenticationError: If the token request fails due to a temporary WeConnect failure.
        """
        # take token from authorization response (those are stored in self.token now!)
        self.parse_from_fragment(authorization_response)

        if self.token is not None and all(key in self.token for key in ('state', 'id_token', 'access_token', 'code')):
            # Generate json body for token request

            body: str = json.dumps(
                {
                    'state': self.token['state'],
                    'id_token': self.token['id_token'],
                    'redirect_uri': self.redirect_uri,
                    'region': 'emea',
                    'access_token': self.token['access_token'],
                    'authorizationCode': self.token['code'],
                })

            request_headers: CaseInsensitiveDict = self.headers  # pyright: ignore reportAssignmentType
            request_headers['accept'] = 'application/json'

            # request tokens from token_url
            token_response = self.post(token_url, headers=request_headers, data=body, allow_redirects=False,
                                       access_type=AccessType.ID)  # pyright: ignore reportCallIssue
            if token_response.status_code != requests.codes['ok']:
                print(token_response.text)
                raise TemporaryAuthenticationError(f'Token could not be fetched due to temporary WeConnect failure: {token_response.status_code}')
            # parse token from response body
            token = self.parse_from_body(token_response.text)

            return token
        return None

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
        # Let OAuthlib parse the token
        return super(WeConnectSession, self).parse_from_body(token_response=fixed_token_response, state=state)

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
        refresh_token = refresh_token or self.refresh_token

        if headers is None:
            headers = self.headers

        # Request new tokens using the refresh token
        token_response = self.get(
            token_url,
            auth=auth,
            timeout=timeout,
            headers=headers,
            verify=verify,
            withhold_token=False,  # pyright: ignore reportCallIssue
            proxies=proxies,
            access_type=AccessType.REFRESH  # pyright: ignore reportCallIssue
        )
        if token_response.status_code == requests.codes['unauthorized']:
            raise AuthenticationError('Refreshing tokens failed: Server requests new authorization')
        elif token_response.status_code in (requests.codes['internal_server_error'], requests.codes['service_unavailable'], requests.codes['gateway_timeout']):
            raise TemporaryAuthenticationError('Token could not be refreshed due to temporary WeConnect failure: {tokenResponse.status_code}')
        elif token_response.status_code == requests.codes['ok']:
            # parse new tokens from response
            self.parse_from_body(token_response.text)
            if self.token is not None and "refresh_token" not in self.token:
                LOG.debug("No new refresh token given. Re-using old.")
                self.token["refresh_token"] = refresh_token
            return self.token
        else:
            raise RetrievalError(f'Status Code from WeConnect while refreshing tokens was: {token_response.status_code}')
