"""Implements a session class that handles OpenID authentication."""
from __future__ import annotations
from typing import TYPE_CHECKING

from enum import Enum, auto
import time
import logging
import requests
import jwt
from datetime import datetime, timezone

from oauthlib.common import UNICODE_ASCII_CHARACTER_SET, generate_nonce, generate_token
from oauthlib.oauth2.rfc6749.parameters import parse_authorization_code_response, parse_token_response, prepare_grant_uri
from oauthlib.oauth2.rfc6749.errors import InsecureTransportError, TokenExpiredError, MissingTokenError
from oauthlib.oauth2.rfc6749.utils import is_secure_transport

from requests.adapters import HTTPAdapter

from carconnectivity.errors import AuthenticationError, RetrievalError

from carconnectivity_connectors.volkswagen.auth.auth_util import add_bearer_auth_header
from carconnectivity_connectors.volkswagen.auth.helpers.blacklist_retry import BlacklistRetry

if TYPE_CHECKING:
    from typing import Dict

LOG = logging.getLogger("carconnectivity.connectors.volkswagen.auth")


class AccessType(Enum):
    """
    Enum representing different types of access tokens used in the authentication process.

    Attributes:
        NONE (auto): No access token.
        ACCESS (auto): Access token used for accessing resources.
        ID (auto): ID token used for identifying the user.
        REFRESH (auto): Refresh token used for obtaining new access tokens.
    """
    NONE = auto()
    ACCESS = auto()
    ID = auto()
    REFRESH = auto()


class OpenIDSession(requests.Session):
    """
    OpenIDSession is a subclass of requests.Session that handles OpenID Connect authentication.
    """
    def __init__(self, client_id=None, redirect_uri=None, refresh_url=None, scope=None, token=None, metadata=None, state=None, timeout=None,
                 force_relogin_after=None, **kwargs) -> None:
        super(OpenIDSession, self).__init__(**kwargs)
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.refresh_url = refresh_url
        self.scope = scope
        self.state: str = state or generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET)

        self.timeout = timeout
        self._token = token
        self.metadata = metadata or {}
        self.last_login = None
        self._force_relogin_after = force_relogin_after

        self._retries: bool | int = False

    @property
    def force_relogin_after(self):
        """
        Get the number of seconds after which a forced re-login is required.

        Returns:
            Number of seconds until a forced re-login is required.
        """
        return self._force_relogin_after

    @force_relogin_after.setter
    def force_relogin_after(self, new_force_relogin_after_value):
        """
        Sets the time after which a forced re-login should occur.

        Args:
            new_force_relogin_after_value (float or None): The new value for the forced re-login time.
                If None, no forced re-login will be set.
        """
        self._force_relogin_after = new_force_relogin_after_value
        if new_force_relogin_after_value is not None and self.last_login is None:
            self.last_login = time.time()

    @property
    def retries(self) -> bool | int:
        """
        Get the number of retries.

        Returns:
            bool | int: The number of retries. It can be a boolean or an integer.
        """
        return self._retries

    @retries.setter
    def retries(self, new_retries_value):
        """
        Set the number of retries for the session and configure retry behavior.

        Args:
            new_retries_value (int): The new number of retries to set. If provided,
                                     configures the session to retry on internal server
                                     errors (HTTP status code 500) and blacklist status
                                     code 429 with a backoff factor of 0.1.

        """
        self._retries = new_retries_value
        if new_retries_value:
            # Retry on internal server error (500)
            retries = BlacklistRetry(total=new_retries_value,
                                     backoff_factor=0.1,
                                     status_forcelist=[500],
                                     status_blacklist=[429],
                                     raise_on_status=False)
            # Configure connection pool to prevent stale connection reuse
            # pool_connections: number of connection pools to cache
            # pool_maxsize: maximum number of connections to save in the pool
            # This helps prevent "Remote end closed connection without response" errors
            self.mount('https://', HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20))

    @property
    def token(self):
        """
        Retrieve the current token.

        Returns:
            str: The current token.
        """
        return self._token

    @token.setter
    def token(self, new_token):
        """
        Updates the current token with a new token and sets expiration details if not provided.

        Args:
            new_token (dict): The new token to be set. If the token does not contain 'expires_in',
                              it will try to decode access_token JWT and calculate 'expires_in'
                              or default to 3600 seconds. If 'expires_in' is provided but 'expires_at'
                              is not, 'expires_at' will be calculated based on the current time.

        Returns:
            None
        """

        if new_token is not None:
            # ALWAYS decode the access_token JWT to see what it actually says
            jwt_expires_in = None
            jwt_expires_at = None
            server_expires_in = new_token.get('expires_in')

            if 'access_token' in new_token:
                try:
                    meta_data = jwt.decode(new_token['access_token'], options={"verify_signature": False})
                    if 'exp' in meta_data:
                        jwt_expires_at = meta_data['exp']
                        expires_at_dt = datetime.fromtimestamp(meta_data['exp'], tz=timezone.utc)
                        jwt_expires_in = (expires_at_dt - datetime.now(tz=timezone.utc)).total_seconds()
                        LOG.debug(f"JWT says access_token expires in: {jwt_expires_in:.0f} seconds")
                except jwt.exceptions.DecodeError:
                    LOG.warning("Could not decode access_token JWT")

            # Log comparison if server provided expires_in
            if server_expires_in is not None and jwt_expires_in is not None:
                server_val = float(server_expires_in)
                LOG.debug(f"Server says: {server_val:.0f}s, JWT says: {jwt_expires_in:.0f}s, Difference: {abs(server_val - jwt_expires_in):.0f}s")

            # Now decide which value to use
            if 'expires_in' not in new_token:
                # Server didn't provide expires_in, use JWT or fallback
                if jwt_expires_in is not None:
                    new_token['expires_in'] = jwt_expires_in
                    new_token['expires_at'] = jwt_expires_at
                    LOG.debug("Using JWT expiry (server didn't provide expires_in)")
                else:
                    new_token['expires_in'] = 3600
                    LOG.debug("Using default 3600s expiry")
            # If expires_in is set and expires_at is not set we calculate expires_at from expires_in using the current time
            if 'expires_in' in new_token and 'expires_at' not in new_token:
                new_token['expires_at'] = time.time() + int(new_token.get('expires_in'))

            # Ensure expires_in and expires_at are always numeric (VW may send them as strings)
            if 'expires_in' in new_token:
                try:
                    new_token['expires_in'] = float(new_token['expires_in'])
                except (ValueError, TypeError):
                    LOG.warning(f"Could not convert expires_in to float: {new_token['expires_in']}")
            if 'expires_at' in new_token:
                try:
                    new_token['expires_at'] = float(new_token['expires_at'])
                except (ValueError, TypeError):
                    LOG.warning(f"Could not convert expires_at to float: {new_token['expires_at']}")

        self._token = new_token

    @property
    def access_token(self):
        """
        Retrieve the access token from the stored token.

        Returns:
            str: The access token if it exists in the stored token, otherwise None.
        """
        if self._token is not None and 'access_token' in self._token:
            return self._token.get('access_token')
        return None

    @access_token.setter
    def access_token(self, new_access_token):
        """
        Sets a new access token.

        Args:
            new_access_token (str): The new access token to be set.
        """
        if self._token is None:
            self._token = {}
        self._token['access_token'] = new_access_token

    @property
    def refresh_token(self):
        """
        Retrieves the refresh token from the stored token.

        Returns:
            str or None: The refresh token if it exists in the stored token, otherwise None.
        """
        if self._token is not None and 'refresh_token' in self._token:
            return self._token.get('refresh_token')
        return None

    @property
    def id_token(self):
        """
        Retrieve the ID token from the stored token.

        Returns:
            str or None: The ID token if it exists in the stored token, otherwise None.
        """
        if self._token is not None and 'id_token' in self._token:
            return self._token.get('id_token')
        return None

    @property
    def token_type(self):
        """
        Retrieve the token type from the stored token.

        Returns:
            str: The type of the token if available, otherwise None.
        """
        if self._token is not None and 'token_type' in self._token:
            return self._token.get('token_type')
        return None

    @property
    def expires_in(self):
        """
        Retrieve the expiration time of the current token.

        Returns:
            int or None: The number of seconds until the token expires if available,
                         otherwise None.
        """
        if self._token is not None and 'expires_in' in self._token:
            return self._token.get('expires_in')
        return None

    @property
    def expires_at(self):
        """
        Retrieve the expiration time of the current token.

        Returns:
            int or None: The expiration time of the token in epoch time if available,
                         otherwise None.
        """
        if self._token is not None and 'expires_at' in self._token:
            return self._token.get('expires_at')
        return None

    @property
    def authorized(self):
        """
        Check if the session is authorized.

        Returns:
            bool: True if the session has a valid access token, False otherwise.
        """
        return bool(self.access_token)

    @property
    def expired(self):
        """
        Check if the session has expired.

        Returns:
            bool: True if the session has expired, False otherwise.
        """
        return self.expires_at is not None and self.expires_at < time.time()

    @property
    def user_id(self):
        """
        Retrieve the user ID from the metadata.
        """
        if 'userId' in self.metadata:
            return self.metadata['userId']
        return None

    @user_id.setter
    def user_id(self, new_user_id):
        """
        Sets the user ID in the metadata.
        """
        self.metadata['userId'] = new_user_id

    def login_with_retry(self):
        """
        Wrapper around login() that retries once on connection errors.

        This handles stale connections that cause "Remote end closed connection without response" errors.
        """
        try:
            self.login()
        except requests.exceptions.ConnectionError as conn_error:
            LOG.warning('Connection error during login, retrying once with fresh connection pool: %s', str(conn_error))
            # Clear connection pools and retry
            if hasattr(self, '_clear_connection_pools'):
                try:
                    self._clear_connection_pools()
                except Exception as e:
                    LOG.debug('Could not clear connection pools: %s', str(e))
            # Retry the login once
            self.login()

    def login(self):
        """
        Logs in the user, needs to be implemetned in subclass

        This method sets the `last_login` attribute to the current time.
        """
        self.last_login = time.time()

    def refresh(self):
        """
        Refresh the current session, needs to be implemetned in subclass

        This method is intended to refresh the authentication session.
        Currently, it is not implemented and does not perform any actions.
        """

    def authorization_url(self, url, state=None, **kwargs):
        """
        Generates the authorization URL for the OpenID Connect flow.

        Args:
            url (str): The base URL for the authorization endpoint.
            state (str, optional): An optional state parameter to maintain state between the request and callback. Defaults to None.
            **kwargs: Additional parameters to include in the authorization URL.

        Returns:
            str: The complete authorization URL with the necessary query parameters.
        """
        state = state or self.state
        auth_url = prepare_grant_uri(uri=url, client_id=self.client_id, redirect_uri=self.redirect_uri, response_type='code id_token token', scope=self.scope,
                                     state=state, nonce=generate_nonce(), **kwargs)
        return auth_url

    def parse_from_fragment(self, authorization_response, state=None):
        """
        Parses the authorization response fragment and extracts the token.

        Args:
            authorization_response (str): The authorization response fragment containing the token.
            state (str, optional): The state parameter to validate the response. Defaults to None.

        Returns:
            dict: The parsed token information.
        """
        state = state or self.state
        self.token = parse_authorization_code_response(authorization_response, state=state)
        return self.token

    def parse_from_body(self, token_response, state=None):
        """
            Parse the JSON token response body into a dict.
        """
        del state
        self.token = parse_token_response(token_response, scope=self.scope)
        return self.token

    def request(  # noqa: C901
        self,
        method,
        url,
        data=None,
        headers=None,
        timeout=None,
        withhold_token=False,
        access_type=AccessType.ACCESS,
        token=None,
        **kwargs
    ) -> requests.Response:
        """Intercept all requests and add the OAuth 2 token if present."""
        if not is_secure_transport(url):
            raise InsecureTransportError()
        if access_type != AccessType.NONE and not withhold_token:
            if self.force_relogin_after is not None and self.last_login is not None and (self.last_login + self.force_relogin_after) < time.time():
                LOG.debug("Forced new login after %ds", self.force_relogin_after)
                self.login_with_retry()
            try:
                url, headers, data = self.add_token(url, body=data, headers=headers, access_type=access_type, token=token)
            # Attempt to retrieve and save new access token if expired
            except TokenExpiredError:
                LOG.info('Token expired')
                # Don't clear access_token here - it will be replaced by refresh()
                # Clearing it causes MissingTokenError during the refresh request itself
                try:
                    self.refresh()
                except AuthenticationError as auth_error:
                    # Check if this is a "Server requests new authorization" error
                    if 'Server requests new authorization' in str(auth_error):
                        LOG.warning('Server requests new authorization - clearing tokens and forcing re-login')
                        # Clear all tokens to force fresh login
                        if hasattr(self, 'clear_tokens'):
                            self.clear_tokens()
                        else:
                            # Fallback for base class
                            self.token = None
                            self.access_token = None
                            self.refresh_token = None
                            self.id_token = None
                    LOG.info('Authentication failed during refresh - attempting new login')
                    self.login_with_retry()
                except TokenExpiredError:
                    self.login_with_retry()
                except MissingTokenError:
                    self.login_with_retry()
                except RetrievalError:
                    LOG.error('Retrieval Error while refreshing token. Probably the token was invalidated. Trying to do a new login instead.')
                    self.login_with_retry()
                except requests.exceptions.ConnectionError as conn_error:
                    LOG.warning('Connection error during token refresh (%s) - attempting new login', str(conn_error))
                    # Connection errors during refresh often mean stale connections
                    # Clear tokens and do a fresh login to establish new connection
                    if hasattr(self, 'clear_tokens'):
                        self.clear_tokens()
                    else:
                        self.token = None
                    self.login_with_retry()
                url, headers, data = self.add_token(url, body=data, headers=headers, access_type=access_type, token=token)
            except MissingTokenError:
                LOG.info('Missing token, need new login')
                self.login_with_retry()
                url, headers, data = self.add_token(url, body=data, headers=headers, access_type=access_type, token=token)

        if timeout is None:
            timeout = self.timeout

        return super(OpenIDSession, self).request(
            method, url, headers=headers, data=data, timeout=timeout, **kwargs
        )

    def add_token(self, uri, body=None, headers=None, access_type=AccessType.ACCESS, token=None, **_):  # pylint: disable=too-many-arguments
        """
        Adds an authorization token to the request headers based on the specified access type.

        Args:
            uri (str): The URI to which the request is being made.
            body (Optional[Any]): The body of the request. Defaults to None.
            headers (Optional[Dict[str, str]]): The headers of the request. Defaults to None.
            access_type (AccessType): The type of access token to use (ID, REFRESH, or ACCESS). Defaults to AccessType.ACCESS.
            token (Optional[str]): The token to use. If None, the method will use the appropriate token based on the access_type. Defaults to None.
            **_ (Any): Additional keyword arguments.

        Raises:
            InsecureTransportError: If the URI does not use a secure transport (HTTPS).
            MissingTokenError: If the required token (ID, REFRESH, or ACCESS) is missing.
            TokenExpiredError: If the access token has expired.

        Returns:
            Tuple[str, Dict[str, str], Optional[Any]]: The URI, updated headers with the authorization token, and the body of the request.
        """
        # Check if the URI uses a secure transport
        if not is_secure_transport(uri):
            raise InsecureTransportError()

        # Only add token if it is not explicitly withheld
        if token is None:
            if access_type == AccessType.ID:
                if not self.id_token:
                    raise MissingTokenError(description="Missing id token.")
                token = self.id_token
            elif access_type == AccessType.REFRESH:
                if not self.refresh_token:
                    raise MissingTokenError(description="Missing refresh token.")
                token = self.refresh_token
            else:
                if not self.authorized:
                    self.login_with_retry()
                if not self.access_token:
                    raise MissingTokenError(description="Missing access token.")
                if self.expired:
                    raise TokenExpiredError()
                token = self.access_token

        return_headers: Dict[str, str] = add_bearer_auth_header(token, headers)

        return (uri, return_headers, body)
