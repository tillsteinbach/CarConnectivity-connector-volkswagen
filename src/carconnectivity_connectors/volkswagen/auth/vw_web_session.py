"""
Module implements a VW Web session.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

import logging
from pathlib import Path
from urllib.parse import parse_qsl, urlparse, urlsplit, urljoin

from urllib3.util.retry import Retry

import requests
from requests.adapters import HTTPAdapter
from requests.models import CaseInsensitiveDict

from carconnectivity.errors import APICompatibilityError, AuthenticationError, RetrievalError

from carconnectivity_connectors.volkswagen.auth.auth_util import CredentialsFormParser, HTMLFormParser, TermsAndConditionsFormParser
from carconnectivity_connectors.volkswagen.auth.login import VWLoginFlow
from carconnectivity_connectors.volkswagen.auth.login.exceptions import (
    LoginCredentialsError,
    LoginError,
    LoginFlowChangedError,
    LoginPageParseError,
)
from carconnectivity_connectors.volkswagen.auth.openid_session import OpenIDSession

if TYPE_CHECKING:
    from typing import Any, Dict, Optional

LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen.auth")


class VWWebSession(OpenIDSession):
    """
    VWWebSession handles the web authentication process for Volkswagen's web services.
    """
    def __init__(self, session_user, cache, accept_terms_on_login=False, auth_cookies_file=None,
                 auth_debug_dump_dir=None, use_fake_user_agent=False, **kwargs):
        super(VWWebSession, self).__init__(**kwargs)
        self.session_user = session_user
        self.cache = cache
        self.accept_terms_on_login: bool = accept_terms_on_login
        self._auth_cookies_file: Optional[Path] = Path(auth_cookies_file) if auth_cookies_file else None
        self._auth_debug_dump_dir: Optional[Path] = Path(auth_debug_dump_dir) if auth_debug_dump_dir else None
        self._use_fake_user_agent: bool = use_fake_user_agent

        # Set up the web session
        retries = Retry(
            total=self.retries,
            backoff_factor=0.1,
            status_forcelist=[500],
            raise_on_status=False
        )

        self.websession: requests.Session = requests.Session()
        self.websession.proxies.update(self.proxies)
        # Configure connection pool to prevent stale connection reuse during login attempts
        # This is critical because login happens after token refresh failures
        # and stale connections cause "Remote end closed connection without response" errors
        self.websession.mount('https://', HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20))
        self.websession.headers = CaseInsensitiveDict({
            'user-agent': 'Volkswagen/3.51.1-android/14',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate',
            'x-requested-with': 'com.volkswagen.weconnect',
            'x-android-package-name': 'com.volkswagen.weconnect',
            'upgrade-insecure-requests': '1',
        })

    def _clear_connection_pools(self) -> None:
        """
        Clear connection pools to prevent stale connection reuse.

        This should be called before login attempts to ensure fresh connections
        are established, preventing "Remote end closed connection without response" errors.
        """
        try:
            # Clear the main session's connection pool
            for adapter in self.adapters.values():
                if hasattr(adapter, 'poolmanager') and adapter.poolmanager is not None:
                    adapter.poolmanager.clear()
            LOG.debug("Cleared main session connection pool before login")
        except Exception as e:
            LOG.debug("Could not clear main session connection pool: %s", str(e))

        try:
            # Clear the websession's connection pool
            for adapter in self.websession.adapters.values():
                if hasattr(adapter, 'poolmanager') and adapter.poolmanager is not None:
                    adapter.poolmanager.clear()
            LOG.debug("Cleared websession connection pool before login")
        except Exception as e:
            LOG.debug("Could not clear websession connection pool: %s", str(e))

    def do_web_auth(self, url: str) -> str:
        """
        Perform web authentication using the provided URL.

        Prefers the IDKit-based login flow (window._IDK). Falls back to the legacy
        form parsers if IDKit parsing is not available on the landing page.
        """
        # Check if we already have the final OAuth callback URL
        if url.startswith('weconnect://authenticated'):
            LOG.info("Already have OAuth callback URL with tokens, returning immediately")
            return url.replace('weconnect://authenticated#', 'https://egal?')

        try:
            url = self._handle_idkit_auth_flow(url)
        except (LoginPageParseError, LoginFlowChangedError) as idkit_error:
            LOG.warning("IDKit login flow failed (%s); trying legacy web auth", idkit_error)
            url = self._do_web_auth_legacy(url)
        except LoginCredentialsError:
            raise
        except LoginError as login_error:
            LOG.warning("IDKit login error (%s); trying legacy web auth", login_error)
            url = self._do_web_auth_legacy(url)

        if self.redirect_uri is None:
            raise ValueError('Redirect URI is not set')
        # Check URL for terms and conditions
        while True:
            LOG.debug("Processing URL in while loop: %s", url[:150])

            # Check for custom scheme FIRST, before any URL manipulation
            if url.startswith('weconnect://authenticated'):
                LOG.info("Reached final OAuth callback URL with tokens")
                break

            # Also check for redirect_uri if it's a custom scheme
            if self.redirect_uri and url.startswith(self.redirect_uri):
                LOG.info("Reached redirect URI: %s", self.redirect_uri)
                break

            # Check for any other custom scheme to prevent HTTP requests
            if url.startswith('weconnect://'):
                LOG.info("Found custom scheme URL, treating as final URL")
                return url.replace('weconnect://', 'https://egal?')

            # Only join URLs that are not custom schemes
            url = urljoin('https://identity.vwgroup.io', url)

            if 'terms-and-conditions' in url:
                if self.accept_terms_on_login:
                    url = self._handle_consent_form(url)
                else:
                    raise AuthenticationError(f'It seems like you need to accept the terms and conditions. '
                                              f'Try to visit the URL "{url}" or log into smartphone app.')

            LOG.debug("Making HTTP GET request to: %s", url[:100])
            response = self.websession.get(url, allow_redirects=False)
            if response.status_code == requests.codes['internal_server_error']:
                raise RetrievalError('Temporary server error during login')

            if 'Location' not in response.headers:
                if 'consent' in url:
                    raise AuthenticationError('Could not find Location in headers, probably due to missing consent. Try visiting: ' + url)
                raise APICompatibilityError('Forwarding without Location in headers')

            url = response.headers['Location']
            LOG.debug("Got Location header, new URL: %s", url[:100])

            # Check again after getting new URL from Location header
            if url.startswith('weconnect://authenticated'):
                LOG.info("OAuth flow completed, received callback URL with tokens")
                break

            # Check for ANY weconnect:// scheme to prevent invalid requests
            if url.startswith('weconnect://'):
                LOG.info("OAuth flow reached custom scheme URL")
                break

            # Also check for redirect_uri if it's set
            if self.redirect_uri and url.startswith(self.redirect_uri):
                LOG.info("OAuth flow completed, received redirect URI")
                break

        LOG.debug("Exited while loop, final URL before transformation: %s", url[:150])

        # Handle the transformation based on the URL pattern
        if url.startswith('weconnect://authenticated#'):
            # Transform weconnect://authenticated# to https://egal?
            transformed_url = url.replace('weconnect://authenticated#', 'https://egal?')
            LOG.debug("Transformed weconnect://authenticated# URL to: %s", transformed_url[:150])
            return transformed_url
        elif self.redirect_uri and url.startswith(self.redirect_uri + '#'):
            # Transform redirect_uri# to https://egal?
            transformed_url = url.replace(self.redirect_uri + '#', 'https://egal?')
            LOG.debug("Transformed redirect_uri# URL to: %s", transformed_url[:150])
            return transformed_url
        else:
            LOG.warning("URL doesn't match expected patterns, returning as-is: %s", url[:150])
            return url

    def _is_oauth_final_url(self, url: str) -> bool:
        if url.startswith('weconnect://'):
            return True
        if self.redirect_uri and url.startswith(self.redirect_uri):
            return True
        if '#access_token=' in url or '#code=' in url:
            return True
        return False

    def _handle_idkit_auth_flow(self, url: str) -> str:
        """Drive identity.vwgroup.io login via window._IDK (IDKit)."""
        if url.startswith('weconnect://authenticated'):
            LOG.info("OAuth callback URL already present in IDKit auth flow, returning immediately")
            return url

        # Use the WeConnect OIDC client_id for form posts during authorize flow
        login_flow = VWLoginFlow(
            html_debug_dir=self._auth_debug_dump_dir,
            use_fake_user_agent=self._use_fake_user_agent,
            client_id=self.client_id or "",
            proxies=dict(self.proxies) if self.proxies else None,
            timeout=self.timeout or 60,
        )
        final_url = login_flow.run_browser_route(
            landing_url=url,
            username=self.session_user.username,
            password=self.session_user.password,
            cookies_file=self._auth_cookies_file,
            session=self.websession,
            mode="oidc",
            is_final_url=self._is_oauth_final_url,
        )
        LOG.debug("IDKit auth flow finished at: %s", final_url[:150])
        return final_url

    def _do_web_auth_legacy(self, url: str) -> str:
        """Legacy form-parser based web authentication (kept for fallback)."""
        # Get the login form
        email_form: HTMLFormParser = self._get_login_form(url)

        if email_form:
            # Legacy authentication flow
            # Set email to the provided username
            email_form.data['email'] = self.session_user.username

            # Get password form
            password_form = self._get_password_form(
                urljoin('https://identity.vwgroup.io', email_form.target),
                email_form.data
            )

            # Set credentials
            password_form.data['email'] = self.session_user.username
            password_form.data['password'] = self.session_user.password

            # Log in and get the redirect URL
            return self._handle_login(
                f'https://identity.vwgroup.io/signin-service/v1/{self.client_id}/{password_form.target}',
                password_form.data
            )

        # New authentication flow (Auth0-style fallback)
        return self._handle_new_auth_flow(url)

    def _get_login_form(self, url: str) -> HTMLFormParser:
        # Check for custom URL schemes before making HTTP requests
        if url.startswith('weconnect://'):
            LOG.info("[_get_login_form] Custom scheme URL detected, skipping legacy auth flow")
            return None

        # Also check if URL contains tokens already (might be a callback URL)
        if '#access_token=' in url or '#code=' in url:
            LOG.info("[_get_login_form] URL already contains OAuth tokens, skipping legacy auth flow")
            return None

        while True:
            LOG.debug("Attempting to fetch: %s", url[:100])

            # Check for custom URL schemes during redirect loop
            if url.startswith('weconnect://'):
                LOG.info("[_get_login_form] Reached OAuth callback URL during redirects: %s", url[:100])
                return None

            response = self.websession.get(url, allow_redirects=False)
            if response.status_code == requests.codes['ok']:
                break

            if response.status_code in (requests.codes['found'], requests.codes['see_other']):
                if 'Location' not in response.headers:
                    raise APICompatibilityError('Forwarding without Location in headers')

                # Resolve relative URL to absolute URL
                url = urljoin(url, response.headers['Location'])

                # Check if the new URL is a custom scheme URL
                if url.startswith('weconnect://'):
                    LOG.info("[_get_login_form] OAuth callback URL found in Location header: %s", url[:100])
                    return None

                continue

            raise APICompatibilityError(f'Retrieving login page was not successful, '
                                        f'status code: {response.status_code}')

        # Find login form on page to obtain inputs
        email_form = HTMLFormParser(form_id='emailPasswordForm')
        email_form.feed(response.text)

        if not email_form.target or not all(x in email_form.data for x in ['_csrf', 'relayState', 'hmac', 'email']):
            # Return None to indicate legacy form not found, new flow should be used
            return None

        return email_form

    def _get_password_form(self, url: str, data: Dict[str, Any]) -> CredentialsFormParser:
        response = self.websession.post(url, data=data, allow_redirects=True)
        if response.status_code != requests.codes['ok']:
            raise APICompatibilityError(f'Retrieving credentials page was not successful, '
                                        f'status code: {response.status_code}')

        # Find login form on page to obtain inputs
        credentials_form = CredentialsFormParser()
        credentials_form.feed(response.text)

        if not credentials_form.target or not all(x in credentials_form.data for x in ['relayState', 'hmac', '_csrf']):
            raise APICompatibilityError('Could not find all required input fields on credentials page')

        if credentials_form.data.get('error', None) is not None:
            if credentials_form.data['error'] == 'validator.email.invalid':
                raise AuthenticationError('Error during login, email invalid')
            raise AuthenticationError(f'Error during login: {credentials_form.data["error"]}')

        if 'errorCode' in credentials_form.data:
            raise AuthenticationError('Error during login, is the username correct?')

        if credentials_form.data.get('registerCredentialsPath', None) == 'register':
            raise AuthenticationError(f'Error during login, account {self.session_user.username} does not exist')

        return credentials_form

    def _handle_login(self, url: str, data: Dict[str, Any]) -> str:
        response: requests.Response = self.websession.post(url, data=data, allow_redirects=False)

        if response.status_code == requests.codes['internal_server_error']:
            raise RetrievalError('Temporary server error during login')

        if response.status_code not in (requests.codes['found'], requests.codes['see_other']):
            raise APICompatibilityError(f'Forwarding expected (status code 302), '
                                        f'but got status code {response.status_code}')

        if 'Location' not in response.headers:
            raise APICompatibilityError('Forwarding without Location in headers')

        # Parse parameters from forwarding url
        params: Dict[str, str] = dict(parse_qsl(urlsplit(response.headers['Location']).query))

        # Check for login error
        if 'error' in params and params['error']:
            error_messages: Dict[str, str] = {
                'login.errors.password_invalid': 'Password is invalid',
                'login.error.throttled': 'Login throttled, probably too many wrong logins. You have to wait '
                                         'a few minutes until a new login attempt is possible'
            }

            raise AuthenticationError(error_messages.get(params['error'], params['error']))

        # Check for user ID
        if 'userId' not in params or not params['userId']:
            if 'updated' in params and params['updated'] == 'dataprivacy':
                raise AuthenticationError('You have to login at myvolkswagen.de and accept the terms and conditions')
            raise APICompatibilityError('No user ID provided')

        self.user_id = params['userId']  # pylint: disable=unused-private-member
        return response.headers['Location']

    def _handle_new_auth_flow(self, url: str) -> str:
        """
        Handle the new authentication flow when legacy form is not available.

        Args:
            url (str): The authorization URL.

        Returns:
            str: The redirect URL after successful authentication.

        Raises:
            AuthenticationError: If authentication fails.
            APICompatibilityError: If there are issues with the authentication flow.
        """
        import re

        # Check if we already have the OAuth callback URL
        if url.startswith('weconnect://authenticated'):
            LOG.info("OAuth callback URL already present in new auth flow, returning immediately")
            return url

        # Get the authorization page (manually follow redirects to avoid custom scheme issues)
        max_initial_redirects = 5
        while max_initial_redirects > 0:
            # Check for custom scheme before making request
            if url.startswith('weconnect://'):
                LOG.info("Found custom scheme URL during initial auth page fetch")
                return url

            response = self.websession.get(url, allow_redirects=False)

            if response.status_code == requests.codes['ok']:
                break

            if response.status_code in (requests.codes['found'], requests.codes['see_other']):
                if 'Location' not in response.headers:
                    raise APICompatibilityError('Forwarding without Location in headers')
                url = urljoin(url, response.headers['Location'])
                max_initial_redirects -= 1
                continue

            raise APICompatibilityError(f'Failed to fetch authorization page, status code: {response.status_code}')

        if max_initial_redirects == 0:
            raise APICompatibilityError('Too many redirects while fetching authorization page')

        # Extract state token using regex
        state_match = re.search(r'<input[^>]*name="state"[^>]*value="([^"]*)"', response.text)
        state = state_match.group(1) if state_match else None

        if not state:
            raise APICompatibilityError('Could not find state token in authorization page')

        # Create login form data
        login_form = {
            'username': self.session_user.username,
            'password': self.session_user.password,
            'state': state
        }

        # Post to login URL
        login_url = f'https://identity.vwgroup.io/u/login?state={state}'
        LOG.debug("Posting to login URL: %s", login_url)
        response = self.websession.post(login_url, data=login_form, allow_redirects=False)

        if response.status_code not in (requests.codes['found'], requests.codes['see_other']):
            raise AuthenticationError(f'Login failed with status code: {response.status_code}')

        if 'Location' not in response.headers:
            raise APICompatibilityError('No Location header in login response')

        # Follow redirects to get the final URL with authorization code
        redirect_url = response.headers['Location']
        LOG.debug("Starting redirect follow loop with URL: %s", redirect_url[:150])
        max_depth = 10
        while max_depth > 0:
            LOG.debug("Loop iteration, max_depth=%s, URL: %s", max_depth, redirect_url[:150])

            # Check for custom scheme IMMEDIATELY before any processing
            if redirect_url.startswith('weconnect://authenticated'):
                LOG.info("Successfully reached OAuth callback URL with custom scheme")
                return redirect_url

            # Also check for any weconnect:// scheme
            if redirect_url.startswith('weconnect://'):
                LOG.info("Found weconnect:// custom scheme URL")
                return redirect_url

            if max_depth == 0:
                raise APICompatibilityError('Too many redirects in new auth flow')

            # Only process non-custom scheme URLs
            redirect_url = urljoin('https://identity.vwgroup.io', redirect_url)
            LOG.debug("URL after urljoin: %s", redirect_url[:150])

            LOG.debug("Making HTTP GET request to: %s", redirect_url[:100])
            response = self.websession.get(redirect_url, allow_redirects=False)

            if response.status_code == requests.codes['internal_server_error']:
                raise RetrievalError('Temporary server error during new auth flow')

            if 'Location' not in response.headers:
                LOG.debug("No Location header in response, status code: %s", response.status_code)
                raise APICompatibilityError('No Location header in redirect')

            redirect_url = response.headers['Location']
            LOG.debug("Got Location header: %s", redirect_url[:150])

            # Check again after getting new redirect URL
            if redirect_url.startswith('weconnect://authenticated'):
                LOG.info("Successfully reached OAuth callback URL with custom scheme after redirect")
                return redirect_url

            # Also check for any weconnect:// scheme
            if redirect_url.startswith('weconnect://'):
                LOG.info("Found weconnect:// custom scheme URL after redirect")
                return redirect_url

            max_depth -= 1

        LOG.debug("Exiting redirect loop after max iterations, returning URL: %s", redirect_url[:150])
        return redirect_url

    def _handle_consent_form(self, url: str) -> str:
        response = self.websession.get(url, allow_redirects=False)
        if response.status_code == requests.codes['internal_server_error']:
            raise RetrievalError('Temporary server error during login')

        # Find form on page to obtain inputs
        tc_form = TermsAndConditionsFormParser()
        tc_form.feed(response.text)

        # Remove query from URL
        url = urlparse(response.url)._replace(query='').geturl()

        response = self.websession.post(url, data=tc_form.data, allow_redirects=False)
        if response.status_code == requests.codes['internal_server_error']:
            raise RetrievalError('Temporary server error during login')

        if response.status_code not in (requests.codes['found'], requests.codes['see_other']):
            raise APICompatibilityError('Forwarding expected (status code 302), '
                                        f'but got status code {response.status_code}')

        if 'Location' not in response.headers:
            raise APICompatibilityError('Forwarding without Location in headers')

        return response.headers['Location']
