"""
Module implements a VW Web session.
"""
from __future__ import annotations
from typing import TYPE_CHECKING


from urllib.parse import ParseResult, ParseResultBytes, parse_qsl, urlparse, urlsplit, urljoin

from urllib3.util.retry import Retry

import requests
from requests.adapters import HTTPAdapter
from requests.models import CaseInsensitiveDict

from carconnectivity.errors import APICompatibilityError, AuthenticationError, RetrievalError

from carconnectivity_connectors.volkswagen.auth.auth_util import CredentialsFormParser, HTMLFormParser, TermsAndConditionsFormParser
from carconnectivity_connectors.volkswagen.auth.openid_session import OpenIDSession

if TYPE_CHECKING:
    from typing import Any, Dict


class VWWebSession(OpenIDSession):
    """
    VWWebSession handles the web authentication process for Volkswagen's web services.
    """
    def __init__(self, session_user, cache, accept_terms_on_login=False, **kwargs):
        super(VWWebSession, self).__init__(**kwargs)
        self.session_user = session_user
        self.cache = cache
        self.accept_terms_on_login: bool = accept_terms_on_login

        # Set up the web session
        retries = Retry(
            total=self.retries,
            backoff_factor=0.1,
            status_forcelist=[500],
            raise_on_status=False
        )

        self.websession: requests.Session = requests.Session()
        self.websession.proxies.update(self.proxies)
        self.websession.mount('https://', HTTPAdapter(max_retries=retries))
        self.websession.headers = CaseInsensitiveDict({
            'user-agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 '
                          'Chrome/74.0.3729.185 Mobile Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate',
            'x-requested-with': 'com.volkswagen.weconnect',
            'upgrade-insecure-requests': '1',
        })

    def do_web_auth(self, url: str) -> str:
        """
        Perform web authentication using the provided URL.

        This method handles the web authentication process by:
        1. Retrieving the login form.
        2. Setting the email to the provided username.
        3. Retrieving the password form.
        4. Setting the credentials (email and password).
        5. Logging in and getting the redirect URL.
        6. Checking the URL for terms and conditions and handling consent if required.
        7. Following redirects until the final URL is reached.

        Args:
            url (str): The URL to start the authentication process.

        Returns:
            str: The final URL after successful authentication.

        Raises:
            AuthenticationError: If terms and conditions need to be accepted.
            RetrievalError: If there is a temporary server error during login.
            APICompatibilityError: If forwarding occurs without 'Location' in headers.
        """
        # Get the login form
        email_form: HTMLFormParser = self._get_login_form(url)

        # Set email to the provided username
        email_form.data['username'] = self.session_user.username
        email_form.data['password'] = self.session_user.password

        # Get password form
        #password_form = self._get_password_form(
        #    urljoin('https://identity.vwgroup.io', email_form.target),
        #    email_form.data
        #)

        # Set credentials
        #password_form.data['email'] = self.session_user.username
        #password_form.data['password'] = self.session_user.password

        # Log in and get the redirect URL
        url = self._handle_login(
            f'https://identity.vwgroup.io/u/login?state={email_form.data['state']}',
            email_form.data
        )

        if self.redirect_uri is None:
            raise ValueError('Redirect URI is not set')
        # Check URL for terms and conditions
        while True:
            if url.startswith(self.redirect_uri):
                break
            if not url.startswith('https://'):
                url = urljoin('https://identity.vwgroup.io', url)
            
            if 'terms-and-conditions' in url:
                if self.accept_terms_on_login:
                    url = self._handle_consent_form(url)
                else:
                    raise AuthenticationError(f'It seems like you need to accept the terms and conditions. '
                                              f'Try to visit the URL "{url}" or log into smartphone app.')

            response = self.websession.get(url, allow_redirects=False)
            if response.status_code == requests.codes['internal_server_error']:
                raise RetrievalError('Temporary server error during login')

            if 'Location' not in response.headers:
                if 'consent' in url:
                    raise AuthenticationError('Could not find Location in headers, probably due to missing consent. Try visiting: ' + url)
                raise APICompatibilityError('Forwarding without Location in headers')

            url = response.headers['Location']

        return url.replace(self.redirect_uri + '#', 'https://egal?')

    def _get_login_form(self, url: str) -> HTMLFormParser:
        while True:
            response = self.websession.get(url, allow_redirects=False)
            if response.status_code == requests.codes['ok']:
                break

            if response.status_code in (requests.codes['found'], requests.codes['see_other']):
                if 'Location' not in response.headers:
                    raise APICompatibilityError('Forwarding without Location in headers')

                url = response.headers['Location']
                if not url.startswith('https://'):
                    parsed_request: ParseResult | ParseResultBytes = urlparse(response.request.url)
                    url = parsed_request.scheme + '://' + parsed_request.hostname + url
                continue

            raise APICompatibilityError(f'Retrieving login page was not successful, '
                                        f'status code: {response.status_code}')

        # Find login form on page to obtain inputs
        email_form = HTMLFormParser(form_id=None)
        email_form.feed(response.text)

        if not all(x in email_form.data for x in ['state', 'username', 'password']):
            raise APICompatibilityError('Could not find all required input fields on login page')

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

        return response.headers['Location']

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
