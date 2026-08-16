"""VW device-flow and IDKit browser login orchestrator (synchronous)."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from http.cookiejar import Cookie
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests

from carconnectivity_connectors.volkswagen.auth.login._idkit import (
    IdKitInfo,
    IdKitPageObject,
    IdKitPageObjectExtractor,
    IdKitStage,
    _IdKitError,
)
from carconnectivity_connectors.volkswagen.auth.login._verification import LoginVerifier
from carconnectivity_connectors.volkswagen.auth.login.const import (
    DEVICE_FLOW_AUTHORIZATION_URL,
    DEVICE_FLOW_BROWSER_HEADERS,
    DEVICE_FLOW_BROWSER_HEADERS_FIREFOX,
    DEVICE_FLOW_CLIENT_ID,
    DEVICE_FLOW_CLIENT_SCOPE,
    DEVICE_FLOW_CODE_CONFIRMATION_URL,
    DEVICE_FLOW_LOGIN_AUTHENTICATE_URL,
    DEVICE_FLOW_LOGIN_IDENTIFIER_URL,
    DEVICE_FLOW_TOKEN_URL,
)
from carconnectivity_connectors.volkswagen.auth.login.exceptions import (
    LoginCredentialsError,
    LoginError,
    LoginFlowChangedError,
    LoginPageParseError,
)
from carconnectivity_connectors.volkswagen.auth.login.util import dump_html_debug, safe_int

LOG = logging.getLogger("carconnectivity.connectors.volkswagen.auth")

FULL_ROUTE = [
    IdKitStage.IDENTIFIER,
    IdKitStage.PASSWORD,
    IdKitStage.CONFIRM,
    IdKitStage.SUCCESS,
]
QUICK_ROUTE = [IdKitStage.CONFIRM, IdKitStage.SUCCESS]
# OIDC authorize hybrid flow: after password, redirect carries tokens (no CONFIRM/SUCCESS).
OIDC_FULL_ROUTE = [
    IdKitStage.IDENTIFIER,
    IdKitStage.PASSWORD,
]
OIDC_PASSWORD_ONLY_ROUTE = [
    IdKitStage.PASSWORD,
]

_TRANSIENT_POLL_STATUSES = {429, 500, 502, 503, 504}
_TRANSIENT_POLL_ERRORS = {"temporarily_unavailable", "server_error"}

# Known VW identity error codes returned as error= in the redirect URL.
_VW_AUTH_ERROR_MESSAGES: dict = {
    "login.errors.password_invalid": "Incorrect password.",
    "login.error.throttled": "Too many failed login attempts — please wait before trying again.",
    "login.error.locked": "Account has been locked due to too many failed attempts.",
    "login.error.blocked": "Login blocked by VW identity service.",
}


@dataclass(frozen=True)
class LoginRequest:
    """Request payload for a single login stage."""

    stage: IdKitStage
    url: str
    payload: dict


class VWLoginFlow:
    """Route-driven VW device-flow / IDKit browser login."""

    def __init__(
        self,
        verifier: LoginVerifier | None = None,
        html_debug_dir: Path | None = None,
        use_fake_user_agent: bool = False,
        client_id: str = DEVICE_FLOW_CLIENT_ID,
        client_scope: str = DEVICE_FLOW_CLIENT_SCOPE,
        proxies: dict | None = None,
        timeout: float | tuple | None = 60,
    ) -> None:
        self._verifier = verifier or LoginVerifier()
        self._html_debug_dir = html_debug_dir
        self._use_fake_user_agent = use_fake_user_agent
        self._client_id = _require_str(client_id, "client_id")
        self._client_scope = _require_str(client_scope, "client_scope")
        self._proxies = proxies or {}
        self._timeout = timeout

    def login(
        self,
        username: str,
        password: str,
        *,
        cookies_file: Path | None = None,
        session: requests.Session | None = None,
    ) -> dict:
        """Complete device authorization flow and return token payload."""
        _require_str(username, "username")
        _require_str(password, "password")

        own_session = session is None
        api_session = session or requests.Session()
        try:
            api_session.headers.update(self._browser_headers())
            if self._proxies:
                api_session.proxies.update(self._proxies)

            device = self._start_device_flow(api_session)
            device_code = _require_str(device.get("device_code"), "device_code")
            verification_uri = (
                device.get("verification_uri_complete")
                or device.get("verification_uri")
                or ""
            )
            if not verification_uri:
                raise LoginError("Device flow response missing verification URI")

            interval = safe_int(device.get("interval", 5), 5)
            expires_in = safe_int(device.get("expires_in", 330), 330)
            max_wait = max(330, max(expires_in - 5, 30))

            try:
                self.run_browser_route(
                    landing_url=verification_uri,
                    username=username,
                    password=password,
                    cookies_file=cookies_file,
                    session=api_session if not own_session else None,
                    mode="device",
                )
            except (LoginFlowChangedError, LoginPageParseError):
                raise
            except _IdKitError as error:
                raise LoginPageParseError(str(error)) from error

            return self._poll_token(
                session=api_session,
                device_code=device_code,
                interval=interval,
                max_wait_seconds=max_wait,
            )
        finally:
            if own_session:
                api_session.close()

    def run_browser_route(
        self,
        landing_url: str,
        username: str,
        password: str,
        cookies_file: Path | None = None,
        session: requests.Session | None = None,
        mode: str = "device",
        is_final_url: Callable[[str], bool] | None = None,
    ) -> str:
        """
        Drive IDKit login pages starting at landing_url.

        mode:
          - "device": expect CONFIRM/SUCCESS (device authorization)
          - "oidc": stop when is_final_url matches (hybrid authorize redirect)

        Returns the final URL after the browser route completes.
        """
        _require_str(username, "username")
        _require_str(password, "password")

        own_session = session is None
        browser = session or requests.Session()
        current_url = ""
        html = ""
        saved_headers = None

        try:
            if not own_session:
                saved_headers = dict(browser.headers)
            browser.headers.update(self._browser_headers())
            if self._proxies:
                browser.proxies.update(self._proxies)

            if cookies_file is not None:
                _load_cookies(browser, cookies_file, "identity.vwgroup.io")

            try:
                LOG.debug("GET %s", landing_url)
                current_url, html, status = self._request_follow(
                    browser, "GET", landing_url, is_final_url=is_final_url
                )
                LOG.debug("initial landing: HTTP %s url=%s", status, current_url)

                if is_final_url is not None and is_final_url(current_url):
                    return current_url

                try:
                    idk_obj = IdKitPageObjectExtractor.from_html(html)
                except _IdKitError as error:
                    self._raise_page_parse_error("initial_landing", current_url, html, error)

                try:
                    initial_stage = idk_obj.stage
                except _IdKitError as error:
                    self._raise_initial_parse_error(current_url, html, error)

                route = self._pick_route(initial_stage, current_url, html, mode=mode)
                LOG.debug(
                    "initial stage=%s route=%s",
                    initial_stage.value,
                    [s.value for s in route],
                )
                idk_info = IdKitInfo()

                # Device mode processes all but last (SUCCESS); OIDC processes listed stages,
                # then may still hit a consent CONFIRM page before the OAuth redirect.
                if mode == "device":
                    stages_to_post = route[:-1]
                else:
                    stages_to_post = list(route)

                index = 0
                while index < len(stages_to_post):
                    expected_stage = stages_to_post[index]
                    try:
                        current_stage = idk_obj.stage
                    except _IdKitError as error:
                        self._raise_initial_parse_error(current_url, html, error)

                    if current_stage != expected_stage:
                        self._raise_flow_changed(
                            "unexpected_current_stage",
                            current_url,
                            html,
                            f"expected {expected_stage.value!r}, got {current_stage.value!r}",
                        )

                    self._verifier.verify_idk_obj(
                        stage=expected_stage,
                        html=html,
                        idk_obj=idk_obj,
                        idk_info=idk_info,
                        configured_client_id=self._client_id,
                        expected_username=username,
                    )

                    self._update_idk_info(idk_info, idk_obj, expected_stage)
                    request = self._build_request(expected_stage, idk_info, username, password)

                    self._verifier.verify_request_matches_form(
                        stage=expected_stage,
                        current_url=current_url,
                        html=html,
                        planned_url=request.url,
                        planned_payload=request.payload,
                    )

                    LOG.debug("POST %s (stage=%s)", request.url, expected_stage.value)
                    current_url, html, status = self._request_follow(
                        browser,
                        "POST",
                        request.url,
                        data=request.payload,
                        is_final_url=is_final_url,
                    )
                    LOG.debug("POST response: HTTP %s url=%s", status, current_url)

                    if status >= 400:
                        raise LoginError(f"HTTP {status} while handling {expected_stage.value}")

                    if expected_stage == IdKitStage.CONFIRM:
                        self._check_final_url(current_url)

                    self._check_url_for_credentials_error(current_url)

                    if is_final_url is not None and is_final_url(current_url):
                        if cookies_file is not None:
                            _save_cookies(browser, cookies_file)
                        return current_url

                    try:
                        idk_obj = IdKitPageObjectExtractor.from_html(html)
                    except _IdKitError as error:
                        # OIDC: redirect chain left identity HTML; outer caller follows remaining redirects.
                        if mode == "oidc":
                            if cookies_file is not None:
                                _save_cookies(browser, cookies_file)
                            return current_url
                        self._raise_page_parse_error(
                            f"after_{expected_stage.value}", current_url, html, error
                        )

                    if mode == "device":
                        expected_next = route[index + 1]
                        try:
                            next_stage = idk_obj.stage
                        except _IdKitError as error:
                            self._raise_initial_parse_error(current_url, html, error)

                        if next_stage != expected_next:
                            self._raise_flow_changed(
                                "unexpected_next_stage",
                                current_url,
                                html,
                                f"after {expected_stage.value!r}: expected {expected_next.value!r}, "
                                f"got {next_stage.value!r}",
                            )
                        index += 1
                        continue

                    # OIDC: optionally append CONFIRM if consent page appears after password
                    try:
                        next_stage = idk_obj.stage
                    except _IdKitError as error:
                        if cookies_file is not None:
                            _save_cookies(browser, cookies_file)
                        return current_url

                    if next_stage == IdKitStage.SUCCESS:
                        if cookies_file is not None:
                            _save_cookies(browser, cookies_file)
                        return current_url

                    if index + 1 < len(stages_to_post):
                        expected_next = stages_to_post[index + 1]
                        if next_stage != expected_next:
                            self._raise_flow_changed(
                                "unexpected_next_stage",
                                current_url,
                                html,
                                f"after {expected_stage.value!r}: expected {expected_next.value!r}, "
                                f"got {next_stage.value!r}",
                            )
                    elif next_stage == IdKitStage.CONFIRM and IdKitStage.CONFIRM not in stages_to_post:
                        stages_to_post.append(IdKitStage.CONFIRM)
                    else:
                        # No further planned stages; return URL for outer redirect handling
                        if cookies_file is not None:
                            _save_cookies(browser, cookies_file)
                        return current_url

                    index += 1

                if cookies_file is not None:
                    _save_cookies(browser, cookies_file)

                return current_url

            except (LoginFlowChangedError, LoginPageParseError, LoginError) as error:
                self._dump_and_reraise(error, current_url, html)
                raise  # pragma: no cover - _dump_and_reraise always raises
        finally:
            if saved_headers is not None:
                browser.headers.clear()
                browser.headers.update(saved_headers)
            if own_session:
                browser.close()

    def _request_follow(
        self,
        browser: requests.Session,
        method: str,
        url: str,
        data: dict | None = None,
        is_final_url: Callable[[str], bool] | None = None,
        max_redirects: int = 15,
    ) -> tuple[str, str, int]:
        """
        Perform a request and follow HTTP redirects manually.

        Stops before requesting custom-scheme URLs (e.g. weconnect://) which requests
        cannot handle, returning that URL as the final location.
        """
        redirect_codes = {
            requests.codes["found"],
            requests.codes["see_other"],
            requests.codes["temporary_redirect"],
            requests.codes["permanent_redirect"],
            requests.codes["moved"],
        }
        current_method = method
        current_url = url
        current_data = data
        last_status = 0
        html = ""

        for _ in range(max_redirects):
            if is_final_url is not None and is_final_url(current_url):
                return current_url, html, last_status or 302
            if current_url.startswith("weconnect://"):
                return current_url, html, last_status or 302

            response = browser.request(
                current_method,
                current_url,
                data=current_data,
                allow_redirects=False,
                timeout=self._timeout,
            )
            last_status = response.status_code
            html = response.text if response.content else ""
            # Prefer response.url (handles relative request URL resolution)
            current_url = str(response.url)

            if last_status not in redirect_codes:
                return current_url, html, last_status

            if "Location" not in response.headers:
                return current_url, html, last_status

            next_url = urljoin(current_url, response.headers["Location"])
            LOG.debug("Redirect %s -> %s", last_status, next_url[:150])

            if is_final_url is not None and is_final_url(next_url):
                return next_url, html, last_status
            if next_url.startswith("weconnect://"):
                return next_url, html, last_status

            current_url = next_url
            current_method = "GET"
            current_data = None

        raise LoginError(f"Too many redirects while requesting {url}")

    def _build_request(
        self,
        stage: IdKitStage,
        idk_info: IdKitInfo,
        username: str,
        password: str,
    ) -> LoginRequest:
        if stage == IdKitStage.IDENTIFIER:
            client_id = idk_info.client_id or self._client_id
            return LoginRequest(
                stage=stage,
                url=DEVICE_FLOW_LOGIN_IDENTIFIER_URL.format(client_id=client_id),
                payload={
                    "_csrf": idk_info.get_csrf_token(),
                    "relayState": idk_info.get_relay_state(),
                    "hmac": idk_info.get_hmac(),
                    "email": username,
                },
            )

        if stage == IdKitStage.PASSWORD:
            client_id = idk_info.client_id or self._client_id
            return LoginRequest(
                stage=stage,
                url=DEVICE_FLOW_LOGIN_AUTHENTICATE_URL.format(client_id=client_id),
                payload={
                    "_csrf": idk_info.get_csrf_token(),
                    "relayState": idk_info.get_relay_state(),
                    "hmac": idk_info.get_hmac(),
                    "email": username,
                    "password": password,
                },
            )

        if stage == IdKitStage.CONFIRM:
            query = urlencode({
                "relayState": idk_info.get_relay_state(),
                "user_id": idk_info.get_user_id(),
                "hmac": idk_info.get_hmac(),
            })
            return LoginRequest(
                stage=stage,
                url=(
                    DEVICE_FLOW_CODE_CONFIRMATION_URL.format(
                        client_id=idk_info.get_client_id(),
                        user_code=idk_info.get_user_code(),
                    )
                    + "?"
                    + query
                ),
                payload={
                    "_csrf": idk_info.get_csrf_token(),
                    "client_identity_name": idk_info.get_client_identity_name(),
                    "allow": "",
                },
            )

        raise LoginFlowChangedError(stage=stage.value)

    def _update_idk_info(
        self,
        idk_info: IdKitInfo,
        idk_obj: IdKitPageObject,
        stage: IdKitStage,
    ) -> None:
        idk_info.stage = stage
        idk_info.csrf_token = _require_str(idk_obj.csrf_token, "csrf_token")

        if stage == IdKitStage.IDENTIFIER:
            idk_info.set_client_id(idk_obj.client_id)
            idk_info.set_relay_state(idk_obj.relay_state)
            idk_info.set_hmac(idk_obj.hmac)
        elif stage == IdKitStage.PASSWORD:
            if idk_obj.client_id is not None and idk_info.client_id is None:
                idk_info.set_client_id(idk_obj.client_id)
            idk_info.set_relay_state(idk_obj.relay_state)
            idk_info.set_hmac(idk_obj.hmac)
        elif stage == IdKitStage.CONFIRM:
            idk_info.set_client_id(idk_obj.client_id)
            idk_info.set_relay_state(idk_obj.relay_state)
            idk_info.set_hmac(idk_obj.hmac)
            idk_info.set_user_code(idk_obj.user_code)
            idk_info.set_user_id(idk_obj.user_id)
            idk_info.set_client_identity_name(idk_obj.client_identity_name)
        elif stage not in (IdKitStage.PASSWORD, IdKitStage.SUCCESS):
            raise LoginFlowChangedError(stage=stage.value)

    def _pick_route(
        self,
        initial_stage: IdKitStage,
        current_url: str,
        html: str,
        mode: str = "device",
    ) -> list:
        if mode == "oidc":
            if initial_stage == IdKitStage.IDENTIFIER:
                return list(OIDC_FULL_ROUTE)
            if initial_stage == IdKitStage.PASSWORD:
                return list(OIDC_PASSWORD_ONLY_ROUTE)
            if initial_stage == IdKitStage.CONFIRM:
                # Consent-style page during authorize
                return [IdKitStage.CONFIRM]
            self._raise_flow_changed(
                "unexpected_initial_stage",
                current_url,
                html,
                f"expected identifier/password/confirm for oidc, got {initial_stage.value!r}",
            )

        if initial_stage == IdKitStage.IDENTIFIER:
            return list(FULL_ROUTE)
        if initial_stage == IdKitStage.CONFIRM:
            return list(QUICK_ROUTE)
        self._raise_flow_changed(
            "unexpected_initial_stage",
            current_url,
            html,
            f"expected identifier or confirm, got {initial_stage.value!r}",
        )

    def _start_device_flow(self, session: requests.Session) -> dict:
        LOG.debug("POST %s", DEVICE_FLOW_AUTHORIZATION_URL)
        response = session.post(
            DEVICE_FLOW_AUTHORIZATION_URL,
            data={"client_id": self._client_id, "scope": self._client_scope},
            timeout=self._timeout,
        )
        LOG.debug("device_authorization response: HTTP %s", response.status_code)
        response.raise_for_status()
        return response.json()

    def _poll_token(
        self,
        session: requests.Session,
        device_code: str,
        interval: int,
        max_wait_seconds: int,
    ) -> dict:
        deadline = time.monotonic() + max_wait_seconds
        poll_interval = max(interval, 1)

        while time.monotonic() < deadline:
            time.sleep(poll_interval)
            LOG.debug("POST %s (polling, interval=%ss)", DEVICE_FLOW_TOKEN_URL, poll_interval)
            response = session.post(
                DEVICE_FLOW_TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": self._client_id,
                },
                timeout=self._timeout,
            )
            if response.status_code == 200:
                return response.json()

            if response.status_code in _TRANSIENT_POLL_STATUSES:
                LOG.debug("Transient token poll HTTP %s", response.status_code)
                continue

            try:
                body = response.json()
            except (json.JSONDecodeError, ValueError):
                body = {}

            error_code = body.get("error", "")

            if error_code == "authorization_pending":
                continue
            if error_code == "slow_down":
                poll_interval += 5
                continue
            if error_code in _TRANSIENT_POLL_ERRORS:
                LOG.debug("Transient token poll OAuth error=%s", error_code)
                continue

            raise LoginError(f"Token polling failed with OAuth error: {error_code!r}")

        raise LoginError("Token polling timed out")

    def _raise_initial_parse_error(
        self, current_url: str, html: str, error: _IdKitError
    ) -> None:
        # registerCredentials means the email is not a VW account.
        if "registerCredentials" in str(error):
            raise LoginCredentialsError("Email address not found in VW account system")
        self._raise_page_parse_error("initial_landing", current_url, html, error)

    def _check_url_for_credentials_error(self, url: str) -> None:
        error_val = parse_qs(urlparse(url).query).get("error", [None])[0]
        if not error_val:
            return
        message = _VW_AUTH_ERROR_MESSAGES.get(error_val) or f"Authentication rejected by VW: {error_val!r}"
        raise LoginCredentialsError(message)

    def _raise_flow_changed(
        self, stage: str, current_url: str, html: str, reason: str
    ) -> None:
        LOG.error("Login flow changed (stage=%s, url=%s): %s", stage, current_url, reason)
        raise LoginFlowChangedError(stage=stage)

    def _raise_page_parse_error(
        self, stage: str, current_url: str, html: str, error: _IdKitError
    ) -> None:
        LOG.error("IDKit parse failed (stage=%s, url=%s): %s", stage, current_url, error)
        raise LoginPageParseError(
            f"IDKit parse failed at {stage} (url={current_url}): {error}"
        ) from error

    def _check_final_url(self, url: str) -> None:
        error_val = parse_qs(urlparse(url).query).get("error", [None])[0]
        if error_val:
            raise LoginError(f"Code confirmation returned error={error_val!r}")

    def _dump_and_reraise(self, error: Exception, current_url: str, html: str) -> None:
        if not current_url or not html or self._html_debug_dir is None:
            raise error
        if not LOG.isEnabledFor(logging.DEBUG):
            raise error

        if isinstance(error, LoginFlowChangedError):
            dump_stage = f"flow_changed_{error.stage}"
        elif isinstance(error, LoginPageParseError):
            dump_stage = "page_parse_error"
        else:
            dump_stage = "login_error"

        dump_path = dump_html_debug(dump_stage, html, self._html_debug_dir, url=current_url)
        dump_path_str = str(dump_path) if dump_path else None

        if isinstance(error, LoginFlowChangedError):
            raise LoginFlowChangedError(
                stage=error.stage, dump_path=dump_path_str
            ) from error
        raise type(error)(f"{error} (dump={dump_path_str})") from error

    def _browser_headers(self) -> dict:
        if self._use_fake_user_agent:
            return DEVICE_FLOW_BROWSER_HEADERS_FIREFOX.copy()
        return DEVICE_FLOW_BROWSER_HEADERS.copy()


def _require_str(value: str | None, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise LoginError(f"Missing or invalid {field_name}")
    return value


def _save_cookies(session: requests.Session, path: Path) -> None:
    data = []
    for cookie in session.cookies:
        data.append({
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain or "",
            "path": cookie.path or "/",
        })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_cookies(session: requests.Session, path: Path, default_domain: str) -> None:
    if not path.exists():
        return
    try:
        cookies = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        LOG.warning("Could not load auth cookies from %s: %s", path, error)
        return
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        domain = cookie.get("domain") or default_domain
        cookie_path = cookie.get("path") or "/"
        session.cookies.set_cookie(Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=bool(domain),
            domain_initial_dot=domain.startswith(".") if domain else False,
            path=cookie_path,
            path_specified=True,
            secure=True,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        ))
