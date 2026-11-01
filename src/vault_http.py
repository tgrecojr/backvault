"""HTTPS transport for the vault client: TLS policy, redirect refusal, retry, error shaping."""

from __future__ import annotations

import base64
import json
import logging
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from vault_crypto import BitwardenError

logger = logging.getLogger(__name__)

RETRY_ATTEMPTS = 3
RETRY_DELAYS = (2.0, 4.0)
HTTP_TIMEOUT = 60
BODY_LOG_LIMIT = 500

HttpResponse = tuple[int, dict[str, str], bytes]
HttpCallable = Callable[[str, str, dict[str, str], bytes | None], HttpResponse]
HeaderProvider = Callable[[bytes | None], dict[str, str]]


# @spec VAULT-HTTP-001
def build_ssl_context(ca_cert: str | None) -> ssl.SSLContext:
    """Default verifying context; ``ca_cert`` adds a PEM bundle without replacing the system store."""
    context = ssl.create_default_context()
    if ca_cert:
        context.load_verify_locations(cafile=ca_cert)
    return context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urllib_http(ca_cert: str | None) -> HttpCallable:
    """Default transport: TLS-verified urllib with redirects refused."""
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=build_ssl_context(ca_cert)), _NoRedirect()
    )

    def send(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with opener.open(request, timeout=HTTP_TIMEOUT) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    return send


def server_message(body: bytes) -> str:
    """Extract the server's human-readable error text from a JSON error body, if any."""
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("error_description", "message", "Message"):
        if isinstance(data.get(key), str):
            return data[key]
    model = data.get("ErrorModel") or data.get("errorModel")
    if isinstance(model, dict) and isinstance(model.get("Message"), str):
        return model["Message"]
    return ""


def jwt_claim(token: str, claim: str) -> str | None:
    """Read a claim from a JWT payload without verifying the signature (TLS authenticates the server)."""
    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded)).get(claim)
    except IndexError, ValueError, AttributeError:
        return None


class RetryingRequester:
    """Issues JSON requests with the retry and failure policy of the vault-access design."""

    def __init__(
        self, http: HttpCallable, sleep: Callable[[float], Any], headers: HeaderProvider
    ) -> None:
        self._http = http
        self._sleep = sleep
        self._headers = headers

    # @spec VAULT-RETRY-001, VAULT-RETRY-002, VAULT-RETRY-003, VAULT-HTTP-005
    def request(
        self, method: str, url: str, body: bytes | None = None, is_token: bool = False
    ) -> Any:
        last_error = "no response"
        for attempt in range(RETRY_ATTEMPTS):
            try:
                status, headers, raw = self._http(
                    method, url, self._headers(body), body
                )
            except OSError as exc:
                last_error = f"network error: {exc}"
                logger.warning(
                    "%s %s failed (%s)", method, url.split("?")[0], last_error
                )
            else:
                if status >= 500 or status == 429:
                    last_error = f"HTTP {status}"
                    self._log_failure(status, raw)
                else:
                    return self._handle(status, headers, raw, is_token)
            if attempt < RETRY_ATTEMPTS - 1:
                self._sleep(RETRY_DELAYS[attempt])
        raise BitwardenError(
            f"{method} {url.split('?')[0]} failed after {RETRY_ATTEMPTS} attempts ({last_error})"
        )

    # @spec VAULT-HTTP-003, VAULT-HTTP-004
    def _handle(
        self, status: int, headers: dict[str, str], raw: bytes, is_token: bool
    ) -> Any:
        if 300 <= status < 400:
            location = {k.lower(): v for k, v in headers.items()}.get(
                "location", "<none>"
            )
            raise BitwardenError(
                f"server redirected (HTTP {status}) to {location}; refusing to follow. Check BW_SERVER"
            )
        if status == 404:
            self._log_failure(status, raw)
            raise BitwardenError(
                "HTTP 404 from the server; check that BW_SERVER points at the vault's base URL"
            )
        if status >= 400:
            self._log_failure(status, raw)
            message = server_message(raw)
            what = (
                "authentication rejected"
                if is_token
                else "token rejected by the server"
            )
            raise BitwardenError(
                f"{what} (HTTP {status}){': ' + message if message else ''}"
            )
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise BitwardenError(
                f"server response (HTTP {status}) is not JSON"
            ) from exc

    # @spec VAULT-LOG-003
    def _log_failure(self, status: int, raw: bytes) -> None:
        body = raw.decode("utf-8", "replace")[:BODY_LOG_LIMIT]
        logger.error(
            "Server returned HTTP %d: %s | body: %s",
            status,
            server_message(raw) or "(no message)",
            body,
        )
