"""Native Bitwarden/Vaultwarden client: API-key login, key unwrap, sync, export (vault-access).

One ``export_vault_json`` call performs the whole cycle in memory and returns the
export as a JSON string in the shape of ``bw export --format json``.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
import uuid
from collections.abc import Callable
from typing import Any

from vault_crypto import (
    KDF_ARGON2ID,
    KDF_PBKDF2,
    BitwardenError,
    EncStringError,
    decrypt_enc_string,
    decrypt_enc_string_bytes,
    derive_master_key,
    stretch_key,
    unwrap_user_key,
)
from vault_export import (
    PLACEHOLDER,
    ExportStats,
    build_export,
    normalize_date,
    serialize_export,
)
from vault_http import HttpCallable, RetryingRequester, jwt_claim, urllib_http
from vault_http import build_ssl_context as _build_ssl_context

__all__ = [
    "PLACEHOLDER",
    "REFERENCE_CLI_VERSION",
    "BitwardenError",
    "EncStringError",
    "ExportStats",
    "VaultSession",
    "_build_ssl_context",
    "build_export",
    "decrypt_enc_string",
    "decrypt_enc_string_bytes",
    "derive_master_key",
    "device_identifier",
    "export_vault_json",
    "normalize_date",
    "resolve_endpoints",
    "serialize_export",
    "stretch_key",
    "unwrap_user_key",
]

logger = logging.getLogger(__name__)

# The CLI release whose export shape this client reproduces and whose version it
# announces. Re-run the pre-merge drill (diff against `bw export`) when changing it.
REFERENCE_CLI_VERSION = "2025.1.3"

DEVICE_TYPE = "25"  # Linux CLI
DEVICE_NAME = "backvault"
CLOUD_HOSTS = {
    "vault.bitwarden.com": (
        "https://identity.bitwarden.com",
        "https://api.bitwarden.com",
    ),
    "vault.bitwarden.eu": ("https://identity.bitwarden.eu", "https://api.bitwarden.eu"),
}
TOKEN_FIELDS = ("access_token", "Key", "Kdf", "KdfIterations")


# @spec VAULT-SESSION-005
def resolve_endpoints(server: str) -> tuple[str, str]:
    """Return (identity_base, api_base) for a BW_SERVER value."""
    base = server.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "https" or not parsed.netloc:
        raise BitwardenError("BW_SERVER must be an https:// URL")
    cloud = CLOUD_HOSTS.get(parsed.netloc.lower())
    if cloud:
        return cloud
    return f"{base}/identity", f"{base}/api"


# @spec VAULT-AUTH-001
def device_identifier(client_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "backvault:" + client_id))


class VaultSession:
    """One authenticate -> unwrap -> sync -> export cycle. Secrets are cleared on exit."""

    def __init__(
        self,
        server: str,
        client_id: str,
        client_secret: str,
        master_password: str,
        ca_cert: str | None = None,
        http: HttpCallable | None = None,
        sleep: Callable[[float], Any] | None = None,
    ) -> None:
        self.identity_base, self.api_base = resolve_endpoints(server)
        self.host = urllib.parse.urlsplit(server.strip()).netloc
        self.client_id = client_id
        self._client_secret = client_secret
        self._master_password = master_password
        self._requester = RetryingRequester(
            http or urllib_http(ca_cert), sleep or time.sleep, self._headers
        )
        self.access_token: str | None = None
        self.master_key: bytes | None = None
        self.stretched_key: bytes | None = None
        self.user_key: bytes | None = None

    # @spec VAULT-SESSION-003, VAULT-SESSION-004
    def export(self) -> str:
        try:
            started = time.monotonic()
            self._authenticate()
            auth_done = time.monotonic()
            payload = self._requester.request(
                "GET", f"{self.api_base}/sync?excludeDomains=true"
            )
            sync_done = time.monotonic()
            export, stats = build_export(payload, self.user_key)
            self._log_summary(
                export,
                stats,
                (
                    auth_done - started,
                    sync_done - auth_done,
                    time.monotonic() - sync_done,
                ),
            )
            return serialize_export(export)
        finally:
            self._clear()

    # @spec VAULT-LOG-004, VAULT-LOG-005, VAULT-EXPORT-007
    def _log_summary(
        self, export: dict, stats: ExportStats, timings: tuple[float, float, float]
    ) -> None:
        logger.info(
            "Export from %s: %d folders, %d items (%d organization items and %d trashed items excluded); "
            "token %.2fs, sync %.2fs, decrypt %.2fs",
            self.host,
            len(export["folders"]),
            len(export["items"]),
            stats.org_excluded,
            stats.trashed_excluded,
            *timings,
        )
        if stats.with_attachments:
            logger.warning(
                "%d exported item(s) have attachments; attachments are not included in the export",
                stats.with_attachments,
            )
        if stats.undecryptable_fields:
            logger.error(
                "%d field(s) could not be decrypted and were exported as %s",
                stats.undecryptable_fields,
                PLACEHOLDER,
            )

    def _clear(self) -> None:
        for attr in ("master_key", "stretched_key", "user_key"):
            value = getattr(self, attr)
            if isinstance(value, bytearray):
                value[:] = bytes(len(value))
            setattr(self, attr, None)
        self.access_token = None
        self._master_password = ""
        self._client_secret = ""

    # @spec VAULT-SESSION-001, VAULT-SESSION-002, VAULT-SESSION-006, VAULT-AUTH-002, VAULT-AUTH-003
    def _authenticate(self) -> None:
        if not self.client_id.startswith("user."):
            raise BitwardenError(
                "BW_CLIENT_ID must be a user API key (user.<uuid>); "
                "organization API keys cannot unlock a personal vault"
            )
        token = self._requester.request(
            "POST",
            f"{self.identity_base}/connect/token",
            body=self._token_form(),
            is_token=True,
        )
        for field in TOKEN_FIELDS:
            if token.get(field) is None:
                raise BitwardenError(
                    f"token response has no {field}; this account cannot be unlocked with a master password"
                )
        self.access_token = token["access_token"]
        kdf = int(token["Kdf"])
        if kdf not in (KDF_PBKDF2, KDF_ARGON2ID):
            raise BitwardenError(f"unsupported KDF type {kdf}")
        email = self._email(token)
        logger.info(
            "Account KDF: %s (iterations=%s, memory=%s MiB, parallelism=%s)",
            "PBKDF2" if kdf == KDF_PBKDF2 else "Argon2id",
            token["KdfIterations"],
            token.get("KdfMemory"),
            token.get("KdfParallelism"),
        )
        self.master_key = derive_master_key(
            self._master_password,
            email,
            kdf,
            token["KdfIterations"],
            token.get("KdfMemory"),
            token.get("KdfParallelism"),
        )
        self.stretched_key = stretch_key(self.master_key)
        self.user_key = unwrap_user_key(token["Key"], self.master_key)

    # @spec VAULT-AUTH-001
    def _token_form(self) -> bytes:
        return urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "scope": "api",
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "deviceType": DEVICE_TYPE,
                "deviceIdentifier": device_identifier(self.client_id),
                "deviceName": DEVICE_NAME,
            }
        ).encode()

    # @spec VAULT-AUTH-004
    def _email(self, token: dict) -> str:
        unlock = (
            (token.get("UserDecryptionOptions") or {}).get("MasterPasswordUnlock")
        ) or {}
        email = unlock.get("Salt") or jwt_claim(token["access_token"], "email")
        if not email:
            self.access_token = token["access_token"]
            email = self._requester.request(
                "GET", f"{self.api_base}/accounts/profile"
            ).get("email")
        if not email:
            raise BitwardenError(
                "could not determine the account email for key derivation"
            )
        return email.strip().lower()

    # @spec VAULT-HTTP-002
    def _headers(self, body: bytes | None) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Bitwarden-Client-Name": "cli",
            "Bitwarden-Client-Version": REFERENCE_CLI_VERSION,
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers


# @spec VAULT-EXPORT-001, VAULT-EXPORT-004, VAULT-EXPORT-005
def export_vault_json(
    server: str,
    client_id: str,
    client_secret: str,
    master_password: str,
    ca_cert: str | None = None,
    http: HttpCallable | None = None,
    sleep: Callable[[float], Any] | None = None,
) -> str:
    """Authenticate, decrypt, and return the vault export JSON string. Writes nothing."""
    return VaultSession(
        server, client_id, client_secret, master_password, ca_cert, http, sleep
    ).export()
