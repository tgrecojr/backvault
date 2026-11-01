"""Assemble a Bitwarden-format JSON export from a decrypted /api/sync payload.

Shape follows ``bw export --format json`` (individual vault). Reference:
bitwarden/clients libs/common/src/models/export/*.export.ts and
libs/tools/export-vault-core/src/services/individual-vault-export.service.ts.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from vault_crypto import (
    AES_HMAC_KEY_LEN,
    BitwardenError,
    EncStringError,
    decrypt_enc_string,
    decrypt_enc_string_bytes,
)

logger = logging.getLogger(__name__)

PLACEHOLDER = "[error: cannot decrypt]"

# Export shape of absent collections. These follow the CLI release named by
# vault_client.REFERENCE_CLI_VERSION and are confirmed by the pre-merge drill.
EMPTY_LIST: list[Any] = []

ITEM_TYPES = {1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey"}

LOGIN_FIELDS = ("username", "password", "totp")
CARD_FIELDS = ("cardholderName", "brand", "number", "expMonth", "expYear", "code")
IDENTITY_FIELDS = (
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "username",
    "passportNumber",
    "licenseNumber",
)
SSH_KEY_FIELDS = ("privateKey", "publicKey", "keyFingerprint")
FIDO2_ENCRYPTED_FIELDS = (
    "credentialId",
    "keyType",
    "keyAlgorithm",
    "keyCurve",
    "keyValue",
    "rpId",
    "userHandle",
    "userName",
    "counter",
    "rpName",
    "userDisplayName",
    "discoverable",
)

_DATE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$"
)


@dataclass
class ExportStats:
    org_excluded: int = 0
    trashed_excluded: int = 0
    with_attachments: int = 0
    undecryptable_fields: int = 0


# @spec VAULT-EXPORT-011
def normalize_date(value: str | None) -> str | None:
    """RFC 3339 of any precision/offset -> UTC with exactly three fractional digits and 'Z'."""
    if value is None:
        return None
    match = _DATE_RE.match(value.strip())
    if not match:
        raise BitwardenError(f"unrecognised date value {value!r}")
    base, fraction, zone = match.groups()
    dt = datetime.fromisoformat(base).replace(tzinfo=UTC)
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
        dt = dt - sign * offset
    millis = int((fraction or "").ljust(3, "0")[:3])
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{millis:03d}Z"


class _ItemDecryptor:
    """Decrypts one item's fields with its effective key, applying the placeholder policy."""

    def __init__(self, item_id: str, key: bytes, stats: ExportStats) -> None:
        self.item_id = item_id
        self.key = key
        self.stats = stats

    # @spec VAULT-CRYPTO-006
    def text(self, value: str | None, path: str) -> str | None:
        try:
            return decrypt_enc_string(value, self.key)
        except EncStringError as exc:
            logger.error(
                "item %s field %s could not be decrypted (%s); emitting placeholder",
                self.item_id,
                path,
                exc,
            )
            self.stats.undecryptable_fields += 1
            return PLACEHOLDER
        except BitwardenError as exc:
            raise BitwardenError(f"item {self.item_id} field {path}: {exc}") from exc

    def mapping(self, source: dict | None, names: tuple[str, ...], path: str) -> dict:
        source = source or {}
        return {name: self.text(source.get(name), f"{path}.{name}") for name in names}

    def login(self, source: dict | None) -> dict:
        source = source or {}
        uris = source.get("uris")
        fido2 = source.get("fido2Credentials")
        return {
            "uris": EMPTY_LIST
            if not uris
            else [
                {
                    "match": u.get("match"),
                    "uri": self.text(u.get("uri"), f"login.uris[{i}].uri"),
                }
                for i, u in enumerate(uris)
            ],
            **self.mapping(source, LOGIN_FIELDS, "login"),
            "fido2Credentials": EMPTY_LIST
            if not fido2
            else [self.fido2(c, i) for i, c in enumerate(fido2)],
        }

    def fido2(self, cred: dict, index: int) -> dict:
        out = self.mapping(
            cred, FIDO2_ENCRYPTED_FIELDS, f"login.fido2Credentials[{index}]"
        )
        out["creationDate"] = normalize_date(cred.get("creationDate"))
        return out

    def fields(self, source: list | None) -> list:
        return [
            {
                "name": self.text(f.get("name"), f"fields[{i}].name"),
                "value": self.text(f.get("value"), f"fields[{i}].value"),
                "type": f.get("type"),
                "linkedId": f.get("linkedId"),
            }
            for i, f in enumerate(source or [])
        ]

    def password_history(self, source: list | None) -> list:
        return [
            {
                "password": self.text(
                    p.get("password"), f"passwordHistory[{i}].password"
                ),
                "lastUsedDate": normalize_date(p.get("lastUsedDate")),
            }
            for i, p in enumerate(source or [])
        ]


def _typed_object(dec: _ItemDecryptor, item_type: int, item: dict) -> tuple[str, dict]:
    key = ITEM_TYPES[item_type]
    source = item.get(key)
    if item_type == 1:
        return key, dec.login(source)
    if item_type == 2:
        return key, {"type": (source or {}).get("type", 0)}
    if item_type == 3:
        return key, dec.mapping(source, CARD_FIELDS, key)
    if item_type == 4:
        return key, dec.mapping(source, IDENTITY_FIELDS, key)
    return key, dec.mapping(source, SSH_KEY_FIELDS, key)


# @spec VAULT-CRYPTO-008, VAULT-CRYPTO-009
def _effective_key(item: dict, item_id: str, user_key: bytes) -> bytes:
    if item.get("name") is None:
        raise BitwardenError(
            f"item {item_id}: encrypted name is null; sealed-blob cipher format is not supported"
        )
    cipher_key = item.get("key")
    if not cipher_key:
        return user_key
    try:
        unwrapped = decrypt_enc_string_bytes(cipher_key, user_key)
    except EncStringError as exc:
        raise BitwardenError(
            f"item {item_id}: could not decrypt cipher key (field key): {exc}"
        ) from exc
    if len(unwrapped) != AES_HMAC_KEY_LEN:
        raise BitwardenError(
            f"item {item_id}: cipher key (field key) has unexpected length {len(unwrapped)}"
        )
    return unwrapped


# @spec VAULT-EXPORT-008, VAULT-EXPORT-009, VAULT-EXPORT-010, VAULT-EXPORT-013
def _export_item(item: dict, user_key: bytes, stats: ExportStats) -> dict:
    item_id = str(item.get("id"))
    item_type = item.get("type")
    if item_type not in ITEM_TYPES:
        raise BitwardenError(f"item {item_id}: unsupported item type {item_type}")
    dec = _ItemDecryptor(item_id, _effective_key(item, item_id, user_key), stats)
    out: dict[str, Any] = {
        "id": item.get("id"),
        "organizationId": None,
        "folderId": item.get("folderId"),
        "type": item_type,
        "reprompt": item.get("reprompt") or 0,
        "name": dec.text(item.get("name"), "name"),
        "notes": dec.text(item.get("notes"), "notes"),
        "favorite": bool(item.get("favorite")),
        "fields": dec.fields(item.get("fields")),
    }
    typed_key, typed = _typed_object(dec, item_type, item)
    out[typed_key] = typed
    out["passwordHistory"] = dec.password_history(item.get("passwordHistory"))
    out["creationDate"] = normalize_date(item.get("creationDate"))
    out["revisionDate"] = normalize_date(item.get("revisionDate"))
    out["deletedDate"] = normalize_date(item.get("deletedDate"))
    out["archivedDate"] = normalize_date(item.get("archivedDate"))
    out["collectionIds"] = None
    return out


# @spec VAULT-EXPORT-005
def _validate_sync_payload(payload: Any) -> None:
    if not isinstance(payload, dict) or payload.get("object") != "sync":
        raise BitwardenError("server response is not a sync object")
    for name in ("folders", "ciphers"):
        if not isinstance(payload.get(name), list):
            raise BitwardenError(f"sync response has no {name!r} array")


# @spec VAULT-EXPORT-003, VAULT-EXPORT-006, VAULT-EXPORT-007
def build_export(payload: Any, user_key: bytes) -> tuple[dict, ExportStats]:
    """Select, decrypt, and shape folders and items. Returns (export, stats)."""
    _validate_sync_payload(payload)
    stats = ExportStats()
    folders = []
    for f in payload["folders"]:
        name = _ItemDecryptor(f"folder {f.get('id')}", user_key, stats).text(
            f.get("name"), "name"
        )
        folders.append({"id": f.get("id"), "name": name})
    items = []
    for item in payload["ciphers"]:
        if item.get("organizationId") is not None:
            stats.org_excluded += 1
            continue
        if item.get("deletedDate") is not None:
            stats.trashed_excluded += 1
            continue
        if item.get("attachments"):
            stats.with_attachments += 1
        items.append(_export_item(item, user_key, stats))
    return {"encrypted": False, "folders": folders, "items": items}, stats


# @spec VAULT-EXPORT-014
def serialize_export(export: dict) -> str:
    return json.dumps(export, ensure_ascii=False, indent=2)


DecryptText = Callable[[str | None, str], str | None]
