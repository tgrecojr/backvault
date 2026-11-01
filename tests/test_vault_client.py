"""Tests for the native Bitwarden/Vaultwarden vault client (vault-access segment).

Fixtures build a miniature encrypted vault with test-side crypto helpers so the
production decryption path is exercised against independently constructed data.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vault_client import (
    PLACEHOLDER,
    REFERENCE_CLI_VERSION,
    BitwardenError,
    EncStringError,
    build_export,
    decrypt_enc_string,
    decrypt_enc_string_bytes,
    derive_master_key,
    device_identifier,
    export_vault_json,
    normalize_date,
    resolve_endpoints,
    serialize_export,
    stretch_key,
    unwrap_user_key,
)

# ---------------------------------------------------------------------------
# Test-side crypto helpers (independent of the implementation under test)
# ---------------------------------------------------------------------------

EMAIL_RAW = "  Test@Example.COM "
EMAIL = "test@example.com"
PASSWORD = "pässwörd☃"
ITERATIONS = 5000
CLIENT_ID = "user.0b3c6e2a-9d44-4c4e-8d4e-1a2b3c4d5e6f"
CLIENT_SECRET = "s3cr3t-client-secret"
SERVER = "https://vault.example.test"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hkdf_expand(prk: bytes, info: str) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info.encode()).derive(
        prk
    )


def stretch_for_test(master_key: bytes) -> bytes:
    return hkdf_expand(master_key, "enc") + hkdf_expand(master_key, "mac")


def enc2(plaintext: bytes, key64: bytes) -> str:
    """Produce a type-2 EncString: AES-256-CBC + HMAC-SHA256 over iv||ct."""
    enc_key, mac_key = key64[:32], key64[32:]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def enc0(plaintext: bytes, key32: bytes) -> str:
    """Produce a legacy type-0 EncString: AES-256-CBC, no MAC."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key32), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return f"0.{b64(iv)}|{b64(ct)}"


def e(text: str, key64: bytes) -> str:
    return enc2(text.encode("utf-8"), key64)


MASTER_KEY = hashlib.pbkdf2_hmac(
    "sha256", PASSWORD.encode("utf-8"), EMAIL.encode(), ITERATIONS, 32
)
STRETCHED = stretch_for_test(MASTER_KEY)
USER_KEY = bytes(range(64))


def fake_jwt(email: str | None = EMAIL) -> str:
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = {"sub": CLIENT_ID[5:], "premium": True}
    if email is not None:
        payload["email"] = email
    return f"{header}.{b64url(json.dumps(payload).encode())}.{b64url(b'sig')}"


def token_response(**overrides) -> dict:
    body = {
        "access_token": fake_jwt(),
        "expires_in": 3600,
        "token_type": "Bearer",
        "Key": enc2(USER_KEY, STRETCHED),
        "PrivateKey": "2.unused|unused|unused",
        "Kdf": 0,
        "KdfIterations": ITERATIONS,
        "KdfMemory": None,
        "KdfParallelism": None,
        "ForcePasswordReset": False,
        "scope": "api",
        "UserDecryptionOptions": {
            "HasMasterPassword": True,
            "MasterPasswordUnlock": {
                "Kdf": {
                    "KdfType": 0,
                    "Iterations": ITERATIONS,
                    "Memory": None,
                    "Parallelism": None,
                },
                "MasterKeyEncryptedUserKey": enc2(USER_KEY, STRETCHED),
                "Salt": EMAIL_RAW,
            },
            "Object": "userDecryptionOptions",
        },
    }
    body.update(overrides)
    return body


def folder(fid: str, name: str, key: bytes = USER_KEY) -> dict:
    return {
        "id": fid,
        "name": e(name, key),
        "revisionDate": "2024-01-01T00:00:00.000000Z",
        "object": "folder",
    }


def login_item(
    iid: str,
    name: str,
    *,
    key: bytes = USER_KEY,
    username: str | None = "alice",
    password: str | None = "hunter2",
    totp: str | None = None,
    uris: list[tuple[str, int | None]] | None = (("https://example.test", None),),
    folder_id: str | None = None,
    organization_id: str | None = None,
    deleted: str | None = None,
    archived: str | None = None,
    attachments: list | None = None,
    fields: list | None = None,
    password_history: list | None = None,
    cipher_key: str | None = None,
    notes: str | None = None,
    favorite: bool = False,
    reprompt: int = 0,
) -> dict:
    def enc_or_none(v: str | None) -> str | None:
        return None if v is None else e(v, key)

    return {
        "object": "cipherDetails",
        "id": iid,
        "organizationId": organization_id,
        "folderId": folder_id,
        "favorite": favorite,
        "reprompt": reprompt,
        "type": 1,
        "name": e(name, key),
        "notes": enc_or_none(notes),
        "fields": fields,
        "login": {
            "username": enc_or_none(username),
            "password": enc_or_none(password),
            "totp": enc_or_none(totp),
            "uris": None
            if uris is None
            else [{"uri": e(u, key), "match": m} for u, m in uris],
            "fido2Credentials": None,
            "autofillOnPageLoad": None,
            "passwordRevisionDate": None,
        },
        "card": None,
        "identity": None,
        "secureNote": None,
        "sshKey": None,
        "passwordHistory": password_history,
        "attachments": attachments,
        "collectionIds": [],
        "key": cipher_key,
        "creationDate": "2024-01-02T03:04:05.123456Z",
        "revisionDate": "2024-02-03T04:05:06.654321Z",
        "deletedDate": deleted,
        "archivedDate": archived,
        "organizationUseTotp": True,
        "edit": True,
        "viewPassword": True,
    }


def note_item(iid: str, name: str, notes: str, key: bytes = USER_KEY) -> dict:
    item = login_item(iid, name, key=key, uris=None, username=None, password=None)
    item["type"] = 2
    item["login"] = None
    item["secureNote"] = {"type": 0}
    item["notes"] = e(notes, key)
    return item


def sync_payload(ciphers: list[dict], folders: list[dict] | None = None) -> dict:
    return {
        "profile": {
            "id": CLIENT_ID[5:],
            "email": EMAIL,
            "key": enc2(USER_KEY, STRETCHED),
            "object": "profile",
        },
        "folders": folders if folders is not None else [folder("f-1", "Work")],
        "collections": [],
        "policies": [],
        "ciphers": ciphers,
        "domains": None,
        "sends": [],
        "object": "sync",
    }


class FakeHttp:
    """Scripted transport: queue of (status, headers, body) per URL suffix; records calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict, bytes | None]] = []
        self.scripts: dict[str, list[tuple[int, dict, bytes]]] = {}

    def on(self, suffix: str, *responses) -> FakeHttp:
        queue = self.scripts.setdefault(suffix, [])
        for status, body in responses:
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            queue.append((status, {"Content-Type": "application/json"}, raw))
        return self

    def on_redirect(self, suffix: str, location: str) -> FakeHttp:
        self.scripts.setdefault(suffix, []).append((302, {"Location": location}, b""))
        return self

    def __call__(self, method: str, url: str, headers: dict, body: bytes | None):
        self.calls.append((method, url, dict(headers), body))
        for suffix, queue in self.scripts.items():
            if url.split("?")[0].endswith(suffix):
                if not queue:
                    raise AssertionError(f"no scripted response left for {url}")
                return queue.pop(0) if len(queue) > 1 else queue[0]
        raise AssertionError(f"unexpected request {method} {url}")

    def requests_to(self, suffix: str) -> list[tuple[str, str, dict, bytes | None]]:
        return [c for c in self.calls if c[1].split("?")[0].endswith(suffix)]


def happy_http(ciphers: list[dict] | None = None, **token_overrides) -> FakeHttp:
    ciphers = (
        ciphers
        if ciphers is not None
        else [login_item("i-1", "Example", folder_id="f-1")]
    )
    return (
        FakeHttp()
        .on("/connect/token", (200, token_response(**token_overrides)))
        .on("/sync", (200, sync_payload(ciphers)))
    )


def run_export(http: FakeHttp, **kwargs) -> dict:
    sleeps: list[float] = []
    http.sleeps = sleeps  # type: ignore[attr-defined]
    text = export_vault_json(
        server=kwargs.pop("server", SERVER),
        client_id=kwargs.pop("client_id", CLIENT_ID),
        client_secret=CLIENT_SECRET,
        master_password=PASSWORD,
        http=http,
        sleep=sleeps.append,
        **kwargs,
    )
    http.sleeps = sleeps  # type: ignore[attr-defined]
    return json.loads(text)


# ---------------------------------------------------------------------------
# Endpoints, device, version constant
# ---------------------------------------------------------------------------


class TestEndpoints:
    # @spec VAULT-SESSION-005
    def test_self_hosted_paths_and_trailing_slash(self):
        identity, api = resolve_endpoints("https://vault.example.test//")
        assert identity == "https://vault.example.test/identity"
        assert api == "https://vault.example.test/api"

    # @spec VAULT-SESSION-005
    @pytest.mark.parametrize(
        ("server", "identity", "api"),
        [
            (
                "https://vault.bitwarden.com",
                "https://identity.bitwarden.com",
                "https://api.bitwarden.com",
            ),
            (
                "https://vault.bitwarden.eu",
                "https://identity.bitwarden.eu",
                "https://api.bitwarden.eu",
            ),
        ],
    )
    def test_cloud_hosts(self, server, identity, api):
        assert resolve_endpoints(server) == (identity, api)

    # @spec VAULT-SESSION-005
    def test_non_https_scheme_fails_before_any_request(self):
        http = FakeHttp()
        with pytest.raises(BitwardenError, match="https"):
            run_export(http, server="http://vault.example.test")
        assert http.calls == []

    # @spec VAULT-SESSION-006
    def test_organization_client_id_rejected_before_any_request(self):
        http = FakeHttp()
        with pytest.raises(BitwardenError, match="organization"):
            run_export(
                http, client_id="organization.0b3c6e2a-9d44-4c4e-8d4e-1a2b3c4d5e6f"
            )
        assert http.calls == []

    # @spec VAULT-AUTH-001
    def test_device_identifier_is_stable_uuid5(self):
        expected = str(uuid.uuid5(uuid.NAMESPACE_URL, "backvault:" + CLIENT_ID))
        assert device_identifier(CLIENT_ID) == expected
        assert device_identifier(CLIENT_ID) == device_identifier(CLIENT_ID)

    # @spec VAULT-HTTP-002
    def test_reference_cli_version_is_recent_enough(self):
        parts = tuple(int(p) for p in REFERENCE_CLI_VERSION.split("."))
        assert len(parts) == 3
        assert parts >= (2024, 12, 0)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


class TestKeyDerivation:
    # @spec VAULT-AUTH-005
    def test_pbkdf2_master_key(self):
        assert (
            derive_master_key(PASSWORD, EMAIL, kdf=0, iterations=ITERATIONS)
            == MASTER_KEY
        )

    # @spec VAULT-AUTH-004
    def test_email_is_trimmed_and_lowercased_by_caller_contract(self):
        # derive_master_key receives the normalised email; the normalisation is
        # exercised end-to-end in TestEmailSource. Here: raw vs normalised differ.
        assert (
            derive_master_key(
                PASSWORD, EMAIL_RAW.strip().lower(), kdf=0, iterations=ITERATIONS
            )
            == MASTER_KEY
        )

    # @spec VAULT-AUTH-007
    def test_password_bytes_are_raw_utf8_no_normalisation(self):
        decomposed = "pässwörd"  # NFD 'ä' differs from NFC 'ä'
        composed = "pässwörd"
        k1 = derive_master_key(decomposed, EMAIL, kdf=0, iterations=ITERATIONS)
        k2 = derive_master_key(composed, EMAIL, kdf=0, iterations=ITERATIONS)
        assert k1 != k2
        assert derive_master_key(
            " pw ", EMAIL, kdf=0, iterations=ITERATIONS
        ) != derive_master_key("pw", EMAIL, kdf=0, iterations=ITERATIONS)

    # @spec VAULT-AUTH-006
    def test_argon2id_master_key_matches_reference_parameters(self):
        from argon2.low_level import Type, hash_secret_raw

        expected = hash_secret_raw(
            secret=PASSWORD.encode("utf-8"),
            salt=hashlib.sha256(EMAIL.encode()).digest(),
            time_cost=3,
            memory_cost=16 * 1024,
            parallelism=2,
            hash_len=32,
            type=Type.ID,
            version=0x13,
        )
        assert (
            derive_master_key(
                PASSWORD, EMAIL, kdf=1, iterations=3, memory=16, parallelism=2
            )
            == expected
        )

    # @spec VAULT-AUTH-003
    def test_unknown_kdf_type_rejected(self):
        with pytest.raises(BitwardenError, match="KDF"):
            derive_master_key(PASSWORD, EMAIL, kdf=7, iterations=ITERATIONS)

    # @spec VAULT-AUTH-008
    def test_stretch_key_matches_bitwarden_sdk_vector(self):
        key = bytes(
            [
                31,
                79,
                104,
                226,
                150,
                71,
                177,
                90,
                194,
                80,
                172,
                209,
                17,
                129,
                132,
                81,
                138,
                167,
                69,
                167,
                254,
                149,
                2,
                27,
                39,
                197,
                64,
                42,
                22,
                195,
                86,
                75,
            ]
        )
        enc = bytes(
            [
                111,
                31,
                178,
                45,
                238,
                152,
                37,
                114,
                143,
                215,
                124,
                83,
                135,
                173,
                195,
                23,
                142,
                134,
                120,
                249,
                61,
                132,
                163,
                182,
                113,
                197,
                189,
                204,
                188,
                21,
                237,
                96,
            ]
        )
        mac = bytes(
            [
                221,
                127,
                206,
                234,
                101,
                27,
                202,
                38,
                86,
                52,
                34,
                28,
                78,
                28,
                185,
                16,
                48,
                61,
                127,
                166,
                209,
                247,
                194,
                87,
                232,
                26,
                48,
                85,
                193,
                249,
                179,
                155,
            ]
        )
        assert stretch_key(key) == enc + mac

    # @spec VAULT-AUTH-009
    def test_unwrap_type2_user_key_yields_64_bytes(self):
        assert unwrap_user_key(enc2(USER_KEY, STRETCHED), MASTER_KEY) == USER_KEY

    # @spec VAULT-AUTH-009
    def test_unwrap_type0_user_key_yields_32_bytes(self):
        legacy = bytes(range(32))
        assert unwrap_user_key(enc0(legacy, MASTER_KEY), MASTER_KEY) == legacy

    # @spec VAULT-AUTH-009
    @pytest.mark.parametrize("length", [16, 48, 65])
    def test_unwrap_rejects_unexpected_lengths(self, length):
        with pytest.raises(BitwardenError, match="length"):
            unwrap_user_key(enc2(bytes(length), STRETCHED), MASTER_KEY)

    # @spec VAULT-CRYPTO-007
    def test_unwrap_with_wrong_master_key_fails_the_cycle(self):
        with pytest.raises(BitwardenError, match="key"):
            unwrap_user_key(enc2(USER_KEY, STRETCHED), bytes(32))


# ---------------------------------------------------------------------------
# EncString decryption
# ---------------------------------------------------------------------------


class TestEncString:
    # @spec VAULT-CRYPTO-001
    def test_type2_roundtrip(self):
        assert decrypt_enc_string(e("héllo ☃", USER_KEY), USER_KEY) == "héllo ☃"

    # @spec VAULT-CRYPTO-001
    def test_type2_mac_mismatch_is_field_failure(self):
        value = e("secret", USER_KEY)
        head, ct, mac = value.split("|")
        tampered = bytearray(base64.b64decode(ct))
        tampered[0] ^= 0xFF
        with pytest.raises(EncStringError):
            decrypt_enc_string(f"{head}|{b64(bytes(tampered))}|{mac}", USER_KEY)

    # @spec VAULT-CRYPTO-001
    def test_type2_wrong_key_is_field_failure(self):
        with pytest.raises(EncStringError):
            decrypt_enc_string(e("secret", USER_KEY), bytes(64))

    # @spec VAULT-CRYPTO-002
    def test_type0_decrypts_with_32_byte_key(self):
        key32 = bytes(range(32))
        assert decrypt_enc_string(enc0(b"legacy", key32), key32) == "legacy"

    # @spec VAULT-CRYPTO-003
    def test_type2_with_32_byte_key_is_field_failure(self):
        with pytest.raises(EncStringError):
            decrypt_enc_string(e("x", USER_KEY), USER_KEY[:32])

    # @spec VAULT-CRYPTO-003
    def test_type0_with_64_byte_key_is_field_failure(self):
        with pytest.raises(EncStringError):
            decrypt_enc_string(enc0(b"x", USER_KEY[:32]), USER_KEY)

    # @spec VAULT-CRYPTO-004
    @pytest.mark.parametrize("etype", [1, 3, 4, 5, 6, 7])
    def test_unimplemented_types_fail_the_cycle(self, etype):
        with pytest.raises(BitwardenError, match=str(etype)):
            decrypt_enc_string(
                f"{etype}.{b64(bytes(16))}|{b64(bytes(32))}|{b64(bytes(32))}", USER_KEY
            )

    # @spec VAULT-CRYPTO-005
    def test_empty_string_is_absent(self):
        assert decrypt_enc_string("", USER_KEY) is None
        assert decrypt_enc_string(None, USER_KEY) is None

    # @spec VAULT-CRYPTO-005
    @pytest.mark.parametrize(
        "value",
        [
            "no-type-prefix|abc|def",
            "2." + b64(bytes(16)) + "|" + b64(bytes(32)),  # missing mac part
            "2.!!!|" + b64(bytes(32)) + "|" + b64(bytes(32)),  # non-base64
            "2."
            + b64(bytes(4))
            + "|"
            + b64(bytes(32))
            + "|"
            + b64(bytes(32)),  # short iv
            "2."
            + b64(bytes(16))
            + "|"
            + b64(bytes(32))
            + "|"
            + b64(bytes(4)),  # short mac
        ],
    )
    def test_malformed_values_are_field_failures(self, value):
        with pytest.raises(EncStringError):
            decrypt_enc_string(value, USER_KEY)

    # @spec VAULT-CRYPTO-005
    def test_non_utf8_plaintext_is_field_failure(self):
        with pytest.raises(EncStringError):
            decrypt_enc_string(enc2(b"\xff\xfe\xfd", USER_KEY), USER_KEY)

    # @spec VAULT-CRYPTO-001
    def test_bytes_variant_returns_raw_bytes(self):
        assert (
            decrypt_enc_string_bytes(enc2(b"\xff\xfe", USER_KEY), USER_KEY)
            == b"\xff\xfe"
        )


# ---------------------------------------------------------------------------
# Dates
# ---------------------------------------------------------------------------


class TestDates:
    # @spec VAULT-EXPORT-011
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("2024-01-02T03:04:05.123456Z", "2024-01-02T03:04:05.123Z"),
            ("2024-01-02T03:04:05.1234567Z", "2024-01-02T03:04:05.123Z"),
            ("2024-01-02T03:04:05Z", "2024-01-02T03:04:05.000Z"),
            ("2024-01-02T03:04:05.5Z", "2024-01-02T03:04:05.500Z"),
            ("2024-01-02T04:04:05.123+01:00", "2024-01-02T03:04:05.123Z"),
            ("2024-01-02T03:04:05.123+00:00", "2024-01-02T03:04:05.123Z"),
        ],
    )
    def test_normalize_to_milliseconds_utc(self, raw, expected):
        assert normalize_date(raw) == expected

    # @spec VAULT-EXPORT-011
    def test_none_passes_through(self):
        assert normalize_date(None) is None


# ---------------------------------------------------------------------------
# Export assembly
# ---------------------------------------------------------------------------

CANONICAL_ITEM_ORDER = [
    "id",
    "organizationId",
    "folderId",
    "type",
    "reprompt",
    "name",
    "notes",
    "favorite",
    "fields",
    "login",
    "secureNote",
    "card",
    "identity",
    "sshKey",
    "passwordHistory",
    "creationDate",
    "revisionDate",
    "deletedDate",
    "archivedDate",
    "collectionIds",
]


def assert_subsequence(keys: list[str], canonical: list[str]) -> None:
    positions = [canonical.index(k) for k in keys]
    assert positions == sorted(positions), f"key order {keys} deviates from CLI order"


class TestBuildExport:
    # @spec VAULT-EXPORT-003
    def test_document_shape(self):
        export, _ = build_export(sync_payload([login_item("i-1", "Example")]), USER_KEY)
        assert list(export.keys()) == ["encrypted", "folders", "items"]
        assert export["encrypted"] is False

    # @spec VAULT-EXPORT-008
    def test_folder_and_item_decrypted_in_cli_order(self):
        export, _ = build_export(
            sync_payload(
                [
                    login_item(
                        "i-1", "Example", folder_id="f-1", notes="n", favorite=True
                    )
                ]
            ),
            USER_KEY,
        )
        assert export["folders"] == [{"id": "f-1", "name": "Work"}]
        item = export["items"][0]
        assert_subsequence(list(item.keys()), CANONICAL_ITEM_ORDER)
        assert item["id"] == "i-1"
        assert item["organizationId"] is None
        assert item["folderId"] == "f-1"
        assert item["type"] == 1
        assert item["reprompt"] == 0
        assert item["name"] == "Example"
        assert item["notes"] == "n"
        assert item["favorite"] is True
        assert item["collectionIds"] is None
        assert "key" not in item

    # @spec VAULT-EXPORT-009
    def test_login_fields_fixed_set_and_order(self):
        export, _ = build_export(
            sync_payload(
                [
                    login_item(
                        "i-1",
                        "Ex",
                        totp="JBSWY3DP",
                        uris=[("https://a", None), ("https://b", 3)],
                    )
                ]
            ),
            USER_KEY,
        )
        login = export["items"][0]["login"]
        assert list(login.keys()) == [
            "uris",
            "username",
            "password",
            "totp",
            "fido2Credentials",
        ]
        assert login["username"] == "alice"
        assert login["password"] == "hunter2"
        assert login["totp"] == "JBSWY3DP"
        assert login["uris"] == [
            {"match": None, "uri": "https://a"},
            {"match": 3, "uri": "https://b"},
        ]

    # @spec VAULT-EXPORT-009
    def test_server_extra_subfields_ignored_and_missing_emitted_null(self):
        item = login_item("i-1", "Ex")
        item["login"]["autofillOnPageLoad"] = True  # server-only field
        del item["login"]["totp"]  # server omitted a known field
        export, _ = build_export(sync_payload([item]), USER_KEY)
        login = export["items"][0]["login"]
        assert "autofillOnPageLoad" not in login
        assert login["totp"] is None

    # @spec VAULT-EXPORT-009
    def test_secure_note_shape(self):
        export, _ = build_export(
            sync_payload([note_item("n-1", "Note", "body")]), USER_KEY
        )
        item = export["items"][0]
        assert item["type"] == 2
        assert item["secureNote"] == {"type": 0}
        assert item["notes"] == "body"
        assert "login" not in item

    # @spec VAULT-EXPORT-009
    def test_fields_and_password_history_decrypted(self):
        item = login_item(
            "i-1",
            "Ex",
            fields=[
                {
                    "name": e("api", USER_KEY),
                    "value": e("k", USER_KEY),
                    "type": 1,
                    "linkedId": None,
                }
            ],
            password_history=[
                {
                    "password": e("old", USER_KEY),
                    "lastUsedDate": "2023-05-06T07:08:09.000000Z",
                }
            ],
        )
        export, _ = build_export(sync_payload([item]), USER_KEY)
        out = export["items"][0]
        assert out["fields"] == [
            {"name": "api", "value": "k", "type": 1, "linkedId": None}
        ]
        assert out["passwordHistory"] == [
            {"password": "old", "lastUsedDate": "2023-05-06T07:08:09.000Z"}
        ]

    # @spec VAULT-EXPORT-011
    def test_item_dates_normalised(self):
        export, _ = build_export(sync_payload([login_item("i-1", "Ex")]), USER_KEY)
        item = export["items"][0]
        assert item["creationDate"] == "2024-01-02T03:04:05.123Z"
        assert item["revisionDate"] == "2024-02-03T04:05:06.654Z"
        assert item["deletedDate"] is None

    # @spec VAULT-EXPORT-006
    def test_org_and_trashed_excluded_archived_included_with_counts(self):
        items = [
            login_item("keep", "Keep"),
            login_item("org", "Org", organization_id="o-1"),
            login_item("trash", "Trash", deleted="2024-03-01T00:00:00.000000Z"),
            login_item("arch", "Arch", archived="2024-03-02T00:00:00.000000Z"),
        ]
        export, stats = build_export(sync_payload(items), USER_KEY)
        ids = [i["id"] for i in export["items"]]
        assert ids == ["keep", "arch"]
        assert stats.org_excluded == 1
        assert stats.trashed_excluded == 1
        archived = export["items"][1]
        assert archived["archivedDate"] == "2024-03-02T00:00:00.000Z"

    # @spec VAULT-EXPORT-007
    def test_attachments_counted(self):
        items = [
            login_item(
                "a",
                "A",
                attachments=[
                    {"id": "x", "fileName": e("f.txt", USER_KEY), "size": "1"}
                ],
            ),
            login_item("b", "B"),
        ]
        _, stats = build_export(sync_payload(items), USER_KEY)
        assert stats.with_attachments == 1

    # @spec VAULT-EXPORT-010
    def test_dangling_folder_id_passes_through(self):
        export, _ = build_export(
            sync_payload([login_item("i-1", "Ex", folder_id="missing")]), USER_KEY
        )
        assert export["items"][0]["folderId"] == "missing"

    # @spec VAULT-CRYPTO-008
    def test_cipher_level_key_decrypts_every_field(self):
        cipher_key = bytes(range(100, 164))
        item = login_item(
            "i-1",
            "Named",
            key=cipher_key,
            notes="noted",
            cipher_key=enc2(cipher_key, USER_KEY),
            fields=[
                {
                    "name": e("f", cipher_key),
                    "value": e("v", cipher_key),
                    "type": 0,
                    "linkedId": None,
                }
            ],
            password_history=[
                {
                    "password": e("ph", cipher_key),
                    "lastUsedDate": "2023-01-01T00:00:00Z",
                }
            ],
        )
        export, stats = build_export(sync_payload([item]), USER_KEY)
        out = export["items"][0]
        assert out["name"] == "Named"
        assert out["notes"] == "noted"
        assert out["login"]["password"] == "hunter2"
        assert out["fields"][0] == {
            "name": "f",
            "value": "v",
            "type": 0,
            "linkedId": None,
        }
        assert out["passwordHistory"][0]["password"] == "ph"
        assert stats.undecryptable_fields == 0

    # @spec VAULT-CRYPTO-007
    def test_cipher_key_unwrap_failure_fails_cycle_naming_item(self):
        item = login_item("i-bad", "X", cipher_key=enc2(bytes(64), bytes(64)))
        with pytest.raises(BitwardenError) as exc:
            build_export(sync_payload([item]), USER_KEY)
        assert "i-bad" in str(exc.value) and "key" in str(exc.value)

    # @spec VAULT-CRYPTO-006
    def test_undecryptable_field_becomes_placeholder_and_cycle_continues(self, caplog):
        item = login_item("i-1", "Ex")
        item["login"]["password"] = e("secret", bytes(64))  # wrong key
        with caplog.at_level("ERROR"):
            export, stats = build_export(sync_payload([item]), USER_KEY)
        out = export["items"][0]
        assert out["login"]["password"] == PLACEHOLDER == "[error: cannot decrypt]"
        assert out["login"]["username"] == "alice"
        assert stats.undecryptable_fields == 1
        assert any(
            "i-1" in r.getMessage() and "password" in r.getMessage()
            for r in caplog.records
        )

    # @spec VAULT-CRYPTO-006
    def test_undecryptable_folder_name_becomes_placeholder(self):
        bad = folder("f-bad", "x", key=bytes(64))
        export, stats = build_export(
            sync_payload([login_item("i-1", "Ex")], folders=[bad]), USER_KEY
        )
        assert export["folders"] == [{"id": "f-bad", "name": PLACEHOLDER}]
        assert stats.undecryptable_fields == 1

    # @spec VAULT-CRYPTO-009
    def test_blob_cipher_with_null_name_fails_cycle(self):
        item = login_item("blob-1", "X")
        item["name"] = None
        item["data"] = "7.AAAA"
        with pytest.raises(BitwardenError, match="blob-1"):
            build_export(sync_payload([item]), USER_KEY)

    # @spec VAULT-CRYPTO-004
    def test_unimplemented_enc_type_in_item_fails_cycle_naming_item_and_type(self):
        item = login_item("i-7", "X")
        item["notes"] = "7." + b64(bytes(40))
        with pytest.raises(BitwardenError) as exc:
            build_export(sync_payload([item]), USER_KEY)
        assert "i-7" in str(exc.value) and "7" in str(exc.value)

    # @spec VAULT-EXPORT-013
    @pytest.mark.parametrize("ctype", [6, 7, 8, 42])
    def test_unknown_item_type_fails_cycle(self, ctype):
        item = login_item("i-t", "X")
        item["type"] = ctype
        with pytest.raises(BitwardenError) as exc:
            build_export(sync_payload([item]), USER_KEY)
        assert "i-t" in str(exc.value) and str(ctype) in str(exc.value)

    # @spec VAULT-EXPORT-005
    @pytest.mark.parametrize(
        "mutate",
        [
            lambda p: p.pop("ciphers"),
            lambda p: p.pop("folders"),
            lambda p: p.update(object="profile"),
            lambda p: p.update(Ciphers=p.pop("ciphers")),
            lambda p: p.update(ciphers=None),
        ],
    )
    def test_payload_without_sync_shape_fails(self, mutate):
        payload = sync_payload([login_item("i-1", "Ex")])
        mutate(payload)
        with pytest.raises(BitwardenError):
            build_export(payload, USER_KEY)

    # @spec VAULT-EXPORT-005
    def test_empty_vault_is_valid(self):
        export, _ = build_export(sync_payload([], folders=[]), USER_KEY)
        assert export == {"encrypted": False, "folders": [], "items": []}

    # @spec VAULT-EXPORT-014
    def test_serialization_utf8_two_space_indent_no_trailing_newline(self):
        export, _ = build_export(
            sync_payload([login_item("i-1", "Ünïcødé ☃")]), USER_KEY
        )
        text = serialize_export(export)
        assert text.startswith('{\n  "encrypted": false,\n  "folders": [')
        assert "Ünïcødé ☃" in text
        assert "\\u" not in text
        assert not text.endswith("\n")
        assert json.loads(text) == export


# ---------------------------------------------------------------------------
# End-to-end over a fake transport
# ---------------------------------------------------------------------------


class TestExportVaultJson:
    # @spec VAULT-SESSION-001
    # @spec VAULT-SESSION-004
    def test_one_token_request_then_one_sync(self):
        http = happy_http()
        export = run_export(http)
        assert [c[0] for c in http.calls] == ["POST", "GET"]
        assert http.calls[0][1] == f"{SERVER}/identity/connect/token"
        assert http.calls[1][1].startswith(f"{SERVER}/api/sync?")
        assert "excludeDomains=true" in http.calls[1][1]
        assert export["items"][0]["name"] == "Example"

    # @spec VAULT-AUTH-001
    def test_token_request_form(self):
        http = happy_http()
        run_export(http)
        _method, _url, headers, body = http.calls[0]
        form = parse_qs(body.decode())
        assert form["grant_type"] == ["client_credentials"]
        assert form["scope"] == ["api"]
        assert form["client_id"] == [CLIENT_ID]
        assert form["client_secret"] == [CLIENT_SECRET]
        assert form["deviceType"] == ["25"]
        assert form["deviceName"] == ["backvault"]
        assert form["deviceIdentifier"] == [device_identifier(CLIENT_ID)]
        assert headers["Content-Type"].startswith("application/x-www-form-urlencoded")

    # @spec VAULT-SESSION-002
    def test_master_password_and_keys_never_sent(self):
        http = happy_http()
        run_export(http)
        for _, _, headers, body in http.calls:
            blob = (body or b"") + json.dumps(headers).encode()
            assert PASSWORD.encode() not in blob
            assert b64(MASTER_KEY).encode() not in blob
            assert b64(USER_KEY).encode() not in blob

    # @spec VAULT-HTTP-002
    def test_client_headers_on_every_request(self):
        http = happy_http()
        run_export(http)
        for _, _, headers, _ in http.calls:
            assert headers["Bitwarden-Client-Name"] == "cli"
            assert headers["Bitwarden-Client-Version"] == REFERENCE_CLI_VERSION

    # @spec VAULT-SESSION-001
    def test_bearer_token_used_for_sync(self):
        http = happy_http()
        run_export(http)
        assert http.calls[1][2]["Authorization"] == f"Bearer {fake_jwt()}"

    # @spec VAULT-AUTH-004
    def test_email_from_salt_is_normalised(self):
        http = happy_http()  # Salt is EMAIL_RAW with spaces and capitals
        assert run_export(http)["items"]

    # @spec VAULT-AUTH-004
    def test_email_falls_back_to_jwt_claim(self):
        http = happy_http(
            UserDecryptionOptions={
                "HasMasterPassword": True,
                "MasterPasswordUnlock": None,
            }
        )
        assert run_export(http)["items"]

    # @spec VAULT-AUTH-004
    def test_email_falls_back_to_profile_endpoint(self):
        http = happy_http(
            access_token=fake_jwt(email=None),
            UserDecryptionOptions={
                "HasMasterPassword": True,
                "MasterPasswordUnlock": None,
            },
        ).on("/accounts/profile", (200, {"email": EMAIL_RAW, "object": "profile"}))
        assert run_export(http)["items"]
        assert http.requests_to("/accounts/profile")

    # @spec VAULT-AUTH-002
    @pytest.mark.parametrize("missing", ["access_token", "Key", "Kdf", "KdfIterations"])
    def test_missing_token_fields_fail_naming_field(self, missing):
        http = happy_http(**{missing: None})
        with pytest.raises(BitwardenError, match=missing):
            run_export(http)
        assert not http.requests_to("/sync")

    # @spec VAULT-AUTH-003
    def test_unsupported_kdf_fails(self):
        http = happy_http(Kdf=5)
        with pytest.raises(BitwardenError, match="KDF"):
            run_export(http)

    # @spec VAULT-AUTH-010
    def test_profile_key_not_used_when_token_key_missing(self):
        http = happy_http(Key=None)
        with pytest.raises(BitwardenError, match="Key"):
            run_export(http)

    # @spec VAULT-AUTH-006
    def test_argon2_account_end_to_end(self):
        from argon2.low_level import Type, hash_secret_raw

        argon_master = hash_secret_raw(
            PASSWORD.encode(),
            hashlib.sha256(EMAIL.encode()).digest(),
            3,
            16 * 1024,
            2,
            32,
            Type.ID,
            version=0x13,
        )
        http = happy_http(
            Kdf=1,
            KdfIterations=3,
            KdfMemory=16,
            KdfParallelism=2,
            Key=enc2(USER_KEY, stretch_for_test(argon_master)),
        )
        assert run_export(http)["items"]

    # @spec VAULT-EXPORT-001
    def test_returns_string_and_writes_nothing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        text = export_vault_json(
            SERVER,
            CLIENT_ID,
            CLIENT_SECRET,
            PASSWORD,
            http=happy_http(),
            sleep=lambda s: None,
        )
        assert isinstance(text, str)
        assert list(tmp_path.iterdir()) == []

    # @spec VAULT-EXPORT-004
    def test_failures_surface_as_bitwarden_error(self):
        http = (
            FakeHttp()
            .on("/connect/token", (200, token_response()))
            .on("/sync", (200, {"object": "nope"}))
        )
        with pytest.raises(BitwardenError):
            run_export(http)

    # @spec VAULT-LOG-002
    def test_secrets_never_logged(self, caplog):
        http = happy_http()
        with caplog.at_level("DEBUG"):
            run_export(http)
        text = caplog.text
        for secret in (
            PASSWORD,
            CLIENT_SECRET,
            fake_jwt(),
            b64(MASTER_KEY),
            b64(STRETCHED),
            b64(USER_KEY),
            "hunter2",
        ):
            assert secret not in text

    # @spec VAULT-LOG-004
    def test_info_summary_logged(self, caplog):
        http = happy_http()
        with caplog.at_level("INFO"):
            run_export(http)
        text = caplog.text
        assert "vault.example.test" in text
        assert "PBKDF2" in text or "kdf" in text.lower()
        assert "1" in text  # item count appears

    # @spec VAULT-EXPORT-007
    def test_attachment_warning_logged(self, caplog):
        item = login_item(
            "a",
            "A",
            attachments=[{"id": "x", "fileName": e("f", USER_KEY), "size": "1"}],
        )
        with caplog.at_level("WARNING"):
            run_export(happy_http([item]))
        assert any(
            r.levelname == "WARNING" and "attachment" in r.getMessage().lower()
            for r in caplog.records
        )

    # @spec VAULT-LOG-005
    def test_undecryptable_total_logged_at_error(self, caplog):
        item = login_item("i-1", "Ex")
        item["login"]["password"] = e("x", bytes(64))
        with caplog.at_level("ERROR"):
            run_export(happy_http([item]))
        assert any(
            r.levelname == "ERROR"
            and "1" in r.getMessage()
            and "decrypt" in r.getMessage().lower()
            for r in caplog.records
        )


class TestHttpAndRetry:
    # @spec VAULT-RETRY-001
    def test_token_5xx_then_success_retries_with_backoff(self):
        http = FakeHttp().on("/connect/token", (503, b"busy"), (200, token_response()))
        http.on("/sync", (200, sync_payload([login_item("i-1", "Ex")])))
        run_export(http)
        assert len(http.requests_to("/connect/token")) == 2
        assert http.sleeps == [2.0]

    # @spec VAULT-RETRY-001
    def test_sync_429_three_failures_then_cycle_fails(self):
        http = FakeHttp().on("/connect/token", (200, token_response()))
        http.on("/sync", (429, b"slow down"), (429, b"slow down"), (429, b"slow down"))
        with pytest.raises(BitwardenError):
            run_export(http)
        assert len(http.requests_to("/sync")) == 3
        assert http.sleeps == [2.0, 4.0]

    # @spec VAULT-RETRY-001
    def test_network_error_retried(self):
        class Flaky(FakeHttp):
            def __init__(self):
                super().__init__()
                self.failures = 1

            def __call__(self, method, url, headers, body):
                if url.endswith("/connect/token") and self.failures:
                    self.failures -= 1
                    self.calls.append((method, url, dict(headers), body))
                    raise OSError("connection reset")
                return super().__call__(method, url, headers, body)

        http = (
            Flaky()
            .on("/connect/token", (200, token_response()))
            .on("/sync", (200, sync_payload([])))
        )
        run_export(http)
        assert len(http.requests_to("/connect/token")) == 2

    # @spec VAULT-RETRY-002
    @pytest.mark.parametrize("status", [400, 401, 403])
    def test_token_rejection_not_retried_and_surfaces_server_message(self, status):
        http = FakeHttp().on(
            "/connect/token",
            (
                status,
                {
                    "error": "invalid_client",
                    "error_description": "Client version too old",
                },
            ),
        )
        with pytest.raises(BitwardenError, match="Client version too old"):
            run_export(http)
        assert len(http.requests_to("/connect/token")) == 1
        assert http.sleeps == []

    # @spec VAULT-RETRY-003
    @pytest.mark.parametrize("status", [401, 403])
    def test_sync_rejection_not_retried_no_new_token(self, status):
        http = (
            FakeHttp()
            .on("/connect/token", (200, token_response()))
            .on("/sync", (status, b"denied"))
        )
        with pytest.raises(BitwardenError):
            run_export(http)
        assert len(http.requests_to("/connect/token")) == 1
        assert len(http.requests_to("/sync")) == 1

    # @spec VAULT-HTTP-003
    def test_404_mentions_server_setting(self):
        http = FakeHttp().on("/connect/token", (404, b"not found"))
        with pytest.raises(BitwardenError, match="BW_SERVER"):
            run_export(http)

    # @spec VAULT-HTTP-004
    def test_redirect_not_followed_and_named(self):
        http = FakeHttp().on_redirect(
            "/connect/token", "https://elsewhere.test/identity/connect/token"
        )
        with pytest.raises(BitwardenError, match="elsewhere.test"):
            run_export(http)
        assert len(http.calls) == 1

    # @spec VAULT-HTTP-005
    def test_non_json_body_fails(self):
        http = FakeHttp().on("/connect/token", (200, b"<html>proxy</html>"))
        with pytest.raises(BitwardenError):
            run_export(http)

    # @spec VAULT-LOG-003
    def test_http_failure_logged_with_status_and_body(self, caplog):
        http = FakeHttp().on(
            "/connect/token", (400, {"error_description": "Bad client"})
        )
        with caplog.at_level("ERROR"), pytest.raises(BitwardenError):
            run_export(http)
        errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
        assert any("400" in m and "Bad client" in m for m in errors)

    # @spec VAULT-HTTP-001
    def test_default_transport_verifies_tls_and_trusts_extra_bundle(self, tmp_path):
        from vault_client import _build_ssl_context

        ctx = _build_ssl_context(None)
        import ssl

        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "backvault-test-ca")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(dt.datetime(2024, 1, 1, tzinfo=dt.UTC))
            .not_valid_after(dt.datetime(2034, 1, 1, tzinfo=dt.UTC))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(key, hashes.SHA256())
        )
        bundle = tmp_path / "ca.pem"
        bundle.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        default_count = len(ctx.get_ca_certs())
        ctx2 = _build_ssl_context(str(bundle))
        assert ctx2.verify_mode == ssl.CERT_REQUIRED
        subjects = [dict(x[0] for x in c["subject"]) for c in ctx2.get_ca_certs()]
        assert any(s.get("commonName") == "backvault-test-ca" for s in subjects)
        assert len(ctx2.get_ca_certs()) >= default_count + 1

    # @spec VAULT-SESSION-003
    def test_key_material_cleared_after_export(self):
        from vault_client import VaultSession

        session = VaultSession(
            SERVER,
            CLIENT_ID,
            CLIENT_SECRET,
            PASSWORD,
            http=happy_http(),
            sleep=lambda s: None,
        )
        session.export()
        for attr in ("access_token", "master_key", "stretched_key", "user_key"):
            value = getattr(session, attr)
            assert value is None or (
                isinstance(value, (bytes, bytearray)) and not any(value)
            ), attr


# ---------------------------------------------------------------------------
# Spec hygiene
# ---------------------------------------------------------------------------


def test_every_spec_cited_here_exists():
    specs_file = (
        Path(__file__).parent.parent / "docs/intent/vault-access/vault-access-specs.md"
    )
    defined = set(re.findall(r"\*\*(VAULT-[A-Z]+-\d{3})\*\*", specs_file.read_text()))
    cited = set(re.findall(r"@spec (VAULT-[A-Z]+-\d{3})", Path(__file__).read_text()))
    assert cited <= defined, cited - defined
