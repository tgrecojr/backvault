"""Bitwarden account cryptography: master key, key stretching, EncString decryption.

Reference: bitwarden/sdk-internal crates/bitwarden-crypto. Only the primitives a
read-only export needs are implemented; anything else is reported as a gap.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

KDF_PBKDF2 = 0
KDF_ARGON2ID = 1

ENC_TYPE_AES_CBC_256 = 0  # legacy, unauthenticated, read-only
ENC_TYPE_AES_CBC_256_HMAC = 2  # current symmetric format

AES_KEY_LEN = 32
AES_HMAC_KEY_LEN = 64
IV_LEN = 16
MAC_LEN = 32


class BitwardenError(Exception):
    """A failure that ends the backup cycle."""


class EncStringError(Exception):
    """A single value could not be decrypted; the caller decides whether that is fatal."""


# @spec VAULT-AUTH-003, VAULT-AUTH-005, VAULT-AUTH-006, VAULT-AUTH-007
def derive_master_key(
    password: str,
    email: str,
    kdf: int,
    iterations: int,
    memory: int | None = None,
    parallelism: int | None = None,
) -> bytes:
    """Derive the 32-byte master key. ``email`` must already be trimmed and lower-cased."""
    secret = password.encode("utf-8")
    salt = email.encode("utf-8")
    if kdf == KDF_PBKDF2:
        return hashlib.pbkdf2_hmac("sha256", secret, salt, int(iterations), AES_KEY_LEN)
    if kdf == KDF_ARGON2ID:
        if memory is None or parallelism is None:
            raise BitwardenError("Argon2id KDF requires KdfMemory and KdfParallelism")
        return hash_secret_raw(
            secret=secret,
            salt=hashlib.sha256(salt).digest(),
            time_cost=int(iterations),
            memory_cost=int(memory) * 1024,
            parallelism=int(parallelism),
            hash_len=AES_KEY_LEN,
            type=Type.ID,
            version=0x13,
        )
    raise BitwardenError(f"unsupported KDF type {kdf}")


# @spec VAULT-AUTH-008
def stretch_key(master_key: bytes) -> bytes:
    """HKDF-Expand the master key into enc (info 'enc') || mac (info 'mac'), 64 bytes."""
    enc = HKDFExpand(algorithm=hashes.SHA256(), length=AES_KEY_LEN, info=b"enc").derive(
        master_key
    )
    mac = HKDFExpand(algorithm=hashes.SHA256(), length=AES_KEY_LEN, info=b"mac").derive(
        master_key
    )
    return enc + mac


def _b64(part: str) -> bytes:
    try:
        return base64.b64decode(part, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EncStringError("part is not valid base64") from exc


def parse_enc_string(value: str) -> tuple[int, list[bytes]]:
    """Split ``<type>.<b64>|<b64>...`` into (type, parts). Malformed -> EncStringError."""
    if not isinstance(value, str) or "." not in value:
        raise EncStringError("missing encryption type prefix")
    prefix, _, rest = value.partition(".")
    if not prefix.isdigit():
        raise EncStringError("encryption type prefix is not numeric")
    etype = int(prefix)
    if etype not in (ENC_TYPE_AES_CBC_256, ENC_TYPE_AES_CBC_256_HMAC):
        # @spec VAULT-CRYPTO-004
        raise BitwardenError(f"EncString type {etype} is not implemented")
    parts = [_b64(p) for p in rest.split("|")]
    expected = 2 if etype == ENC_TYPE_AES_CBC_256 else 3
    if len(parts) != expected:
        raise EncStringError(f"type {etype} expects {expected} parts, got {len(parts)}")
    if len(parts[0]) != IV_LEN:
        raise EncStringError("IV is not 16 bytes")
    if etype == ENC_TYPE_AES_CBC_256_HMAC and len(parts[2]) != MAC_LEN:
        raise EncStringError("MAC is not 32 bytes")
    return etype, parts


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise EncStringError("bad padding or ciphertext length") from exc


# @spec VAULT-CRYPTO-001, VAULT-CRYPTO-002, VAULT-CRYPTO-003, VAULT-CRYPTO-005
def decrypt_enc_string_bytes(value: str, key: bytes) -> bytes:
    """Decrypt an EncString to raw bytes with a 32-byte (type 0) or 64-byte (type 2) key."""
    etype, parts = parse_enc_string(value)
    if etype == ENC_TYPE_AES_CBC_256_HMAC:
        if len(key) != AES_HMAC_KEY_LEN:
            raise EncStringError("type 2 EncString requires a 64-byte key")
        iv, ciphertext, mac = parts
        expected = hmac.new(key[AES_KEY_LEN:], iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, mac):
            raise EncStringError("MAC mismatch")
        return _aes_cbc_decrypt(key[:AES_KEY_LEN], iv, ciphertext)
    if len(key) != AES_KEY_LEN:
        raise EncStringError("type 0 EncString requires a 32-byte key")
    iv, ciphertext = parts
    return _aes_cbc_decrypt(key, iv, ciphertext)


def decrypt_enc_string(value: str | None, key: bytes) -> str | None:
    """Decrypt an EncString to text. Empty or missing input is absent (None)."""
    if value is None or value == "":
        return None
    try:
        return decrypt_enc_string_bytes(value, key).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EncStringError("plaintext is not UTF-8") from exc


# @spec VAULT-AUTH-009, VAULT-CRYPTO-007
def unwrap_user_key(key_value: str, master_key: bytes) -> bytes:
    """Unwrap the account's user key from the token response ``Key`` field."""
    try:
        etype, _ = parse_enc_string(key_value)
        wrapping = (
            stretch_key(master_key)
            if etype == ENC_TYPE_AES_CBC_256_HMAC
            else master_key
        )
        user_key = decrypt_enc_string_bytes(key_value, wrapping)
    except EncStringError as exc:
        raise BitwardenError(
            f"could not decrypt the user key (field Key): {exc}"
        ) from exc
    expected = AES_HMAC_KEY_LEN if etype == ENC_TYPE_AES_CBC_256_HMAC else AES_KEY_LEN
    if len(user_key) != expected:
        raise BitwardenError(
            f"user key has unexpected length {len(user_key)} (expected {expected})"
        )
    return user_key
