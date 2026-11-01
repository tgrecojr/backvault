"""Raw-mode backup file format: password-derived AES-256-GCM (backup-encryption segment).

File layout (version 2):
    version (4 bytes, big-endian) | salt (16) | nonce (12) | AES-256-GCM ciphertext + tag (16)
Key derivation: Argon2id, time cost 3, memory 64 MiB, parallelism 4, 32-byte output.
Version 1 (PBKDF2-HMAC-SHA256, 600,000 iterations) is read by decrypt.py but never written.
"""

from __future__ import annotations

import logging
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256

# Version 1 parameters (legacy, decrypt-only). Kept here so the parity tests
# can assert the service and the restore tool agree.
PBKDF2_ITERATIONS = 600000

# Version 2 parameters (current).
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # KiB (64 MiB)
ARGON2_PARALLELISM = 4

ENCRYPTION_VERSION = 2

logger = logging.getLogger(__name__)


# @spec ENC-FORMAT-001, ENC-FORMAT-002, ENC-FORMAT-003, ENC-FORMAT-004, ENC-FORMAT-005
def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypt ``data`` with a key derived from ``password``; returns the full file bytes."""
    version = ENCRYPTION_VERSION.to_bytes(4, byteorder="big")
    salt = os.urandom(SALT_SIZE)
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    logger.info(
        "Encrypted backup (format version %d, Argon2id + AES-256-GCM)",
        ENCRYPTION_VERSION,
    )
    return version + salt + nonce + ciphertext
