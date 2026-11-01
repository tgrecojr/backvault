"""Tests for the raw-mode backup file format (backup-encryption segment)."""

import os
import re
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import backup_crypto
import decrypt
from backup_crypto import encrypt_data
from decrypt import decrypt_data


class TestEncryptionConstants:
    """Production encryptor and restore tool must agree on every parameter."""

    # @spec ENC-DECRYPT-006
    def test_argon2_parameters_match(self):
        assert backup_crypto.ARGON2_TIME_COST == decrypt.ARGON2_TIME_COST == 3
        assert backup_crypto.ARGON2_MEMORY_COST == decrypt.ARGON2_MEMORY_COST == 65536
        assert backup_crypto.ARGON2_PARALLELISM == decrypt.ARGON2_PARALLELISM == 4

    # @spec ENC-DECRYPT-002
    def test_pbkdf2_iterations_match(self):
        assert backup_crypto.PBKDF2_ITERATIONS == decrypt.PBKDF2_ITERATIONS == 600000

    # @spec ENC-FORMAT-001
    def test_sizes_match(self):
        assert backup_crypto.SALT_SIZE == decrypt.SALT_SIZE == 16
        assert backup_crypto.KEY_SIZE == decrypt.KEY_SIZE == 32

    # @spec ENC-FORMAT-002
    def test_encryption_version(self):
        assert backup_crypto.ENCRYPTION_VERSION == 2


class TestArgon2Encryption:
    """Version 2 (Argon2id) encryption and decryption."""

    # @spec ENC-FORMAT-003
    # @spec ENC-DECRYPT-003
    def test_encrypt_decrypt_roundtrip(self, test_data, test_password):
        assert (
            decrypt_data(encrypt_data(test_data, test_password), test_password)
            == test_data
        )

    # @spec ENC-FORMAT-002
    def test_version_header(self, test_data, test_password):
        encrypted = encrypt_data(test_data, test_password)
        assert int.from_bytes(encrypted[:4], byteorder="big") == 2

    # @spec ENC-FORMAT-001
    def test_encrypted_data_structure(self, test_data, test_password):
        encrypted = encrypt_data(test_data, test_password)
        # version (4) + salt (16) + nonce (12) + data + tag (16)
        assert len(encrypted) == 4 + 16 + 12 + len(test_data) + 16

    # @spec ENC-FORMAT-005
    def test_layout_decrypts_with_plain_aesgcm_and_argon2id(
        self, test_data, test_password
    ):
        from argon2.low_level import Type, hash_secret_raw

        encrypted = encrypt_data(test_data, test_password)
        salt, nonce, ct = encrypted[4:20], encrypted[20:32], encrypted[32:]
        key = hash_secret_raw(test_password.encode(), salt, 3, 65536, 4, 32, Type.ID)
        assert AESGCM(key).decrypt(nonce, ct, None) == test_data

    # @spec ENC-DECRYPT-005
    def test_wrong_password_fails(self, test_data, test_password):
        with pytest.raises(InvalidTag):
            decrypt_data(encrypt_data(test_data, test_password), "WrongPassword123!")

    # @spec ENC-FORMAT-004
    def test_different_password_different_output(self, test_data):
        assert encrypt_data(test_data, "Password1") != encrypt_data(
            test_data, "Password2"
        )

    # @spec ENC-FORMAT-004
    def test_same_password_different_output(self, test_data, test_password):
        e1 = encrypt_data(test_data, test_password)
        e2 = encrypt_data(test_data, test_password)
        assert e1 != e2
        assert (
            decrypt_data(e1, test_password)
            == decrypt_data(e2, test_password)
            == test_data
        )

    # @spec ENC-FORMAT-003
    def test_empty_data(self, test_password):
        assert decrypt_data(encrypt_data(b"", test_password), test_password) == b""

    # @spec ENC-FORMAT-003
    def test_large_data(self, test_password):
        large = b"x" * (1024 * 1024)
        assert decrypt_data(encrypt_data(large, test_password), test_password) == large


class TestBackwardCompatibility:
    """Version 1 (PBKDF2) files stay readable."""

    # @spec ENC-DECRYPT-002
    def test_version_1_encrypt_decrypt(self, test_data, test_password):
        encrypted_v1 = self._encrypt_data_v1(test_data, test_password)
        assert int.from_bytes(encrypted_v1[:4], byteorder="big") == 1
        assert decrypt_data(encrypted_v1, test_password) == test_data

    # @spec ENC-DECRYPT-005
    def test_version_1_wrong_password(self, test_data, test_password):
        with pytest.raises(InvalidTag):
            decrypt_data(
                self._encrypt_data_v1(test_data, test_password), "WrongPassword"
            )

    @staticmethod
    def _encrypt_data_v1(data: bytes, password: str) -> bytes:
        version = (1).to_bytes(4, byteorder="big")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000
        )
        key = kdf.derive(password.encode("utf-8"))
        nonce = os.urandom(12)
        return version + salt + nonce + AESGCM(key).encrypt(nonce, data, None)


class TestErrorHandling:
    # @spec ENC-DECRYPT-004
    def test_invalid_version_number(self, test_data, test_password):
        corrupted = (999).to_bytes(4, byteorder="big") + encrypt_data(
            test_data, test_password
        )[4:]
        with pytest.raises(ValueError, match="Unsupported encryption version"):
            decrypt_data(corrupted, test_password)

    # @spec ENC-DECRYPT-004
    def test_version_zero(self, test_data, test_password):
        corrupted = (0).to_bytes(4, byteorder="big") + encrypt_data(
            test_data, test_password
        )[4:]
        with pytest.raises(ValueError, match="Unsupported encryption version"):
            decrypt_data(corrupted, test_password)

    # @spec ENC-DECRYPT-001
    def test_data_too_short_no_version(self):
        with pytest.raises(Exception):  # noqa: B017
            decrypt_data(b"abc", "password")

    def test_data_too_short_no_salt(self, test_password):
        with pytest.raises(Exception):  # noqa: B017
            decrypt_data((2).to_bytes(4, byteorder="big"), test_password)

    def test_data_too_short_no_nonce(self, test_password):
        with pytest.raises(Exception):  # noqa: B017
            decrypt_data(
                (2).to_bytes(4, byteorder="big") + os.urandom(8), test_password
            )

    # @spec ENC-DECRYPT-005
    def test_corrupted_ciphertext(self, test_data, test_password):
        corrupted = bytearray(encrypt_data(test_data, test_password))
        corrupted[-10] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_data(bytes(corrupted), test_password)

    # @spec ENC-DECRYPT-005
    def test_corrupted_salt(self, test_data, test_password):
        corrupted = bytearray(encrypt_data(test_data, test_password))
        corrupted[5] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_data(bytes(corrupted), test_password)

    # @spec ENC-DECRYPT-005
    def test_corrupted_nonce(self, test_data, test_password):
        corrupted = bytearray(encrypt_data(test_data, test_password))
        corrupted[20] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_data(bytes(corrupted), test_password)

    def test_empty_password(self, test_data):
        encrypted = encrypt_data(test_data, "")
        assert decrypt_data(encrypted, "") == test_data
        with pytest.raises(InvalidTag):
            decrypt_data(encrypted, "not-empty")

    def test_very_long_password(self, test_data):
        pw = "a" * 10000
        assert decrypt_data(encrypt_data(test_data, pw), pw) == test_data

    def test_password_with_null_bytes(self, test_data):
        pw = "pass\x00word\x00test"
        assert decrypt_data(encrypt_data(test_data, pw), pw) == test_data


class TestSecurityProperties:
    # @spec ENC-FORMAT-004
    def test_salt_is_random(self, test_data, test_password):
        assert (
            encrypt_data(test_data, test_password)[4:20]
            != encrypt_data(test_data, test_password)[4:20]
        )

    # @spec ENC-FORMAT-004
    def test_nonce_is_random(self, test_data, test_password):
        assert (
            encrypt_data(test_data, test_password)[20:32]
            != encrypt_data(test_data, test_password)[20:32]
        )

    def test_unicode_password(self, test_data):
        pw = "Pāšş🔐wørd"
        assert decrypt_data(encrypt_data(test_data, pw), pw) == test_data

    def test_special_characters_in_data(self, test_password):
        data = b"\x00\x01\xff\xfe Special chars: \xe2\x9c\x93\xe2\x9c\x97"
        assert decrypt_data(encrypt_data(data, test_password), test_password) == data


class TestRestoreTool:
    # @spec ENC-TOOL-003
    def test_decrypt_module_imports_only_stdlib_and_two_libraries(self):
        source = (Path(__file__).parent.parent / "src" / "decrypt.py").read_text()
        modules = set(
            re.findall(r"^(?:from|import)\s+([a-zA-Z_][\w]*)", source, re.MULTILINE)
        )
        allowed_third_party = {"cryptography", "argon2"}
        stdlib = set(sys.stdlib_module_names)
        assert modules <= stdlib | allowed_third_party, (
            modules - stdlib - allowed_third_party
        )


def test_every_spec_cited_here_exists():
    specs_file = (
        Path(__file__).parent.parent
        / "docs/intent/backup-encryption/backup-encryption-specs.md"
    )
    defined = set(re.findall(r"\*\*(ENC-[A-Z]+-\d{3})\*\*", specs_file.read_text()))
    cited = set(re.findall(r"@spec (ENC-[A-Z]+-\d{3})", Path(__file__).read_text()))
    assert cited <= defined, cited - defined
