"""Vault client backed by the rbw CLI (replaces the Bitwarden CLI)."""

import json
import logging
import os
import re
import subprocess
import time
from functools import wraps
from pathlib import Path
from sys import stdout
from typing import Any, Callable

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Encryption constants
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256

# Argon2id parameters (current — version 2)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB in KiB
ARGON2_PARALLELISM = 4

ENCRYPTION_VERSION = 2  # File format version

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(stdout)],
)

logger = logging.getLogger(__name__)


class BitwardenError(Exception):
    """Base exception for the vault client wrapper."""


def retry_with_backoff(
    max_attempts: int = 3, base_delay: float = 2.0, max_delay: float = 30.0
):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except BitwardenError as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts"
                        )
                        raise
                    delay = min(base_delay * (2**attempt), max_delay)
                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1}/{max_attempts} failed: {e}. "
                        f"Retrying in {delay:.1f} seconds..."
                    )
                    time.sleep(delay)
            raise last_exception

        return wrapper

    return decorator


class BitwardenClient:
    """Wraps the rbw CLI for vault sync + export."""

    def __init__(
        self,
        bw_cmd: str = "/usr/bin/rbw",
        session: str | None = None,
        server: str | None = None,
        email: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_api_key: bool = True,
        pinentry: str = "/app/pinentry.py",
        config_dir: str = "/app/.config/rbw",
    ):
        """
        :param bw_cmd: Path to the rbw binary
        :param server: Vault server URL (Vaultwarden compatible)
        :param email: Vault account email (required by rbw config)
        :param client_id: Personal API key client_id (for `rbw register`)
        :param client_secret: Personal API key client_secret (for `rbw register`)
        :param use_api_key: Reserved for parity; rbw always uses API-key register here
        :param pinentry: Path to the pinentry binary that returns the master password
        :param config_dir: Path where rbw config.json lives
        """
        self.bw_cmd = bw_cmd
        self.session = session  # Retained for interface parity; rbw manages its own session
        self.server = server
        self.email = email
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_api_key = (
            use_api_key and client_id is not None and client_secret is not None
        )
        self.pinentry = pinentry
        self.config_dir = Path(config_dir)

        if not self.email:
            raise BitwardenError("BW_EMAIL is required for the rbw-backed client")
        if not self.server:
            raise BitwardenError("BW_SERVER is required for the rbw-backed client")

        self._write_config()

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    # -------------------------------
    # Config management
    # -------------------------------
    def _write_config(self) -> None:
        """Write rbw's config.json from constructor inputs."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        config_path = self.config_dir / "config.json"
        config = {
            "email": self.email,
            "base_url": self.server,
            "identity_url": None,
            "ui_url": None,
            "notifications_url": None,
            "client_cert_path": None,
            "lock_timeout": 3600,
            "sync_interval": 3600,
            "pinentry": self.pinentry,
            "device_id": None,
        }
        config_path.write_text(json.dumps(config, indent=2))
        logger.info(f"Wrote rbw config to {config_path}")

    def _env(self, include_api_key: bool = False) -> dict[str, str]:
        env = os.environ.copy()
        # rbw reads XDG_CONFIG_HOME for config.json
        env.setdefault("XDG_CONFIG_HOME", str(self.config_dir.parent))
        if include_api_key:
            if self.client_id:
                env["BW_CLIENTID"] = self.client_id
            if self.client_secret:
                env["BW_CLIENTSECRET"] = self.client_secret
        return env

    def _run(
        self,
        cmd: list[str],
        capture_json: bool = False,
        include_api_key: bool = False,
        check: bool = True,
    ) -> Any:
        full_cmd = [self.bw_cmd] + cmd
        logger.info(f"Running command: {' '.join(full_cmd)}")
        try:
            result = subprocess.run(
                full_cmd,
                text=True,
                capture_output=True,
                check=check,
                env=self._env(include_api_key=include_api_key),
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"rbw command failed with exit code {e.returncode}")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")
            logger.error(f"Command: {' '.join(full_cmd)}")
            raise BitwardenError("rbw command failed") from e

        output = result.stdout.strip()
        if capture_json:
            try:
                return json.loads(output)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON output from rbw")
                raise BitwardenError("Failed to parse JSON output") from e
        return output

    # -------------------------------
    # Core API methods
    # -------------------------------
    @retry_with_backoff(max_attempts=3, base_delay=2.0)
    def login(
        self, email: str | None = None, password: str | None = None, raw: bool = True
    ) -> str | None:
        """Register the device with the server using the personal API key.

        rbw's `register` is idempotent — if already registered, it returns quickly.
        After register, no separate `login` step is required.
        """
        logger.info("Registering device with vault server via API key")
        # rbw register <email> <base_url>
        self._run(
            ["register", self.email, self.server],
            include_api_key=True,
        )
        logger.info("Device registered (or already registered)")
        return None

    @retry_with_backoff(max_attempts=3, base_delay=2.0)
    def unlock(self, password: str) -> str | None:
        """Unlock the vault. Password is sourced via pinentry (BW_PASSWORD env).

        The `password` arg is accepted for interface parity but ignored — rbw
        always reads from pinentry. Callers must set BW_PASSWORD in the env
        that this process runs under.
        """
        if not os.environ.get("BW_PASSWORD"):
            raise BitwardenError("BW_PASSWORD must be set in env for rbw unlock")
        logger.info("Unlocking vault via rbw")
        self._run(["unlock"])
        logger.info("Vault unlocked successfully")
        return None

    def logout(self) -> None:
        """Lock the vault and stop the rbw agent."""
        try:
            self._run(["lock"], check=False)
        except BitwardenError:
            pass
        try:
            self._run(["stop-agent"], check=False)
        except BitwardenError:
            pass
        logger.info("Locked vault and stopped rbw agent")

    def status(self) -> dict[str, Any]:
        """Return a minimal status dict (rbw doesn't expose a structured status)."""
        return {"backend": "rbw"}

    # -------------------------------
    # Encryption
    # -------------------------------
    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encrypt data with AES-256-GCM keyed off Argon2id(password, salt).

        Layout: version(4) || salt(16) || nonce(12) || ciphertext || tag(16)
        """
        logger.info("Encrypting data in-memory...")
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

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        logger.info(f"Encryption successful (Version {ENCRYPTION_VERSION}, Argon2id).")
        return version + salt + nonce + ciphertext

    # -------------------------------
    # Path validation
    # -------------------------------
    def _validate_backup_path(
        self, backup_file: str, allowed_base: str = "/app/backups"
    ) -> str:
        backup_path = Path(backup_file).resolve()
        allowed_path = Path(allowed_base).resolve()

        try:
            backup_path.relative_to(allowed_path)
        except ValueError:
            logger.error(
                f"Invalid backup path: {backup_file} is outside allowed directory {allowed_base}"
            )
            raise BitwardenError(f"Invalid backup path: must be within {allowed_base}")

        filename = backup_path.name
        if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
            logger.error(
                f"Invalid backup filename: {filename} contains unsafe characters"
            )
            raise BitwardenError(
                "Invalid backup filename: only alphanumeric, dots, dashes, and underscores allowed"
            )

        if not filename.endswith(".enc"):
            logger.error(f"Invalid backup filename: {filename} must end with .enc")
            raise BitwardenError("Invalid backup filename: must end with .enc")

        return str(backup_path)

    # -------------------------------
    # Export
    # -------------------------------
    def export_raw_encrypted(
        self, backup_file: str, file_pw: str, allowed_dir: str = "/app/backups"
    ):
        """Sync vault, export to JSON, then encrypt with Argon2id + AES-GCM."""
        validated_path = self._validate_backup_path(backup_file, allowed_dir)

        logger.info("Syncing vault from server...")
        self._run(["sync"])

        logger.info("Exporting raw vault JSON from rbw...")
        raw_json_str = self._run(["export"])
        if not raw_json_str:
            raise BitwardenError("rbw export returned no data")

        encrypted_data = self.encrypt_data(raw_json_str.encode("utf-8"), file_pw)
        with open(validated_path, "wb") as f:
            f.write(encrypted_data)
        logger.info(f"Wrote encrypted backup to {validated_path}")

    def export_bitwarden_encrypted(
        self, backup_file: str, file_pw: str, allowed_dir: str = "/app/backups"
    ):
        """Bitwarden-format encrypted export — not supported on the rbw backend."""
        raise BitwardenError(
            "BACKUP_ENCRYPTION_MODE='bitwarden' is no longer supported. "
            "Switch to 'raw' (Argon2id + AES-256-GCM). "
            "Existing 'bitwarden'-mode backups remain restorable via the Bitwarden web vault; "
            "new backups will use the stronger raw mode."
        )
