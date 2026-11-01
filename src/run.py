"""One backup cycle (backup-cycle segment): validate config, export, encrypt, write."""

from __future__ import annotations

import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import vault_client
from backup_crypto import encrypt_data

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

ALLOWED_BASE = "/app"
DEFAULT_BACKUP_DIR = "/app/backups"
REQUIRED_VARS = (
    "BW_CLIENT_ID",
    "BW_CLIENT_SECRET",
    "BW_PASSWORD",
    "BW_SERVER",
    "BW_FILE_PASSWORD",
)
FILENAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


# @spec CYCLE-CONFIG-001
def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


# @spec CYCLE-CONFIG-002, CYCLE-CONFIG-003
def validate_backup_dir(backup_dir: str) -> str:
    """Resolve BACKUP_DIR and require it to sit under ALLOWED_BASE."""
    backup_path = Path(backup_dir).resolve()
    try:
        backup_path.relative_to(Path(ALLOWED_BASE).resolve())
    except ValueError:
        logger.critical(
            f"BACKUP_DIR '{backup_dir}' is outside allowed path '{ALLOWED_BASE}'"
        )
        sys.exit(1)
    return str(backup_path)


# @spec CYCLE-CONFIG-004, CYCLE-CONFIG-005
def validate_encryption_mode() -> None:
    raw = os.getenv("BACKUP_ENCRYPTION_MODE")
    if raw is None or raw.strip().lower() == "raw":
        return
    logger.critical(
        f"BACKUP_ENCRYPTION_MODE='{raw}' is not supported: only raw mode exists (portable "
        "AES-256-GCM, restored with decrypt.py and the backup file password). Unset the variable."
    )
    sys.exit(1)


# @spec CYCLE-CONFIG-008, CYCLE-CONFIG-009
def validate_ca_cert() -> str | None:
    if os.getenv("NODE_TLS_REJECT_UNAUTHORIZED") is not None:
        logger.warning(
            "NODE_TLS_REJECT_UNAUTHORIZED has no effect; set BW_CA_CERT to a PEM bundle to trust a self-signed server"
        )
    ca_cert = os.getenv("BW_CA_CERT")
    if not ca_cert:
        return None
    if not os.path.isfile(ca_cert) or not os.access(ca_cert, os.R_OK):
        logger.critical(f"BW_CA_CERT '{ca_cert}' does not exist or is not readable")
        sys.exit(1)
    return ca_cert


# @spec CYCLE-FILE-002
def validate_backup_path(backup_file: str, allowed_dir: str) -> str:
    """Require the file to sit inside allowed_dir with a safe name ending in .enc."""
    backup_path = Path(backup_file).resolve()
    try:
        backup_path.relative_to(Path(allowed_dir).resolve())
    except ValueError:
        raise ValueError(f"Invalid backup path: must be within {allowed_dir}") from None
    if not FILENAME_RE.match(backup_path.name):
        raise ValueError(
            "Invalid backup filename: only alphanumeric, dots, dashes, and underscores allowed"
        )
    if not backup_path.name.endswith(".enc"):
        raise ValueError("Invalid backup filename: must end with .enc")
    return str(backup_path)


def _configure_log_file() -> None:
    log_file = os.getenv("LOG_FILE")  # @spec CYCLE-CONFIG-006
    if log_file and not any(
        isinstance(h, logging.FileHandler)
        and h.baseFilename == os.path.abspath(log_file)
        for h in logger.handlers
    ):
        logger.addHandler(logging.FileHandler(log_file))


# @spec CYCLE-FLOW-001, CYCLE-FLOW-003, CYCLE-FLOW-004, CYCLE-FILE-001, CYCLE-CONFIG-007
def main() -> None:
    client_id = require_env("BW_CLIENT_ID")
    client_secret = require_env("BW_CLIENT_SECRET")
    master_pw = require_env("BW_PASSWORD")
    server = require_env("BW_SERVER")
    file_pw = require_env("BW_FILE_PASSWORD")

    backup_dir = validate_backup_dir(os.getenv("BACKUP_DIR", DEFAULT_BACKUP_DIR))
    validate_encryption_mode()
    ca_cert = validate_ca_cert()
    _configure_log_file()
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)

    logger.info("Connecting to vault...")
    try:
        export_json = vault_client.export_vault_json(
            server=server,
            client_id=client_id,
            client_secret=client_secret,
            master_password=master_pw,
            ca_cert=ca_cert,
        )
    except Exception as e:
        logger.error(f"Export failed: {e}")
        sys.exit(1)

    # `.astimezone()` attaches the local zone without shifting the clock.
    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    backup_file = validate_backup_path(
        os.path.join(backup_dir, f"backup_{timestamp}.enc"), backup_dir
    )
    encrypted = encrypt_data(export_json.encode("utf-8"), file_pw)
    with open(backup_file, "wb") as f:
        f.write(encrypted)
    logger.info("Export completed successfully.")


if __name__ == "__main__":
    main()
