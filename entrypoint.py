"""BackVault entrypoint — supervises periodic backup + daily cleanup.

Replaces entrypoint.sh and cleanup.sh so the runtime image can be shell-free.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from datetime import date
from pathlib import Path

# src/ is copied flat into /app/, so run.main lives at /app/run.py
sys.path.insert(0, "/app")
from run import main as run_backup_main  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("entrypoint")

_shutdown = False


def _handle_signal(signum: int, _frame: object) -> None:
    global _shutdown
    log.info(f"Received signal {signum}, shutting down gracefully...")
    _shutdown = True


def _interval_hours() -> int:
    raw = os.getenv("BACKUP_INTERVAL_HOURS", "12")
    try:
        value = int(raw)
    except ValueError:
        log.error(f"BACKUP_INTERVAL_HOURS must be a positive integer (got {raw!r})")
        sys.exit(1)
    if value < 1 or value > 8760:
        log.error("BACKUP_INTERVAL_HOURS must be between 1 and 8760 (1 year)")
        sys.exit(1)
    return value


def _retain_days() -> int | None:
    raw = os.getenv("RETAIN_DAYS", "7")
    if not raw.isdigit() or int(raw) == 0:
        log.info(f"RETAIN_DAYS={raw!r}, skipping cleanup")
        return None
    value = int(raw)
    if value > 3650:
        log.error("RETAIN_DAYS must be between 1 and 3650 (10 years), skipping cleanup")
        return None
    return value


def run_backup() -> None:
    log.info("Starting backup...")
    try:
        run_backup_main()
        log.info("Backup completed successfully")
    except SystemExit as exc:
        # run.main() calls sys.exit on failure; don't let it kill the supervisor
        if exc.code in (0, None):
            log.info("Backup completed successfully")
        else:
            log.error(f"Backup failed with exit code {exc.code}")
    except Exception as exc:
        log.exception(f"Backup raised an unexpected exception: {exc}")


def run_cleanup() -> None:
    retain = _retain_days()
    if retain is None:
        return
    backup_dir = Path(os.getenv("BACKUP_DIR", "/app/backups"))
    if not backup_dir.is_dir():
        log.warning(f"Backup dir {backup_dir} does not exist, skipping cleanup")
        return

    log.info(f"Cleaning *.enc backups older than {retain} days in {backup_dir}")
    cutoff = time.time() - retain * 86400
    removed = 0
    for path in backup_dir.iterdir():
        if (
            path.is_file()
            and not path.is_symlink()
            and path.suffix == ".enc"
            and path.stat().st_mtime < cutoff
        ):
            log.info(f"Removing {path.name}")
            path.unlink()
            removed += 1
    log.info(f"Cleanup finished, removed {removed} file(s)")


def _sleep_interruptible(seconds: int) -> None:
    """Sleep in 1s slices so SIGTERM is observed promptly."""
    end = time.monotonic() + seconds
    while not _shutdown:
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("Initializing BackVault backup service")
    interval_seconds = _interval_hours() * 3600

    log.info("Running initial backup on startup...")
    run_backup()

    last_cleanup_day = date.today().toordinal()
    log.info(f"Starting backup loop, interval = {interval_seconds}s")

    while not _shutdown:
        _sleep_interruptible(interval_seconds)
        if _shutdown:
            break

        run_backup()

        today = date.today().toordinal()
        if today != last_cleanup_day:
            run_cleanup()
            last_cleanup_day = today

    log.info("Shutdown complete")


if __name__ == "__main__":
    main()
