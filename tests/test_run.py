"""Tests for one backup cycle (backup-cycle segment): configuration, flow, file placement."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import run
from decrypt import decrypt_data
from vault_client import BitwardenError

# Fixture credentials: deliberately fake, assembled so secret scanners do not
# mistake them for real assignments.
FAKE_CLIENT_SECRET = "-".join(["fixture", "client", "value"])
FAKE_MASTER_PW = "-".join(["fixture", "master", "value"])
FAKE_FILE_PW = "-".join(["fixture", "file", "value"])
REQUIRED = {
    "BW_CLIENT_ID": "user.0b3c6e2a-9d44-4c4e-8d4e-1a2b3c4d5e6f",
    "BW_CLIENT_SECRET": FAKE_CLIENT_SECRET,
    "BW_PASSWORD": FAKE_MASTER_PW,
    "BW_SERVER": "https://vault.example.test",
    "BW_FILE_PASSWORD": FAKE_FILE_PW,
}
EXPORT = json.dumps(
    {"encrypted": False, "folders": [], "items": [{"id": "i-1", "name": "Example"}]},
    indent=2,
)


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Valid baseline configuration confined to a temp 'allowed base'."""
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)
    for name in (
        "BACKUP_DIR",
        "BACKUP_ENCRYPTION_MODE",
        "LOG_FILE",
        "BW_CA_CERT",
        "NODE_TLS_REJECT_UNAUTHORIZED",
    ):
        monkeypatch.delenv(name, raising=False)
    base = tmp_path / "app"
    base.mkdir()
    monkeypatch.setattr(run, "ALLOWED_BASE", str(base))
    monkeypatch.setenv("BACKUP_DIR", str(base / "backups"))
    return base


@pytest.fixture
def fake_export(monkeypatch):
    calls: list[dict] = []

    def fake(server, client_id, client_secret, master_password, ca_cert=None, **kwargs):
        calls.append(
            {
                "server": server,
                "client_id": client_id,
                "client_secret": client_secret,
                "master_password": master_password,
                "ca_cert": ca_cert,
            }
        )
        return EXPORT

    monkeypatch.setattr(run.vault_client, "export_vault_json", fake)
    return calls


def backups_in(base: Path) -> list[Path]:
    d = base / "backups"
    return sorted(d.iterdir()) if d.exists() else []


class TestConfiguration:
    # @spec CYCLE-CONFIG-001
    @pytest.mark.parametrize("missing", sorted(REQUIRED))
    def test_missing_required_variable_named_before_any_export(
        self, env, fake_export, monkeypatch, missing
    ):
        monkeypatch.delenv(missing)
        with pytest.raises(RuntimeError, match=missing):
            run.main()
        assert fake_export == []

    # @spec CYCLE-CONFIG-002
    def test_backup_dir_default(self, env, fake_export, monkeypatch):
        monkeypatch.delenv("BACKUP_DIR")
        monkeypatch.setattr(run, "ALLOWED_BASE", "/app")
        assert run.DEFAULT_BACKUP_DIR == "/app/backups"

    # @spec CYCLE-CONFIG-003
    def test_backup_dir_outside_base_exits_1_without_export(
        self, env, fake_export, monkeypatch, tmp_path
    ):
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        monkeypatch.setenv("BACKUP_DIR", str(outside))
        with pytest.raises(SystemExit) as exc:
            run.main()
        assert exc.value.code == 1
        assert fake_export == []
        assert list(outside.iterdir()) == []

    # @spec CYCLE-CONFIG-004
    @pytest.mark.parametrize("value", [None, "raw", " RAW ", "Raw"])
    def test_unset_or_raw_mode_produces_raw_backup(
        self, env, fake_export, monkeypatch, value
    ):
        if value is None:
            monkeypatch.delenv("BACKUP_ENCRYPTION_MODE", raising=False)
        else:
            monkeypatch.setenv("BACKUP_ENCRYPTION_MODE", value)
        run.main()
        files = backups_in(env)
        assert len(files) == 1
        assert (
            decrypt_data(files[0].read_bytes(), REQUIRED["BW_FILE_PASSWORD"])
            == EXPORT.encode()
        )

    # @spec CYCLE-CONFIG-005
    @pytest.mark.parametrize(
        "value", ["bitwarden", "BITWARDEN", "zip", "encrypted_json"]
    )
    def test_other_mode_exits_1_with_explanation(
        self, env, fake_export, monkeypatch, caplog, value
    ):
        monkeypatch.setenv("BACKUP_ENCRYPTION_MODE", value)
        with caplog.at_level("CRITICAL"), pytest.raises(SystemExit) as exc:
            run.main()
        assert exc.value.code == 1
        assert fake_export == []
        message = " ".join(
            r.getMessage() for r in caplog.records if r.levelname == "CRITICAL"
        )
        assert "raw" in message
        assert "decrypt" in message.lower()

    # @spec CYCLE-CONFIG-006
    def test_log_file_receives_records(
        self, env, fake_export, monkeypatch, tmp_path, caplog
    ):
        log_file = tmp_path / "cycle.log"
        monkeypatch.setenv("LOG_FILE", str(log_file))
        with caplog.at_level("INFO", logger="run"):
            run.main()
        assert log_file.exists()
        assert (
            "Export completed" in log_file.read_text()
            or "completed" in log_file.read_text().lower()
        )

    # @spec CYCLE-CONFIG-007
    def test_backup_dir_created_0700(self, env, fake_export):
        assert not (env / "backups").exists()
        run.main()
        mode = stat.S_IMODE((env / "backups").stat().st_mode)
        assert mode == 0o700

    # @spec CYCLE-CONFIG-008
    def test_ca_cert_passed_to_client(self, env, fake_export, monkeypatch, tmp_path):
        bundle = tmp_path / "ca.pem"
        bundle.write_text("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
        monkeypatch.setenv("BW_CA_CERT", str(bundle))
        run.main()
        assert fake_export[0]["ca_cert"] == str(bundle)

    # @spec CYCLE-CONFIG-008
    def test_missing_ca_cert_fails_naming_path_before_export(
        self, env, fake_export, monkeypatch, tmp_path, caplog
    ):
        missing = tmp_path / "nope.pem"
        monkeypatch.setenv("BW_CA_CERT", str(missing))
        with caplog.at_level("ERROR"), pytest.raises(SystemExit) as exc:
            run.main()
        assert exc.value.code == 1
        assert fake_export == []
        assert str(missing) in caplog.text

    # @spec CYCLE-CONFIG-009
    def test_node_tls_variable_warns_and_continues(
        self, env, fake_export, monkeypatch, caplog
    ):
        monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "0")
        with caplog.at_level("WARNING"):
            run.main()
        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any(
            "NODE_TLS_REJECT_UNAUTHORIZED" in w and "BW_CA_CERT" in w for w in warnings
        )
        assert len(backups_in(env)) == 1

    # @spec CYCLE-FLOW-001
    def test_validation_order_dir_before_mode_before_ca(
        self, env, fake_export, monkeypatch, tmp_path, caplog
    ):
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        monkeypatch.setenv("BACKUP_DIR", str(outside))
        monkeypatch.setenv("BACKUP_ENCRYPTION_MODE", "bitwarden")
        monkeypatch.setenv("BW_CA_CERT", str(tmp_path / "nope.pem"))
        with caplog.at_level("ERROR"), pytest.raises(SystemExit):
            run.main()
        text = caplog.text
        assert "BACKUP_DIR" in text
        assert "BACKUP_ENCRYPTION_MODE" not in text
        assert "nope.pem" not in text

        caplog.clear()
        monkeypatch.setenv("BACKUP_DIR", str(env / "backups"))
        with caplog.at_level("ERROR"), pytest.raises(SystemExit):
            run.main()
        assert "BACKUP_ENCRYPTION_MODE" in caplog.text
        assert "nope.pem" not in caplog.text

        caplog.clear()
        monkeypatch.setenv("BACKUP_ENCRYPTION_MODE", "raw")
        with caplog.at_level("ERROR"), pytest.raises(SystemExit):
            run.main()
        assert "nope.pem" in caplog.text
        assert fake_export == []


class TestFlow:
    # @spec CYCLE-FLOW-001
    def test_client_receives_configuration(self, env, fake_export):
        run.main()
        assert fake_export == [
            {
                "server": REQUIRED["BW_SERVER"],
                "client_id": REQUIRED["BW_CLIENT_ID"],
                "client_secret": REQUIRED["BW_CLIENT_SECRET"],
                "master_password": REQUIRED["BW_PASSWORD"],
                "ca_cert": None,
            }
        ]

    # @spec CYCLE-FLOW-001
    # @spec CYCLE-FLOW-003
    def test_export_failure_exits_1_and_writes_nothing(self, env, monkeypatch, caplog):
        def boom(*args, **kwargs):
            raise BitwardenError("token rejected")

        monkeypatch.setattr(run.vault_client, "export_vault_json", boom)
        with caplog.at_level("ERROR"), pytest.raises(SystemExit) as exc:
            run.main()
        assert exc.value.code == 1
        assert backups_in(env) == []
        assert "token rejected" in caplog.text

    # @spec CYCLE-FLOW-003
    def test_success_returns_normally(self, env, fake_export):
        assert run.main() is None
        assert len(backups_in(env)) == 1

    # @spec CYCLE-FLOW-004
    def test_only_ciphertext_written(self, env, fake_export):
        run.main()
        raw = backups_in(env)[0].read_bytes()
        assert b"Example" not in raw
        assert b"encrypted" not in raw
        assert int.from_bytes(raw[:4], "big") == 2
        assert decrypt_data(raw, REQUIRED["BW_FILE_PASSWORD"]) == EXPORT.encode()

    # @spec CYCLE-FLOW-004
    def test_no_plaintext_files_anywhere_under_base(self, env, fake_export):
        run.main()
        for path in env.rglob("*"):
            if path.is_file():
                assert b"Example" not in path.read_bytes()


class TestFile:
    # @spec CYCLE-FILE-001
    def test_filename_pattern(self, env, fake_export):
        run.main()
        name = backups_in(env)[0].name
        assert re.fullmatch(r"backup_\d{8}_\d{6}\.enc", name)

    # @spec CYCLE-FILE-002
    def test_write_path_validation_rejects_bad_names(self, env):
        with pytest.raises(ValueError):
            run.validate_backup_path(
                str(env / "backups" / "evil;rm.enc"), str(env / "backups")
            )
        with pytest.raises(ValueError):
            run.validate_backup_path(
                str(env / "backups" / "backup.txt"), str(env / "backups")
            )
        with pytest.raises(ValueError):
            run.validate_backup_path(
                str(env / "other" / "backup_x.enc"), str(env / "backups")
            )
        ok = run.validate_backup_path(
            str(env / "backups" / "backup_20240101_000000.enc"), str(env / "backups")
        )
        assert ok.endswith("backup_20240101_000000.enc")


def test_every_spec_cited_here_exists():
    specs_file = (
        Path(__file__).parent.parent / "docs/intent/backup-cycle/backup-cycle-specs.md"
    )
    defined = set(re.findall(r"\*\*(CYCLE-[A-Z]+-\d{3})\*\*", specs_file.read_text()))
    cited = set(re.findall(r"@spec (CYCLE-[A-Z]+-\d{3})", Path(__file__).read_text()))
    assert cited <= defined, cited - defined


def test_no_bw_subprocess_reference_remains():
    """The vault is reached natively; nothing in src/ shells out to a Bitwarden CLI."""
    src = Path(__file__).parent.parent / "src"
    for path in src.glob("*.py"):
        text = path.read_text()
        assert "subprocess" not in text, path
        assert "/usr/local/bin/bw" not in text, path
    assert not (src / "bw_client.py").exists()
    assert os.environ.get("BW_SESSION") is None
