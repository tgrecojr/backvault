//! backup-cycle: configuration intake, flow, naming and placement (CYCLE-*).

mod common;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::*;
use time::macros::datetime;
use zeroize::Zeroizing;

use backvault::cycle::{
    CycleConfig, CycleError, DEFAULT_BACKUP_DIR, VaultExporter, confine_to_app, run_from_env,
    validate_backup_path,
};
use backvault::env::MapEnv;
use backvault::scheduler::Clock;
use backvault::vault::{Credentials, VaultError};

// Fixture credentials: deliberately fake, assembled so secret scanners do not mistake them.
const FAKE_CLIENT_SECRET: &str = "fixture-client-value";
const FAKE_MASTER_PW: &str = "fixture-master-value";
const FAKE_FILE_PW: &str = "fixture-file-value";
const REQUIRED: [(&str, &str); 5] = [
    ("BW_CLIENT_ID", "user.0b3c6e2a-9d44-4c4e-8d4e-1a2b3c4d5e6f"),
    ("BW_CLIENT_SECRET", FAKE_CLIENT_SECRET),
    ("BW_PASSWORD", FAKE_MASTER_PW),
    ("BW_SERVER", "https://vault.example.test"),
    ("BW_FILE_PASSWORD", FAKE_FILE_PW),
];
const EXPORT: &str = "{\n  \"encrypted\": false,\n  \"folders\": [],\n  \"items\": [\n    {\n      \"id\": \"i-1\",\n      \"name\": \"Example\"\n    }\n  ]\n}";

struct FixedClock(time::OffsetDateTime);
impl Clock for FixedClock {
    fn now_utc(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn clock() -> FixedClock {
    FixedClock(datetime!(2024-01-02 03:04:05 UTC))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Captured {
    server: String,
    client_id: String,
    client_secret: Vec<u8>,
    master_password: Vec<u8>,
    ca_cert: Option<PathBuf>,
}

struct FakeVault {
    calls: Vec<Captured>,
    result: Result<String, String>,
}

impl FakeVault {
    fn ok() -> Self {
        Self {
            calls: Vec::new(),
            result: Ok(EXPORT.to_string()),
        }
    }
    fn failing(message: &str) -> Self {
        Self {
            calls: Vec::new(),
            result: Err(message.to_string()),
        }
    }
}

impl VaultExporter for FakeVault {
    fn export(&mut self, creds: &Credentials<'_>) -> Result<Zeroizing<String>, VaultError> {
        self.calls.push(Captured {
            server: creds.server.to_string(),
            client_id: creds.client_id.to_string(),
            client_secret: creds.client_secret.to_vec(),
            master_password: creds.master_password.to_vec(),
            ca_cert: creds.ca_cert.map(Path::to_path_buf),
        });
        match &self.result {
            Ok(text) => Ok(Zeroizing::new(text.clone())),
            Err(m) => Err(VaultError::Payload(m.clone())),
        }
    }
}

/// A temp "allowed base" with a valid baseline environment pointing `BACKUP_DIR` inside it.
struct Fixture {
    _dir: tempfile::TempDir,
    base: PathBuf,
    env: MapEnv,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("app");
    std::fs::create_dir(&base).unwrap();
    let base = base.canonicalize().unwrap();
    let mut env = MapEnv::default();
    for (k, v) in REQUIRED {
        env = env.set(k, v);
    }
    env = env.set(
        "BACKUP_DIR",
        base.join("backups").as_os_str().to_os_string(),
    );
    Fixture {
        _dir: dir,
        base,
        env,
    }
}

fn backups_in(base: &Path) -> Vec<PathBuf> {
    let d = base.join("backups");
    if !d.exists() {
        return Vec::new();
    }
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v
}

fn run(f: &Fixture, vault: &mut FakeVault) -> Result<PathBuf, CycleError> {
    run_from_env(&f.env, &f.base, vault, &clock())
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// @spec CYCLE-CONFIG-001
#[test]
fn missing_required_variable_named_before_any_export() {
    for (missing, _) in REQUIRED {
        let mut f = fixture();
        f.env = f.env.unset(missing);
        let mut vault = FakeVault::ok();
        let err = run(&f, &mut vault).unwrap_err();
        assert!(
            matches!(&err, CycleError::MissingVariable(name) if name == missing),
            "{err}"
        );
        assert!(err.to_string().contains(missing));
        assert!(vault.calls.is_empty());
        // Empty counts as missing.
        let mut f = fixture();
        f.env = f.env.set(missing, "");
        assert!(matches!(
            run(&f, &mut vault).unwrap_err(),
            CycleError::MissingVariable(_)
        ));
    }
}

// @spec CYCLE-CONFIG-002
#[test]
fn backup_dir_defaults_under_app() {
    assert_eq!(DEFAULT_BACKUP_DIR, "/app/backups");
    let f = fixture();
    let env = f.env.clone().unset("BACKUP_DIR");
    let config = CycleConfig::from_env(&env, Path::new("/app")).unwrap();
    assert_eq!(config.backup_dir, Path::new("/app/backups"));
}

// @spec CYCLE-CONFIG-003
#[test]
fn backup_dir_outside_base_fails_without_export() {
    let mut f = fixture();
    let outside = f._dir.path().join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    f.env = f.env.set("BACKUP_DIR", outside.as_os_str().to_os_string());
    let mut vault = FakeVault::ok();
    let err = run(&f, &mut vault).unwrap_err();
    assert!(
        matches!(err, CycleError::DirectoryOutsideBase { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("elsewhere"));
    assert!(vault.calls.is_empty());
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
}

// @spec CYCLE-CONFIG-003
#[test]
fn symlink_escaping_base_is_caught_and_confine_is_shared() {
    let f = fixture();
    let outside = f._dir.path().join("real-elsewhere");
    std::fs::create_dir(&outside).unwrap();
    let link = f.base.join("backups");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(matches!(
        confine_to_app(&link, &f.base).unwrap_err(),
        CycleError::DirectoryOutsideBase { .. }
    ));
    assert!(
        confine_to_app(&f.base.join("backups-missing"), &f.base).is_ok(),
        "a not-yet-created directory under the base is fine"
    );
    assert_eq!(
        confine_to_app(&f.base.join("sub/../ok"), &f.base).unwrap(),
        f.base.join("ok")
    );
}

// @spec CYCLE-CONFIG-004
#[test]
fn unset_or_raw_mode_produces_raw_backup() {
    for value in [None, Some("raw"), Some(" RAW "), Some("Raw")] {
        let mut f = fixture();
        f.env = match value {
            None => f.env.unset("BACKUP_ENCRYPTION_MODE"),
            Some(v) => f.env.set("BACKUP_ENCRYPTION_MODE", v),
        };
        let path = run(&f, &mut FakeVault::ok()).unwrap();
        let files = backups_in(&f.base);
        assert_eq!(files, std::slice::from_ref(&path));
        let plain =
            backvault_format::decrypt(&std::fs::read(&path).unwrap(), FAKE_FILE_PW.as_bytes())
                .unwrap();
        assert_eq!(plain.as_slice(), EXPORT.as_bytes());
    }
}

// @spec CYCLE-CONFIG-005
#[test]
fn other_mode_fails_with_explanation_without_export() {
    for value in ["bitwarden", "BITWARDEN", "zip", "encrypted_json"] {
        let mut f = fixture();
        f.env = f.env.set("BACKUP_ENCRYPTION_MODE", value);
        let mut vault = FakeVault::ok();
        let err = run(&f, &mut vault).unwrap_err();
        assert!(matches!(err, CycleError::UnsupportedMode(_)), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("raw") && text.to_lowercase().contains("decrypt"),
            "{text}"
        );
        assert!(vault.calls.is_empty());
        assert!(backups_in(&f.base).is_empty());
    }
}

// @spec CYCLE-CONFIG-007
#[test]
fn backup_dir_created_0700() {
    let f = fixture();
    assert!(!f.base.join("backups").exists());
    run(&f, &mut FakeVault::ok()).unwrap();
    let mode = std::fs::metadata(f.base.join("backups"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

// @spec CYCLE-CONFIG-008
#[test]
fn ca_cert_passed_to_client() {
    let mut f = fixture();
    let bundle = f._dir.path().join("ca.pem");
    std::fs::write(
        &bundle,
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    f.env = f.env.set("BW_CA_CERT", bundle.as_os_str().to_os_string());
    let mut vault = FakeVault::ok();
    run(&f, &mut vault).unwrap();
    assert_eq!(vault.calls[0].ca_cert.as_deref(), Some(bundle.as_path()));
}

// @spec CYCLE-CONFIG-008
#[test]
fn missing_ca_cert_fails_naming_path_before_export() {
    let mut f = fixture();
    let missing = f._dir.path().join("nope.pem");
    f.env = f.env.set("BW_CA_CERT", missing.as_os_str().to_os_string());
    let mut vault = FakeVault::ok();
    let err = run(&f, &mut vault).unwrap_err();
    assert!(matches!(err, CycleError::CaCert(_)), "{err}");
    assert!(err.to_string().contains("nope.pem"));
    assert!(vault.calls.is_empty());
}

// @spec CYCLE-CONFIG-009
#[test]
fn node_tls_variable_warns_and_continues() {
    capture_logs();
    let mut f = fixture();
    f.env = f.env.set("NODE_TLS_REJECT_UNAUTHORIZED", "0");
    run(&f, &mut FakeVault::ok()).unwrap();
    assert!(records().iter().any(|(l, m)| *l == log::Level::Warn
        && m.contains("NODE_TLS_REJECT_UNAUTHORIZED")
        && m.contains("BW_CA_CERT")));
    assert_eq!(backups_in(&f.base).len(), 1);
}

// @spec CYCLE-CONFIG-010
#[test]
fn passwords_are_raw_bytes_in_zeroizing_buffers() {
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let raw_master = vec![0xff, 0xfe, b' ', b'p', b'w', b' '];
    let raw_file = vec![0xfd, b'f', b'i', b'l', b'e', 0x00, b'x'];
    let mut f = fixture();
    f.env = f
        .env
        .set("BW_PASSWORD", OsString::from_vec(raw_master.clone()))
        .set("BW_FILE_PASSWORD", OsString::from_vec(raw_file.clone()));
    let config = CycleConfig::from_env(&f.env, &f.base).unwrap();
    assert_wiped_on_drop(&config.master_password);
    assert_wiped_on_drop(&config.file_password);
    assert_wiped_on_drop(&config.client_secret);
    assert_eq!(config.master_password.as_slice(), raw_master.as_slice());
    let mut vault = FakeVault::ok();
    let path = run(&f, &mut vault).unwrap();
    assert_eq!(vault.calls[0].master_password, raw_master);
    assert_eq!(vault.calls[0].client_secret, FAKE_CLIENT_SECRET.as_bytes());
    let plain = backvault_format::decrypt(&std::fs::read(path).unwrap(), &raw_file).unwrap();
    assert_eq!(plain.as_slice(), EXPORT.as_bytes());
}

// @spec CYCLE-FLOW-001
#[test]
fn validation_order_required_then_dir_then_mode_then_ca() {
    let mut f = fixture();
    let outside = f._dir.path().join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    let nope = f._dir.path().join("nope.pem");
    f.env = f
        .env
        .unset("BW_SERVER")
        .set("BACKUP_DIR", outside.as_os_str().to_os_string())
        .set("BACKUP_ENCRYPTION_MODE", "bitwarden")
        .set("BW_CA_CERT", nope.as_os_str().to_os_string());
    let mut vault = FakeVault::ok();
    assert!(matches!(
        run(&f, &mut vault).unwrap_err(),
        CycleError::MissingVariable(_)
    ));
    f.env = f.env.set("BW_SERVER", "https://vault.example.test");
    assert!(matches!(
        run(&f, &mut vault).unwrap_err(),
        CycleError::DirectoryOutsideBase { .. }
    ));
    f.env = f.env.set(
        "BACKUP_DIR",
        f.base.join("backups").as_os_str().to_os_string(),
    );
    assert!(matches!(
        run(&f, &mut vault).unwrap_err(),
        CycleError::UnsupportedMode(_)
    ));
    f.env = f.env.set("BACKUP_ENCRYPTION_MODE", "raw");
    assert!(matches!(
        run(&f, &mut vault).unwrap_err(),
        CycleError::CaCert(_)
    ));
    assert!(vault.calls.is_empty());
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

// @spec CYCLE-FLOW-001
#[test]
fn client_receives_configuration() {
    let f = fixture();
    let mut vault = FakeVault::ok();
    run(&f, &mut vault).unwrap();
    assert_eq!(
        vault.calls,
        [Captured {
            server: "https://vault.example.test".into(),
            client_id: "user.0b3c6e2a-9d44-4c4e-8d4e-1a2b3c4d5e6f".into(),
            client_secret: FAKE_CLIENT_SECRET.as_bytes().to_vec(),
            master_password: FAKE_MASTER_PW.as_bytes().to_vec(),
            ca_cert: None,
        }]
    );
}

// @spec CYCLE-FLOW-001, CYCLE-FLOW-003
#[test]
fn export_failure_returns_error_and_writes_nothing() {
    let f = fixture();
    let err = run(&f, &mut FakeVault::failing("token rejected")).unwrap_err();
    assert!(matches!(err, CycleError::Export(_)), "{err}");
    assert!(err.to_string().contains("token rejected"));
    assert!(backups_in(&f.base).is_empty());
}

// @spec CYCLE-FLOW-003
#[test]
fn success_returns_written_path_and_errors_carry_no_secrets() {
    let f = fixture();
    let path = run(&f, &mut FakeVault::ok()).unwrap();
    assert!(path.is_file());
    assert_eq!(backups_in(&f.base), [path]);
    let mut g = fixture();
    g.env = g.env.set("BACKUP_ENCRYPTION_MODE", "bitwarden");
    let text = run(&g, &mut FakeVault::ok()).unwrap_err().to_string();
    for secret in [FAKE_CLIENT_SECRET, FAKE_MASTER_PW, FAKE_FILE_PW] {
        assert!(!text.contains(secret));
    }
}

// @spec CYCLE-FLOW-004
#[test]
fn only_ciphertext_written_and_no_plaintext_anywhere_under_base() {
    let f = fixture();
    let path = run(&f, &mut FakeVault::ok()).unwrap();
    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.windows(7).any(|w| w == b"Example"));
    assert!(!raw.windows(9).any(|w| w == b"encrypted"));
    assert_eq!(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]), 2);
    for entry in walk(&f.base) {
        let bytes = std::fs::read(&entry).unwrap();
        assert!(
            !bytes.windows(7).any(|w| w == b"Example"),
            "{entry:?} holds plaintext"
        );
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

// @spec CYCLE-FLOW-005
#[test]
fn vault_and_clock_are_injected() {
    // The fake vault and fixed clock used throughout this file are the proof; a cycle with a
    // fixed clock always names the file after that clock.
    let f = fixture();
    let path = run(&f, &mut FakeVault::ok()).unwrap();
    assert_eq!(path.file_name().unwrap(), "backup_20240102_030405.enc");
}

// ---------------------------------------------------------------------------
// File naming and placement
// ---------------------------------------------------------------------------

// @spec CYCLE-FILE-001
#[test]
fn filename_is_utc_timestamp() {
    let f = fixture();
    let path = run_from_env(
        &f.env,
        &f.base,
        &mut FakeVault::ok(),
        &FixedClock(datetime!(2024-12-31 23:59:59 UTC)),
    )
    .unwrap();
    assert_eq!(path.file_name().unwrap(), "backup_20241231_235959.enc");
    let name = path.file_name().unwrap().to_str().unwrap();
    assert!(name.len() == "backup_YYYYMMDD_HHMMSS.enc".len());
    assert!(
        name[7..15].chars().all(|c| c.is_ascii_digit())
            && name[16..22].chars().all(|c| c.is_ascii_digit())
    );
}

// @spec CYCLE-FILE-002
#[test]
fn write_path_validation_rejects_bad_names() {
    let f = fixture();
    let dir = f.base.join("backups");
    std::fs::create_dir(&dir).unwrap();
    for bad in [
        dir.join("evil;rm.enc"),
        dir.join("backup.txt"),
        f.base.join("other").join("backup_x.enc"),
        dir.join("../backup_x.enc"),
    ] {
        assert!(
            matches!(
                validate_backup_path(&bad, &dir).unwrap_err(),
                CycleError::InvalidPath(_)
            ),
            "{bad:?}"
        );
    }
    let ok = validate_backup_path(&dir.join("backup_20240101_000000.enc"), &dir).unwrap();
    assert!(ok.ends_with("backup_20240101_000000.enc"));
}

// @spec CYCLE-FILE-003
#[test]
fn file_is_0600_complete_and_no_part_file_remains() {
    let f = fixture();
    let path = run(&f, &mut FakeVault::ok()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(backups_in(&f.base).len(), 1, "no .part file left behind");
    let plain =
        backvault_format::decrypt(&std::fs::read(&path).unwrap(), FAKE_FILE_PW.as_bytes()).unwrap();
    assert_eq!(plain.as_slice(), EXPORT.as_bytes());
}

// @spec CYCLE-FILE-003
#[test]
fn existing_final_or_part_file_is_never_overwritten() {
    let f = fixture();
    let dir = f.base.join("backups");
    std::fs::create_dir(&dir).unwrap();
    let final_path = dir.join("backup_20240102_030405.enc");
    std::fs::write(&final_path, b"older backup").unwrap();
    let err = run(&f, &mut FakeVault::ok()).unwrap_err();
    assert!(matches!(err, CycleError::Write { .. }), "{err}");
    assert_eq!(std::fs::read(&final_path).unwrap(), b"older backup");
    std::fs::remove_file(&final_path).unwrap();

    let part = dir.join("backup_20240102_030405.enc.part");
    std::fs::write(&part, b"abandoned").unwrap();
    let err = run(&f, &mut FakeVault::ok()).unwrap_err();
    assert!(matches!(err, CycleError::Write { .. }), "{err}");
    assert_eq!(std::fs::read(&part).unwrap(), b"abandoned");
    assert!(!final_path.exists());
}

#[test]
fn every_spec_cited_here_exists() {
    assert_cited_specs_exist(
        "crates/backvault/tests/cycle.rs",
        "docs/intent/backup-cycle/backup-cycle-specs.md",
        "CYCLE",
    );
}
