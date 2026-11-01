//! backup-cycle: one attempt to produce one backup file.
//!
//! Validate configuration in a fixed order, obtain the export from vault-access, encrypt it,
//! write `.part`, fsync, rename to `.enc`, and return the path or one typed error.

mod paths;

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use time::macros::format_description;
use zeroize::Zeroizing;

pub use paths::{confine_to_app, validate_backup_path};

use crate::env::Env;
use crate::scheduler::Clock;
use crate::vault::{Credentials, VaultError};

pub const DEFAULT_ALLOWED_BASE: &str = "/app";
pub const DEFAULT_BACKUP_DIR: &str = "/app/backups";
pub const REQUIRED_VARS: [&str; 5] = [
    "BW_CLIENT_ID",
    "BW_CLIENT_SECRET",
    "BW_PASSWORD",
    "BW_SERVER",
    "BW_FILE_PASSWORD",
];

/// Every failure that ends a cycle. Display forms carry no secret material.
#[derive(Debug, thiserror::Error)]
pub enum CycleError {
    #[error("Missing required environment variable: {0}")]
    MissingVariable(String),
    #[error("BACKUP_DIR '{dir}' is outside allowed path '{base}'")]
    DirectoryOutsideBase { dir: String, base: String },
    #[error(
        "BACKUP_ENCRYPTION_MODE='{0}' is not supported: only raw mode exists (portable AES-256-GCM, restored with backvault-decrypt and the backup file password). Unset the variable."
    )]
    UnsupportedMode(String),
    #[error("BW_CA_CERT '{0}' does not exist or is not readable")]
    CaCert(String),
    #[error("could not create backup directory '{dir}': {source}")]
    CreateDir { dir: String, source: std::io::Error },
    #[error("Export failed: {0}")]
    Export(#[from] VaultError),
    #[error("Invalid backup path: {0}")]
    InvalidPath(String),
    #[error("encryption failed: {0}")]
    Encrypt(#[from] backvault_format::FormatError),
    #[error("could not write backup '{path}': {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
}

/// Validated configuration for one cycle. Secrets are raw bytes in zeroizing buffers.
pub struct CycleConfig {
    pub server: String,
    pub client_id: String,
    pub client_secret: Zeroizing<Vec<u8>>,
    pub master_password: Zeroizing<Vec<u8>>,
    pub file_password: Zeroizing<Vec<u8>>,
    pub backup_dir: PathBuf,
    pub ca_cert: Option<PathBuf>,
}

/// The vault client as the cycle sees it; tests substitute a fake.
pub trait VaultExporter {
    fn export(&mut self, creds: &Credentials<'_>) -> Result<Zeroizing<String>, VaultError>;
}

// @spec CYCLE-CONFIG-001, CYCLE-CONFIG-010
fn required(env: &dyn Env, name: &str) -> Result<Zeroizing<Vec<u8>>, CycleError> {
    match env.get(name) {
        Some(value) if !value.is_empty() => Ok(Zeroizing::new(value.into_vec())),
        _ => Err(CycleError::MissingVariable(name.to_string())),
    }
}

fn text(bytes: Zeroizing<Vec<u8>>) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}

impl CycleConfig {
    /// Read and validate in the order: required variables, `BACKUP_DIR`, `BACKUP_ENCRYPTION_MODE`, `BW_CA_CERT`.
    // @spec CYCLE-CONFIG-002, CYCLE-CONFIG-004, CYCLE-CONFIG-005, CYCLE-CONFIG-008, CYCLE-CONFIG-009, CYCLE-FLOW-001
    pub fn from_env(env: &dyn Env, allowed_base: &Path) -> Result<Self, CycleError> {
        let client_id = text(required(env, "BW_CLIENT_ID")?);
        let client_secret = required(env, "BW_CLIENT_SECRET")?;
        let master_password = required(env, "BW_PASSWORD")?;
        let server = text(required(env, "BW_SERVER")?);
        let file_password = required(env, "BW_FILE_PASSWORD")?;

        let backup_dir = env
            .get("BACKUP_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BACKUP_DIR));
        let backup_dir = confine_to_app(&backup_dir, allowed_base)?;

        if let Some(mode) = env.get("BACKUP_ENCRYPTION_MODE") {
            let raw = mode.to_string_lossy().into_owned();
            if !raw.trim().eq_ignore_ascii_case("raw") {
                return Err(CycleError::UnsupportedMode(raw));
            }
        }

        if env.get("NODE_TLS_REJECT_UNAUTHORIZED").is_some() {
            log::warn!(
                "NODE_TLS_REJECT_UNAUTHORIZED has no effect; set BW_CA_CERT to a PEM bundle to trust a self-signed server"
            );
        }
        let ca_cert = match env.get("BW_CA_CERT").filter(|v| !v.is_empty()) {
            None => None,
            Some(path) => {
                let path = PathBuf::from(path);
                let readable = path.is_file() && std::fs::File::open(&path).is_ok();
                if !readable {
                    return Err(CycleError::CaCert(path.display().to_string()));
                }
                Some(path)
            }
        };

        Ok(Self {
            server,
            client_id,
            client_secret,
            master_password,
            file_password,
            backup_dir,
            ca_cert,
        })
    }
}

// @spec CYCLE-CONFIG-007
fn ensure_backup_dir(dir: &Path) -> Result<(), CycleError> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|source| CycleError::CreateDir {
            dir: dir.display().to_string(),
            source,
        })
}

// @spec CYCLE-FILE-003
fn write_durably(final_path: &Path, ciphertext: &[u8]) -> Result<(), CycleError> {
    let write_err = |path: &Path, source: std::io::Error| CycleError::Write {
        path: path.display().to_string(),
        source,
    };
    if final_path.exists() {
        return Err(write_err(
            final_path,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "backup file already exists",
            ),
        ));
    }
    let mut part_name: OsString = final_path.as_os_str().to_os_string();
    part_name.push(".part");
    let part = PathBuf::from(part_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)
        .map_err(|e| write_err(&part, e))?;
    let result = file.write_all(ciphertext).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = result {
        let _ = std::fs::remove_file(&part);
        return Err(write_err(&part, e));
    }
    std::fs::rename(&part, final_path).map_err(|e| {
        let _ = std::fs::remove_file(&part);
        write_err(final_path, e)
    })
}

/// Export, encrypt, write `.part`, fsync, rename. Returns the final path.
// @spec CYCLE-FLOW-003, CYCLE-FLOW-004, CYCLE-FLOW-005, CYCLE-FILE-001
pub fn run(
    config: &CycleConfig,
    vault: &mut dyn VaultExporter,
    clock: &dyn Clock,
) -> Result<PathBuf, CycleError> {
    ensure_backup_dir(&config.backup_dir)?;
    log::info!("Connecting to vault...");
    let export = vault.export(&Credentials {
        server: &config.server,
        client_id: &config.client_id,
        client_secret: &config.client_secret,
        master_password: &config.master_password,
        ca_cert: config.ca_cert.as_deref(),
    })?;
    let stamp = clock
        .now_utc()
        .format(format_description!(
            "[year][month][day]_[hour][minute][second]"
        ))
        .expect("fixed format");
    let final_path = validate_backup_path(
        &config.backup_dir.join(format!("backup_{stamp}.enc")),
        &config.backup_dir,
    )?;
    let ciphertext = backvault_format::encrypt(export.as_bytes(), &config.file_password)?;
    drop(export);
    write_durably(&final_path, &ciphertext)?;
    log::info!("Export completed successfully: {}", final_path.display());
    Ok(final_path)
}

/// `from_env` then `run`.
pub fn run_from_env(
    env: &dyn Env,
    allowed_base: &Path,
    vault: &mut dyn VaultExporter,
    clock: &dyn Clock,
) -> Result<PathBuf, CycleError> {
    let config = CycleConfig::from_env(env, allowed_base)?;
    run(&config, vault, clock)
}
