//! vault-access: native Bitwarden/Vaultwarden client producing the CLI's export JSON in memory.
//!
//! One `export_vault_json` call performs the whole cycle: API-key login, master-key derivation,
//! user-key unwrap, `/api/sync`, local decryption, export assembly. Nothing is written to disk,
//! and every secret lives in a zeroizing container.

pub mod crypto;
pub mod export;
pub mod http;
mod session;

use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

pub use export::{ExportStats, PLACEHOLDER};

use http::{RetryingRequester, UreqTransport};
use session::VaultSession;

/// The CLI release whose export shape this client reproduces and announces.
/// Re-run the drill (diff against `bw export --format json`) when changing it.
pub const REFERENCE_CLI_VERSION: &str = "2025.1.3";
pub const DEVICE_TYPE: &str = "25";
pub const DEVICE_NAME: &str = "backvault";

/// Every failure that ends the backup cycle. Display forms carry no secret material.
// @spec VAULT-LOG-006
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("BW_SERVER must be an https:// URL")]
    ServerUrl,
    #[error(
        "BW_CLIENT_ID must be a user API key (user.<uuid>); organization API keys cannot unlock a personal vault"
    )]
    OrganizationClientId,
    #[error("BW_CA_CERT '{0}' cannot be read or contains no PEM certificate")]
    CaCert(String),
    #[error("token response has no {0}; this account cannot be unlocked with a master password")]
    TokenField(String),
    #[error("unsupported KDF type {0}")]
    UnsupportedKdf(i64),
    #[error("Argon2id KDF requires KdfMemory and KdfParallelism")]
    Argon2Params,
    #[error("could not decrypt the user key (field Key): {0}")]
    UserKey(String),
    #[error("user key has unexpected length {got} (expected {expected})")]
    UserKeyLength { got: usize, expected: usize },
    #[error("could not determine the account email for key derivation")]
    NoEmail,
    #[error("EncString type {0} is not implemented")]
    EncTypeNotImplemented(u32),
    #[error("item {id}: {message}")]
    Item { id: String, message: String },
    #[error("{0}")]
    Payload(String),
    #[error("unrecognised date value {0:?}")]
    Date(String),
    #[error("server redirected (HTTP {status}) to {location}; refusing to follow. Check BW_SERVER")]
    Redirect { status: u16, location: String },
    #[error("HTTP 404 from the server; check that BW_SERVER points at the vault's base URL")]
    NotFound,
    #[error("{what} (HTTP {status}){}", if .message.is_empty() { String::new() } else { format!(": {message}") })]
    Rejected {
        status: u16,
        what: &'static str,
        message: String,
    },
    #[error("server response (HTTP {0}) is not JSON")]
    NotJson(u16),
    #[error("{method} {url} failed after {attempts} attempts ({last})")]
    Exhausted {
        method: String,
        url: String,
        attempts: u32,
        last: String,
    },
}

/// What the caller supplies for one cycle. Secrets are borrowed as raw bytes.
pub struct Credentials<'a> {
    pub server: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a [u8],
    pub master_password: &'a [u8],
    pub ca_cert: Option<&'a Path>,
}

/// One HTTP exchange as the client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Transport abstraction: production is `ureq`; tests script responses.
/// `Err` is a network-level failure (connection, TLS, timeout) and is retried.
pub trait HttpTransport {
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String>;
}

/// Delay abstraction for retry back-off.
pub trait Sleep {
    fn sleep(&mut self, duration: Duration);
}

struct ThreadSleep;

impl Sleep for ThreadSleep {
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Resolve `BW_SERVER` to `(identity_base, api_base)`.
// @spec VAULT-SESSION-005
pub fn resolve_endpoints(server: &str) -> Result<(String, String), VaultError> {
    let base = server.trim().trim_end_matches('/');
    let rest = base.strip_prefix("https://").ok_or(VaultError::ServerUrl)?;
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() {
        return Err(VaultError::ServerUrl);
    }
    Ok(match host.to_ascii_lowercase().as_str() {
        "vault.bitwarden.com" => (
            "https://identity.bitwarden.com".to_string(),
            "https://api.bitwarden.com".to_string(),
        ),
        "vault.bitwarden.eu" => (
            "https://identity.bitwarden.eu".to_string(),
            "https://api.bitwarden.eu".to_string(),
        ),
        _ => (format!("{base}/identity"), format!("{base}/api")),
    })
}

/// Stable device identifier: UUIDv5(NAMESPACE_URL, "backvault:" + client_id).
// @spec VAULT-AUTH-001
pub fn device_identifier(client_id: &str) -> String {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("backvault:{client_id}").as_bytes(),
    )
    .to_string()
}

/// Authenticate, derive keys, sync, decrypt, and return the export JSON. Writes nothing.
// @spec VAULT-EXPORT-001, VAULT-EXPORT-004
pub fn export_vault_json(
    creds: &Credentials<'_>,
    http: &mut dyn HttpTransport,
    sleep: &mut dyn Sleep,
) -> Result<Zeroizing<String>, VaultError> {
    let (identity_base, api_base) = resolve_endpoints(creds.server)?;
    let mut session = VaultSession {
        creds,
        identity_base,
        api_base,
        requester: RetryingRequester { http, sleep },
        access_token: None,
    };
    session.export()
}

/// Production entry point: builds the TLS-verifying `ureq` transport and a real sleeper.
// @spec VAULT-HTTP-001, VAULT-HTTP-007
pub fn export_vault_json_default(creds: &Credentials<'_>) -> Result<Zeroizing<String>, VaultError> {
    let mut http = UreqTransport::new(creds.ca_cert)?;
    export_vault_json(creds, &mut http, &mut ThreadSleep)
}
