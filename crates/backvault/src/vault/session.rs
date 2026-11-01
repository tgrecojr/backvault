//! One authenticate -> unwrap -> sync -> export cycle. Secrets are zeroized on drop.

use std::time::{Duration, Instant};

use serde_json::Value;
use zeroize::Zeroizing;

use super::crypto::{KDF_ARGON2ID, KDF_PBKDF2, derive_master_key, stretch_key, unwrap_user_key};
use super::export::{self, ExportStats, PLACEHOLDER, build_export, serialize_export};
use super::http::{RetryingRequester, jwt_claim};
use super::{
    Credentials, DEVICE_NAME, DEVICE_TYPE, REFERENCE_CLI_VERSION, VaultError, device_identifier,
};

fn urlencode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn host_of(server: &str) -> String {
    server
        .trim()
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Token-response fields the client needs, typed; a missing or wrongly typed field names itself.
// @spec VAULT-AUTH-002, VAULT-AUTH-003
struct TokenFields {
    access_token: Zeroizing<String>,
    key: String,
    kdf: i64,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    salt: Option<String>,
}

impl TokenFields {
    fn parse(token: &Value) -> Result<Self, VaultError> {
        let missing = |name: &str| VaultError::TokenField(name.to_string());
        let access_token = token
            .get("access_token")
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.to_string()))
            .ok_or_else(|| missing("access_token"))?;
        let key = token
            .get("Key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| missing("Key"))?;
        let kdf = token
            .get("Kdf")
            .and_then(Value::as_i64)
            .ok_or_else(|| missing("Kdf"))?;
        let iterations = token
            .get("KdfIterations")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| missing("KdfIterations"))?;
        let optional_u32 = |name: &str| -> Result<Option<u32>, VaultError> {
            match token.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => v
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .map(Some)
                    .ok_or_else(|| missing(name)),
            }
        };
        let memory = optional_u32("KdfMemory")?;
        let parallelism = optional_u32("KdfParallelism")?;
        let salt = token
            .get("UserDecryptionOptions")
            .and_then(|o| o.get("MasterPasswordUnlock"))
            .and_then(|u| u.get("Salt"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Ok(Self {
            access_token,
            key,
            kdf,
            iterations,
            memory,
            parallelism,
            salt,
        })
    }
}

pub(super) struct VaultSession<'a> {
    pub creds: &'a Credentials<'a>,
    pub identity_base: String,
    pub api_base: String,
    pub requester: RetryingRequester<'a>,
    pub access_token: Option<Zeroizing<String>>,
}

impl VaultSession<'_> {
    // @spec VAULT-HTTP-002
    fn headers(&self, form: bool) -> Vec<(String, String)> {
        let mut headers = vec![
            ("Accept".to_string(), "application/json".to_string()),
            ("Bitwarden-Client-Name".to_string(), "cli".to_string()),
            (
                "Bitwarden-Client-Version".to_string(),
                REFERENCE_CLI_VERSION.to_string(),
            ),
        ];
        if form {
            headers.push((
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            ));
        }
        if let Some(token) = &self.access_token {
            headers.push((
                "Authorization".to_string(),
                format!("Bearer {}", token.as_str()),
            ));
        }
        headers
    }

    // @spec VAULT-AUTH-001
    fn token_form(&self) -> Zeroizing<Vec<u8>> {
        let fields: [(&str, Vec<u8>); 7] = [
            ("grant_type", b"client_credentials".to_vec()),
            ("scope", b"api".to_vec()),
            ("client_id", self.creds.client_id.as_bytes().to_vec()),
            ("client_secret", self.creds.client_secret.to_vec()),
            ("deviceType", DEVICE_TYPE.as_bytes().to_vec()),
            (
                "deviceIdentifier",
                device_identifier(self.creds.client_id).into_bytes(),
            ),
            ("deviceName", DEVICE_NAME.as_bytes().to_vec()),
        ];
        let form = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        Zeroizing::new(form.into_bytes())
    }

    // @spec VAULT-AUTH-004
    fn email(&mut self, token: &TokenFields) -> Result<String, VaultError> {
        let mut email = token
            .salt
            .clone()
            .or_else(|| jwt_claim(&token.access_token, "email"));
        if email.is_none() {
            let url = format!("{}/accounts/profile", self.api_base);
            let headers = self.headers(false);
            let profile = self.requester.request("GET", &url, &headers, None, false)?;
            email = profile
                .get("email")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
        }
        email
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .ok_or(VaultError::NoEmail)
    }

    // @spec VAULT-SESSION-001, VAULT-SESSION-002, VAULT-SESSION-006, VAULT-AUTH-010
    fn authenticate(&mut self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if !self.creds.client_id.starts_with("user.") {
            return Err(VaultError::OrganizationClientId);
        }
        let url = format!("{}/connect/token", self.identity_base);
        let form = self.token_form();
        let headers = self.headers(true);
        let token = self
            .requester
            .request("POST", &url, &headers, Some(&form), true)?;
        drop(form);
        let fields = TokenFields::parse(&token)?;
        if fields.kdf != KDF_PBKDF2 && fields.kdf != KDF_ARGON2ID {
            return Err(VaultError::UnsupportedKdf(fields.kdf));
        }
        self.access_token = Some(fields.access_token.clone());
        let email = self.email(&fields)?;
        log::info!(
            "Account KDF: {} (iterations={}, memory={} MiB, parallelism={})",
            if fields.kdf == KDF_PBKDF2 {
                "PBKDF2"
            } else {
                "Argon2id"
            },
            fields.iterations,
            fields.memory.map_or("None".to_string(), |m| m.to_string()),
            fields
                .parallelism
                .map_or("None".to_string(), |p| p.to_string()),
        );
        let master_key = derive_master_key(
            self.creds.master_password,
            &email,
            fields.kdf,
            fields.iterations,
            fields.memory,
            fields.parallelism,
        )?;
        let _stretched = stretch_key(&master_key);
        unwrap_user_key(&fields.key, &master_key)
    }

    // @spec VAULT-SESSION-003, VAULT-SESSION-004, VAULT-EXPORT-005
    pub fn export(&mut self) -> Result<Zeroizing<String>, VaultError> {
        let started = Instant::now();
        let user_key = self.authenticate()?;
        let auth_done = Instant::now();
        let url = format!("{}/sync?excludeDomains=true", self.api_base);
        let headers = self.headers(false);
        let payload = self.requester.request("GET", &url, &headers, None, false)?;
        let sync_done = Instant::now();
        let (export, stats) = build_export(&payload, &user_key)?;
        drop(user_key);
        self.log_summary(
            &export,
            &stats,
            [
                auth_done - started,
                sync_done - auth_done,
                sync_done.elapsed(),
            ],
        );
        Ok(Zeroizing::new(serialize_export(&export)))
    }

    // @spec VAULT-LOG-004, VAULT-LOG-005, VAULT-EXPORT-007
    fn log_summary(&self, export: &export::Export, stats: &ExportStats, timings: [Duration; 3]) {
        log::info!(
            "Export from {}: {} folders, {} items ({} organization items and {} trashed items excluded); token {:.2}s, sync {:.2}s, decrypt {:.2}s",
            host_of(self.creds.server),
            export.folders.len(),
            export.items.len(),
            stats.org_excluded,
            stats.trashed_excluded,
            timings[0].as_secs_f64(),
            timings[1].as_secs_f64(),
            timings[2].as_secs_f64(),
        );
        if stats.with_attachments > 0 {
            log::warn!(
                "{} exported item(s) have attachments; attachments are not included in the export",
                stats.with_attachments
            );
        }
        if stats.undecryptable_fields > 0 {
            log::error!(
                "{} field(s) could not be decrypted and were exported as {PLACEHOLDER}",
                stats.undecryptable_fields
            );
        }
    }
}
