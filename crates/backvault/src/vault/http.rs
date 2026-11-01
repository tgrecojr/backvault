//! HTTPS transport for the vault client: TLS policy, redirect refusal, timeouts, retry, error shaping.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};

use super::{HttpResponse, HttpTransport, Sleep, VaultError};

pub const RETRY_ATTEMPTS: u32 = 3;
pub const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(4)];
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);
pub const BODY_LIMIT: u64 = 256 * 1024 * 1024;
pub const BODY_LOG_LIMIT: usize = 500;

/// Production transport: `ureq` over `rustls`, built-in roots plus an optional PEM bundle, no redirects.
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl std::fmt::Debug for UreqTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UreqTransport")
    }
}

// @spec VAULT-HTTP-007
fn load_bundle(path: &Path) -> Result<Vec<Certificate<'static>>, VaultError> {
    let display = path.display().to_string();
    let pem = std::fs::read(path).map_err(|_| VaultError::CaCert(display.clone()))?;
    let certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        return Err(VaultError::CaCert(display));
    }
    Ok(certs)
}

impl UreqTransport {
    /// Build the transport. A `ca_cert` that cannot be read or holds no PEM certificate is `VaultError::CaCert`.
    // @spec VAULT-HTTP-001, VAULT-HTTP-004, VAULT-HTTP-006
    pub fn new(ca_cert: Option<&Path>) -> Result<Self, VaultError> {
        let mut roots: Vec<Certificate<'static>> = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|der| Certificate::from_der(der.as_ref()))
            .collect();
        if let Some(path) = ca_cert {
            roots.extend(load_bundle(path)?);
        }
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::Specific(Arc::new(roots)))
            .build();
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_recv_body(Some(READ_TIMEOUT))
            .timeout_recv_response(Some(READ_TIMEOUT))
            .tls_config(tls)
            .user_agent(format!("backvault/{}", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Self {
            agent: ureq::Agent::new_with_config(config),
        })
    }

    pub fn config(&self) -> &ureq::config::Config {
        self.agent.config()
    }
}

impl HttpTransport for UreqTransport {
    // @spec VAULT-HTTP-006
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String> {
        let mut builder = ureq::http::Request::builder().method(method).uri(url);
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder
            .body(body.map(<[u8]>::to_vec).unwrap_or_default())
            .map_err(|e| e.to_string())?;
        let mut response = self.agent.run(request).map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response
            .body_mut()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Extract the server's human-readable error text from a JSON error body, if any.
// @spec VAULT-RETRY-002
pub fn server_message(body: &[u8]) -> String {
    let Ok(data) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    let Some(obj) = data.as_object() else {
        return String::new();
    };
    for key in ["error_description", "message", "Message"] {
        if let Some(s) = obj.get(key).and_then(Value::as_str) {
            return s.to_string();
        }
    }
    obj.get("ErrorModel")
        .or_else(|| obj.get("errorModel"))
        .and_then(|m| m.get("Message"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Read a claim from a JWT payload without verifying the signature (TLS authenticates the server).
// @spec VAULT-AUTH-004
pub fn jwt_claim(token: &str, claim: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?.trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .get(claim)?
        .as_str()
        .map(str::to_string)
}

/// Issues JSON requests with the retry and failure policy of the vault-access design.
pub struct RetryingRequester<'a> {
    pub http: &'a mut dyn HttpTransport,
    pub sleep: &'a mut dyn Sleep,
}

impl RetryingRequester<'_> {
    // @spec VAULT-RETRY-001, VAULT-RETRY-002, VAULT-RETRY-003, VAULT-HTTP-005
    pub fn request(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        is_token: bool,
    ) -> Result<Value, VaultError> {
        let path = url.split('?').next().unwrap_or(url);
        let mut last_error = String::from("no response");
        for attempt in 0..RETRY_ATTEMPTS {
            match self.http.send(method, url, headers, body) {
                Err(network) => {
                    last_error = format!("network error: {network}");
                    log::warn!("{method} {path} failed ({last_error})");
                }
                Ok(response) if response.status >= 500 || response.status == 429 => {
                    last_error = format!("HTTP {}", response.status);
                    log_failure(response.status, &response.body);
                }
                Ok(response) => return handle(response, is_token),
            }
            if attempt + 1 < RETRY_ATTEMPTS {
                self.sleep.sleep(RETRY_DELAYS[attempt as usize]);
            }
        }
        Err(VaultError::Exhausted {
            method: method.to_string(),
            url: path.to_string(),
            attempts: RETRY_ATTEMPTS,
            last: last_error,
        })
    }
}

// @spec VAULT-HTTP-003, VAULT-HTTP-004
fn handle(response: HttpResponse, is_token: bool) -> Result<Value, VaultError> {
    let status = response.status;
    if (300..400).contains(&status) {
        let location = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "<none>".to_string());
        return Err(VaultError::Redirect { status, location });
    }
    if status == 404 {
        log_failure(status, &response.body);
        return Err(VaultError::NotFound);
    }
    if status >= 400 {
        log_failure(status, &response.body);
        return Err(VaultError::Rejected {
            status,
            what: if is_token {
                "authentication rejected"
            } else {
                "token rejected by the server"
            },
            message: server_message(&response.body),
        });
    }
    serde_json::from_slice(&response.body).map_err(|_| VaultError::NotJson(status))
}

// @spec VAULT-LOG-003
fn log_failure(status: u16, body: &[u8]) {
    let text = String::from_utf8_lossy(body);
    let excerpt: String = text.chars().take(BODY_LOG_LIMIT).collect();
    let message = server_message(body);
    log::error!(
        "Server returned HTTP {status}: {} | body: {excerpt}",
        if message.is_empty() {
            "(no message)"
        } else {
            message.as_str()
        }
    );
}
