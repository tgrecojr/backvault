//! Shared test helpers for the backvault crate: test-side crypto, payload builders,
//! a scripted HTTP transport, and a thread-local log capture.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeEncrypt, KeyIvInit};
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use backvault::vault::{
    Credentials, HttpResponse, HttpTransport, Sleep, VaultError, export_vault_json,
};

pub const EMAIL_RAW: &str = "  Test@Example.COM ";
pub const EMAIL: &str = "test@example.com";
pub const PASSWORD: &str = "pässwörd☃";
pub const ITERATIONS: u32 = 5000;
pub const CLIENT_ID: &str = "user.0b3c6e2a-9d44-4c4e-8d4e-1a2b3c4d5e6f";
pub const CLIENT_SECRET: &str = "s3cr3t-client-secret";
pub const SERVER: &str = "https://vault.example.test";

pub const USER_KEY: [u8; 64] = {
    let mut a = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        a[i] = i as u8;
        i += 1;
    }
    a
};

// ---------------------------------------------------------------------------
// Test-side crypto (independent of the implementation under test)
// ---------------------------------------------------------------------------

pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn hkdf_expand(prk: &[u8], info: &str) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte prk");
    let mut out = [0u8; 32];
    hk.expand(info.as_bytes(), &mut out).expect("expand");
    out.to_vec()
}

pub fn stretch_for_test(master_key: &[u8]) -> Vec<u8> {
    [
        hkdf_expand(master_key, "enc"),
        hkdf_expand(master_key, "mac"),
    ]
    .concat()
}

static IV_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Unique IV per call (tests need distinctness, not unpredictability).
fn fresh_iv() -> [u8; 16] {
    let n = IV_COUNTER.fetch_add(1, Ordering::Relaxed);
    let h = sha256(&n.to_be_bytes());
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&h[..16]);
    iv
}

/// Type-2 EncString: AES-256-CBC + HMAC-SHA256 over iv||ct.
pub fn enc2(plaintext: &[u8], key64: &[u8]) -> String {
    let (enc_key, mac_key) = key64.split_at(32);
    let iv = fresh_iv();
    let ct = cbc::Encryptor::<Aes256>::new_from_slices(enc_key, &iv)
        .expect("key/iv")
        .encrypt_padded_vec::<Pkcs7>(plaintext);
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).expect("mac key");
    mac.update(&iv);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();
    format!("2.{}|{}|{}", b64(&iv), b64(&ct), b64(&tag))
}

/// Legacy type-0 EncString: AES-256-CBC, no MAC.
pub fn enc0(plaintext: &[u8], key32: &[u8]) -> String {
    let iv = fresh_iv();
    let ct = cbc::Encryptor::<Aes256>::new_from_slices(key32, &iv)
        .expect("key/iv")
        .encrypt_padded_vec::<Pkcs7>(plaintext);
    format!("0.{}|{}", b64(&iv), b64(&ct))
}

pub fn e(text: &str, key64: &[u8]) -> String {
    enc2(text.as_bytes(), key64)
}

pub fn master_key() -> Vec<u8> {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(PASSWORD.as_bytes(), EMAIL.as_bytes(), ITERATIONS, &mut out);
    out.to_vec()
}

pub fn stretched() -> Vec<u8> {
    stretch_for_test(&master_key())
}

pub fn fake_jwt(email: Option<&str>) -> String {
    let header = b64url(json!({"alg": "RS256", "typ": "JWT"}).to_string().as_bytes());
    let mut payload = json!({"sub": &CLIENT_ID[5..], "premium": true});
    if let Some(email) = email {
        payload["email"] = json!(email);
    }
    format!(
        "{header}.{}.{}",
        b64url(payload.to_string().as_bytes()),
        b64url(b"sig")
    )
}

pub fn token_response() -> Value {
    json!({
        "access_token": fake_jwt(Some(EMAIL)),
        "expires_in": 3600,
        "token_type": "Bearer",
        "Key": enc2(&USER_KEY, &stretched()),
        "PrivateKey": "2.unused|unused|unused",
        "Kdf": 0,
        "KdfIterations": ITERATIONS,
        "KdfMemory": null,
        "KdfParallelism": null,
        "ForcePasswordReset": false,
        "scope": "api",
        "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "MasterPasswordUnlock": {
                "Kdf": {"KdfType": 0, "Iterations": ITERATIONS, "Memory": null, "Parallelism": null},
                "MasterKeyEncryptedUserKey": enc2(&USER_KEY, &stretched()),
                "Salt": EMAIL_RAW,
            },
            "Object": "userDecryptionOptions",
        },
    })
}

pub fn folder(fid: &str, name: &str, key: &[u8]) -> Value {
    json!({"id": fid, "name": e(name, key), "revisionDate": "2024-01-01T00:00:00.000000Z", "object": "folder"})
}

pub struct LoginOpts<'a> {
    pub key: &'a [u8],
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub totp: Option<&'a str>,
    pub uris: Option<Vec<(&'a str, Option<i64>)>>,
    pub folder_id: Option<&'a str>,
    pub organization_id: Option<&'a str>,
    pub deleted: Option<&'a str>,
    pub archived: Option<&'a str>,
    pub attachments: Option<Value>,
    pub fields: Option<Value>,
    pub password_history: Option<Value>,
    pub cipher_key: Option<String>,
    pub notes: Option<&'a str>,
    pub favorite: bool,
    pub reprompt: i64,
}

impl Default for LoginOpts<'_> {
    fn default() -> Self {
        Self {
            key: &USER_KEY,
            username: Some("alice"),
            password: Some("hunter2"),
            totp: None,
            uris: Some(vec![("https://example.test", None)]),
            folder_id: None,
            organization_id: None,
            deleted: None,
            archived: None,
            attachments: None,
            fields: None,
            password_history: None,
            cipher_key: None,
            notes: None,
            favorite: false,
            reprompt: 0,
        }
    }
}

pub fn login_item(iid: &str, name: &str, o: LoginOpts<'_>) -> Value {
    let key = o.key;
    let enc_or_null = |v: Option<&str>| v.map(|s| json!(e(s, key))).unwrap_or(Value::Null);
    let uris = match &o.uris {
        None => Value::Null,
        Some(list) => Value::Array(
            list.iter()
                .map(|(u, m)| json!({"uri": e(u, key), "match": m}))
                .collect(),
        ),
    };
    json!({
        "object": "cipherDetails",
        "id": iid,
        "organizationId": o.organization_id,
        "folderId": o.folder_id,
        "favorite": o.favorite,
        "reprompt": o.reprompt,
        "type": 1,
        "name": e(name, key),
        "notes": enc_or_null(o.notes),
        "fields": o.fields.unwrap_or(Value::Null),
        "login": {
            "username": enc_or_null(o.username),
            "password": enc_or_null(o.password),
            "totp": enc_or_null(o.totp),
            "uris": uris,
            "fido2Credentials": null,
            "autofillOnPageLoad": null,
            "passwordRevisionDate": null,
        },
        "card": null,
        "identity": null,
        "secureNote": null,
        "sshKey": null,
        "passwordHistory": o.password_history.unwrap_or(Value::Null),
        "attachments": o.attachments.unwrap_or(Value::Null),
        "collectionIds": [],
        "key": o.cipher_key,
        "creationDate": "2024-01-02T03:04:05.123456Z",
        "revisionDate": "2024-02-03T04:05:06.654321Z",
        "deletedDate": o.deleted,
        "archivedDate": o.archived,
        "organizationUseTotp": true,
        "edit": true,
        "viewPassword": true,
    })
}

pub fn note_item(iid: &str, name: &str, notes: &str, key: &[u8]) -> Value {
    let mut item = login_item(
        iid,
        name,
        LoginOpts {
            key,
            uris: None,
            username: None,
            password: None,
            ..Default::default()
        },
    );
    item["type"] = json!(2);
    item["login"] = Value::Null;
    item["secureNote"] = json!({"type": 0});
    item["notes"] = json!(e(notes, key));
    item
}

pub fn sync_payload(ciphers: Vec<Value>, folders: Option<Vec<Value>>) -> Value {
    json!({
        "profile": {"id": &CLIENT_ID[5..], "email": EMAIL, "key": enc2(&USER_KEY, &stretched()), "object": "profile"},
        "folders": folders.unwrap_or_else(|| vec![folder("f-1", "Work", &USER_KEY)]),
        "collections": [],
        "policies": [],
        "ciphers": ciphers,
        "domains": null,
        "sends": [],
        "object": "sync",
    })
}

// ---------------------------------------------------------------------------
// Scripted transport
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl Call {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
enum Scripted {
    Response(HttpResponse),
    NetworkError(String),
}

#[derive(Default)]
pub struct FakeHttp {
    pub calls: Vec<Call>,
    scripts: Vec<(String, VecDeque<Scripted>)>,
}

fn json_response(status: u16, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body,
    }
}

impl FakeHttp {
    pub fn new() -> Self {
        Self::default()
    }

    fn queue(&mut self, suffix: &str) -> &mut VecDeque<Scripted> {
        if let Some(pos) = self.scripts.iter().position(|(s, _)| s == suffix) {
            &mut self.scripts[pos].1
        } else {
            self.scripts.push((suffix.to_string(), VecDeque::new()));
            &mut self.scripts.last_mut().unwrap().1
        }
    }

    /// Queue JSON responses for a URL suffix. The last response repeats.
    pub fn on_json(mut self, suffix: &str, responses: Vec<(u16, Value)>) -> Self {
        for (status, body) in responses {
            self.queue(suffix)
                .push_back(Scripted::Response(json_response(
                    status,
                    body.to_string().into_bytes(),
                )));
        }
        self
    }

    /// Queue raw-body responses for a URL suffix.
    pub fn on_raw(mut self, suffix: &str, responses: Vec<(u16, &[u8])>) -> Self {
        for (status, body) in responses {
            self.queue(suffix)
                .push_back(Scripted::Response(json_response(status, body.to_vec())));
        }
        self
    }

    pub fn on_redirect(mut self, suffix: &str, location: &str) -> Self {
        self.queue(suffix)
            .push_back(Scripted::Response(HttpResponse {
                status: 302,
                headers: vec![("Location".into(), location.into())],
                body: Vec::new(),
            }));
        self
    }

    /// Make the next `count` requests to the suffix fail at the network level before the scripted responses.
    pub fn fail_first(mut self, suffix: &str, count: usize, message: &str) -> Self {
        let q = self.queue(suffix);
        for _ in 0..count {
            q.push_front(Scripted::NetworkError(message.to_string()));
        }
        self
    }

    pub fn requests_to(&self, suffix: &str) -> Vec<&Call> {
        self.calls
            .iter()
            .filter(|c| path_of(&c.url).ends_with(suffix))
            .collect()
    }
}

fn path_of(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

impl HttpTransport for FakeHttp {
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String> {
        self.calls.push(Call {
            method: method.to_string(),
            url: url.to_string(),
            headers: headers.to_vec(),
            body: body.map(|b| b.to_vec()),
        });
        let path = path_of(url).to_string();
        for (suffix, queue) in self.scripts.iter_mut() {
            if path.ends_with(suffix.as_str()) {
                let next = if queue.len() > 1 {
                    queue.pop_front().unwrap()
                } else {
                    queue
                        .front()
                        .cloned()
                        .unwrap_or_else(|| panic!("no scripted response left for {url}"))
                };
                return match next {
                    Scripted::Response(r) => Ok(r),
                    Scripted::NetworkError(m) => Err(m),
                };
            }
        }
        panic!("unexpected request {method} {url}");
    }
}

#[derive(Default)]
pub struct RecordingSleep {
    pub sleeps: Vec<Duration>,
}

impl Sleep for RecordingSleep {
    fn sleep(&mut self, duration: Duration) {
        self.sleeps.push(duration);
    }
}

pub fn happy_http(ciphers: Option<Vec<Value>>, mutate: impl FnOnce(&mut Value)) -> FakeHttp {
    let ciphers = ciphers.unwrap_or_else(|| {
        vec![login_item(
            "i-1",
            "Example",
            LoginOpts {
                folder_id: Some("f-1"),
                ..Default::default()
            },
        )]
    });
    let mut token = token_response();
    mutate(&mut token);
    FakeHttp::new()
        .on_json("/connect/token", vec![(200, token)])
        .on_json("/sync", vec![(200, sync_payload(ciphers, None))])
}

pub fn creds<'a>(
    server: &'a str,
    client_id: &'a str,
    ca_cert: Option<&'a Path>,
) -> Credentials<'a> {
    Credentials {
        server,
        client_id,
        client_secret: CLIENT_SECRET.as_bytes(),
        master_password: PASSWORD.as_bytes(),
        ca_cert,
    }
}

pub fn run_export_with(
    http: &mut FakeHttp,
    sleep: &mut RecordingSleep,
    server: &str,
    client_id: &str,
) -> Result<Value, VaultError> {
    let text = export_vault_json(&creds(server, client_id, None), http, sleep)?;
    Ok(serde_json::from_str(&text).expect("export is JSON"))
}

pub fn run_export(http: &mut FakeHttp, sleep: &mut RecordingSleep) -> Result<Value, VaultError> {
    run_export_with(http, sleep, SERVER, CLIENT_ID)
}

pub fn export_ok(http: &mut FakeHttp) -> Value {
    let mut sleep = RecordingSleep::default();
    run_export(http, &mut sleep).expect("export succeeds")
}

pub fn export_err(http: &mut FakeHttp) -> VaultError {
    let mut sleep = RecordingSleep::default();
    run_export(http, &mut sleep).expect_err("export fails")
}

// ---------------------------------------------------------------------------
// Log capture (thread-local; the code under test runs on the test thread)
// ---------------------------------------------------------------------------

thread_local! {
    static RECORDS: RefCell<Vec<(log::Level, String)>> = const { RefCell::new(Vec::new()) };
}

struct CaptureLogger;

impl log::Log for CaptureLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        RECORDS.with(|r| {
            r.borrow_mut()
                .push((record.level(), record.args().to_string()))
        });
    }
    fn flush(&self) {}
}

static LOGGER: CaptureLogger = CaptureLogger;
static INIT: Once = Once::new();

/// Install the capture logger once per process and clear this thread's records.
pub fn capture_logs() {
    INIT.call_once(|| {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(log::LevelFilter::Trace);
    });
    RECORDS.with(|r| r.borrow_mut().clear());
}

pub fn records() -> Vec<(log::Level, String)> {
    RECORDS.with(|r| r.borrow().clone())
}

pub fn log_text() -> String {
    records()
        .into_iter()
        .map(|(l, m)| format!("{l} {m}\n"))
        .collect()
}

/// Assert that every `@spec ID` cited in `test_file` is defined in `specs_file` (both repo-relative).
pub fn assert_cited_specs_exist(test_file: &str, specs_file: &str, prefix: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let specs = std::fs::read_to_string(root.join(specs_file)).expect("specs file");
    let tests = std::fs::read_to_string(root.join(test_file)).expect("test file");
    let defined: std::collections::HashSet<String> = ids(&specs, &format!("**{prefix}-"), "**");
    let cited: std::collections::HashSet<String> = ids(&tests, &format!("@spec {prefix}-"), "\n");
    let missing: Vec<_> = cited.difference(&defined).cloned().collect();
    assert!(missing.is_empty(), "cited but undefined: {missing:?}");
}

fn ids(text: &str, start: &str, end: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let bare = start.trim_start_matches("@spec ").trim_start_matches("**");
    for (i, _) in text.match_indices(start) {
        let rest = &text[i + start.len()..];
        let stop = rest.find(end).unwrap_or(rest.len());
        for id in rest[..stop].split(',') {
            let id = id.trim().trim_start_matches(bare);
            if !id.is_empty() {
                out.insert(format!("{bare}{id}"));
            }
        }
    }
    out
}
