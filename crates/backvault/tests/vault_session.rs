//! vault-access: the whole cycle over a scripted transport, retry policy, HTTP shaping, logging.

mod common;

use std::path::Path;
use std::time::Duration;

use common::*;
use serde_json::json;
use zeroize::Zeroizing;

use backvault::vault::http::{
    BODY_LIMIT, CONNECT_TIMEOUT, READ_TIMEOUT, UreqTransport, jwt_claim, server_message,
};
use backvault::vault::{REFERENCE_CLI_VERSION, VaultError, device_identifier, export_vault_json};

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Minimal application/x-www-form-urlencoded decoder for assertions.
fn form(body: &[u8]) -> Vec<(String, String)> {
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() - 1
                    || b'%' == bytes[i] && i + 2 < bytes.len() =>
                {
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                    out.push(u8::from_str_radix(hex, 16).unwrap());
                    i += 2;
                }
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8(out).unwrap()
    }
    std::str::from_utf8(body)
        .unwrap()
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> &'a str {
    &form
        .iter()
        .find(|(k, _)| k == name)
        .unwrap_or_else(|| panic!("no field {name}"))
        .1
}

// ---------------------------------------------------------------------------
// End-to-end over the fake transport
// ---------------------------------------------------------------------------

// @spec VAULT-SESSION-001, VAULT-SESSION-004
#[test]
fn one_token_request_then_one_sync() {
    let mut http = happy_http(None, |_| {});
    let export = export_ok(&mut http);
    let methods: Vec<&str> = http.calls.iter().map(|c| c.method.as_str()).collect();
    assert_eq!(methods, ["POST", "GET"]);
    assert_eq!(
        http.calls[0].url,
        format!("{SERVER}/identity/connect/token")
    );
    assert!(
        http.calls[1]
            .url
            .starts_with(&format!("{SERVER}/api/sync?"))
    );
    assert!(http.calls[1].url.contains("excludeDomains=true"));
    assert_eq!(export["items"][0]["name"], json!("Example"));
}

// @spec VAULT-AUTH-001
#[test]
fn token_request_form() {
    let mut http = happy_http(None, |_| {});
    export_ok(&mut http);
    let call = &http.calls[0];
    let f = form(call.body.as_deref().unwrap());
    assert_eq!(field(&f, "grant_type"), "client_credentials");
    assert_eq!(field(&f, "scope"), "api");
    assert_eq!(field(&f, "client_id"), CLIENT_ID);
    assert_eq!(field(&f, "client_secret"), CLIENT_SECRET);
    assert_eq!(field(&f, "deviceType"), "25");
    assert_eq!(field(&f, "deviceName"), "backvault");
    assert_eq!(field(&f, "deviceIdentifier"), device_identifier(CLIENT_ID));
    assert!(
        call.header("Content-Type")
            .unwrap()
            .starts_with("application/x-www-form-urlencoded")
    );
}

// @spec VAULT-SESSION-002
#[test]
fn master_password_and_keys_never_sent() {
    let mut http = happy_http(None, |_| {});
    export_ok(&mut http);
    for call in &http.calls {
        let mut blob = call.body.clone().unwrap_or_default();
        blob.extend(serde_json::to_vec(&call.headers).unwrap());
        for secret in [
            PASSWORD.as_bytes().to_vec(),
            b64(&master_key()).into_bytes(),
            b64(&USER_KEY).into_bytes(),
        ] {
            assert!(!blob.windows(secret.len()).any(|w| w == secret.as_slice()));
        }
    }
}

// @spec VAULT-HTTP-002
#[test]
fn client_headers_on_every_request() {
    let mut http = happy_http(None, |_| {});
    export_ok(&mut http);
    for call in &http.calls {
        assert_eq!(call.header("Bitwarden-Client-Name"), Some("cli"));
        assert_eq!(
            call.header("Bitwarden-Client-Version"),
            Some(REFERENCE_CLI_VERSION)
        );
    }
}

// @spec VAULT-SESSION-001
#[test]
fn bearer_token_used_for_sync() {
    let mut http = happy_http(None, |_| {});
    export_ok(&mut http);
    assert_eq!(
        http.calls[1].header("Authorization"),
        Some(format!("Bearer {}", fake_jwt(Some(EMAIL))).as_str())
    );
}

// @spec VAULT-AUTH-004
#[test]
fn email_from_salt_is_normalised() {
    // Salt is EMAIL_RAW with spaces and capitals; the key only derives if it is normalised.
    let mut http = happy_http(None, |_| {});
    assert!(!export_ok(&mut http)["items"].as_array().unwrap().is_empty());
}

// @spec VAULT-AUTH-004
#[test]
fn email_falls_back_to_jwt_claim() {
    let mut http = happy_http(None, |t| {
        t["UserDecryptionOptions"] =
            json!({"HasMasterPassword": true, "MasterPasswordUnlock": null});
    });
    assert!(!export_ok(&mut http)["items"].as_array().unwrap().is_empty());
}

// @spec VAULT-AUTH-004
#[test]
fn email_falls_back_to_profile_endpoint() {
    let mut http = happy_http(None, |t| {
        t["access_token"] = json!(fake_jwt(None));
        t["UserDecryptionOptions"] =
            json!({"HasMasterPassword": true, "MasterPasswordUnlock": null});
    })
    .on_json(
        "/accounts/profile",
        vec![(200, json!({"email": EMAIL_RAW, "object": "profile"}))],
    );
    assert!(!export_ok(&mut http)["items"].as_array().unwrap().is_empty());
    assert_eq!(http.requests_to("/accounts/profile").len(), 1);
}

// @spec VAULT-AUTH-004
#[test]
fn no_email_anywhere_fails() {
    let mut http = happy_http(None, |t| {
        t["access_token"] = json!(fake_jwt(None));
        t["UserDecryptionOptions"] =
            json!({"HasMasterPassword": true, "MasterPasswordUnlock": null});
    })
    .on_json(
        "/accounts/profile",
        vec![(200, json!({"object": "profile"}))],
    );
    assert!(matches!(export_err(&mut http), VaultError::NoEmail));
}

// @spec VAULT-AUTH-002
#[test]
fn missing_token_fields_fail_naming_field() {
    for missing in ["access_token", "Key", "Kdf", "KdfIterations"] {
        let mut http = happy_http(None, |t| t[missing] = serde_json::Value::Null);
        let err = export_err(&mut http);
        assert!(err.to_string().contains(missing), "{missing}: {err}");
        assert!(http.requests_to("/sync").is_empty());
    }
}

// @spec VAULT-AUTH-002
#[test]
fn wrongly_typed_token_fields_fail_naming_field() {
    for (name, value) in [
        ("KdfIterations", json!("5000")),
        ("Kdf", json!("0")),
        ("Key", json!(42)),
    ] {
        let mut http = happy_http(None, |t| t[name] = value.clone());
        let err = export_err(&mut http);
        assert!(err.to_string().contains(name), "{name}: {err}");
        assert!(http.requests_to("/sync").is_empty());
    }
}

// @spec VAULT-AUTH-003
#[test]
fn unsupported_kdf_fails() {
    let mut http = happy_http(None, |t| t["Kdf"] = json!(5));
    assert!(export_err(&mut http).to_string().contains("KDF"));
}

// @spec VAULT-AUTH-010
#[test]
fn profile_key_not_used_when_token_key_missing() {
    let mut http = happy_http(None, |t| t["Key"] = serde_json::Value::Null);
    assert!(export_err(&mut http).to_string().contains("Key"));
}

// @spec VAULT-AUTH-006
#[test]
fn argon2_account_end_to_end() {
    use argon2::{Algorithm, Argon2, Params, Version};
    let mut argon_master = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(16 * 1024, 3, 2, Some(32)).unwrap(),
    )
    .hash_password_into(
        PASSWORD.as_bytes(),
        &sha256(EMAIL.as_bytes()),
        &mut argon_master,
    )
    .unwrap();
    let wrapped = enc2(&USER_KEY, &stretch_for_test(&argon_master));
    let mut http = happy_http(None, |t| {
        t["Kdf"] = json!(1);
        t["KdfIterations"] = json!(3);
        t["KdfMemory"] = json!(16);
        t["KdfParallelism"] = json!(2);
        t["Key"] = json!(wrapped);
    });
    assert!(!export_ok(&mut http)["items"].as_array().unwrap().is_empty());
}

// @spec VAULT-EXPORT-001, VAULT-SESSION-003
#[test]
fn returns_zeroizing_string_in_memory() {
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let mut http = happy_http(None, |_| {});
    let mut sleep = RecordingSleep::default();
    let text: Zeroizing<String> =
        export_vault_json(&creds(SERVER, CLIENT_ID, None), &mut http, &mut sleep).unwrap();
    assert_wiped_on_drop(&text);
    assert!(text.starts_with("{\n  \"encrypted\": false"));
}

// @spec VAULT-EXPORT-004
#[test]
fn failures_surface_as_vault_error() {
    let mut http = FakeHttp::new()
        .on_json("/connect/token", vec![(200, token_response())])
        .on_json("/sync", vec![(200, json!({"object": "nope"}))]);
    let err = export_err(&mut http);
    assert!(matches!(err, VaultError::Payload(_)), "{err}");
}

// @spec VAULT-LOG-002
#[test]
fn secrets_never_logged() {
    capture_logs();
    let mut http = happy_http(None, |_| {});
    export_ok(&mut http);
    let text = log_text();
    for secret in [
        PASSWORD.to_string(),
        CLIENT_SECRET.to_string(),
        fake_jwt(Some(EMAIL)),
        b64(&master_key()),
        b64(&stretched()),
        b64(&USER_KEY),
        "hunter2".to_string(),
    ] {
        assert!(
            !text.contains(&secret),
            "log contains secret material: {text}"
        );
    }
}

// @spec VAULT-LOG-004
#[test]
fn info_summary_logged() {
    capture_logs();
    let mut http = happy_http(None, |_| {});
    export_ok(&mut http);
    let infos: Vec<String> = records()
        .into_iter()
        .filter(|(l, _)| *l == log::Level::Info)
        .map(|(_, m)| m)
        .collect();
    let text = infos.join("\n");
    assert!(text.contains("vault.example.test"), "{text}");
    assert!(
        text.contains("PBKDF2") || text.to_lowercase().contains("kdf"),
        "{text}"
    );
    assert!(
        text.contains("1 items") || text.contains("1 item"),
        "{text}"
    );
    assert!(
        text.contains("token") && text.contains("sync") && text.contains("decrypt"),
        "{text}"
    );
}

// @spec VAULT-EXPORT-007
#[test]
fn attachment_warning_logged() {
    capture_logs();
    let item = login_item(
        "a",
        "A",
        LoginOpts {
            attachments: Some(json!([{"id": "x", "fileName": e("f", &USER_KEY), "size": "1"}])),
            ..Default::default()
        },
    );
    let mut http = happy_http(Some(vec![item]), |_| {});
    export_ok(&mut http);
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Warn && m.to_lowercase().contains("attachment"))
    );
}

// @spec VAULT-LOG-005
#[test]
fn undecryptable_total_logged_at_error() {
    capture_logs();
    let mut item = login_item("i-1", "Ex", Default::default());
    item["login"]["password"] = json!(e("x", &[0u8; 64]));
    let mut http = happy_http(Some(vec![item]), |_| {});
    export_ok(&mut http);
    assert!(records().iter().any(|(l, m)| *l == log::Level::Error
        && m.contains('1')
        && m.to_lowercase().contains("decrypt")));
}

// @spec VAULT-LOG-006
#[test]
fn error_display_names_stage_and_carries_no_secrets() {
    let mut http = FakeHttp::new().on_json(
        "/connect/token",
        vec![(
            401,
            json!({"error": "invalid_client", "error_description": "Client version too old"}),
        )],
    );
    let err = export_err(&mut http).to_string();
    assert!(
        err.contains("401") && err.contains("Client version too old"),
        "{err}"
    );
    let item = login_item(
        "i-bad",
        "X",
        LoginOpts {
            cipher_key: Some(enc2(&[0u8; 64], &[0u8; 64])),
            ..Default::default()
        },
    );
    let mut http = happy_http(Some(vec![item]), |_| {});
    let err2 = export_err(&mut http).to_string();
    assert!(err2.contains("i-bad"), "{err2}");
    for text in [&err, &err2] {
        for secret in [
            PASSWORD.to_string(),
            CLIENT_SECRET.to_string(),
            b64(&master_key()),
            b64(&USER_KEY),
            fake_jwt(Some(EMAIL)),
        ] {
            assert!(!text.contains(&secret), "{text}");
        }
    }
}

// ---------------------------------------------------------------------------
// Retry and HTTP shaping
// ---------------------------------------------------------------------------

// @spec VAULT-RETRY-001
#[test]
fn token_5xx_then_success_retries_with_backoff() {
    let mut http = FakeHttp::new()
        .on_raw("/connect/token", vec![(503, b"busy")])
        .on_json("/connect/token", vec![(200, token_response())])
        .on_json(
            "/sync",
            vec![(
                200,
                sync_payload(vec![login_item("i-1", "Ex", Default::default())], None),
            )],
        );
    let mut sleep = RecordingSleep::default();
    run_export(&mut http, &mut sleep).unwrap();
    assert_eq!(http.requests_to("/connect/token").len(), 2);
    assert_eq!(sleep.sleeps, [Duration::from_secs(2)]);
}

// @spec VAULT-RETRY-001
#[test]
fn sync_429_three_failures_then_cycle_fails() {
    let mut http = FakeHttp::new()
        .on_json("/connect/token", vec![(200, token_response())])
        .on_raw(
            "/sync",
            vec![
                (429, b"slow down"),
                (429, b"slow down"),
                (429, b"slow down"),
            ],
        );
    let mut sleep = RecordingSleep::default();
    let err = run_export(&mut http, &mut sleep).unwrap_err();
    assert!(
        matches!(err, VaultError::Exhausted { attempts: 3, .. }),
        "{err}"
    );
    assert_eq!(http.requests_to("/sync").len(), 3);
    assert_eq!(
        sleep.sleeps,
        [Duration::from_secs(2), Duration::from_secs(4)]
    );
}

// @spec VAULT-RETRY-001
#[test]
fn network_error_retried() {
    let mut http = FakeHttp::new()
        .on_json("/connect/token", vec![(200, token_response())])
        .on_json("/sync", vec![(200, sync_payload(vec![], None))])
        .fail_first("/connect/token", 1, "connection reset");
    export_ok(&mut http);
    assert_eq!(http.requests_to("/connect/token").len(), 2);
}

// @spec VAULT-HTTP-006
#[test]
fn timeout_is_a_network_error_and_retried() {
    let mut http = FakeHttp::new()
        .on_json("/connect/token", vec![(200, token_response())])
        .on_json("/sync", vec![(200, sync_payload(vec![], None))])
        .fail_first("/sync", 2, "timed out reading body");
    let mut sleep = RecordingSleep::default();
    run_export(&mut http, &mut sleep).unwrap();
    assert_eq!(http.requests_to("/sync").len(), 3);
    assert_eq!(
        sleep.sleeps,
        [Duration::from_secs(2), Duration::from_secs(4)]
    );
}

// @spec VAULT-RETRY-002
#[test]
fn token_rejection_not_retried_and_surfaces_server_message() {
    for status in [400u16, 401, 403] {
        let mut http = FakeHttp::new().on_json(
            "/connect/token",
            vec![(
                status,
                json!({"error": "invalid_client", "error_description": "Client version too old"}),
            )],
        );
        let mut sleep = RecordingSleep::default();
        let err = run_export(&mut http, &mut sleep).unwrap_err();
        assert!(
            err.to_string().contains("Client version too old"),
            "{status}: {err}"
        );
        assert_eq!(http.requests_to("/connect/token").len(), 1);
        assert!(sleep.sleeps.is_empty());
    }
}

// @spec VAULT-RETRY-003
#[test]
fn sync_rejection_not_retried_no_new_token() {
    for status in [401u16, 403] {
        let mut http = FakeHttp::new()
            .on_json("/connect/token", vec![(200, token_response())])
            .on_raw("/sync", vec![(status, b"denied")]);
        let err = export_err(&mut http);
        assert!(matches!(err, VaultError::Rejected { .. }), "{err}");
        assert_eq!(http.requests_to("/connect/token").len(), 1);
        assert_eq!(http.requests_to("/sync").len(), 1);
    }
}

// @spec VAULT-HTTP-003
#[test]
fn not_found_mentions_server_setting() {
    let mut http = FakeHttp::new().on_raw("/connect/token", vec![(404, b"not found")]);
    assert!(export_err(&mut http).to_string().contains("BW_SERVER"));
}

// @spec VAULT-HTTP-004
#[test]
fn redirect_not_followed_and_named() {
    let mut http = FakeHttp::new().on_redirect(
        "/connect/token",
        "https://elsewhere.test/identity/connect/token",
    );
    let err = export_err(&mut http);
    assert!(err.to_string().contains("elsewhere.test"), "{err}");
    assert_eq!(http.calls.len(), 1);
}

// @spec VAULT-HTTP-005
#[test]
fn non_json_body_fails() {
    let mut http = FakeHttp::new().on_raw("/connect/token", vec![(200, b"<html>proxy</html>")]);
    assert!(matches!(export_err(&mut http), VaultError::NotJson(200)));
}

// @spec VAULT-LOG-003
#[test]
fn http_failure_logged_with_status_and_body() {
    capture_logs();
    let mut http = FakeHttp::new().on_json(
        "/connect/token",
        vec![(400, json!({"error_description": "Bad client"}))],
    );
    export_err(&mut http);
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Error && m.contains("400") && m.contains("Bad client"))
    );
}

// @spec VAULT-RETRY-002
#[test]
fn server_message_extraction() {
    assert_eq!(server_message(br#"{"error_description": "a"}"#), "a");
    assert_eq!(server_message(br#"{"message": "b"}"#), "b");
    assert_eq!(server_message(br#"{"Message": "c"}"#), "c");
    assert_eq!(server_message(br#"{"ErrorModel": {"Message": "d"}}"#), "d");
    assert_eq!(server_message(b"not json"), "");
    assert_eq!(server_message(b"[1,2]"), "");
}

// @spec VAULT-AUTH-004
#[test]
fn jwt_claim_reads_payload_without_verification() {
    assert_eq!(
        jwt_claim(&fake_jwt(Some(EMAIL)), "email").as_deref(),
        Some(EMAIL)
    );
    assert_eq!(jwt_claim(&fake_jwt(None), "email"), None);
    assert_eq!(jwt_claim("garbage", "email"), None);
}

// ---------------------------------------------------------------------------
// Production transport configuration
// ---------------------------------------------------------------------------

fn root_count(t: &UreqTransport) -> usize {
    match t.config().tls_config().root_certs() {
        ureq::tls::RootCerts::Specific(certs) => certs.len(),
        other => panic!("expected an explicit root list, got {other:?}"),
    }
}

// @spec VAULT-HTTP-001, VAULT-HTTP-004, VAULT-HTTP-006
#[test]
fn default_transport_verifies_tls_refuses_redirects_and_times_out() {
    let t = UreqTransport::new(None).unwrap();
    let cfg = t.config();
    assert_eq!(cfg.max_redirects(), 0);
    assert!(!cfg.http_status_as_error());
    assert!(!cfg.tls_config().disable_verification());
    assert_eq!(cfg.timeouts().connect, Some(CONNECT_TIMEOUT));
    assert_eq!(cfg.timeouts().recv_body, Some(READ_TIMEOUT));
    assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(30));
    assert_eq!(READ_TIMEOUT, Duration::from_secs(120));
    assert_eq!(BODY_LIMIT, 256 * 1024 * 1024);
    assert!(
        root_count(&t) > 100,
        "built-in Mozilla root store is present"
    );
}

// @spec VAULT-HTTP-001, VAULT-HTTP-007
#[test]
fn transport_trusts_extra_bundle_in_addition_to_built_in_roots() {
    let base = root_count(&UreqTransport::new(None).unwrap());
    let t = UreqTransport::new(Some(&fixture("test-ca.pem"))).unwrap();
    assert_eq!(root_count(&t), base + 1);
    assert!(!t.config().tls_config().disable_verification());
}

// @spec VAULT-HTTP-007
#[test]
fn transport_rejects_missing_or_certificate_free_bundle() {
    let missing = fixture("nope.pem");
    let err = UreqTransport::new(Some(&missing)).unwrap_err();
    assert!(matches!(err, VaultError::CaCert(_)), "{err}");
    assert!(err.to_string().contains("nope.pem"));
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "just text, no certificate\n").unwrap();
    let err = UreqTransport::new(Some(&empty)).unwrap_err();
    assert!(matches!(err, VaultError::CaCert(_)), "{err}");
}

// @spec VAULT-HTTP-007
#[test]
fn export_fails_before_any_request_when_bundle_is_bad() {
    use backvault::vault::export_vault_json_default;
    let missing = fixture("nope.pem");
    let err = export_vault_json_default(&creds(SERVER, CLIENT_ID, Some(&missing))).unwrap_err();
    assert!(matches!(err, VaultError::CaCert(_)), "{err}");
}

#[test]
fn every_spec_cited_here_exists() {
    assert_cited_specs_exist(
        "crates/backvault/tests/vault_session.rs",
        "docs/intent/vault-access/vault-access-specs.md",
        "VAULT",
    );
}
