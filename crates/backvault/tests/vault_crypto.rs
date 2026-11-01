//! vault-access: endpoints, key derivation, EncString decryption, dates.

mod common;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use common::*;

use backvault::vault::crypto::{
    EncError, decrypt_enc_string, decrypt_enc_string_bytes, derive_master_key, stretch_key,
    unwrap_user_key,
};
use backvault::vault::export::normalize_date;
use backvault::vault::{REFERENCE_CLI_VERSION, VaultError, device_identifier, resolve_endpoints};

fn field_err<T: std::fmt::Debug>(r: Result<T, EncError>) {
    match r {
        Err(EncError::Field(_)) => {}
        other => panic!("expected a field-level failure, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Endpoints, device, version constant
// ---------------------------------------------------------------------------

// @spec VAULT-SESSION-005
#[test]
fn self_hosted_paths_and_trailing_slash() {
    let (identity, api) = resolve_endpoints("https://vault.example.test//").unwrap();
    assert_eq!(identity, "https://vault.example.test/identity");
    assert_eq!(api, "https://vault.example.test/api");
}

// @spec VAULT-SESSION-005
#[test]
fn cloud_hosts() {
    assert_eq!(
        resolve_endpoints("https://vault.bitwarden.com").unwrap(),
        (
            "https://identity.bitwarden.com".to_string(),
            "https://api.bitwarden.com".to_string()
        )
    );
    assert_eq!(
        resolve_endpoints("https://vault.bitwarden.eu").unwrap(),
        (
            "https://identity.bitwarden.eu".to_string(),
            "https://api.bitwarden.eu".to_string()
        )
    );
}

// @spec VAULT-SESSION-005
#[test]
fn non_https_scheme_fails_before_any_request() {
    let mut http = FakeHttp::new();
    let mut sleep = RecordingSleep::default();
    let err = run_export_with(
        &mut http,
        &mut sleep,
        "http://vault.example.test",
        CLIENT_ID,
    )
    .unwrap_err();
    assert!(err.to_string().contains("https"), "{err}");
    assert!(http.calls.is_empty());
}

// @spec VAULT-SESSION-006
#[test]
fn organization_client_id_rejected_before_any_request() {
    let mut http = FakeHttp::new();
    let mut sleep = RecordingSleep::default();
    let err = run_export_with(
        &mut http,
        &mut sleep,
        SERVER,
        "organization.0b3c6e2a-9d44-4c4e-8d4e-1a2b3c4d5e6f",
    )
    .unwrap_err();
    assert!(err.to_string().contains("organization"), "{err}");
    assert!(http.calls.is_empty());
}

// @spec VAULT-AUTH-001
#[test]
fn device_identifier_is_stable_uuid5() {
    let expected = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("backvault:{CLIENT_ID}").as_bytes(),
    )
    .to_string();
    assert_eq!(device_identifier(CLIENT_ID), expected);
    assert_eq!(device_identifier(CLIENT_ID), device_identifier(CLIENT_ID));
}

// @spec VAULT-HTTP-002
#[test]
fn reference_cli_version_is_recent_enough() {
    let parts: Vec<u32> = REFERENCE_CLI_VERSION
        .split('.')
        .map(|p| p.parse().unwrap())
        .collect();
    assert_eq!(parts.len(), 3);
    assert!((parts[0], parts[1], parts[2]) >= (2024, 12, 0));
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

// @spec VAULT-AUTH-005
#[test]
fn pbkdf2_master_key() {
    let key = derive_master_key(PASSWORD.as_bytes(), EMAIL, 0, ITERATIONS, None, None).unwrap();
    assert_eq!(key.as_slice(), master_key().as_slice());
}

// @spec VAULT-AUTH-004
#[test]
fn email_is_trimmed_and_lowercased_by_caller_contract() {
    let normalised = EMAIL_RAW.trim().to_lowercase();
    let key =
        derive_master_key(PASSWORD.as_bytes(), &normalised, 0, ITERATIONS, None, None).unwrap();
    assert_eq!(key.as_slice(), master_key().as_slice());
}

// @spec VAULT-AUTH-007
#[test]
fn password_bytes_are_raw_no_normalisation() {
    let decomposed = "pa\u{0308}sswo\u{0308}rd"; // NFD
    let composed = "pässwörd"; // NFC
    let k1 = derive_master_key(decomposed.as_bytes(), EMAIL, 0, ITERATIONS, None, None).unwrap();
    let k2 = derive_master_key(composed.as_bytes(), EMAIL, 0, ITERATIONS, None, None).unwrap();
    assert_ne!(k1.as_slice(), k2.as_slice());
    let k3 = derive_master_key(b" pw ", EMAIL, 0, ITERATIONS, None, None).unwrap();
    let k4 = derive_master_key(b"pw", EMAIL, 0, ITERATIONS, None, None).unwrap();
    assert_ne!(k3.as_slice(), k4.as_slice());
    // Non-UTF-8 bytes are accepted exactly as supplied.
    derive_master_key(&[0xff, 0xfe, b'p'], EMAIL, 0, ITERATIONS, None, None).unwrap();
}

// @spec VAULT-AUTH-006
#[test]
fn argon2id_master_key_matches_reference_parameters() {
    let mut expected = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(16 * 1024, 3, 2, Some(32)).unwrap(),
    )
    .hash_password_into(
        PASSWORD.as_bytes(),
        &sha256(EMAIL.as_bytes()),
        &mut expected,
    )
    .unwrap();
    let key = derive_master_key(PASSWORD.as_bytes(), EMAIL, 1, 3, Some(16), Some(2)).unwrap();
    assert_eq!(key.as_slice(), &expected);
}

// @spec VAULT-AUTH-006
#[test]
fn argon2id_requires_memory_and_parallelism() {
    let err = derive_master_key(PASSWORD.as_bytes(), EMAIL, 1, 3, None, Some(2)).unwrap_err();
    assert!(matches!(err, VaultError::Argon2Params), "{err}");
}

// @spec VAULT-AUTH-003
#[test]
fn unknown_kdf_type_rejected() {
    let err = derive_master_key(PASSWORD.as_bytes(), EMAIL, 7, ITERATIONS, None, None).unwrap_err();
    assert!(err.to_string().contains("KDF"), "{err}");
}

// @spec VAULT-AUTH-008
#[test]
fn stretch_key_matches_bitwarden_sdk_vector() {
    let key: [u8; 32] = [
        31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69, 167,
        254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
    ];
    let enc: [u8; 32] = [
        111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142, 134, 120,
        249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96,
    ];
    let mac: [u8; 32] = [
        221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127, 166,
        209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155,
    ];
    assert_eq!(stretch_key(&key).as_slice(), [enc, mac].concat().as_slice());
}

// @spec VAULT-AUTH-009
#[test]
fn unwrap_type2_user_key_yields_64_bytes() {
    let out = unwrap_user_key(&enc2(&USER_KEY, &stretched()), &master_key()).unwrap();
    assert_eq!(out.as_slice(), &USER_KEY);
}

// @spec VAULT-AUTH-009
#[test]
fn unwrap_type0_user_key_yields_32_bytes() {
    let legacy: Vec<u8> = (0..32).collect();
    let out = unwrap_user_key(&enc0(&legacy, &master_key()), &master_key()).unwrap();
    assert_eq!(out.as_slice(), legacy.as_slice());
}

// @spec VAULT-AUTH-009
#[test]
fn unwrap_rejects_unexpected_lengths() {
    for length in [16usize, 48, 65] {
        let err =
            unwrap_user_key(&enc2(&vec![0u8; length], &stretched()), &master_key()).unwrap_err();
        assert!(err.to_string().contains("length"), "{length}: {err}");
    }
}

// @spec VAULT-CRYPTO-007
#[test]
fn unwrap_with_wrong_master_key_fails_the_cycle() {
    let err = unwrap_user_key(&enc2(&USER_KEY, &stretched()), &[0u8; 32]).unwrap_err();
    assert!(err.to_string().contains("key"), "{err}");
}

// ---------------------------------------------------------------------------
// EncString decryption
// ---------------------------------------------------------------------------

// @spec VAULT-CRYPTO-001
#[test]
fn type2_roundtrip() {
    assert_eq!(
        decrypt_enc_string(Some(&e("héllo ☃", &USER_KEY)), &USER_KEY).unwrap(),
        Some("héllo ☃".to_string())
    );
}

// @spec VAULT-CRYPTO-001
#[test]
fn type2_mac_mismatch_is_field_failure() {
    let value = e("secret", &USER_KEY);
    let mut parts = value.split('|');
    let head = parts.next().unwrap();
    let ct = parts.next().unwrap();
    let mac = parts.next().unwrap();
    let mut tampered = base64::engine::general_purpose::STANDARD
        .decode(ct)
        .unwrap();
    tampered[0] ^= 0xff;
    field_err(decrypt_enc_string(
        Some(&format!("{head}|{}|{mac}", b64(&tampered))),
        &USER_KEY,
    ));
}

// @spec VAULT-CRYPTO-001
#[test]
fn type2_wrong_key_is_field_failure() {
    field_err(decrypt_enc_string(
        Some(&e("secret", &USER_KEY)),
        &[0u8; 64],
    ));
}

// @spec VAULT-CRYPTO-002
#[test]
fn type0_decrypts_with_32_byte_key() {
    let key32: Vec<u8> = (0..32).collect();
    assert_eq!(
        decrypt_enc_string(Some(&enc0(b"legacy", &key32)), &key32).unwrap(),
        Some("legacy".to_string())
    );
}

// @spec VAULT-CRYPTO-003
#[test]
fn type2_with_32_byte_key_is_field_failure() {
    field_err(decrypt_enc_string(
        Some(&e("x", &USER_KEY)),
        &USER_KEY[..32],
    ));
}

// @spec VAULT-CRYPTO-003
#[test]
fn type0_with_64_byte_key_is_field_failure() {
    field_err(decrypt_enc_string(
        Some(&enc0(b"x", &USER_KEY[..32])),
        &USER_KEY,
    ));
}

// @spec VAULT-CRYPTO-004
#[test]
fn unimplemented_types_fail_the_cycle() {
    for etype in [1u32, 3, 4, 5, 6, 7] {
        let value = format!(
            "{etype}.{}|{}|{}",
            b64(&[0u8; 16]),
            b64(&[0u8; 32]),
            b64(&[0u8; 32])
        );
        match decrypt_enc_string(Some(&value), &USER_KEY) {
            Err(EncError::Fatal(err)) => {
                assert!(err.to_string().contains(&etype.to_string()), "{err}")
            }
            other => panic!("type {etype}: expected fatal, got {other:?}"),
        }
    }
}

// @spec VAULT-CRYPTO-005
#[test]
fn empty_string_is_absent() {
    assert_eq!(decrypt_enc_string(Some(""), &USER_KEY).unwrap(), None);
    assert_eq!(decrypt_enc_string(None, &USER_KEY).unwrap(), None);
}

// @spec VAULT-CRYPTO-005
#[test]
fn malformed_values_are_field_failures() {
    let iv = b64(&[0u8; 16]);
    let ct = b64(&[0u8; 32]);
    let mac = b64(&[0u8; 32]);
    let cases = [
        "no-type-prefix|abc|def".to_string(),
        format!("2.{iv}|{ct}"),                     // missing mac part
        format!("2.!!!|{ct}|{mac}"),                // non-base64
        format!("2.{}|{ct}|{mac}", b64(&[0u8; 4])), // short iv
        format!("2.{iv}|{ct}|{}", b64(&[0u8; 4])),  // short mac
        format!("x.{iv}|{ct}|{mac}"),               // non-numeric type
    ];
    for value in cases {
        field_err(decrypt_enc_string(Some(&value), &USER_KEY));
    }
}

// @spec VAULT-CRYPTO-005
#[test]
fn non_utf8_plaintext_is_field_failure() {
    field_err(decrypt_enc_string(
        Some(&enc2(&[0xff, 0xfe, 0xfd], &USER_KEY)),
        &USER_KEY,
    ));
}

// @spec VAULT-CRYPTO-001
#[test]
fn bytes_variant_returns_raw_bytes() {
    let out = decrypt_enc_string_bytes(&enc2(&[0xff, 0xfe], &USER_KEY), &USER_KEY).unwrap();
    assert_eq!(out.as_slice(), &[0xff, 0xfe]);
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

// @spec VAULT-EXPORT-011
#[test]
fn normalize_to_milliseconds_utc() {
    let cases = [
        ("2024-01-02T03:04:05.123456Z", "2024-01-02T03:04:05.123Z"),
        ("2024-01-02T03:04:05.1234567Z", "2024-01-02T03:04:05.123Z"),
        ("2024-01-02T03:04:05Z", "2024-01-02T03:04:05.000Z"),
        ("2024-01-02T03:04:05.5Z", "2024-01-02T03:04:05.500Z"),
        ("2024-01-02T04:04:05.123+01:00", "2024-01-02T03:04:05.123Z"),
        ("2024-01-02T03:04:05.123+00:00", "2024-01-02T03:04:05.123Z"),
        ("2024-01-02T03:04:05.1239Z", "2024-01-02T03:04:05.123Z"),
    ];
    for (raw, expected) in cases {
        assert_eq!(
            normalize_date(Some(raw)).unwrap().as_deref(),
            Some(expected),
            "{raw}"
        );
    }
}

// @spec VAULT-EXPORT-011
#[test]
fn none_passes_through() {
    assert_eq!(normalize_date(None).unwrap(), None);
}

// @spec VAULT-EXPORT-011
#[test]
fn date_without_offset_or_garbage_is_an_error() {
    for raw in [
        "2024-01-02T03:04:05",
        "yesterday",
        "2024-01-02 03:04:05Z",
        "",
    ] {
        let err = normalize_date(Some(raw)).unwrap_err();
        assert!(matches!(err, VaultError::Date(_)), "{raw}: {err}");
    }
}

#[test]
fn every_spec_cited_here_exists() {
    assert_cited_specs_exist(
        "crates/backvault/tests/vault_crypto.rs",
        "docs/intent/vault-access/vault-access-specs.md",
        "VAULT",
    );
}
