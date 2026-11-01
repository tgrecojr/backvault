//! backup-encryption: the `.enc` format end to end (ENC-FORMAT, ENC-DECRYPT).

use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::Sha256;
use zeroize::Zeroizing;

use backvault_format::{
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST, FormatError, HEADER_LEN, KEY_LEN,
    NONCE_LEN, PBKDF2_ITERATIONS, SALT_LEN, TAG_LEN, VERSION, decrypt, encrypt,
};

const TEST_PASSWORD: &[u8] = "test-password-☃".as_bytes();
const TEST_DATA: &[u8] =
    br#"{"encrypted": false, "folders": [], "items": [{"id": "i-1", "name": "Example"}]}"#;
const FIXTURE_PASSWORD: &[u8] = b"fixture-password-2026";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Test-side version-1 writer with the documented parameters.
fn encrypt_v1(data: &[u8], password: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).unwrap();
    getrandom::fill(&mut nonce).unwrap();
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut key);
    let ct = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(&Nonce::try_from(&nonce[..]).unwrap(), data)
        .unwrap();
    [&1u32.to_be_bytes()[..], &salt, &nonce, &ct].concat()
}

// ---------------------------------------------------------------------------
// Constants shared by encryptor and decryptor
// ---------------------------------------------------------------------------

// @spec ENC-DECRYPT-006, ENC-DECRYPT-003
#[test]
fn argon2_parameters() {
    assert_eq!(ARGON2_TIME_COST, 3);
    assert_eq!(ARGON2_MEMORY_KIB, 65536);
    assert_eq!(ARGON2_PARALLELISM, 4);
}

// @spec ENC-DECRYPT-002
#[test]
fn pbkdf2_iterations() {
    assert_eq!(PBKDF2_ITERATIONS, 600_000);
}

// @spec ENC-FORMAT-001
#[test]
fn sizes() {
    assert_eq!(SALT_LEN, 16);
    assert_eq!(NONCE_LEN, 12);
    assert_eq!(KEY_LEN, 32);
    assert_eq!(TAG_LEN, 16);
    assert_eq!(HEADER_LEN, 32);
}

// @spec ENC-FORMAT-002
#[test]
fn encryption_version() {
    assert_eq!(VERSION, 2);
}

// ---------------------------------------------------------------------------
// Version 2
// ---------------------------------------------------------------------------

// @spec ENC-FORMAT-003, ENC-DECRYPT-003
#[test]
fn encrypt_decrypt_roundtrip() {
    let file = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    assert_eq!(decrypt(&file, TEST_PASSWORD).unwrap().as_slice(), TEST_DATA);
}

// @spec ENC-FORMAT-002
#[test]
fn version_header() {
    assert_eq!(u32_be(&encrypt(TEST_DATA, TEST_PASSWORD).unwrap()[..4]), 2);
}

// @spec ENC-FORMAT-001
#[test]
fn encrypted_data_structure() {
    let file = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    assert_eq!(file.len(), 4 + 16 + 12 + TEST_DATA.len() + 16);
}

// @spec ENC-FORMAT-005, ENC-FORMAT-003
#[test]
fn layout_decrypts_with_plain_aesgcm_and_argon2id() {
    let file = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    let (salt, nonce, ct) = (&file[4..20], &file[20..32], &file[32..]);
    let mut key = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 4, Some(32)).unwrap(),
    )
    .hash_password_into(TEST_PASSWORD, salt, &mut key)
    .unwrap();
    let plain = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(&Nonce::try_from(nonce).unwrap(), ct)
        .unwrap();
    assert_eq!(plain, TEST_DATA);
}

// @spec ENC-DECRYPT-005
#[test]
fn wrong_password_fails() {
    let file = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    assert_eq!(
        decrypt(&file, b"WrongPassword123!").unwrap_err(),
        FormatError::Authentication
    );
}

// @spec ENC-FORMAT-004
#[test]
fn different_password_different_output() {
    assert_ne!(
        encrypt(TEST_DATA, b"Password1").unwrap(),
        encrypt(TEST_DATA, b"Password2").unwrap()
    );
}

// @spec ENC-FORMAT-004
#[test]
fn same_password_different_output() {
    let e1 = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    let e2 = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    assert_ne!(e1, e2);
    assert_eq!(decrypt(&e1, TEST_PASSWORD).unwrap().as_slice(), TEST_DATA);
    assert_eq!(decrypt(&e2, TEST_PASSWORD).unwrap().as_slice(), TEST_DATA);
}

// @spec ENC-FORMAT-004
#[test]
fn salt_and_nonce_are_random() {
    let e1 = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    let e2 = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    assert_ne!(&e1[4..20], &e2[4..20]);
    assert_ne!(&e1[20..32], &e2[20..32]);
}

// @spec ENC-FORMAT-003
#[test]
fn empty_data() {
    let file = encrypt(b"", TEST_PASSWORD).unwrap();
    assert_eq!(decrypt(&file, TEST_PASSWORD).unwrap().len(), 0);
}

// @spec ENC-FORMAT-003
#[test]
fn large_data() {
    let large = vec![b'x'; 1024 * 1024];
    let file = encrypt(&large, TEST_PASSWORD).unwrap();
    assert_eq!(
        decrypt(&file, TEST_PASSWORD).unwrap().as_slice(),
        large.as_slice()
    );
}

// ---------------------------------------------------------------------------
// Version 1 stays readable
// ---------------------------------------------------------------------------

// @spec ENC-DECRYPT-002, ENC-DECRYPT-001
#[test]
fn version_1_decrypts() {
    let file = encrypt_v1(TEST_DATA, TEST_PASSWORD);
    assert_eq!(u32_be(&file[..4]), 1);
    assert_eq!(decrypt(&file, TEST_PASSWORD).unwrap().as_slice(), TEST_DATA);
}

// @spec ENC-DECRYPT-005
#[test]
fn version_1_wrong_password() {
    let file = encrypt_v1(TEST_DATA, TEST_PASSWORD);
    assert_eq!(
        decrypt(&file, b"WrongPassword").unwrap_err(),
        FormatError::Authentication
    );
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

// @spec ENC-DECRYPT-004
#[test]
fn unsupported_versions_rejected_before_key_derivation() {
    let body = &encrypt(TEST_DATA, TEST_PASSWORD).unwrap()[4..];
    for version in [0u32, 3, 999, u32::MAX] {
        let file = [&version.to_be_bytes()[..], body].concat();
        let started = std::time::Instant::now();
        assert_eq!(
            decrypt(&file, TEST_PASSWORD).unwrap_err(),
            FormatError::UnsupportedVersion(version)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "no KDF ran"
        );
    }
    assert!(
        FormatError::UnsupportedVersion(999)
            .to_string()
            .contains("999")
    );
}

// @spec ENC-DECRYPT-007
#[test]
fn truncated_inputs_rejected_before_key_derivation() {
    let valid = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    for len in [0usize, 3, 4, 12, 20, 31] {
        assert_eq!(
            decrypt(&valid[..len], TEST_PASSWORD).unwrap_err(),
            FormatError::Truncated,
            "len {len}"
        );
    }
    // A complete header with no ciphertext is not truncated; it fails authentication.
    assert_eq!(
        decrypt(&valid[..32], TEST_PASSWORD).unwrap_err(),
        FormatError::Authentication
    );
}

// @spec ENC-DECRYPT-005
#[test]
fn corrupted_ciphertext_salt_nonce_and_tag_fail() {
    let valid = encrypt(TEST_DATA, TEST_PASSWORD).unwrap();
    for index in [valid.len() - 10, 5, 20, valid.len() - 1] {
        let mut corrupted = valid.clone();
        corrupted[index] ^= 0xff;
        assert_eq!(
            decrypt(&corrupted, TEST_PASSWORD).unwrap_err(),
            FormatError::Authentication,
            "byte {index}"
        );
    }
}

// @spec ENC-FORMAT-003
#[test]
fn empty_very_long_nul_and_unicode_passwords() {
    for pw in [
        b"".to_vec(),
        vec![b'a'; 10_000],
        b"pass\x00word\x00test".to_vec(),
        "Pāšş🔐wørd".as_bytes().to_vec(),
    ] {
        let file = encrypt(TEST_DATA, &pw).unwrap();
        assert_eq!(decrypt(&file, &pw).unwrap().as_slice(), TEST_DATA);
        assert_eq!(
            decrypt(&file, b"not-the-same").unwrap_err(),
            FormatError::Authentication
        );
    }
}

// @spec ENC-FORMAT-003
#[test]
fn password_bytes_are_used_as_supplied() {
    let raw: &[u8] = &[0xff, 0xfe, b'p', b'w'];
    let file = encrypt(TEST_DATA, raw).unwrap();
    assert_eq!(decrypt(&file, raw).unwrap().as_slice(), TEST_DATA);
}

#[test]
fn special_characters_in_data() {
    let data = b"\x00\x01\xff\xfe Special chars: \xe2\x9c\x93\xe2\x9c\x97";
    let file = encrypt(data, TEST_PASSWORD).unwrap();
    assert_eq!(decrypt(&file, TEST_PASSWORD).unwrap().as_slice(), data);
}

// @spec ENC-DECRYPT-008
#[test]
fn plaintext_is_returned_in_a_zeroizing_buffer() {
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let out: Zeroizing<Vec<u8>> =
        decrypt(&encrypt(TEST_DATA, TEST_PASSWORD).unwrap(), TEST_PASSWORD).unwrap();
    assert_wiped_on_drop(&out);
}

// ---------------------------------------------------------------------------
// Fixtures: what past writers produced must open today
// ---------------------------------------------------------------------------

// @spec ENC-DECRYPT-009, ENC-DECRYPT-002
#[test]
fn fixture_v1_decrypts_to_plaintext() {
    let expected = fixture("plaintext.json");
    let file = fixture("v1.enc");
    assert_eq!(u32_be(&file[..4]), 1);
    assert_eq!(
        decrypt(&file, FIXTURE_PASSWORD).unwrap().as_slice(),
        expected.as_slice()
    );
}

// @spec ENC-DECRYPT-009, ENC-DECRYPT-003
#[test]
fn fixture_v2_decrypts_to_plaintext() {
    let expected = fixture("plaintext.json");
    let file = fixture("v2.enc");
    assert_eq!(u32_be(&file[..4]), 2);
    assert_eq!(
        decrypt(&file, FIXTURE_PASSWORD).unwrap().as_slice(),
        expected.as_slice()
    );
}

// @spec ENC-FORMAT-006
#[test]
fn crate_performs_no_io_and_depends_only_on_primitives() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps: Vec<&str> = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .lines()
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| {
            l.split('=')
                .next()
                .map(|n| n.trim().trim_end_matches(".workspace"))
        })
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let allowed = [
        "aes-gcm",
        "argon2",
        "pbkdf2",
        "sha2",
        "getrandom",
        "zeroize",
    ];
    for dep in &deps {
        assert!(allowed.contains(dep), "unexpected dependency {dep}");
    }
    let src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    for forbidden in ["std::fs", "std::net", "std::io", "std::process"] {
        assert!(
            !src.contains(forbidden),
            "format crate must not use {forbidden}"
        );
    }
}

#[test]
fn every_spec_cited_here_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let specs = std::fs::read_to_string(
        root.join("docs/intent/backup-encryption/backup-encryption-specs.md"),
    )
    .unwrap();
    let this =
        std::fs::read_to_string(root.join("crates/backvault-format/tests/format.rs")).unwrap();
    for line in this
        .lines()
        .filter(|l| l.trim_start().starts_with("// @spec "))
    {
        for id in line
            .split("@spec ")
            .nth(1)
            .unwrap()
            .split(',')
            .map(str::trim)
        {
            assert!(specs.contains(&format!("**{id}**")), "undefined spec {id}");
        }
    }
}
