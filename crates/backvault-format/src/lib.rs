//! The BackVault backup file format (backup-encryption segment).
//!
//! Layout: `version (4, BE) ‖ salt (16) ‖ nonce (12) ‖ AES-256-GCM ciphertext ‖ tag (16)`.
//! Version 2 derives the key with Argon2id; version 1 (read only) with PBKDF2-HMAC-SHA256.
//! This crate performs no file, network, or terminal IO.

use std::fmt;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Format version written by `encrypt`.
pub const VERSION: u32 = 2;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// Bytes before the ciphertext: version + salt + nonce.
pub const HEADER_LEN: usize = 4 + SALT_LEN + NONCE_LEN;

pub const ARGON2_TIME_COST: u32 = 3;
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Why a file could not be opened, or why encryption could not proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// Fewer than `HEADER_LEN` bytes: no complete header.
    Truncated,
    /// The version field is neither 1 nor 2.
    UnsupportedVersion(u32),
    /// Wrong password, or the salt, nonce, ciphertext, or tag was altered.
    Authentication,
    /// The operating system's random source failed.
    Random,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::Truncated => write!(f, "file is truncated: no complete header"),
            FormatError::UnsupportedVersion(v) => {
                write!(f, "unsupported encryption version: {v}")
            }
            FormatError::Authentication => {
                write!(f, "decryption failed: invalid password or corrupted file")
            }
            FormatError::Random => write!(f, "operating system random source failed"),
        }
    }
}

impl std::error::Error for FormatError {}

type Key = Zeroizing<[u8; KEY_LEN]>;

// @spec ENC-FORMAT-003, ENC-DECRYPT-003, ENC-DECRYPT-006
fn derive_v2(password: &[u8], salt: &[u8]) -> Key {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .expect("constant Argon2id parameters are valid");
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .expect("Argon2id with a 16-byte salt and 32-byte output cannot fail");
    key
}

// @spec ENC-DECRYPT-002
fn derive_v1(password: &[u8], salt: &[u8]) -> Key {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERATIONS, key.as_mut());
    key
}

/// Encrypt `plaintext` under `password` into a version-2 backup file image.
// @spec ENC-FORMAT-001, ENC-FORMAT-002, ENC-FORMAT-004, ENC-FORMAT-005
pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| FormatError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| FormatError::Random)?;
    let key = derive_v2(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| FormatError::Authentication)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a backup file image of any supported version.
// @spec ENC-DECRYPT-001, ENC-DECRYPT-004, ENC-DECRYPT-005, ENC-DECRYPT-007, ENC-DECRYPT-008
pub fn decrypt(file: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    if file.len() < HEADER_LEN {
        return Err(FormatError::Truncated);
    }
    let version = u32::from_be_bytes([file[0], file[1], file[2], file[3]]);
    let salt = &file[4..4 + SALT_LEN];
    let nonce: [u8; NONCE_LEN] = file[4 + SALT_LEN..HEADER_LEN].try_into().expect("12 bytes");
    let ciphertext = &file[HEADER_LEN..];
    let key = match version {
        1 => derive_v1(password, salt),
        2 => derive_v2(password, salt),
        other => return Err(FormatError::UnsupportedVersion(other)),
    };
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    cipher
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| FormatError::Authentication)
}
