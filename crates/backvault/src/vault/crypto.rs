//! Bitwarden account cryptography: master key, HKDF stretch, EncString decryption, user-key unwrap.
//! Reference: bitwarden/sdk-internal crates/bitwarden-crypto. Only what a read-only export needs.

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::VaultError;

pub const KDF_PBKDF2: i64 = 0;
pub const KDF_ARGON2ID: i64 = 1;
pub const ENC_TYPE_AES_CBC_256: u32 = 0;
pub const ENC_TYPE_AES_CBC_256_HMAC: u32 = 2;
pub const AES_KEY_LEN: usize = 32;
pub const AES_HMAC_KEY_LEN: usize = 64;
pub const IV_LEN: usize = 16;
pub const MAC_LEN: usize = 32;

/// Outcome of decrypting one EncString.
#[derive(Debug)]
pub enum EncError {
    /// This one value cannot be read (bad MAC, padding, malformed, non-UTF-8). The caller decides.
    Field(String),
    /// The client lacks the capability (EncString type not implemented). Ends the cycle.
    Fatal(VaultError),
}

impl std::fmt::Display for EncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncError::Field(m) => f.write_str(m),
            EncError::Fatal(e) => write!(f, "{e}"),
        }
    }
}

fn field(message: &str) -> EncError {
    EncError::Field(message.to_string())
}

/// Derive the 32-byte master key. `email` must already be trimmed and lower-cased.
// @spec VAULT-AUTH-003, VAULT-AUTH-005, VAULT-AUTH-006, VAULT-AUTH-007
pub fn derive_master_key(
    password: &[u8],
    email: &str,
    kdf: i64,
    iterations: u32,
    memory_mib: Option<u32>,
    parallelism: Option<u32>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut key = Zeroizing::new(vec![0u8; AES_KEY_LEN]);
    match kdf {
        KDF_PBKDF2 => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password, email.as_bytes(), iterations, &mut key);
        }
        KDF_ARGON2ID => {
            let (memory, lanes) = match (memory_mib, parallelism) {
                (Some(m), Some(p)) => (m, p),
                _ => return Err(VaultError::Argon2Params),
            };
            let params = Params::new(memory * 1024, iterations, lanes, Some(AES_KEY_LEN))
                .map_err(|_| VaultError::Argon2Params)?;
            let salt = Sha256::digest(email.as_bytes());
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password, &salt, &mut key)
                .map_err(|_| VaultError::Argon2Params)?;
        }
        other => return Err(VaultError::UnsupportedKdf(other)),
    }
    Ok(key)
}

/// HKDF-Expand-SHA256 the master key into enc (info "enc") ‖ mac (info "mac"), 64 bytes.
// @spec VAULT-AUTH-008
pub fn stretch_key(master_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let hk = Hkdf::<Sha256>::from_prk(master_key).expect("master key is at least 32 bytes");
    let mut out = Zeroizing::new(vec![0u8; AES_HMAC_KEY_LEN]);
    hk.expand(b"enc", &mut out[..AES_KEY_LEN])
        .expect("32-byte expand");
    hk.expand(b"mac", &mut out[AES_KEY_LEN..])
        .expect("32-byte expand");
    out
}

/// Split `<type>.<b64>|<b64>...` into (type, parts). Malformed -> `Field`; unknown type -> `Fatal`.
// @spec VAULT-CRYPTO-004, VAULT-CRYPTO-005
pub fn parse_enc_string(value: &str) -> Result<(u32, Vec<Vec<u8>>), EncError> {
    let (prefix, rest) = value
        .split_once('.')
        .ok_or_else(|| field("missing encryption type prefix"))?;
    let etype: u32 = prefix
        .parse()
        .map_err(|_| field("encryption type prefix is not numeric"))?;
    if etype != ENC_TYPE_AES_CBC_256 && etype != ENC_TYPE_AES_CBC_256_HMAC {
        return Err(EncError::Fatal(VaultError::EncTypeNotImplemented(etype)));
    }
    let parts = rest
        .split('|')
        .map(|p| {
            STANDARD
                .decode(p)
                .map_err(|_| field("part is not valid base64"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected = if etype == ENC_TYPE_AES_CBC_256 { 2 } else { 3 };
    if parts.len() != expected {
        return Err(EncError::Field(format!(
            "type {etype} expects {expected} parts, got {}",
            parts.len()
        )));
    }
    if parts[0].len() != IV_LEN {
        return Err(field("IV is not 16 bytes"));
    }
    if etype == ENC_TYPE_AES_CBC_256_HMAC && parts[2].len() != MAC_LEN {
        return Err(field("MAC is not 32 bytes"));
    }
    Ok((etype, parts))
}

fn aes_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncError> {
    let decryptor = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| field("bad key or IV length"))?;
    decryptor
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| field("bad padding or ciphertext length"))
}

/// Decrypt an EncString to raw bytes with a 32-byte (type 0) or 64-byte (type 2) key.
// @spec VAULT-CRYPTO-001, VAULT-CRYPTO-002, VAULT-CRYPTO-003
pub fn decrypt_enc_string_bytes(value: &str, key: &[u8]) -> Result<Zeroizing<Vec<u8>>, EncError> {
    let (etype, parts) = parse_enc_string(value)?;
    if etype == ENC_TYPE_AES_CBC_256_HMAC {
        if key.len() != AES_HMAC_KEY_LEN {
            return Err(field("type 2 EncString requires a 64-byte key"));
        }
        let (enc_key, mac_key) = key.split_at(AES_KEY_LEN);
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).expect("any key length");
        mac.update(&parts[0]);
        mac.update(&parts[1]);
        mac.verify_slice(&parts[2])
            .map_err(|_| field("MAC mismatch"))?;
        return aes_cbc_decrypt(enc_key, &parts[0], &parts[1]);
    }
    if key.len() != AES_KEY_LEN {
        return Err(field("type 0 EncString requires a 32-byte key"));
    }
    aes_cbc_decrypt(key, &parts[0], &parts[1])
}

/// Decrypt an EncString to text. Empty or missing input is absent (`None`).
// @spec VAULT-CRYPTO-005
pub fn decrypt_enc_string(value: Option<&str>, key: &[u8]) -> Result<Option<String>, EncError> {
    let value = match value {
        None | Some("") => return Ok(None),
        Some(v) => v,
    };
    let bytes = decrypt_enc_string_bytes(value, key)?;
    String::from_utf8(bytes.to_vec())
        .map(Some)
        .map_err(|_| field("plaintext is not UTF-8"))
}

/// Unwrap the account's user key from the token response `Key` field.
// @spec VAULT-AUTH-009, VAULT-CRYPTO-007
pub fn unwrap_user_key(
    key_value: &str,
    master_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let to_vault = |e: EncError| match e {
        EncError::Field(m) => VaultError::UserKey(m),
        EncError::Fatal(v) => v,
    };
    let (etype, _) = parse_enc_string(key_value).map_err(to_vault)?;
    let user_key = if etype == ENC_TYPE_AES_CBC_256_HMAC {
        let stretched = stretch_key(master_key);
        decrypt_enc_string_bytes(key_value, &stretched).map_err(to_vault)?
    } else {
        decrypt_enc_string_bytes(key_value, master_key).map_err(to_vault)?
    };
    let expected = if etype == ENC_TYPE_AES_CBC_256_HMAC {
        AES_HMAC_KEY_LEN
    } else {
        AES_KEY_LEN
    };
    if user_key.len() != expected {
        return Err(VaultError::UserKeyLength {
            got: user_key.len(),
            expected,
        });
    }
    Ok(user_key)
}
