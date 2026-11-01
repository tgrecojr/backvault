//! Assemble a Bitwarden-format JSON export from a decrypted /api/sync payload.
//!
//! Shape follows `bw export --format json` (individual vault). Reference:
//! bitwarden/clients libs/common/src/models/export/*.export.ts and
//! libs/tools/export-vault-core/src/services/individual-vault-export.service.ts.
//! Output structs declare their fields in the CLI's order; serde emits them in that order.

mod item;
mod shape;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

pub use shape::*;

use super::VaultError;
use super::crypto::{AES_HMAC_KEY_LEN, EncError, decrypt_enc_string_bytes};
use item::{ItemDecryptor, export_item};

pub const PLACEHOLDER: &str = "[error: cannot decrypt]";

/// RFC 3339 of any precision/offset -> UTC with exactly three fractional digits and `Z`.
// @spec VAULT-EXPORT-011
pub fn normalize_date(value: Option<&str>) -> Result<Option<String>, VaultError> {
    let Some(raw) = value else { return Ok(None) };
    let text = raw.trim();
    // RFC 3339 proper also allows a space separator; the CLI's dates always carry `T`.
    if text.len() < 20 || text.as_bytes()[10] != b'T' {
        return Err(VaultError::Date(raw.to_string()));
    }
    let parsed = OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|_| VaultError::Date(raw.to_string()))?
        .to_offset(UtcOffset::UTC);
    let base = parsed
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]"
        ))
        .map_err(|_| VaultError::Date(raw.to_string()))?;
    Ok(Some(format!("{base}.{:03}Z", parsed.millisecond())))
}

fn str_of(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

fn get<'a>(v: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    v.and_then(|o| o.get(key)).filter(|x| !x.is_null())
}

pub(super) enum Zeroized {
    Borrowed,
    Owned(zeroize::Zeroizing<Vec<u8>>),
}

// @spec VAULT-CRYPTO-008, VAULT-CRYPTO-009
pub(super) fn effective_key(
    item: &Value,
    item_id: &str,
    user_key: &[u8],
) -> Result<Zeroized, VaultError> {
    if item.get("name").is_none_or(Value::is_null) {
        return Err(VaultError::Item {
            id: item_id.to_string(),
            message: "encrypted name is null; sealed-blob cipher format is not supported"
                .to_string(),
        });
    }
    let cipher_key = match item.get("key").and_then(Value::as_str) {
        None | Some("") => return Ok(Zeroized::Borrowed),
        Some(k) => k,
    };
    let unwrapped =
        decrypt_enc_string_bytes(cipher_key, user_key).map_err(|e| VaultError::Item {
            id: item_id.to_string(),
            message: match e {
                EncError::Field(m) => format!("could not decrypt cipher key (field key): {m}"),
                EncError::Fatal(v) => format!("field key: {v}"),
            },
        })?;
    if unwrapped.len() != AES_HMAC_KEY_LEN {
        return Err(VaultError::Item {
            id: item_id.to_string(),
            message: format!(
                "cipher key (field key) has unexpected length {}",
                unwrapped.len()
            ),
        });
    }
    Ok(Zeroized::Owned(unwrapped))
}

// @spec VAULT-EXPORT-005
fn validate_sync_payload(payload: &Value) -> Result<(&Vec<Value>, &Vec<Value>), VaultError> {
    if !payload.is_object() || payload.get("object").and_then(Value::as_str) != Some("sync") {
        return Err(VaultError::Payload(
            "server response is not a sync object".to_string(),
        ));
    }
    let folders = payload
        .get("folders")
        .and_then(Value::as_array)
        .ok_or_else(|| VaultError::Payload("sync response has no 'folders' array".to_string()))?;
    let ciphers = payload
        .get("ciphers")
        .and_then(Value::as_array)
        .ok_or_else(|| VaultError::Payload("sync response has no 'ciphers' array".to_string()))?;
    Ok((folders, ciphers))
}

/// Validate the sync payload, select, decrypt, and shape folders and items.
// @spec VAULT-EXPORT-003, VAULT-EXPORT-006, VAULT-EXPORT-007
pub fn build_export(payload: &Value, user_key: &[u8]) -> Result<(Export, ExportStats), VaultError> {
    let (folders_in, ciphers) = validate_sync_payload(payload)?;
    let mut stats = ExportStats::default();
    let mut folders = Vec::with_capacity(folders_in.len());
    for f in folders_in {
        let id = f.get("id").and_then(str_of);
        let mut dec = ItemDecryptor {
            item_id: format!("folder {}", id.as_deref().unwrap_or("null")),
            key: user_key,
            stats: &mut stats,
        };
        let name = dec.text(f.get("name"), "name")?;
        folders.push(ExportFolder { id, name });
    }
    let mut items = Vec::new();
    for item in ciphers {
        if item.get("organizationId").is_some_and(|v| !v.is_null()) {
            stats.org_excluded += 1;
            continue;
        }
        if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
            stats.trashed_excluded += 1;
            continue;
        }
        if item
            .get("attachments")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
        {
            stats.with_attachments += 1;
        }
        items.push(export_item(item, user_key, &mut stats)?);
    }
    Ok((
        Export {
            encrypted: false,
            folders,
            items,
        },
        stats,
    ))
}

/// UTF-8, non-ASCII unescaped, two-space indent, `": "` and `","` separators, no trailing newline.
// @spec VAULT-EXPORT-014
pub fn serialize_export(export: &Export) -> String {
    serde_json::to_string_pretty(export).expect("export structs always serialize")
}
