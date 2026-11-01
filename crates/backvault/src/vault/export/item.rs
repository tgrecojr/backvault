//! Decrypting one item (or folder) with its effective key under the placeholder policy.

use serde_json::Value;

use super::shape::*;
use super::{PLACEHOLDER, Zeroized, effective_key, get, normalize_date, str_of};
use crate::vault::VaultError;
use crate::vault::crypto::{EncError, decrypt_enc_string};

/// Decrypts one item's fields with its effective key, applying the placeholder policy.
pub(super) struct ItemDecryptor<'a> {
    pub item_id: String,
    pub key: &'a [u8],
    pub stats: &'a mut ExportStats,
}

impl ItemDecryptor<'_> {
    // @spec VAULT-CRYPTO-006
    pub fn text(
        &mut self,
        value: Option<&Value>,
        path: &str,
    ) -> Result<Option<String>, VaultError> {
        let result = match value {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::String(s)) => decrypt_enc_string(Some(s), self.key),
            Some(_) => Err(EncError::Field("value is not a string".to_string())),
        };
        match result {
            Ok(v) => Ok(v),
            Err(EncError::Field(why)) => {
                log::error!(
                    "item {} field {path} could not be decrypted ({why}); emitting placeholder",
                    self.item_id
                );
                self.stats.undecryptable_fields += 1;
                Ok(Some(PLACEHOLDER.to_string()))
            }
            Err(EncError::Fatal(e)) => Err(VaultError::Item {
                id: self.item_id.clone(),
                message: format!("field {path}: {e}"),
            }),
        }
    }

    fn date(&self, value: Option<&Value>, path: &str) -> Result<Option<String>, VaultError> {
        normalize_date(value.and_then(Value::as_str)).map_err(|e| VaultError::Item {
            id: self.item_id.clone(),
            message: format!("field {path}: {e}"),
        })
    }

    fn login(&mut self, src: Option<&Value>) -> Result<ExportLogin, VaultError> {
        let mut uris = Vec::new();
        if let Some(list) = get(src, "uris").and_then(Value::as_array) {
            for (i, u) in list.iter().enumerate() {
                uris.push(ExportUri {
                    match_type: u.get("match").and_then(Value::as_i64),
                    uri: self.text(u.get("uri"), &format!("login.uris[{i}].uri"))?,
                });
            }
        }
        let username = self.text(get(src, "username"), "login.username")?;
        let password = self.text(get(src, "password"), "login.password")?;
        let totp = self.text(get(src, "totp"), "login.totp")?;
        let mut fido2_credentials = Vec::new();
        if let Some(list) = get(src, "fido2Credentials").and_then(Value::as_array) {
            for (i, c) in list.iter().enumerate() {
                fido2_credentials.push(self.fido2(c, i)?);
            }
        }
        Ok(ExportLogin {
            uris,
            username,
            password,
            totp,
            fido2_credentials,
        })
    }

    fn fido2(&mut self, c: &Value, index: usize) -> Result<ExportFido2, VaultError> {
        let p = format!("login.fido2Credentials[{index}]");
        let mut f = |name: &str| self.text(c.get(name), &format!("{p}.{name}"));
        Ok(ExportFido2 {
            credential_id: f("credentialId")?,
            key_type: f("keyType")?,
            key_algorithm: f("keyAlgorithm")?,
            key_curve: f("keyCurve")?,
            key_value: f("keyValue")?,
            rp_id: f("rpId")?,
            user_handle: f("userHandle")?,
            user_name: f("userName")?,
            counter: f("counter")?,
            rp_name: f("rpName")?,
            user_display_name: f("userDisplayName")?,
            discoverable: f("discoverable")?,
            creation_date: self.date(c.get("creationDate"), &format!("{p}.creationDate"))?,
        })
    }

    fn card(&mut self, src: Option<&Value>) -> Result<ExportCard, VaultError> {
        let mut f = |name: &str| self.text(get(src, name), &format!("card.{name}"));
        Ok(ExportCard {
            cardholder_name: f("cardholderName")?,
            brand: f("brand")?,
            number: f("number")?,
            exp_month: f("expMonth")?,
            exp_year: f("expYear")?,
            code: f("code")?,
        })
    }

    fn identity(&mut self, src: Option<&Value>) -> Result<ExportIdentity, VaultError> {
        let mut f = |name: &str| self.text(get(src, name), &format!("identity.{name}"));
        Ok(ExportIdentity {
            title: f("title")?,
            first_name: f("firstName")?,
            middle_name: f("middleName")?,
            last_name: f("lastName")?,
            address1: f("address1")?,
            address2: f("address2")?,
            address3: f("address3")?,
            city: f("city")?,
            state: f("state")?,
            postal_code: f("postalCode")?,
            country: f("country")?,
            company: f("company")?,
            email: f("email")?,
            phone: f("phone")?,
            ssn: f("ssn")?,
            username: f("username")?,
            passport_number: f("passportNumber")?,
            license_number: f("licenseNumber")?,
        })
    }

    fn ssh_key(&mut self, src: Option<&Value>) -> Result<ExportSshKey, VaultError> {
        let mut f = |name: &str| self.text(get(src, name), &format!("sshKey.{name}"));
        Ok(ExportSshKey {
            private_key: f("privateKey")?,
            public_key: f("publicKey")?,
            key_fingerprint: f("keyFingerprint")?,
        })
    }

    fn fields(&mut self, src: Option<&Value>) -> Result<Vec<ExportField>, VaultError> {
        let mut out = Vec::new();
        if let Some(list) = src.and_then(Value::as_array) {
            for (i, f) in list.iter().enumerate() {
                out.push(ExportField {
                    name: self.text(f.get("name"), &format!("fields[{i}].name"))?,
                    value: self.text(f.get("value"), &format!("fields[{i}].value"))?,
                    field_type: f.get("type").and_then(Value::as_i64),
                    linked_id: f.get("linkedId").and_then(Value::as_i64),
                });
            }
        }
        Ok(out)
    }

    fn password_history(
        &mut self,
        src: Option<&Value>,
    ) -> Result<Vec<ExportPasswordHistory>, VaultError> {
        let mut out = Vec::new();
        if let Some(list) = src.and_then(Value::as_array) {
            for (i, p) in list.iter().enumerate() {
                out.push(ExportPasswordHistory {
                    password: self
                        .text(p.get("password"), &format!("passwordHistory[{i}].password"))?,
                    last_used_date: self.date(
                        p.get("lastUsedDate"),
                        &format!("passwordHistory[{i}].lastUsedDate"),
                    )?,
                });
            }
        }
        Ok(out)
    }
}

// @spec VAULT-EXPORT-008, VAULT-EXPORT-009, VAULT-EXPORT-010, VAULT-EXPORT-013
pub(super) fn export_item(
    item: &Value,
    user_key: &[u8],
    stats: &mut ExportStats,
) -> Result<ExportItem, VaultError> {
    let item_id = item
        .get("id")
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string())
        })
        .unwrap_or_else(|| "null".to_string());
    let item_type = item.get("type").and_then(Value::as_i64).unwrap_or(-1);
    if !(1..=5).contains(&item_type) {
        return Err(VaultError::Item {
            id: item_id,
            message: format!(
                "unsupported item type {}",
                item.get("type")
                    .map(Value::to_string)
                    .unwrap_or_else(|| "null".into())
            ),
        });
    }
    let key_holder = effective_key(item, &item_id, user_key)?;
    let key: &[u8] = match &key_holder {
        Zeroized::Borrowed => user_key,
        Zeroized::Owned(k) => k,
    };
    let mut dec = ItemDecryptor {
        item_id: item_id.clone(),
        key,
        stats,
    };
    let name = dec.text(item.get("name"), "name")?;
    let notes = dec.text(item.get("notes"), "notes")?;
    let fields = dec.fields(item.get("fields"))?;
    let (mut login, mut secure_note, mut card, mut identity, mut ssh_key) =
        (None, None, None, None, None);
    match item_type {
        1 => login = Some(dec.login(item.get("login"))?),
        2 => {
            secure_note = Some(ExportSecureNote {
                note_type: get(item.get("secureNote"), "type")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
            })
        }
        3 => card = Some(dec.card(item.get("card"))?),
        4 => identity = Some(dec.identity(item.get("identity"))?),
        _ => ssh_key = Some(dec.ssh_key(item.get("sshKey"))?),
    }
    let password_history = dec.password_history(item.get("passwordHistory"))?;
    let creation_date = dec.date(item.get("creationDate"), "creationDate")?;
    let revision_date = dec.date(item.get("revisionDate"), "revisionDate")?;
    let deleted_date = dec.date(item.get("deletedDate"), "deletedDate")?;
    let archived_date = dec.date(item.get("archivedDate"), "archivedDate")?;
    Ok(ExportItem {
        id: item.get("id").and_then(str_of),
        organization_id: None,
        folder_id: item.get("folderId").and_then(str_of),
        item_type,
        reprompt: item.get("reprompt").and_then(Value::as_i64).unwrap_or(0),
        name,
        notes,
        favorite: item
            .get("favorite")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        fields,
        login,
        secure_note,
        card,
        identity,
        ssh_key,
        password_history,
        creation_date,
        revision_date,
        deleted_date,
        archived_date,
        collection_ids: None,
    })
}
