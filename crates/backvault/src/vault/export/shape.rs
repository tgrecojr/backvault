//! The export document's shape: structs whose declaration order is the CLI's key order.
//! Reference: bitwarden/clients libs/common/src/models/export/*.export.ts.

use serde::Serialize;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportStats {
    pub org_excluded: usize,
    pub trashed_excluded: usize,
    pub with_attachments: usize,
    pub undecryptable_fields: usize,
}

#[derive(Debug, Serialize)]
pub struct ExportFolder {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExportUri {
    #[serde(rename = "match")]
    pub match_type: Option<i64>,
    pub uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExportField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub field_type: Option<i64>,
    #[serde(rename = "linkedId")]
    pub linked_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ExportPasswordHistory {
    pub password: Option<String>,
    #[serde(rename = "lastUsedDate")]
    pub last_used_date: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFido2 {
    pub credential_id: Option<String>,
    pub key_type: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_curve: Option<String>,
    pub key_value: Option<String>,
    pub rp_id: Option<String>,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: Option<String>,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: Option<String>,
    pub creation_date: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportLogin {
    pub uris: Vec<ExportUri>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub fido2_credentials: Vec<ExportFido2>,
}

#[derive(Debug, Serialize)]
pub struct ExportSecureNote {
    #[serde(rename = "type")]
    pub note_type: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportCard {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportIdentity {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSshKey {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
}

/// One exported item; typed objects are emitted in declaration order and only the present one is serialized.
#[derive(Debug, Serialize)]
pub struct ExportItem {
    pub id: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "type")]
    pub item_type: i64,
    pub reprompt: i64,
    pub name: Option<String>,
    pub notes: Option<String>,
    pub favorite: bool,
    pub fields: Vec<ExportField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<ExportLogin>,
    #[serde(rename = "secureNote", skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<ExportSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<ExportCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ExportIdentity>,
    #[serde(rename = "sshKey", skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<ExportSshKey>,
    #[serde(rename = "passwordHistory")]
    pub password_history: Vec<ExportPasswordHistory>,
    #[serde(rename = "creationDate")]
    pub creation_date: Option<String>,
    #[serde(rename = "revisionDate")]
    pub revision_date: Option<String>,
    #[serde(rename = "deletedDate")]
    pub deleted_date: Option<String>,
    #[serde(rename = "archivedDate")]
    pub archived_date: Option<String>,
    #[serde(rename = "collectionIds")]
    pub collection_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct Export {
    pub encrypted: bool,
    pub folders: Vec<ExportFolder>,
    pub items: Vec<ExportItem>,
}
