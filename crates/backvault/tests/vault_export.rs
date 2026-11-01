//! vault-access: sync payload validation, item selection, export shape, serialization.

mod common;

use common::*;
use serde_json::{Value, json};

use backvault::vault::export::{Export, build_export, serialize_export};
use backvault::vault::{PLACEHOLDER, VaultError};

const CANONICAL_ITEM_ORDER: [&str; 20] = [
    "id",
    "organizationId",
    "folderId",
    "type",
    "reprompt",
    "name",
    "notes",
    "favorite",
    "fields",
    "login",
    "secureNote",
    "card",
    "identity",
    "sshKey",
    "passwordHistory",
    "creationDate",
    "revisionDate",
    "deletedDate",
    "archivedDate",
    "collectionIds",
];

fn keys(v: &Value) -> Vec<String> {
    v.as_object().expect("object").keys().cloned().collect()
}

fn assert_subsequence(keys: &[String], canonical: &[&str]) {
    let positions: Vec<usize> = keys
        .iter()
        .map(|k| {
            canonical
                .iter()
                .position(|c| c == k)
                .unwrap_or_else(|| panic!("unknown key {k}"))
        })
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(
        positions, sorted,
        "key order {keys:?} deviates from CLI order"
    );
}

/// Serialize and parse back (with preserve_order) so key order is observable.
fn value_of(export: &Export) -> Value {
    serde_json::from_str(&serialize_export(export)).unwrap()
}

fn export(payload: Value) -> (Value, backvault::vault::ExportStats) {
    let (e, stats) = build_export(&payload, &USER_KEY).expect("build_export");
    (value_of(&e), stats)
}

fn export_err(payload: Value) -> VaultError {
    build_export(&payload, &USER_KEY).expect_err("build_export fails")
}

fn typed_item(id: &str, item_type: i64, typed_key: &str, typed: Value) -> Value {
    let mut item = login_item(
        id,
        "Typed",
        LoginOpts {
            uris: None,
            ..Default::default()
        },
    );
    item["type"] = json!(item_type);
    item["login"] = Value::Null;
    item[typed_key] = typed;
    item
}

// @spec VAULT-EXPORT-003
#[test]
fn document_shape() {
    let (out, _) = export(sync_payload(
        vec![login_item("i-1", "Example", Default::default())],
        None,
    ));
    assert_eq!(keys(&out), ["encrypted", "folders", "items"]);
    assert_eq!(out["encrypted"], json!(false));
}

// @spec VAULT-EXPORT-008
#[test]
fn folder_and_item_decrypted_in_cli_order() {
    let (out, _) = export(sync_payload(
        vec![login_item(
            "i-1",
            "Example",
            LoginOpts {
                folder_id: Some("f-1"),
                notes: Some("n"),
                favorite: true,
                ..Default::default()
            },
        )],
        None,
    ));
    assert_eq!(out["folders"], json!([{"id": "f-1", "name": "Work"}]));
    let item = &out["items"][0];
    assert_subsequence(&keys(item), &CANONICAL_ITEM_ORDER);
    assert_eq!(item["id"], json!("i-1"));
    assert_eq!(item["organizationId"], Value::Null);
    assert_eq!(item["folderId"], json!("f-1"));
    assert_eq!(item["type"], json!(1));
    assert_eq!(item["reprompt"], json!(0));
    assert_eq!(item["name"], json!("Example"));
    assert_eq!(item["notes"], json!("n"));
    assert_eq!(item["favorite"], json!(true));
    assert_eq!(item["collectionIds"], Value::Null);
    assert!(item.get("key").is_none());
}

// @spec VAULT-EXPORT-009
#[test]
fn login_fields_fixed_set_and_order() {
    let (out, _) = export(sync_payload(
        vec![login_item(
            "i-1",
            "Ex",
            LoginOpts {
                totp: Some("JBSWY3DP"),
                uris: Some(vec![("https://a", None), ("https://b", Some(3))]),
                ..Default::default()
            },
        )],
        None,
    ));
    let login = &out["items"][0]["login"];
    assert_eq!(
        keys(login),
        ["uris", "username", "password", "totp", "fido2Credentials"]
    );
    assert_eq!(login["username"], json!("alice"));
    assert_eq!(login["password"], json!("hunter2"));
    assert_eq!(login["totp"], json!("JBSWY3DP"));
    assert_eq!(
        login["uris"],
        json!([{"match": null, "uri": "https://a"}, {"match": 3, "uri": "https://b"}])
    );
}

// @spec VAULT-EXPORT-009
#[test]
fn server_extra_subfields_ignored_and_missing_emitted_null() {
    let mut item = login_item("i-1", "Ex", Default::default());
    item["login"]["autofillOnPageLoad"] = json!(true);
    item["login"].as_object_mut().unwrap().remove("totp");
    let (out, _) = export(sync_payload(vec![item], None));
    let login = &out["items"][0]["login"];
    assert!(login.get("autofillOnPageLoad").is_none());
    assert_eq!(login["totp"], Value::Null);
}

// @spec VAULT-EXPORT-009
#[test]
fn secure_note_shape() {
    let (out, _) = export(sync_payload(
        vec![note_item("n-1", "Note", "body", &USER_KEY)],
        None,
    ));
    let item = &out["items"][0];
    assert_eq!(item["type"], json!(2));
    assert_eq!(item["secureNote"], json!({"type": 0}));
    assert_eq!(item["notes"], json!("body"));
    assert!(item.get("login").is_none());
}

// @spec VAULT-EXPORT-009
#[test]
fn card_identity_and_key_item_shapes() {
    let k = &USER_KEY;
    let card = typed_item(
        "c-1",
        3,
        "card",
        json!({"cardholderName": e("A B", k), "brand": e("Visa", k), "number": e("4111", k),
               "expMonth": e("1", k), "expYear": e("2030", k), "code": e("123", k), "serverOnly": "x"}),
    );
    let ident = typed_item(
        "id-1",
        4,
        "identity",
        json!({"firstName": e("Ann", k), "email": e("a@x", k)}),
    );
    let keyitem = typed_item(
        "s-1",
        5,
        "sshKey",
        json!({"privateKey": e("PRIV", k), "publicKey": e("PUB", k), "keyFingerprint": e("FP", k)}),
    );
    let (out, _) = export(sync_payload(vec![card, ident, keyitem], None));
    let card = &out["items"][0]["card"];
    assert_eq!(
        keys(card),
        [
            "cardholderName",
            "brand",
            "number",
            "expMonth",
            "expYear",
            "code"
        ]
    );
    assert_eq!(card["number"], json!("4111"));
    let ident = &out["items"][1]["identity"];
    assert_eq!(
        keys(ident),
        [
            "title",
            "firstName",
            "middleName",
            "lastName",
            "address1",
            "address2",
            "address3",
            "city",
            "state",
            "postalCode",
            "country",
            "company",
            "email",
            "phone",
            "ssn",
            "username",
            "passportNumber",
            "licenseNumber"
        ]
    );
    assert_eq!(ident["firstName"], json!("Ann"));
    assert_eq!(ident["title"], Value::Null);
    let keyitem = &out["items"][2]["sshKey"];
    assert_eq!(keys(keyitem), ["privateKey", "publicKey", "keyFingerprint"]);
    assert_eq!(keyitem["keyFingerprint"], json!("FP"));
    for (i, typed) in [(0, "card"), (1, "identity"), (2, "sshKey")] {
        let item = &out["items"][i];
        assert!(
            item.get("login").is_none(),
            "{typed} item must not carry login"
        );
        assert!(item.get(typed).is_some());
    }
}

// @spec VAULT-EXPORT-009
#[test]
fn fido2_credentials_decrypted_with_fixed_fields() {
    let k = &USER_KEY;
    let mut item = login_item("i-1", "Ex", Default::default());
    item["login"]["fido2Credentials"] = json!([{
        "credentialId": e("cid", k), "keyType": e("public-key", k), "keyAlgorithm": e("ECDSA", k),
        "keyCurve": e("P-256", k), "keyValue": e("kv", k), "rpId": e("example.test", k),
        "userHandle": e("uh", k), "userName": e("un", k), "counter": e("0", k),
        "rpName": e("Example", k), "userDisplayName": e("Alice", k), "discoverable": e("true", k),
        "creationDate": "2024-05-06T07:08:09.000000Z"
    }]);
    let (out, _) = export(sync_payload(vec![item], None));
    let cred = &out["items"][0]["login"]["fido2Credentials"][0];
    assert_eq!(
        keys(cred),
        [
            "credentialId",
            "keyType",
            "keyAlgorithm",
            "keyCurve",
            "keyValue",
            "rpId",
            "userHandle",
            "userName",
            "counter",
            "rpName",
            "userDisplayName",
            "discoverable",
            "creationDate"
        ]
    );
    assert_eq!(cred["rpId"], json!("example.test"));
    assert_eq!(cred["creationDate"], json!("2024-05-06T07:08:09.000Z"));
}

// @spec VAULT-EXPORT-009
#[test]
fn fields_and_password_history_decrypted() {
    let k = &USER_KEY;
    let item = login_item(
        "i-1",
        "Ex",
        LoginOpts {
            fields: Some(
                json!([{"name": e("api", k), "value": e("k", k), "type": 1, "linkedId": null}]),
            ),
            password_history: Some(
                json!([{"password": e("old", k), "lastUsedDate": "2023-05-06T07:08:09.000000Z"}]),
            ),
            ..Default::default()
        },
    );
    let (out, _) = export(sync_payload(vec![item], None));
    let item = &out["items"][0];
    assert_eq!(
        item["fields"],
        json!([{"name": "api", "value": "k", "type": 1, "linkedId": null}])
    );
    assert_eq!(
        item["passwordHistory"],
        json!([{"password": "old", "lastUsedDate": "2023-05-06T07:08:09.000Z"}])
    );
}

// @spec VAULT-EXPORT-011
#[test]
fn item_dates_normalised() {
    let (out, _) = export(sync_payload(
        vec![login_item("i-1", "Ex", Default::default())],
        None,
    ));
    let item = &out["items"][0];
    assert_eq!(item["creationDate"], json!("2024-01-02T03:04:05.123Z"));
    assert_eq!(item["revisionDate"], json!("2024-02-03T04:05:06.654Z"));
    assert_eq!(item["deletedDate"], Value::Null);
}

// @spec VAULT-EXPORT-011
#[test]
fn unparseable_item_date_fails_cycle_naming_item_and_field() {
    let mut item = login_item("i-d", "Ex", Default::default());
    item["revisionDate"] = json!("2024-02-03T04:05:06");
    let text = export_err(sync_payload(vec![item], None)).to_string();
    assert!(
        text.contains("i-d") && text.contains("revisionDate"),
        "{text}"
    );
}

// @spec VAULT-EXPORT-006
#[test]
fn org_and_trashed_excluded_archived_included_with_counts() {
    let items = vec![
        login_item("keep", "Keep", Default::default()),
        login_item(
            "org",
            "Org",
            LoginOpts {
                organization_id: Some("o-1"),
                ..Default::default()
            },
        ),
        login_item(
            "trash",
            "Trash",
            LoginOpts {
                deleted: Some("2024-03-01T00:00:00.000000Z"),
                ..Default::default()
            },
        ),
        login_item(
            "arch",
            "Arch",
            LoginOpts {
                archived: Some("2024-03-02T00:00:00.000000Z"),
                ..Default::default()
            },
        ),
    ];
    let (out, stats) = export(sync_payload(items, None));
    let ids: Vec<&str> = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["keep", "arch"]);
    assert_eq!(stats.org_excluded, 1);
    assert_eq!(stats.trashed_excluded, 1);
    assert_eq!(
        out["items"][1]["archivedDate"],
        json!("2024-03-02T00:00:00.000Z")
    );
}

// @spec VAULT-EXPORT-007
#[test]
fn attachments_counted() {
    let items = vec![
        login_item(
            "a",
            "A",
            LoginOpts {
                attachments: Some(
                    json!([{"id": "x", "fileName": e("f.txt", &USER_KEY), "size": "1"}]),
                ),
                ..Default::default()
            },
        ),
        login_item("b", "B", Default::default()),
    ];
    let (_, stats) = export(sync_payload(items, None));
    assert_eq!(stats.with_attachments, 1);
}

// @spec VAULT-EXPORT-010
#[test]
fn dangling_folder_id_passes_through() {
    let (out, _) = export(sync_payload(
        vec![login_item(
            "i-1",
            "Ex",
            LoginOpts {
                folder_id: Some("missing"),
                ..Default::default()
            },
        )],
        None,
    ));
    assert_eq!(out["items"][0]["folderId"], json!("missing"));
}

// @spec VAULT-CRYPTO-008
#[test]
fn cipher_level_key_decrypts_every_field() {
    let cipher_key: Vec<u8> = (100..164).collect();
    let ck = cipher_key.as_slice();
    let item = login_item(
        "i-1",
        "Named",
        LoginOpts {
            key: ck,
            notes: Some("noted"),
            cipher_key: Some(enc2(ck, &USER_KEY)),
            fields: Some(
                json!([{"name": e("f", ck), "value": e("v", ck), "type": 0, "linkedId": null}]),
            ),
            password_history: Some(
                json!([{"password": e("ph", ck), "lastUsedDate": "2023-01-01T00:00:00Z"}]),
            ),
            ..Default::default()
        },
    );
    let (out, stats) = export(sync_payload(vec![item], None));
    let item = &out["items"][0];
    assert_eq!(item["name"], json!("Named"));
    assert_eq!(item["notes"], json!("noted"));
    assert_eq!(item["login"]["password"], json!("hunter2"));
    assert_eq!(
        item["fields"][0],
        json!({"name": "f", "value": "v", "type": 0, "linkedId": null})
    );
    assert_eq!(item["passwordHistory"][0]["password"], json!("ph"));
    assert_eq!(stats.undecryptable_fields, 0);
}

// @spec VAULT-CRYPTO-007
#[test]
fn cipher_key_unwrap_failure_fails_cycle_naming_item() {
    let item = login_item(
        "i-bad",
        "X",
        LoginOpts {
            cipher_key: Some(enc2(&[0u8; 64], &[0u8; 64])),
            ..Default::default()
        },
    );
    let text = export_err(sync_payload(vec![item], None)).to_string();
    assert!(text.contains("i-bad") && text.contains("key"), "{text}");
}

// @spec VAULT-CRYPTO-006
#[test]
fn undecryptable_field_becomes_placeholder_and_cycle_continues() {
    capture_logs();
    let mut item = login_item("i-1", "Ex", Default::default());
    item["login"]["password"] = json!(e("secret", &[0u8; 64])); // wrong key
    let (out, stats) = export(sync_payload(vec![item], None));
    let login = &out["items"][0]["login"];
    assert_eq!(login["password"], json!(PLACEHOLDER));
    assert_eq!(PLACEHOLDER, "[error: cannot decrypt]");
    assert_eq!(login["username"], json!("alice"));
    assert_eq!(stats.undecryptable_fields, 1);
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Error && m.contains("i-1") && m.contains("password"))
    );
}

// @spec VAULT-CRYPTO-006
#[test]
fn undecryptable_folder_name_becomes_placeholder() {
    let bad = folder("f-bad", "x", &[0u8; 64]);
    let (out, stats) = export(sync_payload(
        vec![login_item("i-1", "Ex", Default::default())],
        Some(vec![bad]),
    ));
    assert_eq!(
        out["folders"],
        json!([{"id": "f-bad", "name": PLACEHOLDER}])
    );
    assert_eq!(stats.undecryptable_fields, 1);
}

// @spec VAULT-CRYPTO-009
#[test]
fn blob_cipher_with_null_name_fails_cycle() {
    let mut item = login_item("blob-1", "X", Default::default());
    item["name"] = Value::Null;
    item["data"] = json!("7.AAAA");
    assert!(
        export_err(sync_payload(vec![item], None))
            .to_string()
            .contains("blob-1")
    );
}

// @spec VAULT-CRYPTO-004
#[test]
fn unimplemented_enc_type_in_item_fails_cycle_naming_item_and_type() {
    let mut item = login_item("i-7", "X", Default::default());
    item["notes"] = json!(format!("7.{}", b64(&[0u8; 40])));
    let text = export_err(sync_payload(vec![item], None)).to_string();
    assert!(text.contains("i-7") && text.contains('7'), "{text}");
}

// @spec VAULT-EXPORT-013
#[test]
fn unknown_item_type_fails_cycle() {
    for ctype in [6i64, 7, 8, 42] {
        let mut item = login_item("i-t", "X", Default::default());
        item["type"] = json!(ctype);
        let text = export_err(sync_payload(vec![item], None)).to_string();
        assert!(
            text.contains("i-t") && text.contains(&ctype.to_string()),
            "{text}"
        );
    }
}

// @spec VAULT-EXPORT-005
#[test]
fn payload_without_sync_shape_fails() {
    type Mutation = Box<dyn Fn(&mut Value)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|p| {
            p.as_object_mut().unwrap().remove("ciphers");
        }),
        Box::new(|p| {
            p.as_object_mut().unwrap().remove("folders");
        }),
        Box::new(|p| p["object"] = json!("profile")),
        Box::new(|p| {
            let c = p.as_object_mut().unwrap().remove("ciphers").unwrap();
            p["Ciphers"] = c;
        }),
        Box::new(|p| p["ciphers"] = Value::Null),
        Box::new(|p| p["folders"] = json!("not a list")),
    ];
    for (i, m) in mutations.iter().enumerate() {
        let mut payload = sync_payload(vec![login_item("i-1", "Ex", Default::default())], None);
        m(&mut payload);
        assert!(
            build_export(&payload, &USER_KEY).is_err(),
            "mutation {i} should fail"
        );
    }
    assert!(build_export(&json!("not an object"), &USER_KEY).is_err());
}

// @spec VAULT-EXPORT-005
#[test]
fn empty_vault_is_valid() {
    let (out, _) = export(sync_payload(vec![], Some(vec![])));
    assert_eq!(out, json!({"encrypted": false, "folders": [], "items": []}));
}

// @spec VAULT-EXPORT-014
#[test]
fn serialization_utf8_two_space_indent_no_trailing_newline() {
    let (export, _) = build_export(
        &sync_payload(
            vec![login_item("i-1", "Ünïcødé ☃", Default::default())],
            None,
        ),
        &USER_KEY,
    )
    .unwrap();
    let text = serialize_export(&export);
    assert!(
        text.starts_with("{\n  \"encrypted\": false,\n  \"folders\": ["),
        "{text}"
    );
    assert!(text.contains("Ünïcødé ☃"));
    assert!(!text.contains("\\u"));
    assert!(!text.ends_with('\n'));
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap(),
        serde_json::to_value(&export).unwrap()
    );
    assert!(
        text.contains("\"uri\": \"https://example.test\""),
        "separators are ': ' and ','"
    );
}

#[test]
fn every_spec_cited_here_exists() {
    assert_cited_specs_exist(
        "crates/backvault/tests/vault_export.rs",
        "docs/intent/vault-access/vault-access-specs.md",
        "VAULT",
    );
}
