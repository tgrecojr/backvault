# vault-access — EARS Specs

Prefix `VAULT`. Facets: `SESSION` (lifecycle contract), `AUTH` (token and key derivation), `CRYPTO` (EncString decryption), `EXPORT` (payload validation, selection, shape), `HTTP` (transport), `RETRY`, `LOG`.

Status: `[x]` implemented and observed working · `[ ]` specified, not yet implemented or unverified · `[D]` deferred.

## Session lifecycle

- [x] **VAULT-SESSION-001**: When a backup cycle begins, the vault client shall authenticate to the configured server with the API-key client ID and client secret before requesting any vault data.
- [x] **VAULT-SESSION-002**: When authentication succeeds, the vault client shall derive the master key from the master password and unwrap the user key locally before requesting the vault, and shall not send the master password or any derived key to the server.
- [x] **VAULT-SESSION-003**: When a backup cycle ends, whether the export succeeded or failed, the vault client shall overwrite its copies of the access token, master key, stretched keys, user key, and any cipher-level keys, and shall not persist any of them.
- [x] **VAULT-SESSION-004**: The vault client shall make exactly one token request and one sync request per successful cycle (plus retries of a failed request) and shall not reuse or refresh a token across cycles.
- [x] **VAULT-SESSION-005**: The vault client shall address every server interaction to the configured server URL (`BW_SERVER`) with trailing slashes removed, resolving `vault.bitwarden.com` and `vault.bitwarden.eu` to their separate identity and api hosts and every other server to `/identity` and `/api` paths beneath the URL; if the URL's scheme is not `https`, then the vault client shall fail the cycle before any request.
- [x] **VAULT-SESSION-006**: If `BW_CLIENT_ID` does not begin with `user.`, then the vault client shall fail the cycle before any request, stating that organization API keys cannot unlock a personal vault.

## Authentication and key derivation

- [x] **VAULT-AUTH-001**: The token request shall be `POST {identity}/connect/token` with `grant_type=client_credentials`, `scope=api`, the client ID and secret, `deviceType=25`, `deviceName=backvault`, and a `deviceIdentifier` equal to `uuid5(NAMESPACE_URL, "backvault:" + client_id)`, so that one deployment presents one device on every cycle.
- [x] **VAULT-AUTH-002**: If the token response lacks `access_token`, `Key`, `Kdf`, or `KdfIterations`, then the vault client shall fail the cycle naming the missing field.
- [x] **VAULT-AUTH-003**: If the token response's `Kdf` is neither 0 (PBKDF2) nor 1 (Argon2id), then the vault client shall fail the cycle as an unsupported KDF type.
- [x] **VAULT-AUTH-004**: The vault client shall take the account email from `UserDecryptionOptions.MasterPasswordUnlock.Salt`, falling back to the `email` claim of the access token and then to `GET {api}/accounts/profile`, and shall trim and lower-case it before using it as the KDF salt.
- [x] **VAULT-AUTH-005**: When `Kdf` is 0, the vault client shall derive the 32-byte master key with PBKDF2-HMAC-SHA256 from the UTF-8 master password, the email bytes as salt, and `KdfIterations` iterations.
- [x] **VAULT-AUTH-006**: When `Kdf` is 1, the vault client shall derive the 32-byte master key with Argon2id version 1.3 from the UTF-8 master password, SHA-256 of the email bytes as salt, `KdfIterations` passes, `KdfMemory` × 1024 KiB of memory, and `KdfParallelism` lanes.
- [x] **VAULT-AUTH-007**: The vault client shall use the master password as its raw UTF-8 bytes, without trimming or Unicode normalisation.
- [x] **VAULT-AUTH-008**: The vault client shall stretch the master key with HKDF-Expand-SHA256, using the master key directly as the pseudorandom key, into a 32-byte encryption key (info `enc`) and a 32-byte MAC key (info `mac`).
- [x] **VAULT-AUTH-009**: When the token response's `Key` is a type-2 EncString, the vault client shall decrypt it with the stretched key and require a 64-byte result (encryption key followed by MAC key); when it is a type-0 EncString, the vault client shall decrypt it with the master key and require a 32-byte result; any other length shall fail the cycle.
- [x] **VAULT-AUTH-010**: The vault client shall not use the sync payload's `profile.key` as a source for the user key.

## EncString decryption

- [x] **VAULT-CRYPTO-001**: When decrypting a type-2 EncString (`2.iv|ciphertext|mac`) with a 64-byte key, the vault client shall verify HMAC-SHA256 over iv ‖ ciphertext with the MAC key using a constant-time comparison before decrypting with AES-256-CBC and removing PKCS#7 padding.
- [x] **VAULT-CRYPTO-002**: When decrypting a type-0 EncString (`0.iv|ciphertext`) with a 32-byte key, the vault client shall decrypt with AES-256-CBC without authentication; the vault client shall never produce type-0 values.
- [x] **VAULT-CRYPTO-003**: If a type-2 EncString is paired with a 32-byte key, or a type-0 EncString with a 64-byte key, then the vault client shall treat the value as a decryption failure.
- [x] **VAULT-CRYPTO-004**: If an EncString's type is 1 or 3 through 7, then the vault client shall fail the cycle naming the type and the item ID.
- [x] **VAULT-CRYPTO-005**: The vault client shall treat an empty-string field value as absent (`null`), and shall treat a value that lacks a type prefix, has the wrong number of parts for its type, contains non-base64 data, has an IV other than 16 bytes, or has a MAC other than 32 bytes as a decryption failure.
- [x] **VAULT-CRYPTO-006**: If a content field or a folder name fails to decrypt (MAC mismatch, bad padding, malformed value, or non-UTF-8 plaintext), then the vault client shall emit the literal string `[error: cannot decrypt]` for that field, log the item ID and field path at ERROR, and continue the cycle.
- [x] **VAULT-CRYPTO-007**: If the token response's `Key` or a cipher-level `key` fails to decrypt or has an unexpected length, then the vault client shall fail the cycle naming the field `key` and, for a cipher-level key, the item ID.
- [x] **VAULT-CRYPTO-008**: When a cipher carries a `key`, the vault client shall unwrap it with the user key to a 64-byte key and use that key for every encrypted value of the cipher (`name`, `notes`, the typed object, `fields`, `passwordHistory`, and FIDO2 credential fields); when a cipher carries no `key`, the vault client shall use the user key directly.
- [x] **VAULT-CRYPTO-009**: If a cipher's `name` is `null`, then the vault client shall treat the cipher as sealed-blob format and fail the cycle naming the item ID.

## Sync payload, selection, and export shape

- [x] **VAULT-EXPORT-001**: The vault client shall return the vault export as a Bitwarden-format JSON string in memory and shall not write plaintext vault data to disk.
- [x] **VAULT-EXPORT-003**: The vault client shall produce the export in the JSON shape of `bw export --format json` (`encrypted: false`, `folders`, `items`) so that the result imports through "Import data → Bitwarden (json)".
- [x] **VAULT-EXPORT-004**: If the export cannot be produced, then the vault client shall raise `BitwardenError` to the caller rather than returning partial output.
- [x] **VAULT-EXPORT-005**: The sync request shall be `GET {api}/sync?excludeDomains=true` with the bearer token, and the vault client shall fail the cycle unless the response is a JSON object with `"object": "sync"` and both `folders` and `ciphers` present as arrays (empty arrays are valid).
- [x] **VAULT-EXPORT-006**: The vault client shall exclude items whose `organizationId` is not null and items whose `deletedDate` is not null, shall include items whose `archivedDate` is not null, and shall log the counts of excluded organization items and trashed items at INFO.
- [x] **VAULT-EXPORT-007**: When exported items carry `attachments`, the vault client shall log the number of such items at WARNING, stating that attachments are not included in the export.
- [x] **VAULT-EXPORT-008**: Each exported folder shall be `{ id, name }` with `name` decrypted; each exported item shall carry, in this order: `id`, `organizationId` (null), `folderId`, `type`, `reprompt`, `name`, `notes`, `favorite`, `fields`, the single typed object for its `type`, `passwordHistory`, `creationDate`, `revisionDate`, `deletedDate`, `archivedDate`, and `collectionIds` (null).
- [x] **VAULT-EXPORT-009**: Each typed object shall carry exactly the fields listed in the vault-access design for its type (login, secureNote, card, identity, sshKey, and FIDO2 credential), in that order, emitting `null` for a field the server omits and ignoring any field the server adds.
- [x] **VAULT-EXPORT-010**: The vault client shall pass an item's `folderId` through unchanged even when no folder with that ID is present in the payload.
- [x] **VAULT-EXPORT-011**: The vault client shall emit every date field (`creationDate`, `revisionDate`, `deletedDate`, `archivedDate`, `passwordHistory[].lastUsedDate`, and FIDO2 `creationDate`) as RFC 3339 UTC with exactly three fractional digits and a `Z` suffix, truncating longer fractions, zero-padding shorter ones, and converting numeric offsets to UTC.
- [ ] **VAULT-EXPORT-012**: The vault client shall emit a missing `fields`, `passwordHistory`, `fido2Credentials`, or `uris` collection, and an absent `archivedDate`, in the same shape (`[]`, `null`, or omitted) as the CLI release named by `REFERENCE_CLI_VERSION`, the same constant announced in `Bitwarden-Client-Version`.
- [x] **VAULT-EXPORT-013**: If an item's `type` is not 1 through 5, then the vault client shall fail the cycle naming the item ID and type.
- [x] **VAULT-EXPORT-014**: The vault client shall serialize the export as UTF-8 without ASCII escaping, with two-space indentation, `": "` and `","` separators, and no trailing newline.

## HTTP transport

- [x] **VAULT-HTTP-001**: The vault client shall use HTTPS with certificate verification for every request, and where `BW_CA_CERT` names a PEM file, shall trust that bundle in addition to the system store; the vault client shall offer no option that disables verification.
- [x] **VAULT-HTTP-002**: The vault client shall send `Bitwarden-Client-Name: cli` and `Bitwarden-Client-Version` equal to its single `REFERENCE_CLI_VERSION` constant, which shall be at least `2024.12.0`, on every request, so that the server includes SSH-key items in the sync.
- [x] **VAULT-HTTP-003**: If either request returns HTTP 404, then the vault client shall fail the cycle with a message suggesting that `BW_SERVER` is wrong.
- [x] **VAULT-HTTP-004**: If either request returns an HTTP 3xx, then the vault client shall not follow the redirect and shall fail the cycle naming the redirect target.
- [x] **VAULT-HTTP-005**: If a response body cannot be parsed as JSON, then the vault client shall fail the cycle.

## Retry

- [x] **VAULT-RETRY-001**: If the token request or the sync request fails with a network error, HTTP 5xx, or HTTP 429, then the vault client shall retry that request until 3 attempts in total have been made, waiting 2 s before the second attempt and 4 s before the third, and shall fail the cycle after the final failure.
- [x] **VAULT-RETRY-002**: If the token request returns HTTP 400, 401, or 403, then the vault client shall fail the cycle without retry, surfacing the server's `error_description`, `ErrorModel.Message`, or `message` when the body carries one.
- [x] **VAULT-RETRY-003**: If the sync request returns HTTP 401 or 403, then the vault client shall fail the cycle without retry and without requesting a new token.

## Logging

- [x] **VAULT-LOG-002**: The vault client shall not log the master password, the client secret, the access token, the master key, the stretched keys, the user key, any cipher-level key, any decrypted field, or the export itself, at any log level.
- [x] **VAULT-LOG-003**: If a server request fails, then the vault client shall log at ERROR the HTTP status code, the extracted server message when present, and the first 500 characters of the response body.
- [x] **VAULT-LOG-004**: The vault client shall log at INFO the server host, the KDF type and parameters, the counts of folders and items exported, and the elapsed time of the token, sync, and decryption phases.
- [x] **VAULT-LOG-005**: When a cycle ends with one or more fields emitted as `[error: cannot decrypt]`, the vault client shall log their total count at ERROR.
