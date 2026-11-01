---
parent: high-level-design
prefix: VAULT
---

# vault-access

## Context and Design Philosophy

vault-access is the part of BackVault that talks to the Bitwarden or Vaultwarden server. Given an API-key credential pair, the master password, and a server URL, it produces the vault's contents as a Bitwarden-format JSON export string in memory, then discards every secret it derived. Everything downstream (encrypting, naming, placing the file, scheduling) belongs to other segments; everything that involves the server or the vault's cryptography belongs here.

The segment is a native Python client of the Bitwarden API. It performs the same steps the official CLI performs internally: authenticate with the API key, derive the master key from the password, unwrap the user key, fetch the sync payload, decrypt each item locally, and assemble the export. Three principles govern it:

- **The export must stay importable.** The only reason BackVault exists is to restore a vault after a disaster. The output has to be the JSON shape that `bw export --format json` produces, so the Bitwarden web vault's "Import data → Bitwarden (json)" accepts it. Where this design and the CLI could differ, the CLI wins (tenet: *Match the reference, don't improve it*).
- **Never lose vault content silently.** Two failure classes are distinguished. When the client *cannot do its job* (the server response is not a vault, an item uses a format this client does not implement), the cycle fails with a clear error, because a backup that looks complete but is missing items is worse than no backup. When *one field* of an item cannot be decrypted (bad MAC, malformed string), the client does what the CLI does: it emits the literal `[error: cannot decrypt]` for that field, logs the item and field at ERROR, and the cycle succeeds. Backups keep flowing and the loss is visible and bounded (tenet: *Restorable beats hardened*).
- **Nothing leaves the process.** Credentials, keys, and plaintext exist only in memory and only for the duration of one cycle. No child processes, no argv, no temp files.

## Server Endpoints and URL Resolution

| Purpose | Method and path | Auth |
|---------|-----------------|------|
| Token | `POST {identity}/connect/token` | client credentials in the form body |
| Sync | `GET {api}/sync?excludeDomains=true` | `Authorization: Bearer <access_token>` |
| Profile (fallback only) | `GET {api}/accounts/profile` | Bearer |

`{identity}` and `{api}` derive from `BW_SERVER`:

- Self-hosted (Vaultwarden or Bitwarden self-host): `{identity} = BW_SERVER/identity`, `{api} = BW_SERVER/api`.
- Bitwarden Cloud: `https://vault.bitwarden.com` → `https://identity.bitwarden.com` and `https://api.bitwarden.com`; `https://vault.bitwarden.eu` → the `.eu` equivalents.

`BW_SERVER` is normalised by stripping trailing slashes; a scheme other than `https` fails the cycle before any request. Transport is the standard library's `urllib.request` over HTTPS with certificate verification on. An optional `BW_CA_CERT` environment variable names a PEM bundle to trust for self-signed deployments; there is no switch that disables verification. HTTP redirects are not followed: a 3xx on either endpoint fails the cycle with the redirect target in the message, since it almost always means `BW_SERVER` is wrong (a trailing path, `http://`, or a reverse proxy in front of the wrong host).

Every request carries `Bitwarden-Client-Name: cli` and `Bitwarden-Client-Version: <REFERENCE_CLI_VERSION>`. That single constant names the CLI release whose export shape this client reproduces and against which the pre-merge drill was last run; it must be at least `2024.12.0`, because Vaultwarden omits SSH-key items (type 5) from `/sync` for clients that announce an older version.

When the server answers with an error status, the client surfaces the status code plus the first 500 characters of the body, and additionally extracts `error_description`, `ErrorModel.Message`, or `message` when the body is JSON, so a rejected client version or an `invalid_scope` is reported as the server phrased it rather than as a generic credential failure.

## Session Lifecycle

```mermaid
sequenceDiagram
    participant C as backup-cycle
    participant V as vault-access
    participant S as server
    C->>V: export_vault_json(server, client_id, client_secret, master_pw)
    V->>S: POST /identity/connect/token (client_credentials)
    S-->>V: access_token, Key, Kdf*, UserDecryptionOptions
    V->>V: master key ← KDF(password, email); stretch; unwrap user key
    V->>S: GET /api/sync?excludeDomains=true (Bearer)
    S-->>V: profile, folders, ciphers, …
    V->>V: validate payload; select items; decrypt; assemble export JSON
    V->>V: discard token and key material
    V-->>C: export JSON string
```

One call per cycle. There is no server-side logout for an API-key token; the client simply stops using it and overwrites its copies of the token, master key, stretched keys, and user key before returning. The token's `expires_in` is far longer than a cycle and is not refreshed; a 401 or 403 on the sync request fails the cycle rather than re-authenticating, and the next cycle starts fresh.

## Authentication and Key Derivation

**Input validation.** `BW_CLIENT_ID` must begin with `user.`; an `organization.` key is rejected before any request, with a message explaining that organization API keys cannot unlock a personal vault.

**Token request.** Form fields: `grant_type=client_credentials`, `scope=api`, `client_id`, `client_secret`, `deviceType=25` (Linux CLI), `deviceIdentifier`, `deviceName=backvault`. The device identifier is `uuid5(NAMESPACE_URL, "backvault:" + client_id)`, so the same deployment presents the same device on every cycle without storing state; the server creates the device record once and sends its new-device notification once. The derivation is permanent: changing it would register a new device for every existing deployment.

**Token response** (Vaultwarden and Bitwarden both return these; casing as sent):

| Field | Use | If missing |
|-------|-----|------------|
| `access_token` | Bearer token for `/api/*`; a JWT whose payload carries an `email` claim | fail: "token response has no access_token" |
| `Key` | the user key, wrapped with the stretched master key (EncString, normally type 2) | fail: "token response has no Key; this account cannot be unlocked with a master password" |
| `Kdf`, `KdfIterations`, `KdfMemory`, `KdfParallelism` | KDF parameters for the master password | fail naming the missing field; `Kdf` other than 0 or 1 fails as "unsupported KDF type N" |
| `UserDecryptionOptions.MasterPasswordUnlock.Salt` | the account email (the KDF salt) | fall back (below) |
| `PrivateKey` | not used (organization items are excluded; see Export Assembly) | ignored |

The sync `profile.key` is never used as a fallback for `Key`; the token response is the single source.

**Email.** Taken from `MasterPasswordUnlock.Salt`; if absent, from the JWT `email` claim (payload decoded without signature verification, since the TLS channel already authenticates the server); if still absent, from `/api/accounts/profile`. The email is trimmed and lower-cased before use.

**Password encoding.** The master password is used as its UTF-8 bytes exactly as supplied, with no trimming and no Unicode normalisation. This matches the official clients, which encode the raw string.

**Master key** (32 bytes), by `Kdf`:

- `0` PBKDF2: PBKDF2-HMAC-SHA256(password, salt = email bytes, iterations = `KdfIterations`).
- `1` Argon2id: Argon2id v1.3(password, salt = SHA-256(email bytes), time = `KdfIterations`, memory = `KdfMemory` MiB × 1024 KiB, parallelism = `KdfParallelism`, 32-byte output).

**Stretched key.** `enc = HKDF-Expand-SHA256(prk = master key, info = "enc", 32)`, `mac = HKDF-Expand-SHA256(prk = master key, info = "mac", 32)`. Expand only; the master key is used directly as the PRK.

**User key.** `Key` is decrypted as an EncString to raw bytes. A type-2 `Key` is decrypted with the stretched key and must yield 64 bytes: the first 32 are the user's AES key, the last 32 the user's MAC key. A legacy type-0 `Key` is decrypted with the master key directly and must yield 32 bytes (an AES-only key). Any other length fails the cycle as "user key has unexpected length N".

## EncString Decryption

Every encrypted value in the sync payload is a string of the form `<type>.<part>|<part>…`, each part base64. Decryption has two entry points: *to bytes* (for `Key` and cipher-level keys) and *to string* (UTF-8 decode of the bytes, for every content field).

| Type | Parts | Handling |
|------|-------|----------|
| `2` | `iv\|ciphertext\|mac` | Requires a 64-byte key. Compute HMAC-SHA256(mac key, iv ‖ ciphertext); compare in constant time; on match, AES-256-CBC decrypt with the enc key and strip PKCS#7 padding. With a 32-byte key (no MAC key) this is a decryption failure. |
| `0` | `iv\|ciphertext` | Legacy, unauthenticated. Requires a 32-byte key; AES-256-CBC decrypt. With a 64-byte key this is a decryption failure, as in the SDK, which refuses to use an authenticated key without a MAC. Supported for reading only. |
| `1`, `3`–`7` | — | Not implemented. Fails the *cycle*, naming the type and the item ID, because the client lacks the capability rather than the data being bad. |

**Malformed values.** An empty string is treated as absent (`null`). A value with no `<type>.` prefix, the wrong number of parts for its type, non-base64 content, an IV that is not 16 bytes, or a MAC that is not 32 bytes is a *decryption failure*.

**Decryption failure of a content field** (MAC mismatch, bad padding, malformed value, non-UTF-8 plaintext) does not fail the cycle. The field is emitted as the literal string `[error: cannot decrypt]`, which is what the official CLI emits, and the item ID and field path are logged at ERROR. The count of such fields is logged at the end of the cycle. The same applies to a folder `name`. Decryption failure of a *key* (`Key`, or a cipher-level `key`) is different: nothing beneath it can be read, so the cycle fails naming the item ID and the field `key`.

**Cipher-level keys.** A cipher may carry its own `key` (an EncString wrapped with the user key). When present, it is unwrapped to a 64-byte key first, and that key decrypts *every* encrypted value of the cipher: `name`, `notes`, the typed object, `fields[]`, `passwordHistory[]`, and FIDO2 credential sub-fields. When absent, the user key decrypts them directly.

**Blob-format ciphers.** A cipher whose `name` is `null` is in the sealed-blob format (legacy-format ciphers always carry an encrypted `name`); its content lives in a `data` payload this client does not implement. The cycle fails naming the item ID. A `null` in any *other* field (`notes`, `totp`, `username`, and so on) is ordinary and passes through as `null`.

## Sync and Export Assembly

**Payload validation.** The response must be a JSON object with `"object": "sync"` and with both `folders` and `ciphers` present as arrays. An absent key, a different `object` value, a different casing, or a non-JSON body fails the cycle; an *empty* array is valid. This rule exists so that a proxy page, an older server, or a renamed field can never produce a well-formed export with no items.

**Item selection** mirrors the CLI's individual-vault export: items whose `organizationId` is not null are excluded (they belong to an organization export), and items whose `deletedDate` is not null (trash) are excluded. Archived items (`archivedDate` not null) are *included*; the CLI applies no archive filter. The counts of both exclusions are logged at INFO. Items that carry `attachments` are counted and that count is logged at WARNING, because no Bitwarden export format carries attachment data and the operator should know the backup cannot restore them.

**Document shape**, serialized as UTF-8 without ASCII escaping (`ensure_ascii=False`), two-space indentation, `": "` and `","` separators, no trailing newline:

```
{
  "encrypted": false,
  "folders": [ { "id", "name" } … ],
  "items":   [ <item> … ]
}
```

**Item** (keys in the CLI's assignment order):

| Key | Source | Notes |
|-----|--------|-------|
| `id`, `organizationId` (null), `folderId`, `type`, `reprompt`, `name`, `notes`, `favorite` | plain or decrypted | `type`: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key. `folderId` is passed through even when no folder with that ID is present; the CLI does not validate it. |
| `fields` | decrypted | `[{ name, value, type, linkedId }]` |
| one of `login`, `secureNote`, `card`, `identity`, `sshKey` | decrypted | see below |
| `passwordHistory` | decrypted | `[{ password, lastUsedDate }]` |
| `creationDate`, `revisionDate`, `deletedDate` (null), `archivedDate` | plain | see Dates |
| `collectionIds` | — | always `null` in an individual export |

**Type-specific objects**, with field sets and order fixed here; a sub-field the server omits is emitted as `null`, a sub-field the server adds is ignored:

- `login`: `uris` (`[{ match, uri }]`), `username`, `password`, `totp`, `fido2Credentials`.
- `secureNote`: `type`.
- `card`: `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code`.
- `identity`: `title`, `firstName`, `middleName`, `lastName`, `address1`, `address2`, `address3`, `city`, `state`, `postalCode`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passportNumber`, `licenseNumber`.
- `sshKey`: `privateKey`, `publicKey`, `keyFingerprint`.
- FIDO2 credential (inside `login.fido2Credentials`): `credentialId`, `keyType`, `keyAlgorithm`, `keyCurve`, `keyValue`, `rpId`, `userHandle`, `userName`, `counter`, `rpName`, `userDisplayName`, `discoverable`, `creationDate`.

Every string in these objects is an EncString to decrypt except `creationDate`; `match`, `type`, and `linkedId` are integers passed through.

**Empty collections and absent `archivedDate`.** Whether a missing `fields`, `passwordHistory`, `fido2Credentials`, or `uris`, or an absent `archivedDate`, is emitted as `[]`, `null`, or omitted follows the CLI release named by `REFERENCE_CLI_VERSION`. The drill's comparison treats `null`, `[]`, and absent as distinct so that any divergence is caught rather than papered over.

**Dates.** Every date field (`creationDate`, `revisionDate`, `deletedDate`, `archivedDate`, `passwordHistory[].lastUsedDate`, FIDO2 `creationDate`) is parsed as RFC 3339 and re-emitted in UTC with exactly three fractional digits and a `Z` suffix: six or seven digits are truncated, fewer than three are zero-padded, and a numeric offset is converted to UTC. This is the shape JavaScript's `toISOString()` produces and the CLI emits.

**Unknown item types.** Items of any `type` other than 1–5 (6–8: bank account, passport, driver's licence) fail the cycle naming the item ID and type. Vaultwarden does not yet serve them and the CLI's handling is still changing; failing is safer than guessing.

**Contract with the drill.** Two exports of the same vault are considered equivalent when, after parsing, sorting `folders` and `items` by `id`, and sorting any arrays of objects by their JSON serialization, the structures are equal, with `[error: cannot decrypt]` compared literally. Key order and whitespace are not part of the contract, but the client follows the CLI's order so that text diffs stay readable.

## Retry and Failure Handling

| Failure | Behaviour |
|---------|-----------|
| Network error, HTTP 5xx, or HTTP 429 on the token or sync request | Retry the request: 3 attempts in total, waiting 2 s then 4 s |
| HTTP 400/401/403 on the token request | Fail immediately, surfacing the server's error text (bad credentials, disabled account, rejected client version, wrong scope); no retry |
| HTTP 401/403 on the sync request | Fail immediately ("token rejected"); no re-authentication within the cycle |
| HTTP 404 on either request | Fail immediately with a hint that `BW_SERVER` may be wrong |
| HTTP 3xx on either request | Fail immediately naming the redirect target |
| HTTP 200 with a non-JSON body, or JSON that is not a sync object | Fail immediately |
| Decryption failure of `Key` or a cipher-level `key`; EncString type not implemented; blob-format cipher; unknown item type; user key of unexpected length | Fail immediately naming the item ID (where applicable) and the reason; no partial output |
| Decryption failure of a content field or folder name | Emit `[error: cannot decrypt]`, log at ERROR, continue |

Every cycle-level failure raises `BitwardenError` to backup-cycle, which turns it into a failed cycle (exit 1). The segment never writes anything itself.

## Logging and Redaction

Logged at INFO: server host, KDF type and parameters, counts of folders, items exported, organization items excluded, trashed items excluded, and elapsed time per phase. Logged at WARNING: the number of exported items that carry attachments. Logged at ERROR: each undecryptable content field (item ID and field path) and, at the end of the cycle, their total; on HTTP failure, the status code, the extracted server message, and the first 500 characters of the body.

Never logged, at any level: the master password, the client secret, the access token, the master key, the stretched keys, the user key, any cipher key, any decrypted field, or the export itself.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Mechanism | Native Python client of the Bitwarden API | Drive the official `bw` CLI (the previous implementation); `rbw` | The CLI is a pkg-bundled Node binary that needs `seccomp=unconfined`, an unpinned download, and carries a Node CVE surface, and it puts the master password on argv. `rbw` has no export command. The protocol is small and fully specified by the open-source SDK, and every primitive is already a dependency (`cryptography`, `argon2-cffi`). |
| Export modes | Raw JSON only (the caller encrypts) | Also produce Bitwarden's password-protected `encrypted_json` | The portable format is restorable without Bitwarden tooling (tenet: *Portable beats native*) and is the maintainer's operational mode. The password-protected format is documented (16-byte salt, the account's KDF, `encKeyValidation_DO_NOT_EDIT`, `data`) and could be added later if a `bw import`-native file is ever wanted. |
| Undecryptable content field | Emit `[error: cannot decrypt]`, log at ERROR, cycle succeeds | Fail the cycle | Matches the CLI's output exactly, so the drill and the importer see the same thing; keeps the DR copy fresh when one server-side value is corrupt and the operator cannot repair it. The loss is one field, named in the log. |
| Capability gaps (blob ciphers, EncString types 1/3–7, item types 6–8, missing `Key`/`Kdf`) | Fail the cycle | Skip the item and continue | These mean BackVault needs an upgrade, not that the vault has one bad value. A silently incomplete backup defeats the project's purpose (tenet: *Restorable beats hardened*). |
| Organization items | Excluded, with a logged count | Decrypt organization keys via the RSA private key and include them | The CLI's individual export excludes them, so including them would diverge from the reference and change what restores. Excluding them also removes the RSA path entirely. An organization export is a separate feature. |
| Archived items | Included | Excluded like trash | The CLI's individual export has no archive filter; matching it keeps archived items restorable. |
| Attachments | Not exported; count logged at WARNING | Download and bundle attachments | No Bitwarden export format carries attachments, and the importer cannot accept them; the warning makes the gap visible. |
| Sync payload validation | Require `object == "sync"` and both `folders` and `ciphers` present as arrays | Default missing keys to empty lists | Defaulting could turn a proxy error page or a renamed field into a valid-looking empty export, the project's worst outcome. |
| HTTP client | Standard library `urllib` with redirects disabled | `httpx`, `requests` | Two small requests per cycle; no new dependency to scan and pin (tenet: *Pinned beats fresh*). Refusing redirects turns a misconfigured `BW_SERVER` into a clear error instead of a silent GET against the wrong host. |
| TLS for self-signed servers | `BW_CA_CERT` path to a trusted bundle | A verify-off switch (the `NODE_TLS_REJECT_UNAUTHORIZED=0` the CLI honoured) | Disabling verification would let any host on the path read the master password hash and the vault. Trusting a named CA is the same convenience without that exposure. |
| Device identity | UUIDv5 of the client ID, `deviceType` 25, name `backvault` | Random UUID per cycle; persisted file | Stateless yet stable: one device record and one new-device email per deployment instead of one per cycle. |
| Email source | `MasterPasswordUnlock.Salt`, then JWT claim, then profile | Require a `BW_EMAIL` variable | No new configuration; the server already tells the client the salt it must use. |
| Password bytes | Raw UTF-8, no normalisation or trimming | NFKC normalisation; trimming | The official clients encode the raw string; any normalisation here would derive a different key for some passwords and lock the account out of its own backups. |
| Retry scope | Network/5xx/429 on HTTP; never on authentication rejection or decryption | Retry everything; retry nothing | Transient faults are network-shaped; a wrong password or a MAC mismatch will not improve on retry. |
| Sub-field schema | Fixed field lists and order in this document; server-missing → `null`, server-extra → ignored | Pass through whatever the server sends | The export must be the CLI's shape regardless of server version; passing through unknown keys would leak server-specific fields into the import. |
| Empty-collection shape | Pinned to the CLI release used in the pre-merge drill, recorded as a constant | Choose `[]`/`null`/omit by taste | Only the reference can settle it, and it changes between CLI releases; recording the release makes the choice auditable. |
| Date precision | Normalise every date to milliseconds, UTC, `Z` | Pass the server's values through | The CLI emits JavaScript `toISOString()` values; the Bitwarden importer and the drill's diff both expect that shape, and servers differ (Vaultwarden microseconds, Cloud seven digits). |
| Equivalence for the drill | Semantic (sorted, parsed) equality with `null`/`[]`/absent kept distinct | Byte-for-byte equality | Key order is an artefact of the CLI's object construction and changes between CLI releases; the importer does not depend on it. The three empty shapes stay distinct so a real divergence is not hidden. |
| Module layout | `src/vault_client.py` (session, public API) over `src/vault_crypto.py` (keys, EncStrings), `src/vault_export.py` (shape), `src/vault_http.py` (transport, retry); the file-format code lives in backup-encryption's `src/backup_crypto.py` | One module holding the client and `encrypt_data` | The crypto, the export shape, and the transport change for different reasons and are each testable in isolation; keeping every file under 300 lines is a project quality gate. Separating `encrypt_data` lets backup-encryption's tests import the production encryptor directly. |
| Transport injection | `export_vault_json` accepts an `http` callable (default: `urllib` with redirects disabled) and a `sleep` callable | Monkeypatch `urllib` in tests | A fake transport makes every HTTP and retry spec testable without a server and keeps the production path a single small function. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Password-protected export is encrypted.** `bw export --format json --password <pw>` switches to the `encrypted_json` format, so the previous bitwarden mode did write an encrypted file. It is dropped for the portability reasons above, not because it was broken.
2. ✅ **Archived items are exported** and `archivedDate` is emitted; the CLI's individual export applies no archive filter.

### Deferred
1. **Bitwarden Cloud token response.** The field set above is confirmed against Vaultwarden's source. Bitwarden's hosted identity server is expected to match (the SDK consumes the same `UserDecryptionOptions`), but a live check against Cloud has not been done.
2. **Accounts without a master password** (Key Connector, trusted-device decryption). `MasterPasswordUnlock` is null and `Key` may be absent for these; the client fails with the "cannot be unlocked with a master password" message. Support is out of scope.
3. **Argon2 memory ceiling.** Vaultwarden allows up to 1024 MiB; the container should document memory headroom for Argon2id accounts.
4. **`uriChecksum`.** The CLI's login-URI export model carries this newer field. Confirm whether the current CLI emits it in a decrypted export and mirror it.
5. **CLI handling of item types 6–8.** Confirm whether the CLI exports or drops them, and match once Vaultwarden serves them.
6. **Key material in memory.** Python cannot guarantee zeroization; the client overwrites `bytearray` copies on exit but immutable `bytes` intermediates may linger until garbage collection.
7. **Pre-merge drill tooling.** A comparison script (parse, sort, diff two exports, distinguishing `null`/`[]`/absent) belongs in the repository so the drill is repeatable; its home is decided in Phase 6.

## Cascade Notes

- **backup-cycle**: the `bitwarden` mode and its whitelist disappear (`BACKUP_ENCRYPTION_MODE` becomes raw-only or is removed); `export_raw_encrypted`'s write tail moves fully into backup-cycle; `BW_CA_CERT` becomes an optional variable; `NODE_TLS_REJECT_UNAUTHORIZED` is no longer read.
- **image-delivery**: the `bw` download stage, the `seccomp=unconfined` requirement in compose and docs, and the `bw --version` smoke test are removed; `IMAGE-BUILD-006`, `IMAGE-BUILD-008`, `IMAGE-RUN-001`, and `IMAGE-CI-001` carry the change.
- **backup-encryption**: no change; it still receives a UTF-8 JSON string.

## References

- Bitwarden SDK (reference implementation of the protocol and crypto): https://github.com/bitwarden/sdk-internal — `crates/bitwarden-crypto` (KDF, HKDF stretch, EncString, AES-CBC-HMAC), `crates/bitwarden-vault/src/cipher/cipher.rs` (cipher-level keys), `crates/bitwarden-exporters/src/json.rs` (export shape)
- Bitwarden CLI export: https://github.com/bitwarden/clients — `apps/cli/src/tools/export.command.ts`, `libs/tools/export-vault-core/src/services/individual-vault-export.service.ts`, `libs/common/src/models/export/*.export.ts`
- Vaultwarden server: https://github.com/dani-garcia/vaultwarden — `src/api/identity.rs` (API-key login), `src/api/core/ciphers.rs` (sync), `src/db/models/cipher.rs` (cipher JSON)
- Bitwarden import formats: https://bitwarden.com/help/import-data/
- Sibling segments: backup-cycle (caller), backup-encryption (encrypts the returned string), image-delivery (loses the `bw` and seccomp requirements)
