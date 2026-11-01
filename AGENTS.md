# BackVault

## Overview

BackVault is a Dockerized service that periodically backs up a Bitwarden or Vaultwarden vault into password-protected encrypted files. Its purpose is disaster recovery: after a Vaultwarden rebuild, the operator decrypts the newest backup with the standalone `backvault-decrypt` tool and restores it through "Import data → Bitwarden (json)". Functional correctness of that restore path outranks every other concern.

## Tech Stack

- Language: Rust (toolchain pinned in `rust-toolchain.toml`, edition 2024), one Cargo workspace with three crates
- Runtime: Chainguard `static` distroless container, one statically linked musl binary, non-root, `linux/amd64`
- Vault access: native client of the Bitwarden API over `ureq` + `rustls` (`crates/backvault/src/vault/`)
- Crypto: RustCrypto crates (`aes-gcm`, `argon2`, `pbkdf2`, `aes` + `cbc`, `hmac`, `hkdf`, `sha2`); secrets in `zeroize` containers
- Restore tool: `backvault-decrypt`, released for macOS (arm64, x86_64) and Linux (x86_64, arm64) on `v*` tags
- Tests: `cargo test` (integration tests under each crate's `tests/`); lint: `cargo clippy -D warnings`; format: `cargo fmt`
- CI: GitHub Actions (test, supply-chain scan with OSV and cargo-deny, build/sign/publish image, restore-tool release, GHCR retention); Renovate

## Commands

- `cargo test --workspace --locked` — run all tests (format fixtures and restore-tool subprocess tests included)
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — lint
- `cargo fmt --all -- --check` — format check
- `cargo deny check` — advisories, licences, bans, sources (policy in `deny.toml`)
- `cargo build --release -p backvault-decrypt` — build the restore tool locally
- `docker build --platform linux/amd64 -t backvault:local .` — build the image
- `docker run --rm backvault:local --version` — smoke-test the image
- `docker compose up -d` — run the reference deployment (needs `.env`)
- `backvault-decrypt <file.enc>` — decrypt a backup (prompts for the password; plaintext to stdout)

## Architecture

One Cargo workspace:

| Crate | Kind | Holds |
|-------|------|-------|
| `backvault-format` | library | The `.enc` layout, key derivation, encrypt and decrypt. No IO. |
| `backvault` | library + binary | The service: `vault/` (client), `cycle/` (one backup), `scheduler.rs` (loop, retention), `logging.rs`, `main.rs` (PID 1) |
| `backvault-decrypt` | binary | The restore tool: password prompt, file IO, one call into `backvault-format` |

The service's `main` installs logging, registers SIGTERM/SIGINT, and runs the supervisor: every `BACKUP_INTERVAL_HOURS` it runs one cycle (validate configuration, call the vault client, encrypt in memory, write `.part`, fsync, rename to `backup_<UTC timestamp>.enc` under `/app/backups`); once per UTC calendar day it prunes files older than `RETAIN_DAYS`. Every secret lives in a zeroizing container; the restore tool is never in the image.

The design is tracked as five arrow segments under `docs/intent/`: vault-access, backup-encryption, backup-cycle, scheduler-retention, delivery. See `docs/high-level-design.md` for the map.

## Environment Variables

Required: `BW_CLIENT_ID`, `BW_CLIENT_SECRET`, `BW_PASSWORD`, `BW_SERVER`, `BW_FILE_PASSWORD`.
Optional: `BACKUP_DIR`, `BACKUP_INTERVAL_HOURS`, `RETAIN_DAYS`, `LOG_FILE`, `BW_CA_CERT`. (`BACKUP_ENCRYPTION_MODE` is accepted only as `raw`; any other value fails the cycle with an explanation.)
Template: `.env-example`. Never commit `.env`.

## LID
- Mode: Full
- Version: 1.3.0

## Linked-Intent Development (MANDATORY)

**Consult the `linked-intent-dev` skill for ALL code changes.** All changes flow through the arrow of intent in one direction:

```
HLD → LLDs → EARS → Tests → Code
```

- **New features and refactors**: full six-phase workflow (HLD check → LLD check/draft → EARS → intent-narrowing edge audit → tests-first → code).
- **Bug fixes**: walk the arrow like any other change — find where behavior diverged from intent and cascade from there. No short-circuit.
- **If unsure**: use the full workflow.

Stop after each phase for user review. **Docs carry current intent, written to be read cold** — write each doc as if authored fresh today, from current intent alone: no narration of how it changed, no meaning that needs the conversation that produced it, no rebuttals to questions only a past discussion raised. Rationale, considered alternatives, and constraints a fresh author would independently write stay; record rejected alternatives and why in the LLD's Decisions & Alternatives table, not as asides in body prose.

**Memory vs. intent.** Before saving durable project knowledge to agent or tool memory, test whether it is project *intent* — would a fresh agent, in any tool, next session, need it to build this system correctly? If yes, record it in the arrow (HLD / LLD / EARS / decision doc), which travels and cascades — not in private, per-tool memory, where intent escapes the arrow. Knowledge about the user or how they like to work stays in memory.

### Navigation

| What you need | Where to look |
|---|---|
| High-level design | `docs/high-level-design.md` |
| Design tree (sub-HLDs, LLDs, their specs) | `docs/intent/` — one folder per node |
| EARS specs | beside each design doc as `{node}-specs.md` in the node's folder under `docs/intent/` |
| Decision docs | `docs/decisions/` (project-level) and `docs/intent/<segment>/decisions/` |
| Arrow of intent overlay | `docs/arrows/index.yaml` and per-segment docs in `docs/arrows/` |

### Terminology

- **HLD**: High-Level Design — single project-level doc at `docs/high-level-design.md`.
- **LLD**: Low-Level Design — detailed component design doc in `docs/intent/`. The design layer is a recursive tree: the root is the HLD, leaf LLDs own EARS, and a component deep enough to outgrow one doc becomes a sub-HLD (HLD-shaped, owns no EARS) with children beneath it. "HLD" and "LLD" are roles by position; depth-2 (one HLD over flat leaf LLDs) is the default.
- **EARS**: Easy Approach to Requirements Syntax — structured one-line requirements beside each design doc as `{node}-specs.md` in the node's folder under `docs/intent/`. IDs are path-concatenated — the root-to-leaf path of the owning segment plus a number — so a prefix grep gathers a subtree. Markers: `[x]` implemented, `[ ]` active gap, `[D]` deferred.
- **Arrow**: the unidirectional chain from vision to code (HLD → LLDs → EARS → Tests → Code). Strictly a DAG of intent.
- **Arrow segment**: the territory owned by one leaf LLD — the LLD itself plus the specs, tests, and code that cite its EARS IDs. The boundary is the leaf prefix. Within-segment cascade is free; across-segment cascade pauses.
- **Cascade**: propagating a change downstream through the arrow so adjacent levels stay coherent.

### Code annotations

Annotate code and tests with `@spec` comments citing EARS IDs:

```
// @spec VAULT-SESSION-001, VAULT-SESSION-002
```

Place the annotation at the *entry point of the behavior's implementation graph* — the topmost function or module owning the specified behavior, not every helper. When a behavior spans multiple subsystems (UI + API + database, for example), annotate at the entry point in each subsystem. Tests follow the same rule: annotate the test that directly exercises the spec, not every inner assertion.
