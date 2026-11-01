# Contributing to BackVault

Thanks for your interest. BackVault exists for one purpose: a backup that restores cleanly into a fresh Vaultwarden after a disaster. Every change is judged against that first.

## Prerequisites

- A Rust toolchain via [rustup](https://rustup.rs/). The repository's `rust-toolchain.toml` selects the exact version and components; rustup installs it on first use.
- Docker, for building the service image.
- Git.

## Local workflow

```bash
git clone https://github.com/tgrecojr/backvault.git
cd backvault

cargo fmt --all -- --check                                   # formatting
cargo clippy --workspace --all-targets --locked -- -D warnings  # lint, warnings are errors
cargo test --workspace --locked                              # all tests, fixtures included

docker build --platform linux/amd64 -t backvault:dev .       # the service image
docker run --rm backvault:dev --version                      # smoke test
```

Run all four checks before pushing; CI runs the same commands and nothing else.

## How changes are made: linked-intent development

This repository is developed with linked-intent development (LID). Design intent lives in `docs/` and flows one way: `docs/high-level-design.md` → the segment designs under `docs/intent/<segment>/` → the EARS specs beside each design → tests → code. A change starts in the docs, not in the code, and tests are written before the implementation. `CLAUDE.md` (mirrored as `AGENTS.md`) describes the workflow; `docs/arrows/index.yaml` tracks each segment's status.

Tests and code cite the spec they satisfy with `// @spec <ID>` comments. Every test file checks that the IDs it cites exist.

## Layout

| Path | What |
|---|---|
| `crates/backvault-format` | The `.enc` file format: encrypt and decrypt, no IO |
| `crates/backvault-decrypt` | The standalone restore tool released for macOS and Linux |
| `crates/backvault` | The service: vault client, backup cycle, scheduler, logging |
| `docs/` | Design tree, specs, decision records |
| `.github/workflows/` | PR checks, supply-chain scan, image publish, restore-tool release, registry retention |

## Pull requests

1. Branch from `main`.
2. Walk the arrow: update the design and specs if intent changes, write or update tests, then code.
3. Run the four local checks.
4. Open a PR. CI must pass; Renovate PRs follow the same rules.

## Releases

- The service image publishes on every merge to `main` as `ghcr.io/tgrecojr/backvault:latest` and `main-<sha>`, signed with cosign and attested with an SBOM and build provenance.
- The restore tool is released by pushing a tag `vX.Y.Z`. The workflow builds four targets, runs the tool's tests on each, signs every binary, attests provenance, and creates the GitHub Release with the notes in `.github/release-notes.md`.

## Security

Do not open public issues for vulnerabilities. Email the maintainer privately with a description and reproduction steps, and allow time for a fix before disclosure.

Never commit secrets. `.env` is ignored; `.env-example` holds placeholders only.

## Licence

Contributions are licensed under AGPL-3.0, like the project.
