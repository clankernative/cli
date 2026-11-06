# Verification and review contract

The CLI follows Platform's principles: one supported implementation for each
job, explicit authority, closed failure behavior, and evidence for the exact
inputs checked. The CLI's gates use Cargo and the toolchain in
`rust-toolchain.toml`. Platform's Roc recipes, Bazel build, native admission,
Linux sandbox qualification, provider campaigns and infrastructure checks stay
in Platform. Copying those jobs here would not verify this executable.

## Required local checks

Run these from the repository root, with the pinned toolchain available:

```console
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
CLIPPY_CONF_DIR="$PWD/architecture" CARGO_TARGET_DIR=target/architecture cargo clippy --locked --lib --all-features -- -D warnings -F clippy::disallowed_methods -F clippy::disallowed_types -F clippy::disallowed_macros
RUSTFLAGS='-D warnings' cargo test --locked --all-targets --all-features
RUSTFLAGS='-D warnings' cargo test --locked --doc --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --all-features --document-private-items
RUSTFLAGS='-D warnings' cargo build --locked --release --all-targets --all-features
```

Linux CI additionally runs `sh scripts/qualify-secret-service.sh` against a disposable
real GNOME Secret Service session, with cross-process access, rotation/deletion and
unavailable-store refusal. It stores synthetic test values only and supplies no
human login credentials. The ignored helper is not evidence unless actually run.

All compiler, Clippy and documentation warnings fail CI. Clippy enables `all`,
`pedantic` and `nursery`, plus selected restrictions against unchecked panics,
casts, debugging, unfinished implementation, process exits and lint allowances.
Unsafe Rust is forbidden. Public APIs require documentation, including failure
semantics. Assertions and unwraps are allowed in test functions and explicitly
test-only helpers; production paths return errors.

Keep the lint groups and configuration in Cargo.toml and the Clippy policy files.
Do not blanket-enable `clippy::restriction`: some of its rules conflict with
each other. Restriction lints use `deny`, because clap's generated code contains
its own lint allowances; the library effect boundary uses `forbid` and cannot be
suppressed. Any necessary authored exception needs a narrow `#[expect(...,
reason = "...")]` and review; unused expectations fail under warnings-as-errors.

## Architecture boundary

`src/lib.rs` owns embedded historical data and models. Its dedicated Clippy pass
uses `architecture/clippy.toml` and a separate compilation directory so ordinary
lint outputs cannot satisfy it. Compiler-resolved restrictions reject the listed
environment, clock, filesystem, process, network and output APIs, including
aliases. The process tests also compile positive and negative fixtures and
require the expected diagnostic; a setup failure is not rejection evidence.

This is a guard on authored library code, not a hostile-code sandbox or a proof
that arbitrary dependency implementations are pure. New adapters, dependencies,
macros and boundary changes still need review. Keep runtime app discovery,
admission, authorization and operational step ordering in Platform. Do not import
its private crates/protocols or turn the historical catalog into a live registry.

For any changed authority, response validation, redaction or retry boundary, add
a negative regression. Reject wrong instance/connection/environment identities,
malformed or oversized responses and stale evidence. A timeout after dispatch
does not authorize repeating a mutation. Keep credentials and private instance
configuration out of this repository. Remove replaced paths and update callers
in place; do not add compatibility shims or competing operational implementations.

## CI gates

Every pull request, merge-group candidate and main push runs the same gates.
Manual dispatch and a weekly schedule rerun them even without source changes.
There are no path filters, production credentials or privileged PR triggers.

| Gate | Evidence |
| --- | --- |
| `check (ubuntu-24.04)` / `check (macos-15)` | Formatting, strict lint, library boundary, process/compiler tests, doctests, rustdoc and release compilation. Verification must not change tracked files. |
| `secrets` | Gitleaks scans current files and all fetched Git history with full redaction and no repository exclusions. |
| `dependencies` | Cargo audit denies advisory warnings; cargo-deny rejects duplicate versions, wildcard requirements, unapproved registries/Git sources and third-party licenses outside the explicit allowlist. |
| `workflows` | ShellCheck checks installer/packaging scripts; Actionlint validates workflows and shell steps; offline pedantic Zizmor checks workflow security. |
| `verify` | Always runs and fails unless every prerequisite succeeded, including both OS jobs. Failed, cancelled and skipped jobs cannot produce a passing gate. |

Actions use full commit pins; downloaded scanners use reviewed version and
SHA-256 pins under `.github/`. Update and verify the executable and checksum
together. Rust has one version declaration in `rust-toolchain.toml` rather than
a second CI-only version. No build caches or reused verification receipts are
used. Dependency licensing excludes this unpublished application, whose own
distribution license has not been declared; all third-party dependencies are
checked. It does not assign a license to this repository.

To reproduce the security/tooling gates with the versions pinned in the workflow:

```console
gitleaks dir . --redact=100 --config .gitleaks.toml
gitleaks git . --redact=100 --config .gitleaks.toml --log-opts=--all
cargo audit --deny warnings
cargo deny --locked --all-features check --deny warnings bans licenses sources
actionlint
zizmor --offline --no-progress --pedantic .github/workflows
```

## Merge enforcement

`.github/branch-protection.json` records the intended main-branch policy: the
GitHub Actions `verify` check must pass against an up-to-date candidate, changes
must go through a pull request, all conversations must be resolved, and
administrators cannot bypass protection. Only the explicitly allowlisted
maintainer may merge; other organization members and outside contributors gain
no merge access. Force pushes and branch deletion are forbidden. The workflow handles
`merge_group` if a merge queue is enabled later.

There is currently one trusted writer, so a second reviewer's approval is not
required. Checks are required for that maintainer too; there is no bypass.

This file is configuration to apply, not proof that protection is active. When
publishing a new public repository, apply and read back this policy before
accepting contributions. GitHub Free supports these protections for public
repositories. An administrator can apply the checked-in policy:

```console
gh api --method PUT repos/clankernative/cli/branches/main/protection --input .github/branch-protection.json
```

Verify the active server settings rather than treating this file as enforcement.
Report the checks actually completed, the inspected commit and any limitations.
Local or mocked checks never establish live provider or Platform qualification.

## Login adapter review

`docs/LOGIN.md` defines the implemented human auth contract and the separate live
instance gate. A local HTTPS server with ephemeral certificates exercises the
production TLS provider, certificate/hostname verification, redirect refusal and
response-byte bounds; fragmented loopback requests cover accepted-socket mode.
Tests cover the required Google callback issuer (including missing, duplicate,
wrong and malformed issuers), ephemeral RSA-signed ID tokens (including wrong
issuer/audience/domain/nonce/expiry/signature), PKCE, a real loopback callback,
instance binding changes, cookie/CSRF validation, bounded malformed responses,
redaction, refresh rotation and local-first logout. Headless process tests prove
login refuses before browser/credential-store work. Provider/app/store mocks do
not qualify native credential storage or hosted Google/IAP access.

TLS uses Rustls with one AWS-LC provider. Linux Secret Service uses the native
D-Bus adapter with encrypted communication and vendored libdbus; macOS uses
Keychain Services. The lockfile keeps one compatible procedural-macro generation
across the graph, including Clap 4.5.60 and Serde 1.0.228. Review upgrades together;
the duplicate-version ban remains enabled with no package skips. The pinned TLS
packages' ISC/BSD and Mozilla root data's CDLA licenses have exact-version
approvals in deny.toml; the general license allowlist remains unchanged.

## Release gate

`release.yml` calls this exact revision's complete CI before building tagged native
archives. Tags must match Cargo's version and be reachable from main. Archive
builds use the repository-pinned compiler/lockfile, include dependency notices
harvested with SHA-pinned cargo-about 0.9.3 and a source manifest, and create
GitHub-hosted provenance attestations. Archive creation strips macOS metadata
and checks the exact five-entry payload before attestation. Publishing requires both native builds and
verifies their attestations. Installer and checksums receive their own attestations.
The installer checks repository/workflow/tag provenance and checksum before
installation, refuses existing destinations, and retains notices. One narrow
Zizmor annotation documents its local-action-only self-repository suggestion on a
reusable workflow call; GitHub and pinned Actionlint require the `./` workflow
syntax. No check is disabled or skipped.

`.github/release-tag-rules.json` records two server-applied tag rules: only the
trusted maintainer can create `v*` refs; no actor bypasses tag update/deletion
restrictions. These are independent of main's mandatory checks and PR policy.
Read back actual repository settings before publishing; a configuration file
alone is not enforcement.
