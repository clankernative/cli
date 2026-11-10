# Day 2 CLI

The new Rust CLI for Day 2, in `clankernative/cli`, alongside
[`clankernative/platform`](https://github.com/clankernative/platform).

The CLI catalogs public command use cases and manages **active app owners**
through a selected local platform installation. `login`, `whoami` and `logout`
implement browser authentication for company-configured Google IAP apps, with
credentials in the OS store. Companies must configure discovery and allowlist
their desktop OAuth client; see [company login](docs/LOGIN.md).
`call` invokes admitted app queries/commands, and `openapi` prints the current
generated API contract; see [app calls](docs/API.md). `catalog` and `roadmap`
remain offline.
`completion bash`, `completion zsh` and `completion fish` generate offline shell completion from
the implemented parser; see [shell completion](docs/COMPLETION.md).
`app secrets list/create/rotate/status/reveal/delete` stores supplied values through an
owner-authenticated app session; [secret setup and semantics](docs/SECRETS.md)
describe the required platform deployment. `app sqlite download` produces a
private business-data debugging export; see [SQLite download](docs/SQLITE.md).
App activation and protected retirement remain separate work.

## Start here

- [Command catalog](docs/COMMAND-CATALOG.md): use-case summaries, safety
  boundaries, public platform references and proposed commands.
- [Implementation roadmap](docs/ROADMAP.md): delivery order, platform gaps and
  acceptance criteria.
- [Architecture](docs/ARCHITECTURE.md): the new Rust frontend and existing
  platform ownership boundary.
- [App owners](docs/OWNERS.md): local operator commands, permissions and receipts.
- [Company login](docs/LOGIN.md): employee sign-in and required instance setup.
- [App calls](docs/API.md): authenticated OpenAPI, queries, commands and receipts.
- [App secrets](docs/SECRETS.md): owner-authenticated storage and rotation.
- [Shell completion](docs/COMPLETION.md): offline Bash/Zsh/Fish generation.
- [Machine-readable catalog](catalog/legacy-cli.json) and
  [phase definitions](catalog/roadmap.json): embedded in the binary.

The inventory retains **41 historical command spellings: 39 canonical commands,
the `alerts` alias, and retired `metrics`**. Catalog schema 2 contains generalized
use cases and public platform evidence. The private source audit, original parser
metadata, company endpoints and operational implementation details are excluded.
It does not claim live provider verification.

## Install

Release [v0.4.2](https://github.com/clankernative/cli/releases/tag/v0.4.2) includes owner-authorized
secret reveal/deletion and business-data SQLite download. It retains secret
creation/rotation/status and offline Bash, Zsh and Fish completion.
These operations require the matching platform endpoints, current ownership and
an operator-activated secret namespace. See [secret commands](docs/SECRETS.md) and
[SQLite download](docs/SQLITE.md) for output protection and qualification limits.

See [verified native installers](docs/INSTALL.md) for macOS Apple Silicon and
Linux x86_64 release archives, checksums, provenance and credential-store requirements.
The installer preserves any existing `day2` executable.

## Build and run

Install Rust with the toolchain in `rust-toolchain.toml` (Rust 1.98.1), then:

```console
cargo run --locked -- --help
cargo run --locked -- catalog
cargo run --locked -- catalog 'sqlite query' --json
cargo run --locked -- catalog secrets --phase M5 --agent
cargo run --locked -- roadmap
cargo run --locked -- roadmap M1 --json
```

Use `cargo build --locked --release` to create `target/release/day2`.
Native TLS builds require a C/C++ toolchain; some targets also need CMake. Linux
builds the vendored D-Bus adapter. On a configured company app:

```console
day2 login --instance https://tools.company.example
day2 whoami --json
day2 logout
```

The embedded catalogs require no source checkout, network, login, platform
installation or local configuration at runtime. `catalog` accepts an exact
legacy command or a namespace such as `secrets`; `--phase` narrows catalog results.
Phase identifiers are case-insensitive.

The platform already distributes a `day2` executable. Run this project through
`cargo run` or its explicit binary path during development. The verified installer refuses to replace an existing executable; select another
prefix to keep the employee frontend alongside the operator distribution.

## Output contract

`--json` and its `--agent` alias emit one JSON document for command results,
usage errors and not-found errors. Help and version intentionally print text.
Planned operations are data, not executable `next_actions`.

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "roadmap",
  "exit_code": 0,
  "result": { "phases": [] },
  "error": null,
  "next_actions": []
}
```

The empty result above illustrates the envelope; real roadmap results contain
the selected phases. Exit codes are `0` success, `1` internal/output failure,
`2` usage and `4` no matching command/phase. Human-readable errors use stderr;
JSON errors use stdout. `call` and `openapi` intentionally print raw API JSON, including with `--json`;
app HTTP errors return exit 3. See [app calls](docs/API.md) for recovery semantics.
Owner commands additionally use exit `3` for denied permissions, unavailable
context or platform rejection, and `5` for invalid/bounded/timed-out platform
responses. Unknown mutation outcomes are never retried automatically.
Exit `130` reports an interrupted local command; it can also have an unknown
mutation outcome.
Authentication commands use exit `3` for required login, rejected identity,
unavailable credentials, refused responses or transport failure. Login errors
never include provider response bodies or credential values.

## Verify

```console
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

See [the verification contract](docs/VERIFICATION.md) for the complete local
gate, security tools, architecture restrictions and intended branch protection.
CI checks Linux and macOS, rejects compiler/Clippy/rustdoc warnings, compiles the
release targets, and scans dependencies, secrets and workflow security. Compiler
fixtures check that the catalog library rejects ambient effects and suppression.
Process tests cover inventory classification, publication boundaries,
filtering, phase dependencies, structured failures and unimplemented commands.
No production services or credentials are needed. Platform verification remains
separate. The intended merge policy requires the complete `verify` gate and
restricts merges to explicitly trusted maintainers.

Private instance configuration and the original source audit belong outside this
repository. Use reserved example domains and synthetic identities in examples;
never add company defaults, credentials or private operational evidence.
