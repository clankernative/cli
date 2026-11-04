# Rust CLI architecture

## Ownership

The user-facing executable, command parsing, context selection, presentation,
transport adapters and credential-store integration belong in this Rust
repository. The platform remains the authority for app contracts, operation
catalogs, execution, authorization, admission and workflow evidence.

The current platform CLI is Roc with a private Rust native host. Its documented
contract explicitly calls the adjacent host protocol private. Owners now use the
versioned `platform owners` command/result contract described in [OWNERS.md](OWNERS.md).
Other operations still need their own reviewed integration surface. The CLI must not
import private platform crates, discover a broker from an arbitrary PATH, or
reimplement build/release/local-development recipes as Rust orchestration.

The intended boundary is:

```text
Rust day2 CLI
  ├─ context, parsing, text/JSON, OS credential storage
  ├─ generated app HTTP contracts → ordinary authorized operation runtime
  ├─ versioned control service → approved instance provider adapters
  └─ reviewed local distribution entry point → platform ops recipes
                                                ↓
                                    native enforcement and evidence
```

Platform build/check/local-dev/backup step ordering stays in `ops/*.roc`.
Rust being the CLI language does not require moving those operational decisions
into this repository. If the final integration replaces the existing platform
CLI frontend, change its callers and packaging together in place. Do not add a
v1 compatibility shim or maintain two recipe implementations.

## Current code

- `src/main.rs`: clap arguments, offline selection and output envelope.
- `src/lib.rs`: typed catalog and roadmap decoding.
- `src/owners.rs`: local owner arguments, bounded explicit platform CLI execution,
  and versioned result validation. The native platform owns all grants and writes.
- `src/auth.rs` and `src/auth/`: exact-origin company discovery, Google desktop
  OAuth with PKCE, signed identity validation, bounded HTTPS, app sessions and OS
  credential storage. See [company login](LOGIN.md) for deployment prerequisites.
- `catalog/legacy-cli.json`: public use-case summaries, current support
  assessment and public platform evidence. Private parser/source metadata is
  excluded from schema 2.
- `catalog/roadmap.json`: phases, dependencies, deliverables and acceptance.
- `tests/cli.rs`: executable behavior and cross-catalog invariants.

Both JSON resources are embedded at build time. `catalog` and `roadmap` perform no
filesystem reads, credential lookup or network requests. Owner operations explicitly
select a private instance and local operator distribution. The historical catalog is never
a registry of app operations. Future discovery must consume the platform's
shared admitted operation catalog used by OpenAPI and MCP.

## Context and identity

Human login selects an exact app origin, installation/environment and company
OAuth client through versioned public discovery. Tokens, app cookies and the
selected origin live in the OS credential store. No company defaults are compiled
into the CLI. Company-wide app discovery and general API calls remain planned.
Do not infer authorization from a repo name, app name, email or unverified JWT.

Keep three identities distinct:

| Identity | Intended channel | Required boundary |
| --- | --- | --- |
| Human | IAP edge and app session | Edge login alone is not an app session. Human API writes require cookie, exact Origin, CSRF and idempotency key. |
| Managed API client/personal credential | Dedicated managed bearer ingress | Fixed eligible families, exact operation roots, live selected authority/epoch/key readiness and qualified deployment. No human cookies/IAP headers. |
| Operator | Approved control service or explicit local operator workflow | A local operator-name string is not authenticated remote authority. |

The platform implements managed bearer admission at
`/_day2/credentials/api/<operation-path>` for eligible fixed families. Its
documentation also explicitly gates live installation readiness. Do not describe
this as absent, universally enabled, or a replacement for every human API call.
The v1 Google IAP token, GitHub OIDC and injected-token lanes need separate
end-to-end qualification; accepting a CLI flag does not establish backend access.

## HTTP and recovery

Use the generated `/openapi.json` rather than porting the v1 path convention.
Human clients retain the app cookie and obtain CSRF from `/api/session`.
Commands preserve the same idempotency key across retries and follow pending
invocation receipts. The managed channel has its own headers and receipt paths.

Bound response bytes, input bytes, deadlines and polling. Validate credential
destination, scheme, origin and secret-route restrictions before reading a body
source. Never carry authentication across an unapproved redirect. Redact tokens,
cookies, request bodies and provider errors before diagnostics.

Treat timeout after dispatch as an unknown outcome. Reconcile using the exact
request identity and authorized receipt; never create a new request or repeat a
provider mutation merely because a response was lost. Fresh snapshots, source
publication, secret changes and recovery are effects even when they are part of
an otherwise read-oriented workflow.

## Provider and package boundaries

The instance chooses Git hosting, infrastructure CI, cloud providers,
observability and secret managers. No GitHub/Gitea/Google Workspace host,
corporate bastion or tenant identifier is a universal installation prerequisite.
Corporate PostgreSQL access is an optional instance capability; the app runtime
continues to use SQLite.

The current platform bundle includes native binaries, pinned recipes and verified
UI build dependencies and is source-checkout-bound on Apple Silicon macOS.
Shipping this Rust inventory binary on another OS does not qualify platform
operations there. The reviewed entry point needs version negotiation, binary and
recipe identity, dependency closure and clear unsupported-platform errors before
the CLI can claim relocatable operational support.

## Source evidence

Public platform references record the inspected revision. In particular, see the
[CLI contract](https://github.com/clankernative/platform/blob/c203a2262d19d5b3667172a67fe3126a6efcdba6/cli/README.md),
[recipe ownership](https://github.com/clankernative/platform/blob/c203a2262d19d5b3667172a67fe3126a6efcdba6/ops/README.md),
[generated API](https://github.com/clankernative/platform/blob/c203a2262d19d5b3667172a67fe3126a6efcdba6/crates/day2/src/openapi.rs),
[managed credential boundary](https://github.com/clankernative/platform/blob/c203a2262d19d5b3667172a67fe3126a6efcdba6/docs/CREDENTIALS.md)
and [control-plane boundary](https://github.com/clankernative/platform/blob/c203a2262d19d5b3667172a67fe3126a6efcdba6/docs/CONTROL-PLANE.md).
