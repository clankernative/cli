# Implementation roadmap

Start with a useful local Rust CLI and add hosted operations as their authenticated
platform services become available. This is use-case coverage for a new product,
not a line-for-line port or a v1 compatibility program.

The inventory accounts for 41 legacy spellings. Local app-owner commands now
implement the permission foundation for later secret values and snapshot export;
they are new commands rather than additional historical v1 parser leaves.
M0 and M0.1 are complete. M1 includes human login and admitted app API calls.
A private macOS company canary has live auth and query evidence; Linux credential
storage has native Secret Service evidence. Each company and target still needs
its own hosted qualification per [LOGIN.md](LOGIN.md) and [API.md](API.md).
Verified employee CLI packaging is described in [INSTALL.md](INSTALL.md).
Other operational successors remain planned. Dates and effort
estimates are intentionally unset until the local integration contract and hosted
service scope are known.

## Delivery order

| Phase | Outcome | Main legacy coverage | Dependencies |
| --- | --- | --- | --- |
| M0 · complete | Public use-case inventory, roadmap and Rust foundation | Retired `metrics` accounted for; 41 spellings mapped | None |
| M0.1 · complete | Active app owner list/check/add/remove and shared permission enforcement | Foundation for later secret and snapshot control operations | M0; supporting platform distribution |
| M1 | Explicit context, human identity and API access | `login`, `whoami`, `token`, `logout`, `call`, `openapi`, completion | M0 |
| M2 | Create and run a Roc app locally | `prototype new`, `local-dev`; expose existing describe/build/check/test | M1 integration/context foundation |
| M3 | Inspect snapshots and app operations | Five `sqlite` commands, logs/traces/monitors/dashboards; `alerts` consolidated | M1, M2 |
| M4 | Provision and publish approved app source | `directory search`, `app provision`, `prototype publish` | M1, M2 |
| M5 | Manage secrets and recover exact requests | All thirteen `secrets` commands | M1, M4 |
| M6 | Install, update and optionally tunnel to corporate DBs | `update`, optional `db connect` | M1–M5 for a full operational release |

M3 and M4 can proceed independently after the common foundations. Start release
engineering and target qualification earlier; M6 is the full-release gate, not a
requirement to defer packaging. M2's offline work need not wait for the hosted
identity qualification within M1. An inventory-only binary release is distinct
from a qualified operational distribution.

The executable `day2 roadmap M1` and
[`catalog/roadmap.json`](../catalog/roadmap.json) contain the exact deliverables,
platform work and acceptance criteria for each phase.

## First implementation slice

1. Review the platform integration boundary. Define a small versioned local
   distribution entry point, or coordinate replacement of the platform frontend
   in place. Preserve the existing Roc recipes and native enforcement. Do not
   invoke `day2-host`'s private protocol as if it were a public SDK.
2. Add an explicit local context and a session-authenticated client for Reports.
   Fetch `/openapi.json` and `/api/session`; execute a query, a command with an
   exact idempotency key, and a pending invocation status read.
3. Prove the negative paths: wrong origin/context, expired/missing cookie,
   missing CSRF, reused conflicting key, redirect leakage and timeout after
   dispatch. Preserve raw API bodies while keeping control receipts structured.
4. Generate completion from the Rust parser and expose only implemented
   commands. Keep cache refresh explicit and context-scoped.
5. Add canonical Roc app scaffolding and route local build/check/development to
   the reviewed platform entry point. New app startup must work without a
   production login and retain local state until explicit reset.

This produces a usable local loop while hosted onboarding, observability and
secret services are designed and qualified.

## Gaps that require platform or instance work

| Gap | Existing foundation | Work required before CLI support |
| --- | --- | --- |
| Standalone local integration | Source-bound Roc frontend, private Rust broker and pinned operational recipes | Reviewed versioned entry point, relocation/dependency closure, exact platform compatibility and target qualification |
| Hosted human auth | IAP validation/app sessions and implemented desktop login client | Publish discovery, allowlist company desktop OAuth client, qualify the real hosted flow and native credential stores |
| Managed machine access | Fixed-family credential API admission and receipt polling | Selected live authority/key/epoch/identity adapters, consumer and installation qualification; no blanket machine-login fallback |
| Directory/onboarding | Authority, instance config and durable control kernel | Authorized directory provider, canonical access validation and authenticated create/status/approval API |
| Snapshot operations | Local online backup/restore and artifact integrity | Remote snapshot index/capture/export, read-only inspection, execution/byte budgets and app/owner authorization |
| Fleet observability | Local-dev logs, invocation receipts and evidence | Provider-bound app-scoped logs/traces/monitors/dashboard endpoints and redaction |
| Source publication | Exact-commit reads, isolated builds and release guards | Canonical Roc source inventory, durable publication protocol, provider qualification and approval UX |
| Secrets and recovery | Version/resource identity, consumer protection, retirement and release models | Authorized material entry, metadata APIs, provider projection/readback, exact operator recovery/history contracts |

Do not classify a local adapter, simulation, example stack or operator assertion
as a qualified hosted service. The source audit is pinned and must be refreshed
where a phase depends on a changed contract.

## Deliberate product choices

- Build the frontend in Rust; preserve platform-owned recipe composition.
- Use Day 2's canonical Roc app layout and generated operation contracts. Replace
  v1 F# templates and .NET OpenAPI conventions.
- Keep instance/provider selection outside portable CLI source. Support explicit
  context and exact-origin credential storage instead of corporate defaults.
- Keep normal local development offline with persistent state. Snapshot import
  is explicit; use development credentials rather than copying production secrets.
- Keep raw SQL outside app capabilities. Inspect verified snapshots with enforced
  read-only and resource bounds; retain Day 2 restore authority fencing.
- Keep `monitors` as one command and omit retired `metrics`. The historical
  alias is cataloged, not carried forward as a compatibility requirement.
- Treat `db connect` as optional corporate infrastructure support. Do not impose
  PostgreSQL, a cloud CLI, a bastion or a container runtime on every installation.
- Preserve GoLinks persisted link data. Other disposable test/canary state does
  not need a v1 migration layer.

## Definition of support

A command is supported only when it has real end-to-end behavior through the
selected instance/platform surface, typed and bounded inputs, structured failure
and recovery guidance, authorization/redaction negative checks, and appropriate
process/provider qualification. A parsed command, placeholder, synthetic receipt
or planned row does not count.

Keep the JSON inventory and docs updated with each completed operation. Add
tests for actual trust and behavioral boundaries, rather than tests that merely
mirror parser definitions. Run platform verification for platform changes and
provider qualification for live integration claims; this repository's Cargo
checks verify only the Rust CLI.
