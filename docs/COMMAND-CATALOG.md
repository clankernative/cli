# Public command catalog

This catalog retains historical command spellings to organize public product
requirements. It contains generalized use-case summaries, proposed commands,
delivery phases and references to public platform source. It excludes the
private source audit, parser flags/defaults, company endpoints, source locations
and operational implementation details. Catalog schema 2 removes that metadata
rather than publishing placeholder source identities.

The inventory contains 41 spellings: 39 canonical commands, the `alerts` alias
and retired `metrics`. These are requirements, not executable capability claims.
Only `catalog`, `roadmap` and the documented local `app owners` commands are
implemented. See [owner management](OWNERS.md) and [architecture](ARCHITECTURE.md).

| Historical spelling | Public use case | Proposed command | Phase |
| --- | --- | --- | --- |
| `update` | Update the CLI through a verified release channel. | `day2 update` | M6 |
| `login` | Start an explicitly selected authentication flow. | `day2 login` | M1 |
| `whoami` | Show the selected identity and session status. | `day2 whoami` | M1 |
| `token` | Request an explicitly scoped short-lived credential. | `day2 token` | M1 |
| `call` | Invoke an authorized application API operation. | `day2 call APP METHOD PATH` | M1 |
| `openapi` | Read the selected application API contract. | `day2 openapi APP` | M1 |
| `db connect` | Connect to an instance-approved database through a supervised tunnel. | `day2 db connect ENVIRONMENT` | M6 |
| `directory search` | Resolve principals through an authorized directory service. | `day2 directory search --kind KIND` | M4 |
| `app provision` | Request application provisioning through the selected control service. | `day2 app provision` | M4 |
| `prototype new` | Create application source using a reviewed platform template. | `day2 app new` | M2 |
| `prototype publish` | Submit reviewed application source through the platform delivery interface. | `day2 app publish` | M4 |
| `secrets list` | List authorized application secret metadata. | `day2 secrets list` | M5 |
| `secrets prepare` | Prepare metadata for an explicitly authorized secret change. | `day2 secrets prepare add|update` | M5 |
| `secrets add` | Request creation of an application secret through protected material entry. | `day2 secrets add` | M5 |
| `secrets update` | Request an authorized application secret update. | `day2 secrets update` | M5 |
| `secrets latest` | Inspect the latest authorized secret-change request. | `day2 secrets latest` | M5 |
| `secrets status` | Read the status of an authorized secret-change request. | `day2 secrets status REQUEST` | M5 |
| `secrets wait` | Wait for an authorized secret-change request within a fixed deadline. | `day2 secrets wait REQUEST` | M5 |
| `secrets recover-exact` | Request an explicitly authorized recovery of a secret change. | `day2 secrets recover-exact REQUEST` | M5 |
| `secrets recover-transition` | Request an explicitly authorized recovery of a secret transition. | `day2 secrets recover-transition REQUEST` | M5 |
| `secrets recover-terminated` | Request an explicitly authorized recovery of an interrupted secret change. | `day2 secrets recover-terminated REQUEST` | M5 |
| `secrets retry` | Request a reviewed retry of an existing secret-change request. | `day2 secrets retry REQUEST` | M5 |
| `secrets reconcile` | Observe and reconcile an authorized secret-change request. | `day2 secrets reconcile REQUEST` | M5 |
| `secrets install-agent-guidance` | Install reviewed secret-handling guidance for application contributors. | `day2 secrets install-agent-guidance` | M5 |
| `local-dev` | Run an application locally with development configuration. | `day2 local-dev [SOURCE]` | M2 |
| `logs` | Read authorized application logs. | `day2 logs APP` | M3 |
| `traces` | Read authorized application traces. | `day2 traces APP` | M3 |
| `metrics` | Retired historical command; no replacement implementation is planned. | Omitted | M0 |
| `monitors` | Read application monitor definitions and status. | `day2 monitors APP` | M3 |
| `alerts` | Historical alias of monitors; no separate implementation is planned. | `day2 monitors APP` | M3 |
| `dashboards` | Read authorized application dashboard links. | `day2 dashboards APP` | M3 |
| `sqlite backups` | List metadata for authorized application snapshots. | `day2 sqlite backups APP` | M3 |
| `sqlite download` | Download an explicitly selected and authorized application snapshot. | `day2 sqlite download APP` | M3 |
| `sqlite tables` | Inspect table names in an authorized snapshot. | `day2 sqlite tables APP` | M3 |
| `sqlite schema` | Inspect the schema of an authorized snapshot. | `day2 sqlite schema APP` | M3 |
| `sqlite query` | Run a bounded read-only query against an authorized snapshot. | `day2 sqlite query APP` | M3 |
| `completion bash` | Generate completion definitions for Bash. | `day2 completion bash` | M1 |
| `completion zsh` | Generate completion definitions for Zsh. | `day2 completion zsh` | M1 |
| `completion fish` | Generate completion definitions for Fish. | `day2 completion fish` | M1 |
| `completion refresh-apps` | Refresh authorized application discovery for shell completion. | `day2 completion refresh-apps` | M1 |
| `logout` | Remove the selected locally stored session. | `day2 logout` | M1 |

The [machine-readable catalog](../catalog/legacy-cli.json) records the same
summaries, safety requirements and public platform references. Public evidence
pins a reviewed platform revision; it is not live integration qualification.
Implementation requires the [verification contract](VERIFICATION.md), including
negative tests at changed authorization, validation, redaction and retry boundaries.
