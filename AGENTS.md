# Day 2 CLI

Build this CLI in Rust. Follow docs/VERIFICATION.md and run its complete local
gate before handing off code. Use the repository-pinned toolchain. All compiler,
Clippy and rustdoc warnings fail CI; keep formatting and lint policy centralized.
Do not weaken gates, add broad lint suppressions or skip negative regressions to
make a change pass. Report exactly which checks ran and any qualification gaps.

Keep the catalog/model library free of ambient effects. Its separate Clippy
configuration forbids listed environment, clock, filesystem, process, network
and output APIs by compiler-resolved identity. Keep I/O in reviewed executable
adapters. A new dependency or macro can cross this boundary and requires review;
the compiler checks are not a hostile-code sandbox. Keep unsafe Rust forbidden.

The executable implements offline `catalog` and `roadmap`, human `login`/`whoami`/
`logout` per docs/LOGIN.md, and local `app owners` list/check/add/remove through
the documented platform CLI contract. Auth uses company discovery and the existing
IAP/app-session channel; it does not provision instance setup or establish live
qualification. Other planned
operations in the catalog are requirements, never executable capability claims.
Keep JSON output versioned, errors structured, and diagnostics on stderr.

`catalog/legacy-cli.json` is the public use-case inventory, including historical
spellings, aliases, retired commands, public platform evidence, proposed
successors and delivery phases. Schema 2 deliberately excludes private source
locations, parser metadata and operational implementation details.
`catalog/roadmap.json` contains phase dependencies and acceptance criteria.
Keep docs and executable output consistent with those files. The unredacted
historical audit stays outside this repository. Do not restore private source
URLs, company endpoints, personal information, credentials or proprietary
implementation details from an old clone or audit.

The platform owns runtime contracts, admission, authorization and operational
recipes. Owners use the versioned `platform owners` command and JSON result
contract; invoke only the explicitly selected absolute platform CLI path. Do not
depend on private crate/protocol details or duplicate Roc
recipes in Rust. App discovery comes from the platform's admitted operation
catalog. This historical CLI catalog must never become a runtime app catalog.

Keep company domains, source hosts, cloud projects and credentials in private
instance configuration. No source-host or provider is a global CLI prerequisite.
Preserve the distinctions between human sessions, managed API credentials and
operator authority. Do not silently import v1 credentials, add v1 compatibility
shims, or retry writes whose outcome is unknown.

Keep auth credentials in the OS store, scoped to the exact app origin and company
binding. Fixed Google endpoints, PKCE/state/nonce, signed ID-token validation,
current app identity checks, bounded HTTPS and redirect refusal are enforcement
boundaries. Do not add plaintext, environment-token, browser-cookie import or
operator-identity fallbacks. Local/mocked verification never proves hosted login.
