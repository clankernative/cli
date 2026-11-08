# App secret storage

`app secrets list/create/rotate/status/reveal/delete` uses the saved human login for the
selected app origin. The platform authenticates the actual session actor and
checks active app ownership for every operation. Local operator assertions do
not authenticate these requests. Configure company login first per
[LOGIN.md](LOGIN.md).

```console
day2 login --instance https://reports.example.com
day2 app secrets list reports
day2 app secrets create reports API_KEY --file /private/new-value --request-id create-123
day2 app secrets rotate reports API_KEY --expected-version 1 --file /private/replacement --request-id rotate-124
day2 app secrets status reports rotate-124
```

Use `--instance` to select a saved origin explicitly. `--stdin` and `--file` are
exclusive. Input preserves exact bytes, including trailing newlines, and must
contain 1–65,536 bytes. Terminal stdin is refused. Values have no command-line
flag, environment fallback or output field. Names contain 1–40 ASCII letters,
digits, underscores or hyphens, beginning with a letter or digit.

Rotation **is adding a new stored version**. Supply the listed version with
`--expected-version`; use `none` only for an existing empty container. There is
no separate `versions add` command. Stored versions do not activate themselves
in running apps, update runtime bindings, generate upstream API keys or revoke
upstream credentials. Receipts explicitly say `activation_performed: false`.

The operator must configure `managed_secrets` in the app's instance binding and
activate the same namespace in current authority. This includes an explicit
GCP project number and a private, refreshed bearer-token file on the platform
host. The adapter performs no ambient credential discovery. The initial
platform schema requires fresh app initialization; existing app data must not
be deleted to enable this feature. See Platform's `docs/APP-SECRETS.md`.

Writes take effect immediately in the approved provider namespace, after
audited admission. The platform stores names, request IDs, actor, authority,
dispatch state and version numbers; it does not journal values, payload hashes
or CRCs. CLI output contains metadata only. Ordinary app users and installation
operators who are not active owners are denied.

Every submission requires a new request ID. The provider cannot deduplicate a
lost version-write acknowledgement, so the client never retries writes. A
timeout, malformed receipt or `unknown`/pending state exits with uncertainty
(exit 5); inspect `status` with the original ID. Resubmitting any used ID is
refused. An unresolved write blocks later writes to that name. No automatic
recovery or reconciliation is implemented. Definitively refused writes can be
reprepared from current metadata with a new ID.

`list` reports only secrets managed by this feature in the current app namespace;
it does not enumerate or adopt existing infrastructure secrets. Secret reveal and deletion use the same owner/session channel. Consumer-aware retirement and app activation remain separate work.
Local HTTP/protocol tests and synthetic live provider canaries do not qualify
hosted IAP access, native credential stores or a deployed app endpoint.


## Reveal and deletion

```console
day2 app secrets reveal reports API_KEY --output /private/api-key --request-id reveal-125
day2 app secrets delete reports API_KEY --expected-version 2 --request-id delete-126
```

Reveal selects the exact currently listed incarnation and version. `--version`
can require that version explicitly. Use a new `--output` file (mode 0600,
exclusive creation); existing files and symlinks are refused. Exact bytes,
including newlines, are preserved. `--stdout` deliberately returns only value
bytes and is incompatible with `--json`/`--agent`. Structured output and
diagnostics never include the value. A failed or interrupted command can leave
a private partial destination; inspect it before repeating the operation with a
new request ID. Filesystem parent directories remain the user's trust boundary.

Delete removes the managed provider container and all its stored versions.
It requires the currently listed version (`none` only for an empty container),
a fresh request ID and current ownership. Admission compares authority,
incarnation and version before dispatch. The provider must match the app scope,
original creation label and current ETag. Unknown deletion outcomes block that
name; the CLI never retries. Inspect `status` with the original ID.

Recreating a deleted logical name creates a different physical resource. Old
immutable provider version references continue to identify the old resource;
they cannot resolve to replacement bytes. Deletion does not revoke an upstream
API key or alter any running app binding.

This surface requires Platform app-secret protocol 2 and fresh metadata schema
2. There is no implicit upgrade or compatibility fallback. Recreate disposable
canaries; preserve persisted GoLinks data.
