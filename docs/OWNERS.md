# App owners

`day2 app owners list`, `check`, `add` and `remove` operate against a selected
local platform installation. The platform owns and enforces the permissions;
this Rust CLI handles arguments, bounded process execution and validated results.
It never edits SQLite or infers an owner from mutable instance configuration.

The existing private `instance.json` must declare its trusted installation
operators. A minimal control selection, with no source/provider grants, is:

```json
{"control":{"version":1,"state_directory":"/private/control-state","operators":["operator@example.com"],"sources":{},"apps":{}}}
```

This is an excerpt of the existing instance, not a second configuration file.
Initializing that operator selection is installation administration; owner
commands cannot change it or establish production remote identity.

Select the private instance, an explicitly trusted absolute platform CLI path,
and an operator listed in that instance's `control.operators`. For example:

```console
day2 app owners list reports --instance /private/instance.json --platform-cli /trusted/platform/cli/day2 --operator operator@example.com --json
day2 app owners check reports alice@example.com --permission secrets.read --instance /private/instance.json --platform-cli /trusted/platform/cli/day2 --operator operator@example.com --json
```

`check` is a local operator diagnostic, not login as the named actor. It returns
exit 3 when denied and performs no secret read or snapshot export. The role's
permission names are `audit.read`, `secrets.list`, `secrets.read`, `secrets.create`,
`secrets.rotate`, `secrets.delete` and `sqlite.download`. Audit, secret operations and SQLite download use the shared guard. Sensitive reads
must authenticate the actor and recheck current authority inside the actual
protected transaction; a prior `check` response or stamp cannot authorize them.
Each endpoint must separately bind the requested secret or snapshot to that
app; this role check does not authorize shared/platform secrets or provider-wide access.

Use the exact `result.result.stamp` from `list` for a change:

```console
day2 app owners add reports alice@example.com --expected '{"epoch":"sha256:ACTUAL_64_HEX_EPOCH","revision":7}' --request-id owner-change-123 --instance /private/instance.json --platform-cli /trusted/platform/cli/day2 --operator operator@example.com --json
day2 app owners remove reports bob@example.com --expected '{"epoch":"sha256:ACTUAL_64_HEX_EPOCH","revision":8}' --request-id owner-change-124 --instance /private/instance.json --platform-cli /trusted/platform/cli/day2 --operator operator@example.com --json
```

The example epochs/revisions must be replaced with the actual returned values.
Every add/remove checks the expected revision and changes only active policy
admins. It retains the platform's append-only authority history and idempotency
receipt. Removing the last owner is refused. Owners cannot promote themselves to
installation operators; ordinary readers and writers cannot change owner lists.
Only individual principals are admitted, with exact verified-domain identities
for IAP installations. Managed-client (`client/`) principals cannot become owners,
including in local development. Group ownership needs separate directory integration.

Changes take effect immediately. The command preserves all other active policy,
memberships, resources and artifact identity, including when the instance file
contains unrelated pending edits. It does not change the desired file. `list`
reports active and desired owners separately, and `desired_matches_active`
identifies drift. Reconcile the private instance source before a future full
authority activation; that separate operation applies its entire desired policy.

Use exactly the same request ID, operator, owner, operation and expected stamp
after a lost response. Retrying returns the original receipt without granting
the role again after a later revocation. A new owner/operation/stamp needs a new
review and request ID. A receipt is historical evidence; use `list` for current
authority. Restores rotate the epoch and disable owner access until deliberately
reactivated under current policy.

## Platform integration

The selected platform distribution must implement protocol 1 of the documented
`platform owners list|check|add|remove INSTANCE APP LOCAL_OPERATOR INPUT_JSON`
entry point. Its response carries `protocol`, `kind: app-owners`, `scope`, `app`,
`action`, `mode: local-operator-only` and a typed `result`. The Rust client checks
operation identity, owner/request/stamp receipts, drift consistency and enum
values before reporting success. The broker/workflow private protocol is never
called by this CLI. An older distribution fails rather than falling back.

The process has a 30-second deadline, stdout is limited to 1 MiB and stderr to
64 KiB. On Unix, the spawned process group is terminated on overflow/deadline;
the CLI does not automatically retry. SIGINT/SIGTERM also terminate that group
and report exit 130 with unknown-outcome guidance. Raw platform stderr is not reflected into
agent output. Inspect current authority after any uncertain write, then retry
only the original identity. This interface asserts a trusted local operator;
remote operator authentication remains separate work. Secret values and SQLite
downloads use human app sessions, not this local assertion.
