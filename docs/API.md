# Authenticated app calls

Sign in with `day2 login --instance https://tools.company.example` first. The
selected exact app origin and company binding come from the OS credential store.
Both commands revalidate company discovery, refresh identity when necessary, and
verify the current app session. They use the human IAP and app-session channel.

```console
day2 openapi > openapi.json
day2 call reports.list --input '{"search":""}'
day2 call reports.create --input-file request.json --idempotency-key request_001
day2 call reports.create --input-file request.json --idempotency-key request_002 --async
day2 call --invocation INVOCATION_ID
```

The input fields in these examples are illustrative: read the selected app's
OpenAPI document for its actual operation IDs, required input schemas and
examples. `--instance https://other.company.example` explicitly selects another
previously authenticated app. It never borrows the selected app's credentials.

`call` accepts an operation ID, not a URL, HTTP method or arbitrary path. It fetches
the app's current generated OpenAPI 3.1.1 document and checks its exact server,
artifact identity and session-cookie binding. Only admitted `query` GET and
`command` POST operations are callable. The historical offline catalog is not
used. Platform support routes, credential export, arbitrary headers, delegation
and operator workflows are outside this interface.

Queries encode scalar fields as query parameters; optional and structured fields
use the generated contract's JSON query encoding. Input must be a JSON object.
Commands send the original JSON bytes with the app cookie, IAP identity, exact
Origin, current CSRF token and an explicit idempotency key. Keys contain 1–128
ASCII letters, digits, underscores or hyphens. Queries refuse command-only flags.
Use `--input-file -` to read stdin. Files/stdin are consumed only after validating
the destination, current identity, admitted operation and command flags.

Responses are raw JSON bytes on stdout, including app error bodies. `--json` and
`--agent` do not wrap these two commands' responses. A successful HTTP response
returns exit 0; an app HTTP error returns exit 3. Failures before a valid API
response use the usual structured CLI error in JSON mode. HTML/provider error
pages and redirects are refused; their bodies never enter diagnostics.

Each HTTP exchange has a 15-second deadline, a 5-second connection deadline and
16 KiB of response headers. Auth documents remain limited to 64 KiB; OpenAPI and
API response bodies are limited to 1 MiB. Inputs are limited to 64 KiB and encoded
query strings to 16 KiB. No ambient proxy, cookie import or redirect is followed.

`--async` asks a command to return after durable acceptance. A 202 response must
contain one exact relative `/api/invocations/ID` Location matching its receipt.
Read that receipt with `day2 call --invocation ID`; this performs a GET and never
resubmits the command. There is no automatic polling or mutation retry. If a
command times out, loses its response or returns an invalid receipt, its outcome
may be unknown. Reconcile the original invocation, or explicitly repeat the
**same key, operation and input** under the app's idempotency contract. A new key
represents a new command. Conflicting reuse is left to the authoritative app and
its raw error response is preserved.

Local mocks cover the transport and admission boundaries. Live company access,
operation permissions and native credential storage require separate evidence
for each installation and target; a passing mock is not hosted qualification.
