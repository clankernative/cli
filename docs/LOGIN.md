# Company login

The CLI implements browser login for the platform's current **Google IAP human
identity** channel. A company configures its own OAuth registration and discovery
document. The same executable works across configured companies.

```console
day2 login --instance https://tools.company.example
day2 whoami
day2 whoami --instance https://tools.other.example --json
day2 logout
```

`--instance` names an exact HTTPS **app origin**. The platform currently serves
each app at its own origin; it has no company-wide CLI authentication service.
This login grants no access to other apps or to local operator commands. App
authorization remains enforced by IAP and the platform on every request.

Login opens the system browser and receives the authorization code on a random
`127.0.0.1` port on the same machine. `--no-browser` prints the authorization URL
on stderr for manual opening on that machine. `--timeout` bounds the callback
wait to 30–300 seconds (default 180). A remote SSH browser or pasted token is not
an alternative callback transport. Login requires an interactive terminal;
`--json`/`--agent` and headless login return `interactive_required` before network,
browser or credential-store work. `whoami --json` is available after interactive
sign-in.

The last successful login becomes the default instance. Explicit `--instance`
selects only that origin's credentials. Credentials for other origins remain
separate. `whoami` checks the current company configuration, refreshes an expiring
ID token when possible, and verifies the actor through `GET /api/session`.
The result's `expires_at` is the current ID token's Unix expiry, not a claim
about the browser's SSO or app-session lifetime.

Tokens, refresh tokens and the app cookie live in macOS Keychain or Linux Secret
Service, under service `com.clankernative.day2-cli.v1` and a hash of the exact
origin. The selected origin also lives in that store. Linux needs an available,
unlocked desktop Secret Service. An unavailable store fails closed. There is no
file/environment credential fallback, token import or token-printing command.
Windows is not a qualified target of this implementation.
Authentication commands hold a private, nonsecret `auth.lock` under
`$XDG_CACHE_HOME/day2-cli` or `$HOME/.cache/day2-cli`. Concurrent auth commands
return `auth_busy`, so a refresh cannot write credentials back after logout.

Logout removes local credentials first, then attempts to end the saved app
session with its exact origin, cookie and CSRF token. JSON reports
`local_credentials_removed` and `app_session_ended` separately. An expired token,
changed configuration or remote outage can leave the remote session unconfirmed;
it expires under the platform's session policy. Logout does not sign the system
browser out of Google, revoke the company's Google OAuth grant, or affect another
instance's credentials.

## Company setup

1. Register an internal **Desktop app** OAuth client owned by the company. Enable
   its intended users on the company's consent configuration. The CLI requests
   only `openid email`, using an authorization code, S256 PKCE, state and nonce.
   Google requires the Desktop registration's client ID and client secret for
   token exchange and refresh. Desktop apps are public clients and cannot keep
   that registration value confidential. The company must explicitly approve
   publishing this pair for URL-only setup. Never use a confidential Web
   application secret, service-account key or user token here.
2. Allowlist that desktop client for IAP programmatic access to the selected app.
   Configure its users' ordinary IAP access and the app's ordinary reader/writer
   permissions. An allowlisted client does not itself grant those permissions.
   Follow [Google's desktop IAP authentication instructions](https://docs.cloud.google.com/iap/docs/authentication-howto#authenticate_from_a_desktop_app)
   and [desktop OAuth contract](https://developers.google.com/identity/protocols/oauth2/native-app).
   An IAP deployment's OAuth mode must support the chosen client; prove this in
   the live canary rather than assuming an existing Google-managed client works.
3. Publish the following public JSON at the app origin's exact
   `/.well-known/day2-cli.json` path. Serve it with `Content-Type: application/json`
   over valid HTTPS, without a redirect or login requirement. The instance edge
   must serve this one static metadata route before IAP; keep the app's API and
   all other human routes protected. The current platform does **not** publish
   this route automatically. Hosting this metadata is an instance deployment
   prerequisite, not a capability supplied by the CLI binary.

```json
{
  "schema_version": 1,
  "instance_origin": "https://tools.company.example",
  "installation": "company",
  "environment": "production",
  "identity": {
    "scheme": "google_iap",
    "desktop_client": {
      "client_id": "123-desktop.apps.googleusercontent.com",
      "client_secret": "synthetic-desktop-registration-value"
    },
    "hosted_domain": "company.example"
  }
}
```

These values are intentionally public Desktop registration metadata. They prove
neither a user identity nor permission to access the app. The example pair is
synthetic and cannot sign anyone in. The registration value is sent only in
POST bodies to Google's fixed token endpoint, never the browser authorization
URL, an app request, result JSON or diagnostics. Both fields are required;
the value is 16–256 ASCII letters, digits, hyphens or underscores.
`instance_origin` must equal the selected
origin exactly, without a trailing slash. Origins use lowercase ASCII DNS names
without ports, paths, user info, query strings or fragments. Installation and
environment identifiers match the platform: at most 48 lowercase letters,
digits or underscores, starting with a letter; `day2_` and `sqlite_` prefixes
are reserved. The hosted domain is an exact lowercase DNS name.
Unknown fields, partial registrations, versions and identity schemes are refused. A discovery change
requires a fresh login before a saved credential is dispatched to the app.

4. Qualify `login`, `whoami`, refresh and logout against the real deployment.
   Confirm that another domain, another client, denied app access, a changed
   instance binding and revoked credentials all fail. Confirm the platform
   creates its `__Host-day2_*` Secure/HttpOnly/SameSite=Strict session cookie and
   `/api/session` returns the verified actor and session-bound CSRF token.

Company app origins, client registrations and deployments remain in the private
instance repository. Publishing this CLI does not configure a company's IAP
backend, DNS, OAuth consent or discovery hosting.

## Protocol and verification boundary

Google authorization, token and signing-key endpoints are fixed in the adapter;
discovery cannot redirect tokens to an arbitrary issuer. ID tokens require a
valid Google RS256 signature and exact client audience, authorized party when
present, hosted domain, verified human email, subject, nonce on initial login,
issued-at and expiry. The app response must identify the same actor. Refresh
also preserves the exact subject; a rotated refresh token is stored before a
later app request can fail.

HTTPS requests have a 15-second deadline, a 5-second connection deadline, a
16 KiB header limit and a 64 KiB response-body limit. Ambient proxies and
redirects are disabled; token exchanges and logout are never retried by the CLI.
Provider bodies, callback codes, tokens and cookies never enter result JSON or
diagnostics. Callback handling checks the exact loopback host, path, method,
state, duplicate fields and bounded input. It requires exactly one `iss` equal
to `https://accounts.google.com`, including on cancellation responses, as defined
by [Google's RFC 9207 authorization response](https://developers.google.com/identity/openid-connect/reference#response-parameters).
Missing, duplicate or different issuers are refused before token exchange.
Offline catalogs never consult login.

The local tests use ephemeral RSA keys, mock provider/app responses, an in-memory
credential store, fragmented real loopback callbacks and a local HTTPS server
with ephemeral certificates. The HTTPS tests exercise the selected TLS provider,
certificate/hostname checks, redirect refusal and response-byte limits. They
verify client behavior and negative boundaries. They do not qualify Google, a
company's IAP deployment or a
native desktop credential store.

A separate private company canary has passed real browser login on macOS,
Google/IAP/app identity verification, fresh-process Keychain persistence, token
refresh with an unchanged subject, and confirmed local/app-session logout.
Refresh was triggered by changing only the scoped local expiry marker; token
exchange and verification used the real Google endpoints. Exact instance,
runtime and client evidence stays in private company records. This establishes
that tested macOS flow, not other companies, Linux Secret Service, or live
wrong-account/revoked-grant cases; those still need their own qualification.

Admitted `call`/`openapi` are implemented separately; see [API.md](API.md).
Offline Bash/Zsh/Fish generation is documented in [COMPLETION.md](COMPLETION.md).
Company-wide app discovery, token export and managed-machine
authentication remain separate work. Login currently selects an exact app origin.
