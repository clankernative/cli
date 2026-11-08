Owner-authenticated app secret metadata, creation, rotation and request status are now available through `app secrets list/create/rotate/status`. Rotation stores another supplied value as a new version; it does not activate the value in an app or revoke an upstream credential. Secret commands require a supporting platform deployment and an operator-activated provider namespace.

Offline `completion bash`, `completion zsh` and `completion fish` generate scripts for implemented commands. The release retains company browser login, OS credential storage, app-owner management, generated OpenAPI, authenticated app calls and invocation status.

Native archives support Apple Silicon macOS 15+ and x86_64 glibc 2.39+ Linux. Each archive includes dependency notices, source identity, SHA-256 checksums and signed GitHub Actions provenance. The installer preserves existing Platform operator installations and verifies attached Sigstore bundles without an employee GitHub login. See docs/INSTALL.md.

Live macOS login/refresh/logout and read-only app calls have evidence. Native Linux Secret Service storage and synthetic GCP secret create/rotate/readback/cleanup campaigns have separate evidence. Hosted secret access and live Linux browser/IAP login require deployment qualification.

Secret values are accepted only from a file or nonterminal stdin and never appear in normal receipts or audit. Unknown writes are not automatically retried; inspect the original request status. Secret reveal/deletion, runtime activation, reconciliation and SQLite download remain future operations. This release does not install the Roc operator runtime or grant app access.
