Standalone employee CLI with company-scoped browser login, OS credential storage,
identity checks, logout, generated OpenAPI and authenticated app queries/commands.
Commands require explicit idempotency keys; pending invocations can be read without
resubmitting a command. Existing Platform operator installations are preserved.

Native archives: Apple Silicon macOS 15+ and x86_64 glibc 2.39+ Linux. Each archive
includes dependency notices and source identity, SHA-256 checksums and signed
GitHub Actions build provenance. See docs/INSTALL.md in the tagged source for
installation and verification.

macOS company login/refresh/logout and a read-only API canary have live evidence.
Linux Secret Service storage has native Debian 13 evidence; live Linux Google
browser/IAP login remains an installation qualification step. App authorization
and company setup are required. This release does not install the Roc operator
runtime, export credentials, or implement planned snapshot/secret operations.
