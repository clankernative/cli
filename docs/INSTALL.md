# Install the employee CLI

Release v0.2.0 provides the standalone employee frontend for Apple Silicon macOS
15+ and x86_64 Linux with glibc 2.39+ (for example Ubuntu 24.04 or Debian 13).
Windows, Intel macOS, Linux ARM64 and musl targets have no qualified archive.
This does not install Platform's source-bound operator tools or Roc recipes.

Install GitHub CLI (`gh`), curl, tar and a SHA-256 tool through your usual package
manager. Download the installer from the exact release, verify its provenance,
then run it:

```console
gh release download v0.2.0 --repo clankernative/cli --pattern install.sh
gh attestation verify install.sh --repo clankernative/cli --signer-workflow clankernative/cli/.github/workflows/release.yml --source-ref refs/tags/v0.2.0 --deny-self-hosted-runners
sh install.sh
```

The installer verifies the target archive's SHA-256 and GitHub-hosted build
provenance, bound to this repository, release workflow and exact tag, before
installing executable bytes. It requires network access to GitHub; it does not
need your company's credentials. It installs to `$HOME/.local/bin` and keeps the
archive's dependency notices and source manifest beside the executable in a
private `.day2-cli-vVERSION.*` directory. Add `$HOME/.local/bin` to PATH.

Use `--prefix /absolute/path/to/bin` for another destination. An existing `day2`,
including a symlink or Platform operator installation, is always refused. The
installer never replaces package-manager files and has no force option. Use a
separate prefix for the employee CLI and invoke the operator distribution by its
explicit path. Updates currently require an intentional reinstall; `day2 update`
remains planned. Remove the installed `day2` hard link and its matching hidden
bundle directory to uninstall; run `day2 logout` first to clear saved credentials.

You can instead download your target's `.tar.gz`, `SHA256SUMS`, verify the archive
with `gh attestation verify` using the same repository/workflow/tag arguments,
verify its checksum, and extract the whole archive. Keep its notices with the
executable. `SOURCE.json` records source commit, target and Rust compiler. Every
release reruns the full reusable CI on the tagged inputs, checks main ancestry,
builds on each native target, and publishes only after both archives succeed.
The source application has no license declaration; dependency notices do not
assign a license to the application.

On Linux, sign in from the same machine and desktop login session as your browser.
An unlocked Secret Service (for example GNOME Keyring) and a session D-Bus are
required. There is no plaintext, environment-token, browser-cookie or headless
fallback. Native Secret Service write/read/rotation/deletion, independent-process
access and unavailable-store refusal have been exercised on Debian 13 x86_64.
This does not establish live Linux Google/browser/IAP qualification. The macOS
company canary has real Google sign-in, Keychain, refresh and logout evidence.
Each company must configure its own discovery, Desktop OAuth registration, IAP
allowlist and app permissions; see [login](LOGIN.md).

```console
day2 login --instance https://tools.company.example
day2 whoami --json
day2 openapi > openapi.json
day2 call reports.list --input '{"after":"","limit":20}'
day2 logout
```

Use your app's actual schemas and operation IDs from its OpenAPI document. App
permissions remain enforced by the instance; installing the CLI grants none.
See [API calls](API.md) for commands, exact request keys, pending receipts and
recovery after unknown outcomes.
