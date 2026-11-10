#!/bin/sh
# Install a checksum- and provenance-verified standalone employee CLI.
set -eu
version=0.4.2
prefix="${HOME}/.local/bin"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) [ "$#" -ge 2 ] || exit 2; prefix=$2; shift 2 ;;
    --version) [ "$#" -ge 2 ] || exit 2; version=$2; shift 2 ;;
    --help) printf '%s\n' 'Usage: sh install.sh [--prefix /absolute/bin] [--version X.Y.Z]' 'Requires curl, tar, gh and a SHA-256 tool. Never overwrites an existing day2.'; exit 0 ;;
    *) printf '%s\n' 'Unknown installer option.' >&2; exit 2 ;;
  esac
done
printf '%s\n' "$version" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { printf '%s\n' 'Invalid release version.' >&2; exit 2; }
case "$prefix" in /*) ;; *) printf '%s\n' 'The install prefix must be absolute.' >&2; exit 2 ;; esac
case "$(uname -s):$(uname -m)" in
  Darwin:arm64) target=aarch64-apple-darwin ;;
  Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
  *) printf '%s\n' 'This operating system or architecture has no qualified release.' >&2; exit 2 ;;
esac
for tool in curl tar gh; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'Required tool is unavailable: %s\n' "$tool" >&2; exit 2; }
done
if [ -e "$prefix/day2" ] || [ -L "$prefix/day2" ]; then
  printf '%s\n' 'The destination already contains day2. Choose another --prefix; existing platform or package-manager installations must be preserved.' >&2
  exit 2
fi
archive="day2-cli-v${version}-${target}.tar.gz"
base="https://github.com/clankernative/cli/releases/download/v${version}"
bundle=
installed=no
work=$(mktemp -d "${TMPDIR:-/tmp}/day2-cli-install.XXXXXX")
trap 'if [ "$installed" = no ] && [ -n "$bundle" ] && [ ! "$bundle/day2" -ef "$prefix/day2" ]; then rm -rf "$bundle"; fi; rm -rf "$work"' EXIT HUP INT TERM
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 120 "$base/$archive" -o "$work/$archive"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 30 "$base/SHA256SUMS" -o "$work/SHA256SUMS"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 30 --max-filesize 1048576 "$base/$archive.sigstore.jsonl" -o "$work/$archive.sigstore.jsonl"
awk -v file="$archive" '$2 == file { print; count++ } END { if (count != 1) exit 1 }' "$work/SHA256SUMS" > "$work/selected.sha256"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$work" && sha256sum --check selected.sha256)
else
  (cd "$work" && shasum -a 256 --check selected.sha256)
fi
# Bind provenance to this repository, workflow and immutable release tag.
gh attestation verify "$work/$archive" --bundle "$work/$archive.sigstore.jsonl" --repo clankernative/cli --signer-workflow clankernative/cli/.github/workflows/release.yml --source-ref "refs/tags/v${version}" --deny-self-hosted-runners >/dev/null
tar -xzf "$work/$archive" -C "$work" day2-cli/day2 day2-cli/THIRD_PARTY_LICENSES.txt day2-cli/SOURCE.json day2-cli/README.md
for file in day2 THIRD_PARTY_LICENSES.txt SOURCE.json README.md; do
  [ -f "$work/day2-cli/$file" ] && [ ! -L "$work/day2-cli/$file" ] || exit 1
done
mkdir -p "$prefix"
bundle=$(mktemp -d "$prefix/.day2-cli-v${version}.XXXXXX")
cp "$work/day2-cli/"* "$bundle/"
chmod 755 "$bundle/day2"
# Hard-link creation fails if another installer or owner claims the path first.
ln "$bundle/day2" "$prefix/day2"
installed=yes
printf 'Installed %s. Notices and source identity: %s.\n' "$prefix/day2" "$bundle"
printf 'Add %s to PATH, then run day2 login --instance https://your-company-app.\n' "$prefix"
