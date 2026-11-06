#!/bin/sh
# Called by the release workflow after the complete reusable CI gate.
set -eu
target=$1
version=$(cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "day2-cli") | .version')
[ "${GITHUB_REF_NAME}" = "v$version" ]
[ "$(rustc -vV | sed -n 's/^host: //p')" = "$target" ]
git merge-base --is-ancestor HEAD origin/main
case "$target" in
  aarch64-apple-darwin) about_target=aarch64-apple-darwin; export MACOSX_DEPLOYMENT_TARGET=15.0 ;;
  x86_64-unknown-linux-gnu) about_target=x86_64-unknown-linux-musl ;;
  *) exit 2 ;;
esac
about_archive="cargo-about-0.9.3-${about_target}.tar.gz"
gh release download 0.9.3 --repo EmbarkStudios/cargo-about --pattern "$about_archive" --dir /tmp/day2-about
awk -v file="$about_archive" '$2 == file { print; count++ } END { if (count != 1) exit 1 }' .github/cargo-about.sha256 > /tmp/day2-about/selected.sha256
(cd /tmp/day2-about && shasum -a 256 --check selected.sha256)
tar -xzf "/tmp/day2-about/$about_archive" -C /tmp/day2-about
cargo build --locked --release --bin day2
mkdir -p dist/day2-cli
cp target/release/day2 dist/day2-cli/
"/tmp/day2-about/cargo-about-0.9.3-${about_target}/cargo-about" generate --locked --all-features --target "$target" about.hbs > dist/day2-cli/THIRD_PARTY_LICENSES.txt
cp docs/INSTALL.md dist/day2-cli/README.md
jq -n --arg version "$version" --arg commit "$GITHUB_SHA" --arg target "$target" --arg rust "$(rustc --version)" '{schema_version:1,version:$version,commit:$commit,target:$target,rust:$rust}' > dist/day2-cli/SOURCE.json
target/release/day2 --version
target/release/day2 call --help >/dev/null
tar -czf "dist/day2-cli-v${version}-${target}.tar.gz" -C dist day2-cli
