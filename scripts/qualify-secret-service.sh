#!/bin/sh
# Disposable native credential-store qualification; uses no human credentials.
set -eu
store_root=$(mktemp -d "${TMPDIR:-/tmp}/day2-secret-service.XXXXXX")
trap 'rm -rf "$store_root"' EXIT HUP INT TERM
export XDG_DATA_HOME="$store_root/data"
export XDG_RUNTIME_DIR="$store_root/run"
mkdir -m 700 "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
dbus-run-session -- sh -eu -c '
  head -c 32 /dev/urandom | base64 | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  cargo test --locked --bin day2 auth::store::tests::native_secret_service_roundtrip -- --ignored --exact --test-threads=1
'
