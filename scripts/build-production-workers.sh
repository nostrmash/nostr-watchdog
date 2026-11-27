#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--install-toolchain" ]; then
  # Workers Builds includes Node but does not preinstall Rust.
  if ! command -v rustup >/dev/null 2>&1; then
    installer=$(mktemp)
    trap 'rm -f "$installer"' EXIT
    curl --fail --silent --show-error --location https://sh.rustup.rs --output "$installer"
    sh "$installer" -y --profile minimal --default-toolchain none --no-modify-path
  fi
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
  rustup target add wasm32-unknown-unknown
  rustup component add llvm-tools
  cargo install worker-build --version 0.9.0 --locked
fi

worker-build --release crates/watchdog-worker -- --locked
sh crates/watchdog-marmot-worker/worker/build-release.sh
