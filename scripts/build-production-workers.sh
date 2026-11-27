#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--install-toolchain" ]; then
  # Workers Builds includes Node but does not preinstall Rust.
  tooling=$(mktemp -d)
  trap 'rm -rf "$tooling"' EXIT
  if ! command -v rustup >/dev/null 2>&1; then
    curl --fail --silent --show-error --location https://sh.rustup.rs --output "$tooling/rustup-init.sh"
    sh "$tooling/rustup-init.sh" -y --profile minimal --default-toolchain none --no-modify-path
  fi
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
  rustup target add wasm32-unknown-unknown
  rustup component add llvm-tools
  cargo install worker-build --version 0.9.0 --locked

  # The Ubuntu x86_64 Workers Builds image lacks a C compiler with a Wasm target.
  if ! command -v clang >/dev/null 2>&1; then
    sdk=wasi-sdk-32.0-x86_64-linux
    url="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-32/$sdk.tar.gz"
    curl --fail --silent --show-error --location "$url" --output "$tooling/$sdk.tar.gz"
    printf '%s  %s\n' 55fc523ebfbc98f69d1034fcfcb83d1ff5610cd9ab7eceef6cd097a30ba4ef93 "$tooling/$sdk.tar.gz" | sha256sum --check
    tar -xzf "$tooling/$sdk.tar.gz" -C "$tooling"
    export CC_wasm32_unknown_unknown="$tooling/$sdk/bin/clang"
  fi
fi

worker-build --release crates/watchdog-worker -- --locked
sh crates/watchdog-marmot-worker/worker/build-release.sh
