#!/bin/sh
# Deterministic release bundle for the Marmot Durable Object.
# worker-build can fail while moving its staging directory after the wasm
# and the shim have already been written. This script deletes build/, runs
# the release build, and accepts that move failure only when every required
# file is present, non-empty, and the wasm header is intact.
set -eu
cd "$(dirname "$0")"
rm -rf build
export CARGO_INCREMENTAL=0
set +e
worker-build --release
build_status=$?
set -e

wasm=build/index_bg.wasm
js=build/index.js
shim=build/worker/shim.mjs
staged=build/.tmp/worker/shim.mjs

if [ ! -s "$wasm" ] || [ ! -s "$js" ]; then
  echo "release build is incomplete: index_bg.wasm or index.js is missing" >&2
  exit 1
fi
magic=$(od -An -tx1 -N4 "$wasm" | tr -d ' \n')
if [ "$magic" != "0061736d" ]; then
  echo "release build is incomplete: wasm magic is $magic" >&2
  exit 1
fi
if [ ! -s "$shim" ]; then
  if [ ! -s "$staged" ]; then
    echo "release build is incomplete: shim.mjs is missing" >&2
    exit 1
  fi
  mkdir -p build/worker
  cp "$staged" "$shim"
fi
if ! grep -q "index.js" "$shim"; then
  echo "release build is incomplete: shim does not load index.js" >&2
  exit 1
fi
raw=$(wc -c < "$wasm" | tr -d ' ')
gzip_bytes=$(gzip -c "$wasm" | wc -c | tr -d ' ')
echo "wasm_bytes=$raw"
echo "gzip_bytes=$gzip_bytes"
if [ "$build_status" -ne 0 ]; then
  echo "worker-build exited $build_status; required files were verified"
fi
exit 0
