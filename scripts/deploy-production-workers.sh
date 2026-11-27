#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

commit=$(git rev-parse HEAD)
wrangler deploy --config wrangler.marmot-production.toml --message "$commit"
wrangler deploy --config wrangler.production.toml --message "$commit"
