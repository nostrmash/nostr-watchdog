#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

commit=$(git rev-parse HEAD)
(
  # Workers Builds supplies the operational script name and tag. Scope those
  # overrides to the operational deployment so the private manifest can target
  # its own Worker.
  unset WRANGLER_CI_OVERRIDE_NAME WRANGLER_CI_MATCH_TAG
  wrangler deploy --config wrangler.marmot-production.toml --message "$commit"
)
wrangler deploy --config wrangler.production.toml --message "$commit"
