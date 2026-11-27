# Contributing

Work happens on a branch. Cloudflare Workers Builds deploys the Rust Worker pair from `main`. Use the local manifests when developing or testing.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --exclude watchdog-worker --all-targets -- -W clippy::all
cargo test --workspace --exclude watchdog-worker
```

`watchdog-worker` is checked with `--target wasm32-unknown-unknown`. The MDK probe is `probes/mdk-engine` and is not part of the workspace.

Do not add a homemade MLS, NIP-44, or push-token implementation. If MDK needs a change, keep it as a small patch against the pinned revision and describe it in `docs/mdk-compatibility.md`.

Keep Wrangler secrets, `.dev.vars`, `.setup-secrets.json`, and operational backups out of Git and logs.

The license is the Unlicense. Do not add a dependency whose license `deny.toml` rejects without explaining the exception.
