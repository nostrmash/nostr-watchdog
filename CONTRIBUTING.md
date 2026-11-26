# Contributing

Work happens on a branch. Do not push to `main` to try the Rust rewrite. The production Worker is the TypeScript tree on `main`.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --exclude watchdog-worker --all-targets -- -W clippy::all
cargo test --workspace --exclude watchdog-worker
```

`watchdog-worker` is checked with `--target wasm32-unknown-unknown`. The MDK probe is `probes/mdk-engine` and is not part of the workspace.

Do not add a homemade MLS, NIP-44, or push-token implementation. If MDK needs a change, keep it as a small patch against the pinned revision and describe it in `docs/mdk-compatibility.md`.

Do not log secrets. Do not commit `.dev.vars`, `.setup-secrets.json`, or a filled-in production Wrangler database id.

The license is the Unlicense. Do not add a dependency whose license `deny.toml` rejects without explaining the exception.
