# Security policy

## Supported versions

Security fixes ship on the latest `main` commit.

## Reporting a vulnerability

Do not open a public GitHub issue for an unfixed vulnerability.

Email `security@nostrmash.dev`. If you do not receive an acknowledgement within 3 business days, open a [private GitHub security advisory](https://github.com/nostrmash/nostr-watchdog/security/advisories/new) and include the original report time.

Include:

- the component and commit
- steps to reproduce
- impact on confidentiality, integrity, or availability
- a suggested fix if you have one

Confirm `security@nostrmash.dev` is monitored before relying on it for a release. If that address changes, update this file in the same change.

## Scope

The Worker, its configuration, and the dependencies it ships are in scope. Cloudflare's platform, the Nostr protocol, recipient apps, and the third-party services being monitored are out of scope unless the bug is in how this Worker calls them.

Operator routes fail closed when `OPERATOR_TOKEN` is unset. Probes use configured URLs only. Heartbeat and test-alert routes are authenticated.

## Response

We acknowledge and triage as quickly as we can, then coordinate disclosure with the reporter. The usual targets are an initial response within 2 business days, a status update within 7 days, and public disclosure after a fix is available. We credit you unless you ask to stay anonymous.

## Dependencies

Dependabot opens weekly pull requests for npm and GitHub Actions. Production dependencies are also audited at high severity in CI. Review changelog notes before merging a dependency update. Major upgrades need an explicit look at breaking changes.
