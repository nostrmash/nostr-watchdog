# Migration and rollback

Use a dedicated staging database and a dedicated cryptographic namespace. The TypeScript production reference is `a236b35a9dda14aa6f1a96dc37fc2daccc838ed8`. Staging authorization and deployment order are in [deployment.md](deployment.md).

## Operational migration manifest

Apply the files in order. Track the applied versions in each environment. Take an operational database backup before a migration or version rollback.

| Migration | Purpose |
| --- | --- |
| `0001_init.sql` | Operational tables for monitors, incidents, heartbeats, outbox, and scheduler. |
| `0002_hardening.sql` | Inconclusive monitor state and notification claim fields. |
| `0003_vendor_checks.sql` | Vendor observations and check history. |
| `0004_vendor_source_state.sql` | Separate vendor source progress and cached evidence. |
| `0005_source_failures.sql` | Vendor source failure tracking. |
| `0006_marmot.sql` | Marmot project metadata. |
| `0007_marmot_push_identity.sql` | Push record identity fields and indexes. |
| `0008_commit_token.sql` | Commit tokens for fenced monitor writes. |
| `0009_operations.sql` | Stable delivery operation fields. |
| `0010_lifecycle.sql` | Reconciliation and claim metadata. |
| `0011_delivery_fencing.sql` | Authoritative counters and fallback fences. |
| `0012_transport_evidence.sql` | Sanitized evidence and timestamps. |

The native migration tests upgrade an older schema and exercise interruption of the last migration. The workerd harness applies all files to an isolated D1 database. It checks both fallback interruption directions through the real adapter. Remote D1 migration and convergence remain part of staging.

## Cryptographic state

The private Cloudflare Worker uses the `v1` SQLite Durable Object class migration. Its runtime creates the account row and historical index in that namespace. Snapshot version 2 authenticates the revision, writer, and index commitments. The native helper stores its SQLCipher database and durable operation journal under the same state root. Each platform requires its cryptographic state and journal to restore the original conversation.

Keep sender secrets, MLS state, and wake capabilities in their designated cryptographic or secret stores. The operational migrations carry only the application data and sanitized transport projection needed by the watchdog.

## Rehearse rollback in staging

1. Disable alert delivery and pause monitors for the selected staging project. Record the active Worker versions and retain the staging D1 database and Durable Object namespace.
2. Roll back the operational Worker to a reviewed version compatible with the applied additive migrations. Leave the migration columns and operation IDs in place.
3. Roll back the cryptographic Worker only to a version compatible with the current sealed snapshot and history. Resume using the same namespace after readiness and a controlled alert pass.
4. Treat restored or incomplete cryptographic storage as a recovery event. Keep affected operations quarantined pending an integrity check. Use a deliberate fresh onboarding and namespace when the original epoch and deduplication state cannot be proven.

A runtime restart uses the current data. A point-in-time restore changes the data and can rewind a whole consistent state. Use separate authorization before touching production, and keep one enabled scheduler per project identity through any cutover.
