# Migration and rollback

Do not run this against production. `main` at `a236b35a9dda14aa6f1a96dc37fc2daccc838ed8` is the Worker to roll back to. There is no release tag.

## What can move

The Rust store applies migrations `0001` through `0006`. `0006` only adds columns and tables. It does not rewrite or delete existing rows. A D1 database that has already applied `0001`–`0005` can apply `0006` later. Taking a backup first is still required.

Copy these if the cutover is approved later:

- Project sender keys, as the same secret names.
- `PROJECT_RECIPIENTS`, `ADMIN_NPUB`, relay bootstrap, and monitor URLs.
- Operator and status tokens.
- The D1 rows for incidents, monitor state, and the outbox, after `0006`.

Do not copy an MLS database that does not exist yet. If a future deploy writes Marmot state and then fails, restore the operational D1 backup only. Create a new Marmot conversation. Do not load an older epoch over a newer one.

## Staging first

1. Export the production D1 database with Wrangler and store that file offline. Do not commit it.
2. Create `nostr-watchdog-rust-staging` and its own D1 database. Apply the migrations there. Use test keys and a test recipient.
3. Run the native binary against a copy of the backup if you want to read old incidents. Do not point it at production relays with production keys while the TypeScript cron is also sending.
4. Leave the TypeScript cron in place until the Rust process has been accepted. Two schedulers with the same keys will send duplicate alerts.

## Cutover, only after approval

1. Stop the TypeScript cron without deleting the Worker or the D1 database.
2. Start the Rust process with the same keys and a restored database that includes `0006`.
3. Send one test alert and confirm the destination you enabled.
4. Watch the outbox. `relay_accepted` means a relay took the event. It does not mean the phone showed it.

## Rollback

1. Stop the Rust process.
2. Deploy `main` at `a236b35` again. That commit is the last TypeScript revision this branch was cut from.
3. The TypeScript Worker ignores the `0006` columns. Leaving them in place is safe. Do not drop them as part of rollback if a future Rust retry might need them.
4. If the Rust process published NIP-17 events that the TypeScript outbox does not know about, those messages are already public to the relays. Rollback does not unsend them. It stops new ones.
5. There is no Marmot conversation to roll back in this build. If that changes, re-onboard instead of restoring cryptographic state.

## Duplicate monitoring

The failure mode to avoid is both schedulers running. The Rust native process and the TypeScript cron must not be enabled on the same projects at the same time.
