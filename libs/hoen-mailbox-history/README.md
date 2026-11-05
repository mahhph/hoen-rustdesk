# Hoen mailbox history outbox

This standalone Rust library stores typed remote-session history events in a bounded SQLite outbox. Events use stable UUIDs, allowlisted terminal reasons, and persisted endpoint and body values for identical retries. SQLite transactions enforce the configured pending-event limit and per-session acknowledgement order; a full outbox rejects enqueue without evicting pending events.

The included blocking HTTPS adapter trusts an explicit PEM certificate root, validates the hostname, disables redirects and environment proxies, and acknowledges only correlated success responses. It must run on a dedicated worker. No RustDesk runtime hook is connected to this library. It does not authenticate the viewer, prove that a mailbox identity is enrolled, provision credentials, configure directory ACLs, perform retry scheduling, or deploy the mailbox backend. The caller must derive each identity from verified enrollment, provision an access-restricted directory, serialize sends for each session, and acknowledge only after validating the mailbox response. Inputs contain metadata only; do not place tokens, clipboard content, keystrokes, or free-form error messages in the outbox.

Each newly queued create reserves one slot for its terminal event, including across restart and after the create is acknowledged. Pending events plus reservations cannot exceed the configured capacity. The capacity is fixed on database creation; every process opening that database must use the same value. Heartbeats or new sessions are rejected when they would consume a reservation; enqueueing the terminal event consumes its reserved slot. Unknown and already-terminated sessions reject further heartbeat or terminal events. After terminal acknowledgement the session state is removed, so callers must never reuse an old create event or session ID. When full, the caller must surface the failure and follow an explicit product policy. Durable local storage does not guarantee delivery after local data loss or an indefinite mailbox outage. A connection without a reported end remains unknown or stale. Provisioning, identity mapping, runtime integration, and the host's failure policy remain to be implemented and tested.

This crate is intentionally independent of RustDesk's root workspace for this initial slice. Test with the pinned lockfile:

```powershell
cargo +1.75.0 test --locked --manifest-path libs/hoen-mailbox-history/Cargo.toml
```

The crate is licensed under AGPL-3.0-only. Its local `.gitignore` excludes Cargo's `target/` build directory.

Legacy mailbox-generated certificates without a subject alternative name are incompatible with strict hostname verification. New mailbox source generates a SAN for the explicit listen host, preserving existing certificates. Before using a legacy deployment for integrated delivery, arrange a managed certificate reissue with an appropriate DNS or IP subject alternative name and provision its trust root and client pins; do not disable verification. No live certificate was changed.

Outboxes created by the earlier pre-reservation prototype require explicit migration: they do not contain enough state to reconstruct active sessions safely. The library returns `MigrationRequired` without deleting their events. Recovery must preserve the old data and reconcile active sessions before replacing that database.
