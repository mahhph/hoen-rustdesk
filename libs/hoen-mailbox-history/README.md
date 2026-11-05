# Hoen mailbox history outbox

This standalone Rust library stores typed remote-session history events in a bounded SQLite outbox. Events use stable UUIDs, allowlisted terminal reasons, and persisted endpoint and body values for identical retries. SQLite transactions enforce the configured pending-event limit and per-session acknowledgement order; a full outbox rejects enqueue without evicting pending events.

No RustDesk runtime hook or HTTP client is connected to this library. It does not authenticate the viewer, prove that a mailbox identity is enrolled, provision credentials, configure directory ACLs, perform retry scheduling, or deploy the mailbox backend. The caller must derive each identity from verified enrollment, provision an access-restricted directory, serialize sends for each session, and acknowledge only after validating the mailbox response. Inputs contain metadata only; do not place tokens, clipboard content, keystrokes, or free-form error messages in the outbox.

The outbox does not reserve terminal-event capacity. When full, the caller must surface the failure and follow an explicit product policy; it must not claim the missing event was recorded. Durable local storage does not guarantee delivery after local data loss or an indefinite mailbox outage. A connection without a reported end remains unknown or stale. Provisioning, identity mapping, runtime integration, and the host's failure policy remain to be implemented and tested.

This crate is intentionally independent of RustDesk's root workspace for this initial slice. Test with the pinned lockfile:

```powershell
cargo +1.75.0 test --locked --manifest-path libs/hoen-mailbox-history/Cargo.toml
```

The crate is licensed under AGPL-3.0-only. Its local `.gitignore` excludes Cargo's `target/` build directory.
