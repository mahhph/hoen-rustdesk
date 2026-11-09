# Mac consolidated-configuration adapter handoff

This handoff is for parallel implementation, not permission to activate an unverified migration. Shared baseline: PR 26; check out its exact head, recorded in the coordinating mailbox message. Existing machine identity, Keychain items, credentials, trust, watcher cursor and session history must remain intact. Existing operator/machine access policy remains unchanged. Mac host/client separation is a separate change: reconcile its branch before touching overlapping lifecycle code.

## Shared interface

`src/hoen/machine_config.rs` defines strict public metadata and `src/hoen/lan_contract.rs::parse` enforces the 4096-byte input bound. `src/hoen/runtime_migration.rs::prepare` takes a protected `Secret` and expected current revision, returning a zeroizing `Secret` containing the prepared record. A missing embedded `machine_config` is revision zero. It preserves the existing identity, signing seed, token, URL, alias, port, trust and legacy fields. It fails on stale revision, invalid trust, mismatched metadata or legacy aliases outside the new schema; do not rename an existing alias silently. This prepares bytes in memory only: it does not provide transactional writes, authentication, reference ownership, TLS handshake or activation.

The embedded metadata must match the protected enrollment exactly. Existing leaf pin remains a leaf pin; existing CA mode retains its bundle SHA-256. Fixed references are service-owned identifiers, not filesystem paths. Do not expose the machine bearer, private key, decrypted record or raw Keychain contents in IPC, diagnostics or logs.

## Mac work

1. Implement a platform adapter in a Mac-specific module using the existing `MacStore` and its current Keychain namespace. Make read-only preflight open and parse the existing host/viewer enrollment without creating, changing or deleting an item. Return only public metadata, status and public fingerprint; report unavailable or incompatible state without generating an identity.
2. Reconcile Mac viewer-to-host provisioning with the shared `host_secret_from_viewer` fix. Preserve the viewer record, credentials and revision; ensure the host metadata reflects the host role. Verify behavior against the independent host service work.
3. Design and implement a protected staged migration and atomic revision switch with exclusive ownership, explicit verified rollback and interruption recovery. Keep a privately protected backup and check expected revision immediately before activation. Do not overwrite an existing host/Keychain item merely because a read failed. Do not remove legacy app settings until every consumer has migrated. Existing operator/user credentials remain separate.
4. Provide narrowly scoped authenticated local IPC for public configuration/revision and allowlisted operations. Verify the actual caller and its privileges; do not permit arbitrary URLs or general secret reads. Coordinate exact shared IPC shape with Lenovo before modifying shared interfaces.
5. Prepare application-scoped CA renewal compatibility and strict hostname/chain checks in isolation. Do not rotate the live certificate or install a global root. Validate the deployed Rust, Electron and watcher runtimes before proposing production rollout.

## Acceptance evidence

Supply exact source and artifact revisions, tests and failures. Test existing/absent/unreadable Keychain items; unchanged token and signing-key identity in memory; viewer-to-host conversion; conflicting identities and unsupported aliases; concurrent and interrupted preparation/activation; rollback to a compatible prior build; caller rejection; and certificate wrong-host/unknown-CA cases before credentials are sent. Exercise real protected Keychain and platform permissions in an authorized local context. A syntactically valid configuration, a successful build or a running service alone is not release readiness. Preserve the user's Wi-Fi and active sessions.

PR 26 adds a Windows service preflight request only for already-authorized local service callers. It reports proposed metadata, not an active revision. It is not the cross-platform IPC contract and must not be copied as an authentication design for macOS.
