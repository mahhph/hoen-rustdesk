# Protected configuration migration checkpoint

The current scope preserves existing operator access and machine authentication. Personal accounts, invitations, administrator promotion and a new active-session termination policy are not part of this release. Existing credentials, watcher state, machine keys and session history remain intact.

## Single protected record

An enrollment may now contain optional `machine_config` metadata. Existing enrollments without it use the old runtime path. Metadata is stored inside the existing DPAPI/Keychain-protected enrollment, not a second ordinary configuration file. The loader validates the bounded shared schema and requires every duplicated setting to agree with the existing protected fields. Disagreement fails closed; it never chooses one source silently.

The initial migration preserves the exact identity, alias, mailbox URL, port and trust mode. A hosting-enabled legacy machine maps to `both`, preserving its existing ability to act as viewer; a non-hosting machine maps to `client`. The fixed handles `existing-machine-credential`, `existing-machine-key` and `mailbox-trust-v1` refer only to material already in that same protected record. They are not caller-selected filesystem or secret-store paths. No token or key is returned through public metadata.

`prepare` requires the expected current revision, creates the next revision in memory, and returns a zeroizing Secret for a future protected-store write. It preserves all legacy fields, the token and signing seed. Repeating preparation against the unchanged original yields identical bytes. Preparing against a different current revision fails. This check is not a filesystem transaction or an activation lock; the installer must still provide exclusive access and recheck immediately before commit.

Windows `--hoen-machine-config-preflight` directly reads the existing service ProtectedStore under its required LocalSystem identity. It does not provision directories, finalize bootstrap, write files, send credentials, register an endpoint or restart services. It outputs only proposed public metadata, current revision and the public signing-key fingerprint. `activationReady` and `authenticatedMailboxVerified` remain false. A user-context read must fail rather than bypass service ACL/DPAPI protection.

## Remaining activation gates

No installation or activation is supplied by this checkpoint. Protected backup/staging, exclusive activation, authenticated TLS/API probes, IPC/app/watcher reload, interruption recovery and compatible rollback remain required. Certificate parsing and exact pin/bundle binding are not a successful server TLS handshake. URL, alias, role or trust changes are intentionally not supported by this initial preparation operation.

Older binaries reject the new metadata field under their strict enrollment parser. Keep the original encrypted enrollment backup and a verified compatible rollback package; never assume an old executable can read a migrated record. Do not erase or replace the existing protected enrollment during this checkpoint.

Regression surface: runtime.rs accepts and validates the optional field and initializes it as absent during legacy bootstrap; all ordinary load/init/auth paths otherwise remain unchanged. enrollment.rs adds only the explicit Windows read-only command. Migration logic is isolated in runtime_migration.rs. No live configuration or security policy is modified.

## Windows service status request

The Windows service accepts a bounded `HoenConfigurationStatusRequest` only after its existing active-session, local-pipe and executable authorization checks. It runs the read-only protected-store preflight on a blocking worker and returns its public metadata and public-key fingerprint, or an unavailable response. The metadata describes a proposed migration revision, not a committed or active configuration; `activationReady` and `authenticatedMailboxVerified` remain false. It exposes no bearer, key seed or arbitrary secret read. This is not yet wired into the mailbox app or watcher, and it does not authorize a switch. Actual protected LocalSystem and unauthorized-caller integration tests remain required before release.
