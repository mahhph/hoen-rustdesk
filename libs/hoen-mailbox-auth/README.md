# Hoen mailbox authentication primitives

This standalone library implements the byte encodings and strict detached Ed25519 viewer-proof verification specified in `docs/HOEN-AUTH.md`. Its blocking mailbox client supports machine registration and discovery and one-use grant issuance and consumption over HTTPS with an explicit trusted root and strict hostname validation. Run it on a dedicated worker, not inside an async runtime. It is not connected to RustDesk and does not itself authenticate a desktop transport, verify a host handshake, enforce LAN policy, or establish a trusted mailbox pin. Callers must verify the returned host and viewer fingerprints and proof against the authenticated connection. Tokens are held in memory, never logged or persisted by this library; grant issuance or consumption with an ambiguous result requires a fresh grant and connection. Responses are limited to 256 KiB.

`MailboxClient::new_pinned` additionally requires the expected SHA-256 digest of the mailbox leaf certificate's DER bytes. TLS checks the normal certificate chain and hostname first, then that exact pin, before sending an authenticated request. The caller must obtain the pin through trusted provisioning. The original `new` constructor remains available without this additional pin for compatibility.

Run from the RustDesk root:

```powershell
cargo +1.75.0 test --locked --manifest-path libs/hoen-mailbox-auth/Cargo.toml
```

The deterministic signing key in the tests is a fixture only. Licensed under AGPL-3.0-only.
