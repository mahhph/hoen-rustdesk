# Hoen mailbox authentication primitives

This standalone library implements the byte encodings and strict detached Ed25519 viewer-proof verification specified in `docs/HOEN-AUTH.md`. It is not connected to RustDesk, and by itself does not authenticate a host or network connection, enforce LAN policy, consume a grant, or establish a trusted mailbox pin. Callers must pass values derived from a verified handshake and a trusted registry, and must reject errors. The viewer proof takes a raw 32-byte token; callers must first validate and decode the canonical unpadded base64url token. No private keys, tokens or network data are stored by this library.

Run from the RustDesk root:

```powershell
cargo +1.75.0 test --locked --manifest-path libs/hoen-mailbox-auth/Cargo.toml
```

The deterministic signing key in the tests is a fixture only. Licensed under AGPL-3.0-only.
