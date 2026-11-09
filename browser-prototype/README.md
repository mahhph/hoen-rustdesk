# Browser remote desktop prototype

This is an early transport component, not yet a working browser desktop. The gateway translates binary WebSocket messages into the framed TCP messages used by the existing host and translates replies back. It neither implements nor bypasses the host's mailbox handshake. The browser viewer and identity/grant integration are still required before a real desktop can be shown.

`authentication.mjs` implements the channel-binding, host-fingerprint, split-key and viewer-proof primitives. Tests compare its byte-level output against fixed vectors from the native Rust implementation. It is not yet connected to a browser session or mailbox grant service.

Run `npm ci` and `npm test` to test framing and an actual loopback WebSocket-to-TCP exchange. The gateway listens on loopback by default and connects only to a fixed destination configured through `DESKTOP_HOST` and `DESKTOP_HOST_PORT`; `LISTEN_HOST` and `LISTEN_PORT` select its listening address. Do not expose this unfinished component as a customer service. The tests use a synthetic TCP peer, not an enrolled desktop.

An MIT-licensed browser viewer was evaluated at https://github.com/bropines/rdweb (commit `bdb92fae6c32d175e7633c6c68c4279ee9a994ba`). Its video and input components may be reusable, but its standard RustDesk relay and handshake do not implement our mailbox authentication. No third-party viewer code is included in this directory.
