# Browser remote desktop prototype

This prototype connects an MIT-licensed browser video and input viewer to the existing mailbox-authenticated desktop protocol. The WebSocket gateway translates messages to the native framed TCP protocol. The browser verifies the host's signed handshake and requests a connection-bound viewer proof from the server-side provider; the host's existing authentication remains in place.

The handshake has been tested against the real Area51 host through a temporary SSH tunnel. The full browser desktop login has not yet been verified: the prototype still needs a separately enrolled test viewer identity and credentials. The tests use synthetic peers and mailbox responses.

Run `npm ci`, `npm test`, and `npm run build` to install dependencies, run tests, and build the browser assets. The gateway listens on loopback by default and connects only to a fixed destination configured through `DESKTOP_HOST` and `DESKTOP_HOST_PORT`; `LISTEN_HOST` and `LISTEN_PORT` select its listening address. The private viewer configuration is selected by `PROTOTYPE_VIEWER_CONFIG`. Do not expose this unfinished prototype as a customer service.

The viewer includes an MIT-licensed subset of https://github.com/bropines/rdweb at commit `bdb92fae6c32d175e7633c6c68c4279ee9a994ba`, adapted for the Hoen handshake. Its license and notices are in `vendor/rdweb`.
