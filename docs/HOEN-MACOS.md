# macOS mailbox host development

Current seq210 integration supersedes earlier network policy and readiness notes below.
The native TCP transport checks its configured local binding; adapter/network IDs,
SSID, interface type, OS category and peer route are not authorization checks.
Mac retains Keychain enrollment and the development app namespace, but no longer
queries Wi-Fi identifiers or automatically selects a pinned-network address.
Network notifications may terminate a session; reconnection requires fresh proof.
The configured bind address does not automatically follow DHCP. Relay is unimplemented.
Earlier seq191/193 admission descriptions are historical and superseded.

The development build uses the `hoen-mac-dev` feature and separate application, Keychain, and history names. The production mailbox feature keeps network admission disabled until the real-device trial has passed. Stock RustDesk installation, removal, and update commands are disabled in mailbox mode pending a separate installer. The application bundle identifier and launch-agent isolation still require verification before running alongside an existing installation.

With Rust, Flutter, CocoaPods and the native dependencies already configured, `python3 scripts/build-hoen-mac-dev.py` builds a separate development bundle and signs it locally for testing. It preserves the existing Xcode project contents, saves recovery copies under the build directory, and refuses to overwrite a project file changed during the build. This ad-hoc signature is not a production signing identity.

The mailbox-enabled Mac build uses a logged-in user's Keychain for enrollment and a private user-owned directory for the history outbox. The login-window/root context is not enrolled by this implementation. Host and viewer entries have distinct names, but Keychain access control identifies the executable, so those names are not an isolation boundary between processes running as the same user and executable.

The host checks an explicitly enrolled Wi-Fi interface and access point, a private IPv4 address, and a direct route to each peer. It obtains the current address again at startup and advertises it only after the listener binds. A changed access point identity requires renewed approval. SSID and BSSID matching is not cryptographic authentication; the mailbox grant and authenticated host handshake remain required. Missing permission, identity, route, or network data fails closed.

The following commands are development setup operations for the signed application executable inside the app bundle. Run them as the intended logged-in user, not as root:

- `--hoen-request-wifi-access` requests Location Services authorization because macOS restricts access to Wi-Fi identity. The app does not request location coordinates.
- `--hoen-network-identifiers` displays opaque candidate adapter and network identifiers and the current local IPv4 address. Discovery is not approval. Independently verify the intended Wi-Fi before using these identifiers in an enrollment bundle; do not place mailbox tokens or private keys in command arguments or logs.
- `--hoen-import-host` reads the validated enrollment bundle only from standard input and saves it to the user's Keychain.

The code and synthetic tests do not establish production readiness. A signed application and stable signing identity, explicit network approval, real-device enrollment, a second authenticated machine, screen-recording and accessibility permissions, real Wi-Fi and reboot transitions, and complete interactive session tests remain necessary. The macOS network observer and Keychain behavior must also be verified in the installed application's actual launch-agent context. A login-time address change only works when the mailbox service itself remains reachable and its TLS identity still validates.
