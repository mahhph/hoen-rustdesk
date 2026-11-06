# macOS mailbox host development

The development build uses the `hoen-mac-dev` feature and separate application, Keychain, and history names. The production mailbox feature keeps network admission disabled until the real-device trial has passed. Stock RustDesk installation, removal, and update commands are disabled in mailbox mode pending a separate installer. The application bundle identifier and launch-agent isolation still require verification before running alongside an existing installation.

The mailbox-enabled Mac build uses a logged-in user's Keychain for enrollment and a private user-owned directory for the history outbox. The login-window/root context is not enrolled by this implementation. Host and viewer entries have distinct names, but Keychain access control identifies the executable, so those names are not an isolation boundary between processes running as the same user and executable.

The host checks an explicitly enrolled Wi-Fi interface and access point, a private IPv4 address, and a direct route to each peer. It obtains the current address again at startup and advertises it only after the listener binds. A changed access point identity requires renewed approval. SSID and BSSID matching is not cryptographic authentication; the mailbox grant and authenticated host handshake remain required. Missing permission, identity, route, or network data fails closed.

The following commands are development setup operations for the signed application executable inside the app bundle. Run them as the intended logged-in user, not as root:

- `--hoen-request-wifi-access` requests Location Services authorization because macOS restricts access to Wi-Fi identity. The app does not request location coordinates.
- `--hoen-network-identifiers` displays opaque candidate adapter and network identifiers and the current local IPv4 address. Discovery is not approval. Independently verify the intended Wi-Fi before using these identifiers in an enrollment bundle; do not place mailbox tokens or private keys in command arguments or logs.
- `--hoen-import-host` reads the validated enrollment bundle only from standard input and saves it to the user's Keychain.

The code and synthetic tests do not establish production readiness. A signed application and stable signing identity, explicit network approval, real-device enrollment, a second authenticated machine, screen-recording and accessibility permissions, real Wi-Fi and reboot transitions, and complete interactive session tests remain necessary. The macOS network observer and Keychain behavior must also be verified in the installed application's actual launch-agent context. A login-time address change only works when the mailbox service itself remains reachable and its TLS identity still validates.
