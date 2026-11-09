import type { Codec } from "./video.js";
import type { PeerOs } from "./keymap.js";

export type ImageQualityPreset = "best" | "balanced" | "low" | "custom";
export type CodecPreference = "auto" | Codec;
export type KeyboardModeName = "map" | "translate" | "legacy";

/** Per-session display/control settings, mirroring the desktop client. */
export interface SessionSettings {
  /** "best" = Good image, "balanced", "low" = Optimize reaction time, or "custom". */
  imageQuality: ImageQualityPreset;
  /** Custom quality in percent of the default bitrate (10–100, up to 2000 on own servers). */
  customQuality: number;
  /** Custom frame rate cap (5–120). Used with imageQuality "custom". */
  customFps: number;
  codec: CodecPreference;
  /** Ask for 4:4:4 chroma when the codec and browser support it. */
  trueColor: boolean;
  /** Render the peer's cursor at its reported position even when we did not move it. */
  showRemoteCursor: boolean;
  followRemoteCursor: boolean;
  followRemoteWindow: boolean;
  disableAudio: boolean;
  disableClipboard: boolean;
  lockAfterSessionEnd: boolean;
  /** View only: no keyboard/mouse, no clipboard. */
  viewOnly: boolean;
  /** In view-only mode, show our pointer to the remote user. */
  showMyCursor: boolean;
  keyboardMode: KeyboardModeName;
  /** Swap Ctrl and Cmd (macOS browser controlling a non-mac peer and vice versa). */
  swapCtrlMeta: boolean;
}

export const DEFAULT_SETTINGS: SessionSettings = {
  imageQuality: "balanced",
  customQuality: 50,
  customFps: 30,
  codec: "auto",
  trueColor: false,
  showRemoteCursor: false,
  followRemoteCursor: false,
  followRemoteWindow: false,
  disableAudio: false,
  disableClipboard: false,
  lockAfterSessionEnd: false,
  viewOnly: false,
  showMyCursor: false,
  keyboardMode: "map",
  swapCtrlMeta: false,
};

export interface ServerConfig {
  /** WebSocket URL of hbbs, e.g. wss://example.com/ws/id */
  rendezvousUrl: string;
  /**
   * Maps the relay announced by hbbs (host:port, TCP) to a WebSocket URL.
   * Defaults to the same host as rendezvousUrl (/ws/id -> /ws/relay, see
   * relayUrlNextTo): the announced relay is a TCP address for native
   * clients and rarely serves TLS. `announcedRelayUrl` maps it instead.
   */
  relayUrl?: (relayServer: string) => string;
  /** The server's public key (base64 Ed25519, id_ed25519.pub). Required. */
  key: string;
  /** Client access token, for servers that require login. */
  token?: string;
}

export interface SessionOptions {
  server: ServerConfig;
  peerId: string;
  hoen?: {
    gatewayUrl: string;
    hostFingerprint: Uint8Array;
    issueProof: (host: string, binding: Uint8Array) => Promise<{viewerKey: Uint8Array; grantToken: Uint8Array; signature: Uint8Array}>;
  };
  /** Stored SHA256(password || salt) from an earlier "remember password". */
  rememberedHash?: Uint8Array;
  /** Shown to the remote user in the connection request. */
  myName?: string;
  /** Our id as shown on the remote side; defaults to a web-specific marker. */
  myId?: string;
  settings?: Partial<SessionSettings>;
  /** Version string announced to the peer (affects which features it uses). */
  clientVersion?: string;
}

export type SessionState =
  | "idle"
  | "rendezvous"
  | "relay"
  | "handshake"
  | "login"
  | "connected"
  | "closed";

export interface DisplayRect {
  index: number;
  x: number;
  y: number;
  width: number;
  height: number;
  name: string;
  online: boolean;
  cursorEmbedded: boolean;
  /** Physical resolution before the peer's own scaling, if reported. */
  originalWidth: number;
  originalHeight: number;
  scale: number;
}

export interface ResolutionOption {
  width: number;
  height: number;
}

export interface PeerSummary {
  id: string;
  username: string;
  hostname: string;
  platform: string;
  os: PeerOs;
  version: string;
  displays: DisplayRect[];
  currentDisplay: number;
  /** Resolutions the current display can switch to. */
  resolutions: ResolutionOption[];
  /** Codecs the peer can encode that this browser can decode. */
  codecs: Codec[];
  /** Codecs usable in 4:4:4 on both sides. */
  codecs444: Codec[];
  privacyModeSupported: boolean;
  /** Ctrl+Alt+Del can be injected (Windows service mode). */
  sasEnabled: boolean;
  windowsSessions: { sid: number; name: string }[];
  currentWindowsSession: number;
}

export type PermissionName =
  | "keyboard"
  | "clipboard"
  | "audio"
  | "file"
  | "restart"
  | "recording"
  | "blockInput"
  | "privacyMode";

export interface SessionStats {
  codec: Codec | null;
  chroma444: boolean;
  width: number;
  height: number;
  fps: number;
  kbps: number;
  decoded: number;
  received: number;
  dropped: number;
  /** Round trip measured by the peer, ms. */
  delayMs: number;
  /** Bitrate the peer is currently aiming for, kbit/s. */
  targetKbps: number;
}

export interface CloseInfo {
  reason: string;
  /** True when the peer or server ended the session (not us). */
  remote: boolean;
  /** Reconnecting makes sense (network trouble, peer restart). */
  retryable: boolean;
}

export interface SessionEventMap {
  state: { state: SessionState };
  /** The peer wants a password. `wrong` is set after a failed attempt. */
  password: { wrong: boolean };
  /** The peer wants a 2FA code. */
  twoFactor: { wrong: boolean };
  /** No password needed/known: waiting for the remote user to click accept. */
  waitingForApproval: Record<string, never>;
  /** Login succeeded; `rememberedHash` can be stored for next time if wanted. */
  connected: { peer: PeerSummary; rememberedHash: Uint8Array | null };
  peer: { peer: PeerSummary };
  /** Current display geometry (also fires after a display switch). */
  display: { display: DisplayRect; resolutions: ResolutionOption[] };
  frame: { frame: VideoFrame };
  cursorShape: { id: string };
  cursorPosition: { x: number; y: number };
  clipboard: { text: string };
  permission: { name: PermissionName; enabled: boolean };
  message: { type: string; title: string; text: string; link: string };
  chat: { text: string };
  privacyMode: { on: boolean; message: string };
  blockInput: { on: boolean; message: string };
  stats: SessionStats;
  /** Remote audio: "blocked" means the browser waits for a user gesture (Session.resumeAudio). */
  audio: { state: import("./audio.js").AudioState };
  close: CloseInfo;
}
