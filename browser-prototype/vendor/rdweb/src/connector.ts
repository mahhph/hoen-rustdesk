// Connection setup shared by every session kind (remote desktop, file
// transfer): rendezvous, relay, the authenticated key exchange, the encrypted
// message stream and the login dialogue (password, remembered hash, 2FA,
// approval on the remote side). What happens after login is up to the owner.

import { create, fromBinary, toBinary, type MessageInitShape } from "@bufbuild/protobuf";
import type { ConnType } from "./proto/rendezvous_pb.js";
import {
  MessageSchema,
  LoginRequestSchema,
  type LoginRequest,
  type Message,
  type PeerInfo,
} from "./proto/session_pb.js";
import {
  HandshakeError,
  StreamCipher,
  createKeyExchange,
  loginProof,
  parseServerKey,
  rememberedPasswordHash,
  verifyPeerEphemeralKey,
  verifyPeerLongTermKey,
} from "./crypto.js";
import { joinRelay, RendezvousError, requestRelay } from "./rendezvous.js";
import { TransportError, WsTransport } from "./transport.js";
import type { CloseInfo, ServerConfig, SessionOptions } from "./types.js";
import { authenticateHost, bytesField, wireMessage, type SessionCipher } from "../../../handshake.mjs";

/** Announced to peers; they enable features by version. */
export const CLIENT_VERSION = "1.4.3";
const WEB_ID_PREFIX = "web";

export class SessionError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = "SessionError";
  }
}

export function versionNumber(v: string): number {
  // "1.2.4" -> 1002004; tolerant of suffixes like "1.4.0-1"
  const parts = v.split(/[.-]/).map((p) => parseInt(p, 10) || 0);
  return (parts[0] ?? 0) * 1_000_000 + (parts[1] ?? 0) * 1_000 + (parts[2] ?? 0);
}

function randomSessionId(): bigint {
  const b = crypto.getRandomValues(new Uint8Array(8));
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v & 0x7fff_ffff_ffff_ffffn;
}

/**
 * The hbbr WebSocket URL next to an hbbs one, the default relay endpoint:
 * wss://host/ws/id -> wss://host/ws/relay, a direct ws://host:21118 ->
 * ws://host:21119, any other path -> /ws/relay on the same host.
 */
export function relayUrlNextTo(rendezvousUrl: string): string {
  try {
    const u = new URL(rendezvousUrl);
    u.search = "";
    u.hash = "";
    if (u.port === "21118") u.port = "21119";
    else u.pathname = /\/ws\/id\/?$/.test(u.pathname) ? u.pathname.replace(/\/ws\/id\/?$/, "/ws/relay") : "/ws/relay";
    return u.toString();
  } catch {
    return rendezvousUrl.replace(/\/ws\/id\/?$/, "/ws/relay");
  }
}

/**
 * Maps the relay that hbbs announces (a TCP host:port for native clients) to
 * wss://<host>/ws/relay, or ws(s)://<ip>:<port + 2> for IP addresses. Opt in
 * with `relayUrl: announcedRelayUrl` when every relay has its own TLS proxy.
 */
export function announcedRelayUrl(relayServer: string): string {
  const secure = typeof location === "undefined" || location.protocol === "https:";
  let host = relayServer;
  let port = "";
  const v6 = /^\[(.+)\](?::(\d+))?$/.exec(relayServer);
  if (v6) {
    host = v6[1]!;
    port = v6[2] ?? "";
  } else if (relayServer.split(":").length === 2) {
    [host, port] = relayServer.split(":") as [string, string];
  }
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
  if (isIp) {
    const p = port ? Number(port) + 2 : 21119;
    const h = host.includes(":") ? `[${host}]` : host;
    return `${secure ? "wss" : "ws"}://${h}:${p}`;
  }
  return `wss://${host}/ws/relay`;
}

export function toSessionError(e: unknown): SessionError {
  if (e instanceof SessionError) return e;
  if (e instanceof RendezvousError) return new SessionError(e.message, e.code);
  if (e instanceof HandshakeError) return new SessionError(`secure handshake failed: ${e.message}`, "handshake");
  if (e instanceof TransportError) return new SessionError(e.message, e.code === "aborted" ? "aborted" : "network");
  return new SessionError(e instanceof Error ? e.message : String(e), "internal");
}

export function isRetryable(e: SessionError): boolean {
  return e.code === "network" || e.code === "unreachable" || e.code === "timeout" || e.code === "offline";
}

type LoginInit = Exclude<MessageInitShape<typeof LoginRequestSchema>, LoginRequest>;
export type ConnectState = "rendezvous" | "relay" | "handshake" | "login";

export interface ConnectorConfig {
  peerId: string;
  server: ServerConfig;
  hoen?: SessionOptions["hoen"];
  connType: ConnType;
  rememberedHash?: Uint8Array;
  myName?: string;
  myId?: string;
  clientVersion?: string;
  /**
   * After this many milliseconds without a message either way, send a
   * `testDelay` probe (the peer echoes it back). A relay drops a connection
   * that carries nothing — hbbr after 30 s — which a video session never hits
   * but an idle terminal does. 0 or unset: no probes.
   */
  keepAliveMs?: number;
  /** LoginRequest fields specific to the session kind (options, file transfer, ...). */
  loginExtras: () => Omit<LoginInit, "username" | "password" | "myId" | "myName" | "myPlatform" | "version" | "sessionId">;
  /** Error code for a login refusal the dialogue cannot handle (default "login"). */
  loginErrorCode?: (error: string) => string;
}

export interface ConnectorEvents {
  state(state: ConnectState): void;
  password(wrong: boolean): void;
  twoFactor(wrong: boolean): void;
  waitingForApproval(): void;
  /** Login accepted; runs synchronously before connect() resolves. */
  loggedIn(pi: PeerInfo): void;
  /** Every message after the key exchange except the login dialogue itself. */
  message(msg: Message): void;
  /** The link is gone: transport lost, undecryptable data or a refused login. */
  failed(info: CloseInfo): void;
}

/** One authenticated, encrypted link to a peer, up to and including login. */
export class PeerConnector {
  readonly peerId: string;
  private relay: WsTransport | null = null;
  private relayUrlUsed = "";
  private cipher: StreamCipher | SessionCipher | null = null;
  private hoenProof: {viewerKey: Uint8Array; grantToken: Uint8Array; signature: Uint8Array} | null = null;
  private salt = "";
  private challenge = "";
  private hash: Uint8Array | null = null;
  private triedRemembered = false;
  private loginResolve: (() => void) | null = null;
  private loginReject: ((e: Error) => void) | null = null;
  private readonly sessionId = randomSessionId();
  private closed = false;
  private keepAliveTimer: ReturnType<typeof setInterval> | null = null;
  private lastActivity = Date.now();

  constructor(
    private readonly cfg: ConnectorConfig,
    private readonly ev: ConnectorEvents,
  ) {
    this.peerId = cfg.peerId;
  }

  get clientVersion(): string {
    return this.cfg.clientVersion ?? CLIENT_VERSION;
  }

  /** The relay WebSocket URL this link goes through (empty before the relay step). */
  get relayUrl(): string {
    return this.relayUrlUsed;
  }

  /** The salted password hash that worked, for "remember password". */
  get rememberedHash(): Uint8Array | null {
    return this.hash ? new Uint8Array(this.hash) : null;
  }

  get isOpen(): boolean {
    return !this.closed && !!this.cipher && !!this.relay?.isOpen;
  }

  /** Bytes waiting in the WebSocket send buffer. */
  get bufferedAmount(): number {
    return this.relay?.bufferedAmount ?? 0;
  }

  /**
   * Rendezvous, relay, key exchange and login. Resolves once the peer
   * accepted the login (after `loggedIn`); while waiting it may emit
   * `password`, `twoFactor` or `waitingForApproval`.
   */
  async connect(signal: AbortSignal): Promise<void> {
    if (this.cfg.hoen) {
      this.ev.state("relay");
      const relay = await WsTransport.open(this.cfg.hoen.gatewayUrl, { signal });
      if (this.closed) { relay.close("closed"); throw new TransportError("aborted", "aborted"); }
      this.relay = relay;
      this.relayUrlUsed = this.cfg.hoen.gatewayUrl;
      this.ev.state("handshake");
      const session = await authenticateHost({ next: () => relay.next(10_000, signal), send: (data: Uint8Array) => relay.send(data) }, this.cfg.hoen.hostFingerprint);
      this.cipher = session.cipher;
      this.hoenProof = await this.cfg.hoen.issueProof(this.peerId, session.binding);
      this.ev.state("login");
      const loggedIn = new Promise<void>((resolve, reject) => { this.loginResolve = resolve; this.loginReject = reject; });
      relay.onClose((reason) => this.onTransportClosed(reason));
      relay.onMessage((raw) => this.onRaw(raw));
      await loggedIn;
      return;
    }
    const { server } = this.cfg;
    const serverKey = parseServerKey(server.key);
    this.ev.state("rendezvous");
    const ticket = await requestRelay({
      url: server.rendezvousUrl,
      peerId: this.peerId,
      licenceKey: server.key.trim(),
      token: server.token,
      connType: this.cfg.connType,
      version: this.clientVersion,
      signal,
    });
    if (ticket.signedPeerKey.length === 0) {
      throw new SessionError(
        "the server did not vouch for the remote device's key; refusing an unauthenticated connection",
        "unverified-peer",
      );
    }
    const peerLongTerm = verifyPeerLongTermKey(ticket.signedPeerKey, serverKey, this.peerId);

    this.ev.state("relay");
    const relayUrl = server.relayUrl ? server.relayUrl(ticket.relayServer) : relayUrlNextTo(server.rendezvousUrl);
    this.relayUrlUsed = relayUrl;
    const relay = await joinRelay(relayUrl, ticket.uuid, this.peerId, server.key.trim(), signal, this.cfg.connType);
    if (this.closed) {
      relay.close("closed");
      throw new TransportError("aborted", "aborted");
    }
    this.relay = relay;

    this.ev.state("handshake");
    const first = await nextPlain(relay, 30_000, signal);
    if (first.union.case !== "signedId") {
      throw new HandshakeError("the remote device did not identify itself");
    }
    const boxKey = verifyPeerEphemeralKey(first.union.value.id, peerLongTerm, this.peerId);
    const kx = createKeyExchange(boxKey);
    relay.send(
      toBinary(
        MessageSchema,
        create(MessageSchema, {
          union: { case: "publicKey", value: { asymmetricValue: kx.ourPublicKey, symmetricValue: kx.sealedKey } },
        }),
      ),
    );
    this.cipher = new StreamCipher(kx.key);

    this.ev.state("login");
    const loggedIn = new Promise<void>((resolve, reject) => {
      this.loginResolve = resolve;
      this.loginReject = reject;
    });
    relay.onClose((reason) => this.onTransportClosed(reason));
    relay.onMessage((raw) => this.onRaw(raw));
    await loggedIn;
  }

  /** Answers a `password` event. */
  async login(password: string): Promise<void> {
    if (!this.salt) throw new SessionError("not waiting for a password", "state");
    this.hash = await rememberedPasswordHash(password, this.salt);
    await this.sendLogin(this.hash);
  }

  /** Answers a `twoFactor` event. */
  submitTwoFactor(code: string): void {
    this.send({ union: { case: "auth2fa", value: { code: code.trim() } } });
  }

  send(init: MessageInitShape<typeof MessageSchema>): void {
    const relay = this.relay;
    const cipher = this.cipher;
    if (this.closed || !relay || !cipher || !relay.isOpen) return;
    const bytes = toBinary(MessageSchema, create(MessageSchema, init));
    relay.send(cipher.seal(bytes));
    this.lastActivity = Date.now();
  }

  /** Fails a pending connect() with `err` (the link itself stays as is). */
  rejectLogin(err: Error): void {
    const reject = this.loginReject;
    this.loginResolve = this.loginReject = null;
    reject?.(err);
  }

  /** Tears the link down; a pending connect() fails with code "closed". */
  close(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    if (this.keepAliveTimer) clearInterval(this.keepAliveTimer);
    this.keepAliveTimer = null;
    this.relay?.close(reason);
    this.relay = null;
    this.cipher?.destroy();
    this.cipher = null;
    this.hash?.fill(0);
    this.rejectLogin(new SessionError(reason, "closed"));
  }

  // ---------------------------------------------------------------- private

  private onTransportClosed(reason: string): void {
    if (this.closed) return;
    const err = new SessionError(`connection lost: ${reason}`, "network");
    this.rejectLogin(err);
    this.ev.failed({ reason: err.message, remote: true, retryable: true });
  }

  /**
   * Keeps an idle link alive: a `testDelay` with from_client set, which the
   * peer echoes back. Both directions reset a relay's idle timer, so the probe
   * works even with a peer that ignores it.
   */
  private startKeepAlive(): void {
    const everyMs = this.cfg.keepAliveMs ?? 0;
    if (everyMs <= 0 || this.keepAliveTimer) return;
    const tick = Math.max(1_000, Math.round(everyMs / 2));
    this.keepAliveTimer = setInterval(() => {
      if (this.closed) return;
      if (Date.now() - this.lastActivity < tick) return;
      this.send({ union: { case: "testDelay", value: { time: BigInt(Date.now()), fromClient: true } } });
    }, tick);
  }

  private onRaw(raw: Uint8Array): void {
    if (!this.cipher || this.closed) return;
    this.lastActivity = Date.now();
    let msg: Message;
    try {
      msg = fromBinary(MessageSchema, this.cipher.open(raw));
    } catch (e) {
      const err = toSessionError(e);
      this.rejectLogin(err);
      this.ev.failed({ reason: err.message, remote: false, retryable: true });
      return;
    }
    try {
      this.onMessage(msg);
    } catch (e) {
      // A bad message must not kill the session; surface it for debugging.
      console.warn("rdweb: failed to handle message", msg.union.case, e);
    }
  }

  private onMessage(msg: Message): void {
    const u = msg.union;
    switch (u.case) {
      case "hash":
        this.salt = u.value.salt;
        this.challenge = u.value.challenge;
        void this.onHash().catch((error) => {
          const failure = toSessionError(error);
          this.rejectLogin(failure);
          this.ev.failed({ reason: failure.message, remote: false, retryable: false });
        });
        return;
      case "loginResponse": {
        const r = u.value.union;
        if (r.case === "error") this.onLoginError(r.value);
        else if (r.case === "peerInfo") this.onLoggedIn(r.value);
        return;
      }
      default:
        this.ev.message(msg);
    }
  }

  private async onHash(): Promise<void> {
    if (this.cfg.hoen) {
      if (!this.hoenProof) throw new SessionError("Mailbox proof is no longer available", "login");
      await this.sendLogin(null);
      return;
    }
    if (this.cfg.rememberedHash?.length && !this.triedRemembered) {
      this.triedRemembered = true;
      this.hash = new Uint8Array(this.cfg.rememberedHash);
      await this.sendLogin(this.hash);
      return;
    }
    // No password yet: an empty login asks the remote user to accept us,
    // and we ask our user for the password at the same time.
    await this.sendLogin(null);
    this.ev.password(false);
  }

  private async sendLogin(saltedHash: Uint8Array | null): Promise<void> {
    const proof = saltedHash ? await loginProof(saltedHash, this.challenge) : new Uint8Array(0);
    if (this.hoenProof) {
      const value = { ...this.cfg.loginExtras(), username: this.peerId, myId: this.cfg.myId ?? WEB_ID_PREFIX, myName: this.cfg.myName ?? "Web client", myPlatform: "Web", version: this.clientVersion, sessionId: this.sessionId };
      const login = toBinary(LoginRequestSchema, create(LoginRequestSchema, value));
      const p = this.hoenProof;
      const encodedProof = wireMessage(bytesField(1, p.viewerKey), bytesField(2, p.grantToken), bytesField(3, p.signature));
      const raw = bytesField(7, wireMessage(login, bytesField(20, encodedProof)));
      if (!this.relay || !this.cipher || !this.relay.isOpen) throw new SessionError("connection closed", "closed");
      this.relay.send(this.cipher.seal(raw));
      this.hoenProof = null;
      return;
    }
    this.send({
      union: {
        case: "loginRequest",
        value: {
          ...this.cfg.loginExtras(),
          username: this.peerId,
          password: proof,
          myId: this.cfg.myId ?? WEB_ID_PREFIX,
          myName: this.cfg.myName ?? "Web client",
          myPlatform: "Web",
          version: this.clientVersion,
          sessionId: this.sessionId,
        },
      },
    });
  }

  private onLoginError(err: string): void {
    if ((globalThis as { RDWEB_DEBUG?: boolean }).RDWEB_DEBUG) console.debug("rdweb: login error", JSON.stringify(err));
    switch (err) {
      case "Empty Password":
        this.ev.password(false);
        return;
      case "Wrong Password":
        this.hash = null;
        this.ev.password(true);
        return;
      case "2FA Required":
        this.ev.twoFactor(false);
        return;
      case "Wrong 2FA Code":
        this.ev.twoFactor(true);
        return;
      case "No Password Access":
        this.ev.waitingForApproval();
        return;
      default: {
        this.rejectLogin(new SessionError(err, this.cfg.loginErrorCode?.(err) ?? "login"));
        this.ev.failed({ reason: err, remote: true, retryable: false });
      }
    }
  }

  private onLoggedIn(pi: PeerInfo): void {
    this.startKeepAlive();
    this.ev.loggedIn(pi);
    const resolve = this.loginResolve;
    this.loginResolve = this.loginReject = null;
    resolve?.();
  }
}

async function nextPlain(t: WsTransport, timeoutMs: number, signal: AbortSignal): Promise<Message> {
  for (;;) {
    const raw = await t.next(timeoutMs, signal);
    if (raw.length === 0) continue;
    try {
      return fromBinary(MessageSchema, raw);
    } catch {
      throw new HandshakeError("the remote device sent a malformed message");
    }
  }
}
