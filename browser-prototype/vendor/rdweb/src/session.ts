// A remote desktop session with one peer: the shared connector handles
// rendezvous, relay, the authenticated key exchange and login; this class runs
// the media/input message loop.

import type { MessageInitShape } from "@bufbuild/protobuf";
import {
  BackNotification_BlockInputState as BlockState,
  BackNotification_PrivacyModeState as PrivacyState,
  Chroma,
  ClipboardFormat,
  ControlKey,
  ImageQuality,
  KeyboardMode,
  OptionMessage_BoolOption as BoolOption,
  PermissionInfo_Permission as Permission,
  SupportedDecoding_PreferCodec as PreferCodec,
  type Clipboard,
  type KeyEventSchema,
  type Message,
  type MessageSchema,
  type OptionMessage,
  type OptionMessageSchema,
  type PeerInfo,
  type SupportedEncoding,
  type SwitchDisplay,
  type VideoFrame as WireVideoFrame,
} from "./proto/session_pb.js";
import { AudioPlayer, type AudioState } from "./audio.js";
import { isRetryable, PeerConnector, SessionError, toSessionError, versionNumber } from "./connector.js";
import { parseServerKey } from "./crypto.js";
import { CursorStore, type CursorShape } from "./cursor.js";
import { Emitter } from "./emitter.js";
import { isModifierCode, KEYMAP, mapCode, peerOsFromPlatform } from "./keymap.js";
import { ConnType } from "./proto/rendezvous_pb.js";
import {
  DEFAULT_SETTINGS,
  type DisplayRect,
  type PeerSummary,
  type PermissionName,
  type ResolutionOption,
  type SessionEventMap,
  type SessionOptions,
  type SessionSettings,
  type SessionState,
  type SessionStats,
} from "./types.js";
import { probeCodecs, VideoPipeline, type Codec, type CodecSupport } from "./video.js";
import { inflateCapped } from "./zstd.js";

type OptInit = Exclude<MessageInitShape<typeof OptionMessageSchema>, OptionMessage>;

export { CLIENT_VERSION, SessionError } from "./connector.js";
const MAX_CLIPBOARD = 4 << 20;

export const MOUSE_TYPE = { move: 0, down: 1, up: 2, wheel: 3, trackpad: 4 } as const;
export const MOUSE_BUTTON = { left: 1, right: 2, middle: 4, back: 8, forward: 16 } as const;
export type MouseButtonName = keyof typeof MOUSE_BUTTON;

export interface KeyInput {
  /** KeyboardEvent.code */
  code: string;
  /** KeyboardEvent.key */
  key: string;
  down: boolean;
  repeat?: boolean;
  /** Lock-key state at the time of the event. */
  capsLock?: boolean;
  numLock?: boolean;
}

interface Modifiers {
  shift: boolean;
  ctrl: boolean;
  alt: boolean;
  meta: boolean;
}

export class Session {
  readonly peerId: string;
  private settingsValue: SessionSettings;
  private readonly events = new Emitter<SessionEventMap>();
  private stateValue: SessionState = "idle";
  private abort = new AbortController();
  private readonly link: PeerConnector;

  private codecSupport: CodecSupport = { decode: new Set(), decode444: new Set() };
  private video: VideoPipeline | null = null;
  private frameSink: ((frame: VideoFrame) => void) | null = null;
  private readonly audio = new AudioPlayer((state) => this.events.emit("audio", { state }));
  readonly cursors = new CursorStore();
  private currentCursor: CursorShape | null = null;

  private peerInfo: PeerSummary | null = null;
  private displayIndex = 0;
  private displays: DisplayRect[] = [];
  private resolutions: ResolutionOption[] = [];
  private peerEncoding: SupportedEncoding | null = null;
  private permissions: Record<PermissionName, boolean> = {
    keyboard: true,
    clipboard: true,
    audio: true,
    file: true,
    restart: true,
    recording: true,
    blockInput: true,
    privacyMode: true,
  };

  private lastDelay = 0;
  private targetKbps = 0;
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  private keyFrameRequested = 0;
  private mods: Modifiers = { shift: false, ctrl: false, alt: false, meta: false };
  private pressedCodes = new Set<string>();
  private scrollRest = { x: 0, y: 0 };
  private closedInfo: SessionEventMap["close"] | null = null;

  private readonly rendezvousUrl: string;

  /**
   * How the session is connected: the browser always goes through the relay
   * (WebSocket; TLS when wss://), end-to-end encrypted with the device.
   */
  get connection(): { rendezvousUrl: string; relayUrl: string; tls: boolean } {
    const relayUrl = this.link.relayUrl;
    return { rendezvousUrl: this.rendezvousUrl, relayUrl, tls: relayUrl.startsWith("wss:") };
  }

  constructor(opts: SessionOptions) {
    this.peerId = opts.peerId.replace(/\s+/g, "");
    if (!this.peerId) throw new SessionError("peer id is empty", "bad-config");
    this.settingsValue = { ...DEFAULT_SETTINGS, ...opts.settings };
    // fail early on a missing/bad key: we never connect unauthenticated
    if (!opts.hoen) parseServerKey(opts.server.key);
    this.rendezvousUrl = opts.server.rendezvousUrl;
    this.link = new PeerConnector(
      {
        peerId: this.peerId,
        server: opts.server,
        hoen: opts.hoen,
        connType: ConnType.DEFAULT_CONN,
        rememberedHash: opts.rememberedHash,
        myName: opts.myName,
        myId: opts.myId,
        clientVersion: opts.clientVersion,
        loginExtras: () => ({ videoAckRequired: true, option: this.loginOptions(this.settingsValue) }),
      },
      {
        state: (state) => this.setState(state),
        password: (wrong) => this.events.emit("password", { wrong }),
        twoFactor: (wrong) => this.events.emit("twoFactor", { wrong }),
        waitingForApproval: () => this.events.emit("waitingForApproval", {}),
        loggedIn: (pi) => this.onLoggedIn(pi),
        message: (msg) => this.onMessage(msg),
        failed: (info) => this.shutdown(info),
      },
    );
  }

  // ------------------------------------------------------------------ public

  get state(): SessionState {
    return this.stateValue;
  }

  get settings(): Readonly<SessionSettings> {
    return this.settingsValue;
  }

  get peer(): PeerSummary | null {
    return this.peerInfo;
  }

  get display(): DisplayRect | null {
    return this.displays[this.displayIndex] ?? null;
  }

  get cursor(): CursorShape | null {
    return this.currentCursor;
  }

  get permission(): Readonly<Record<PermissionName, boolean>> {
    return this.permissions;
  }

  /** True when keyboard/mouse input is currently allowed. */
  get canControl(): boolean {
    return this.stateValue === "connected" && !this.settingsValue.viewOnly && this.permissions.keyboard;
  }

  on<K extends keyof SessionEventMap>(type: K, fn: (ev: SessionEventMap[K]) => void): () => void {
    return this.events.on(type, fn);
  }

  /** Receives decoded frames; the sink owns each frame and must close() it. */
  setFrameSink(sink: ((frame: VideoFrame) => void) | null): void {
    this.frameSink = sink;
  }

  /**
   * Connects and logs in. Resolves once the session is streaming; while
   * waiting it may emit `password`, `twoFactor` or `waitingForApproval`.
   */
  async connect(): Promise<void> {
    if (this.stateValue !== "idle") throw new SessionError("connect() can only be called once", "state");
    try {
      this.codecSupport = await probeCodecs();
      await this.link.connect(this.abort.signal);
    } catch (e) {
      const err = toSessionError(e);
      this.shutdown({ reason: err.message, remote: false, retryable: isRetryable(err) });
      throw err;
    }
  }

  /** Answers a `password` event. */
  login(password: string): Promise<void> {
    return this.link.login(password);
  }

  /** Answers a `twoFactor` event. */
  submitTwoFactor(code: string): void {
    this.link.submitTwoFactor(code);
  }

  close(reason = "closed by user"): void {
    if (this.stateValue === "closed") return;
    if (this.link.isOpen) {
      try {
        this.send({ union: { case: "misc", value: { union: { case: "closeReason", value: reason } } } });
      } catch {
        /* ignore */
      }
    }
    this.shutdown({ reason, remote: false, retryable: false });
  }

  /** Changes settings; sends the corresponding option updates to the peer. */
  updateSettings(patch: Partial<SessionSettings>): void {
    const prev = this.settingsValue;
    const next = { ...prev, ...patch };
    this.settingsValue = next;
    if (this.stateValue !== "connected") return;
    const opt: OptInit = {};
    let changed = false;
    const yn = (v: boolean) => (v ? BoolOption.Yes : BoolOption.No);
    if (
      prev.imageQuality !== next.imageQuality ||
      (next.imageQuality === "custom" && (prev.customQuality !== next.customQuality || prev.customFps !== next.customFps))
    ) {
      Object.assign(opt, this.qualityOptions(next, false));
      changed = true;
    }
    if (prev.codec !== next.codec || prev.trueColor !== next.trueColor) {
      opt.supportedDecoding = this.supportedDecoding(next);
      changed = true;
    }
    const toggles: [keyof SessionSettings, keyof OptInit][] = [
      ["showRemoteCursor", "showRemoteCursor"],
      ["followRemoteCursor", "followRemoteCursor"],
      ["followRemoteWindow", "followRemoteWindow"],
      ["disableAudio", "disableAudio"],
      ["disableClipboard", "disableClipboard"],
      ["lockAfterSessionEnd", "lockAfterSessionEnd"],
    ];
    for (const [k, field] of toggles) {
      if (prev[k] !== next[k]) {
        (opt as Record<string, unknown>)[field] = yn(next[k] as boolean);
        changed = true;
      }
    }
    if (prev.viewOnly !== next.viewOnly) {
      opt.disableKeyboard = yn(next.viewOnly);
      opt.showRemoteCursor = yn(next.viewOnly || next.showRemoteCursor);
      opt.disableClipboard = yn(next.viewOnly || next.disableClipboard);
      if (next.viewOnly) this.releaseAllKeys();
      changed = true;
    }
    if (prev.showMyCursor !== next.showMyCursor) {
      opt.showMyCursor = yn(next.viewOnly && next.showMyCursor);
      changed = true;
    }
    if (prev.disableAudio !== next.disableAudio) this.audio.setMuted(next.disableAudio);
    if (changed) this.send({ union: { case: "misc", value: { union: { case: "option", value: opt } } } });
  }

  switchDisplay(index: number): void {
    if (!this.displays[index]) return;
    this.send({ union: { case: "misc", value: { union: { case: "switchDisplay", value: { display: index } } } } });
    this.send({ union: { case: "misc", value: { union: { case: "captureDisplays", value: { set: [index] } } } } });
  }

  /** Changes the remote display resolution (0x0 restores the original one). */
  changeResolution(width: number, height: number, display = this.displayIndex): void {
    const resolution = { width, height };
    if (versionNumber(this.peerInfo?.version ?? "") >= versionNumber("1.2.4")) {
      this.send({
        union: { case: "misc", value: { union: { case: "changeDisplayResolution", value: { display, resolution } } } },
      });
    } else {
      this.send({ union: { case: "misc", value: { union: { case: "changeResolution", value: resolution } } } });
    }
  }

  refreshVideo(): void {
    this.requestKeyFrame(true);
  }

  restartRemote(): void {
    this.send({ union: { case: "misc", value: { union: { case: "restartRemoteDevice", value: true } } } });
  }

  ctrlAltDel(): void {
    if (!this.canControl) return;
    if (this.peerInfo?.os === "windows") {
      this.sendKeyEvent({ union: { case: "controlKey", value: ControlKey.CtrlAltDel }, down: true, mode: KeyboardMode.Legacy });
    } else {
      this.sendKeyEvent({
        union: { case: "controlKey", value: ControlKey.Delete },
        modifiers: [ControlKey.Alt, ControlKey.Control],
        press: true,
        mode: KeyboardMode.Legacy,
      });
    }
  }

  lockScreen(): void {
    if (!this.canControl) return;
    this.sendKeyEvent({ union: { case: "controlKey", value: ControlKey.LockScreen }, down: true, mode: KeyboardMode.Legacy });
  }

  setPrivacyMode(on: boolean, implKey = ""): void {
    this.send({ union: { case: "misc", value: { union: { case: "togglePrivacyMode", value: { implKey, on } } } } });
  }

  setBlockInput(on: boolean): void {
    this.send({
      union: { case: "misc", value: { union: { case: "option", value: { blockInput: on ? BoolOption.Yes : BoolOption.No } } } },
    });
  }

  /** Switches the Windows session (RDP/multi-user hosts). */
  selectWindowsSession(sid: number): void {
    this.send({ union: { case: "misc", value: { union: { case: "selectedSid", value: sid } } } });
  }

  sendChat(text: string): void {
    if (!text) return;
    this.send({ union: { case: "misc", value: { union: { case: "chatMessage", value: { text } } } } });
  }

  /** Puts text on the remote clipboard. */
  sendClipboard(text: string): void {
    if (!this.canControl || this.settingsValue.disableClipboard || !this.permissions.clipboard) return;
    const content = new TextEncoder().encode(text);
    if (content.length > MAX_CLIPBOARD) return;
    this.send({ union: { case: "clipboard", value: { content, format: ClipboardFormat.Text } } });
  }

  /** Types text on the remote side (IME / soft keyboard / paste-as-typing). */
  typeText(text: string): void {
    if (!this.canControl || !text) return;
    this.sendKeyEvent({ union: { case: "seq", value: text }, down: true, mode: KeyboardMode.Translate });
  }

  // ---------------------------------------------------------------- pointer

  /** Absolute pointer position in remote screen coordinates. */
  mouseMove(x: number, y: number): void {
    if (!this.canPoint()) return;
    this.sendMouse(MOUSE_TYPE.move, Math.round(x), Math.round(y));
  }

  mouseButton(button: MouseButtonName, down: boolean, x: number, y: number): void {
    if (!this.canControl) return;
    const mask = (MOUSE_BUTTON[button] << 3) | (down ? MOUSE_TYPE.down : MOUSE_TYPE.up);
    this.sendMouse(mask, Math.round(x), Math.round(y));
  }

  /** Discrete wheel steps; positive y scrolls up (towards the top). */
  wheel(stepsX: number, stepsY: number): void {
    if (!this.canControl || (!stepsX && !stepsY)) return;
    this.sendMouse(MOUSE_TYPE.wheel, Math.round(stepsX), Math.round(stepsY));
  }

  /** Smooth (pixel) scrolling as from a touchpad; positive y scrolls up. */
  trackpadScroll(dx: number, dy: number): void {
    if (!this.canControl) return;
    let x: number;
    let y: number;
    if (this.peerInfo?.os === "linux") {
      // Linux peers scroll in wheel-sized units; accumulate the fraction.
      this.scrollRest.x += dx * 0.06;
      this.scrollRest.y += dy * 0.06;
      x = Math.trunc(this.scrollRest.x);
      y = Math.trunc(this.scrollRest.y);
      this.scrollRest.x -= x;
      this.scrollRest.y -= y;
    } else {
      x = Math.trunc(dx);
      y = Math.trunc(dy);
      if (!x && !y) {
        if (Math.abs(dx) > Math.abs(dy)) x = dx > 0.1 ? 1 : dx < -0.1 ? -1 : 0;
        else y = dy > 0.1 ? 1 : dy < -0.1 ? -1 : 0;
      }
    }
    if (x || y) this.sendMouse(MOUSE_TYPE.trackpad, x, y);
  }

  // --------------------------------------------------------------- keyboard

  key(ev: KeyInput): void {
    if (!this.canControl) return;
    this.keyInternal(ev);
  }

  /**
   * Presses the remote side's paste shortcut (Cmd+V on macOS, Ctrl+V
   * elsewhere), first releasing the other command modifier if the local
   * shortcut left it down there (a Mac's Cmd is the Windows key remotely).
   */
  pasteShortcut(): void {
    if (!this.canControl) return;
    const mac = this.peerInfo?.os === "macos";
    const want = mac ? ["MetaLeft", "MetaRight"] : ["ControlLeft", "ControlRight"];
    const other = mac ? ["ControlLeft", "ControlRight"] : ["MetaLeft", "MetaRight"];
    const name = (c: string) => (c.startsWith("Meta") ? "Meta" : "Control");
    for (const c of other) if (this.pressedCodes.has(c)) this.keyInternal({ code: c, key: name(c), down: false }, false);
    const held = want.some((c) => this.pressedCodes.has(c));
    if (!held) this.keyInternal({ code: want[0]!, key: name(want[0]!), down: true }, false);
    this.keyInternal({ code: "KeyV", key: "v", down: true }, false);
    this.keyInternal({ code: "KeyV", key: "v", down: false }, false);
    if (!held) this.keyInternal({ code: want[0]!, key: name(want[0]!), down: false }, false);
  }

  /** swap: apply the swapCtrlMeta setting (false for codes already meant for the remote side). */
  private keyInternal(ev: KeyInput, swap = true): void {
    let code = ev.code;
    if (swap && this.settingsValue.swapCtrlMeta) code = swapCtrlMetaCode(code);
    this.trackModifier(code, ev.down);
    if (ev.down) this.pressedCodes.add(code);
    else this.pressedCodes.delete(code);

    const os = this.peerInfo?.os ?? "unknown";
    let mode = this.settingsValue.keyboardMode;
    if (os === "android" || os === "ios" || os === "unknown") mode = "legacy";

    if (mode === "translate" && ev.down && isPrintable(ev.key) && !this.mods.ctrl && !this.mods.alt && !this.mods.meta) {
      this.sendKeyEvent({ union: { case: "seq", value: ev.key }, down: true, mode: KeyboardMode.Translate });
      return;
    }
    if (mode === "map" || mode === "translate") {
      if (os === "windows" && code === "Pause") {
        this.sendKeyEvent({
          union: { case: "controlKey", value: ControlKey.Pause },
          down: ev.down,
          mode: KeyboardMode.Legacy,
          modifiers: this.legacyModifiers(),
        });
        return;
      }
      const chr = mapCode(code, os);
      if (chr !== undefined) {
        this.sendKeyEvent({
          union: { case: "chr", value: chr },
          down: ev.down,
          mode: mode === "map" ? KeyboardMode.Map : KeyboardMode.Translate,
        });
        return;
      }
    }
    this.sendLegacyKey(code, ev.key, ev.down);
  }

  /** Releases every key we think is held (on blur, view-only, etc.). */
  releaseAllKeys(): void {
    const codes = [...this.pressedCodes];
    this.pressedCodes.clear();
    for (const code of codes) this.keyInternal({ code, key: "", down: false });
    this.mods = { shift: false, ctrl: false, alt: false, meta: false };
  }

  /** Remote audio state; "blocked" needs a user gesture (resumeAudio). */
  get audioState(): AudioState {
    return this.audio.state;
  }

  /** Must be called from a user gesture before audio can play. */
  resumeAudio(): void {
    this.audio.resume();
  }

  setVolume(v: number): void {
    this.audio.setVolume(v);
  }

  // ---------------------------------------------------------------- private

  private setState(state: SessionState): void {
    if (this.stateValue === state) return;
    this.stateValue = state;
    this.events.emit("state", { state });
  }

  private canPoint(): boolean {
    if (this.stateValue !== "connected") return false;
    if (this.settingsValue.viewOnly) return this.settingsValue.showMyCursor;
    return this.permissions.keyboard;
  }

  private send(init: MessageInitShape<typeof MessageSchema>): void {
    this.link.send(init);
  }

  private shutdown(info: SessionEventMap["close"]): void {
    if (this.stateValue === "closed") return;
    this.closedInfo = info;
    this.abort.abort();
    if (this.statsTimer) clearInterval(this.statsTimer);
    this.statsTimer = null;
    this.link.close(info.reason);
    this.video?.close();
    this.video = null;
    this.audio.close();
    this.cursors.clear();
    this.setState("closed");
    this.events.emit("close", info);
  }

  /** Why the session closed, once it has. */
  get closeInfo(): SessionEventMap["close"] | null {
    return this.closedInfo;
  }

  private onMessage(msg: Message): void {
    const u = msg.union;
    switch (u.case) {
      case "testDelay":
        if (!u.value.fromClient) {
          this.lastDelay = u.value.lastDelay;
          this.targetKbps = u.value.targetBitrate;
          this.send({ union: { case: "testDelay", value: u.value } });
        }
        return;
      case "videoFrame":
        this.onVideo(u.value);
        return;
      case "cursorData":
        try {
          this.currentCursor = this.cursors.decode(u.value);
        } catch {
          return;
        }
        this.events.emit("cursorShape", { id: u.value.id });
        return;
      case "cursorId": {
        const shape = this.cursors.get(u.value);
        if (shape) {
          this.currentCursor = shape;
          this.events.emit("cursorShape", { id: u.value });
        }
        return;
      }
      case "cursorPosition":
        this.events.emit("cursorPosition", { x: u.value.x, y: u.value.y });
        return;
      case "clipboard":
        this.onClipboard([u.value]);
        return;
      case "multiClipboards":
        this.onClipboard(u.value.clipboards);
        return;
      case "audioFrame":
        if (!this.settingsValue.disableAudio) this.audio.push(u.value.data);
        return;
      case "messageBox": {
        const m = u.value;
        this.events.emit("message", { type: m.msgtype, title: m.title, text: m.text, link: m.link });
        return;
      }
      case "peerInfo":
        this.applyPeerInfo(u.value);
        this.events.emit("peer", { peer: this.peerInfo! });
        return;
      case "misc":
        this.onMisc(u.value);
        return;
      default:
        return;
    }
  }

  private onLoggedIn(pi: PeerInfo): void {
    this.applyPeerInfo(pi);
    this.video = new VideoPipeline(
      (frame) => {
        if (this.frameSink) this.frameSink(frame);
        else frame.close();
      },
      () => this.requestKeyFrame(false),
      (e) => console.warn("rdweb:", e.message),
    );
    this.audio.setMuted(this.settingsValue.disableAudio);
    this.setState("connected");
    this.statsTimer = setInterval(() => this.emitStats(), 1000);
    this.events.emit("connected", { peer: this.peerInfo!, rememberedHash: this.link.rememberedHash });
    this.emitDisplay();
  }

  private applyPeerInfo(pi: PeerInfo): void {
    this.peerEncoding = pi.encoding ?? this.peerEncoding;
    if (pi.displays.length) {
      this.displays = pi.displays.map((d, i) => ({
        index: i,
        x: d.x,
        y: d.y,
        width: d.width,
        height: d.height,
        name: d.name,
        online: d.online,
        cursorEmbedded: d.cursorEmbedded,
        originalWidth: d.originalResolution?.width ?? 0,
        originalHeight: d.originalResolution?.height ?? 0,
        scale: d.scale || 1,
      }));
      this.displayIndex = Math.min(Math.max(0, pi.currentDisplay), this.displays.length - 1);
    }
    if (pi.resolutions) this.resolutions = pi.resolutions.resolutions.map((r) => ({ width: r.width, height: r.height }));
    let privacy = pi.features?.privacyMode ?? false;
    if (pi.platformAdditions) {
      try {
        const extra = JSON.parse(pi.platformAdditions) as Record<string, unknown>;
        if (Array.isArray(extra["supported_privacy_mode_impl"]) && extra["supported_privacy_mode_impl"].length) {
          privacy = true;
        }
      } catch {
        /* ignore */
      }
    }
    const os = peerOsFromPlatform(pi.platform);
    this.peerInfo = {
      id: this.peerId,
      username: pi.username,
      hostname: pi.hostname,
      platform: pi.platform,
      os,
      version: pi.version,
      displays: this.displays,
      currentDisplay: this.displayIndex,
      resolutions: this.resolutions,
      codecs: this.usableCodecs(false),
      codecs444: this.usableCodecs(true),
      privacyModeSupported: privacy,
      sasEnabled: pi.sasEnabled,
      windowsSessions: (pi.windowsSessions?.sessions ?? []).map((s) => ({ sid: s.sid, name: s.name })),
      currentWindowsSession: pi.windowsSessions?.currentSid ?? 0,
    };
  }

  private usableCodecs(i444: boolean): Codec[] {
    const enc = this.peerEncoding;
    const peerHas: Record<Codec, boolean> = {
      vp9: true,
      vp8: enc?.vp8 ?? false,
      av1: enc?.av1 ?? false,
      h264: enc?.h264 ?? false,
      h265: enc?.h265 ?? false,
    };
    const peer444 = enc?.i444;
    const browser = i444 ? this.codecSupport.decode444 : this.codecSupport.decode;
    return (["vp8", "vp9", "av1", "h264", "h265"] as Codec[]).filter((c) => {
      if (!browser.has(c)) return false;
      if (!i444) return peerHas[c];
      return !!peer444 && (peer444 as unknown as Record<string, boolean>)[c] === true;
    });
  }

  private emitDisplay(): void {
    const d = this.display;
    if (d) this.events.emit("display", { display: d, resolutions: this.resolutions });
  }

  private onMisc(misc: Extract<Message["union"], { case: "misc" }>["value"]): void {
    const u = misc.union;
    switch (u.case) {
      case "audioFormat":
        this.audio.configure(u.value.sampleRate, u.value.channels);
        return;
      case "chatMessage":
        this.events.emit("chat", { text: u.value.text });
        return;
      case "permissionInfo":
        this.onPermission(u.value.permission, u.value.enabled);
        return;
      case "switchDisplay":
        this.onSwitchDisplay(u.value);
        return;
      case "closeReason": {
        this.link.rejectLogin(new SessionError(u.value, "remote-closed"));
        this.shutdown({ reason: u.value || "closed by the remote side", remote: true, retryable: false });
        return;
      }
      case "backNotification": {
        const n = u.value;
        if (n.union.case === "privacyModeState") {
          const on = n.union.value === PrivacyState.PrvOnSucceeded || n.union.value === PrivacyState.PrvOnByOther;
          this.events.emit("privacyMode", { on, message: privacyMessage(n.union.value, n.details) });
        } else if (n.union.case === "blockInputState") {
          const on = n.union.value === BlockState.BlkOnSucceeded;
          this.events.emit("blockInput", { on, message: blockMessage(n.union.value) });
        }
        return;
      }
      case "uac":
        if (u.value) {
          this.events.emit("message", {
            type: "info",
            title: "UAC",
            text: "The remote side is showing a UAC prompt; input may be blocked until it is answered.",
            link: "",
          });
        }
        return;
      case "foregroundWindowElevated":
        if (u.value) {
          this.events.emit("message", {
            type: "info",
            title: "Elevated window",
            text: "The focused remote window runs with higher privileges and may ignore input.",
            link: "",
          });
        }
        return;
      case "supportedEncoding":
        this.peerEncoding = u.value;
        if (this.peerInfo) {
          this.peerInfo = { ...this.peerInfo, codecs: this.usableCodecs(false), codecs444: this.usableCodecs(true) };
          this.events.emit("peer", { peer: this.peerInfo });
        }
        return;
      case "followCurrentDisplay":
        if (this.settingsValue.followRemoteWindow && u.value !== this.displayIndex) this.switchDisplay(u.value);
        return;
      default:
        return;
    }
  }

  private onPermission(p: Permission, enabled: boolean): void {
    const names: Partial<Record<Permission, PermissionName>> = {
      [Permission.Keyboard]: "keyboard",
      [Permission.Clipboard]: "clipboard",
      [Permission.Audio]: "audio",
      [Permission.File]: "file",
      [Permission.Restart]: "restart",
      [Permission.Recording]: "recording",
      [Permission.BlockInput]: "blockInput",
      [Permission.PrivacyMode]: "privacyMode",
    };
    const name = names[p];
    if (!name) return;
    this.permissions = { ...this.permissions, [name]: enabled };
    if (name === "keyboard" && !enabled) this.releaseAllKeys();
    this.events.emit("permission", { name, enabled });
  }

  private onSwitchDisplay(s: SwitchDisplay): void {
    const prev = this.displays[s.display];
    const rect: DisplayRect = {
      index: s.display,
      x: s.x,
      y: s.y,
      width: s.width || prev?.width || 0,
      height: s.height || prev?.height || 0,
      name: prev?.name ?? "",
      online: prev?.online ?? true,
      cursorEmbedded: s.cursorEmbedded,
      originalWidth: s.originalResolution?.width ?? prev?.originalWidth ?? 0,
      originalHeight: s.originalResolution?.height ?? prev?.originalHeight ?? 0,
      scale: prev?.scale ?? 1,
    };
    this.displays = [...this.displays];
    this.displays[s.display] = rect;
    this.displayIndex = s.display;
    if (s.resolutions) this.resolutions = s.resolutions.resolutions.map((r) => ({ width: r.width, height: r.height }));
    if (this.peerInfo) {
      this.peerInfo = { ...this.peerInfo, displays: this.displays, currentDisplay: s.display, resolutions: this.resolutions };
    }
    this.video?.reset();
    this.emitDisplay();
  }

  private onVideo(vf: WireVideoFrame): void {
    // Ack first: the peer paces capture on these.
    this.send({ union: { case: "misc", value: { union: { case: "videoReceived", value: true } } } });
    if (!this.video) return;
    if (vf.display !== this.displayIndex && this.displays.length > 1) return;
    const u = vf.union;
    let codec: Codec;
    switch (u.case) {
      case "vp9s":
        codec = "vp9";
        break;
      case "vp8s":
        codec = "vp8";
        break;
      case "av1s":
        codec = "av1";
        break;
      case "h264s":
        codec = "h264";
        break;
      case "h265s":
        codec = "h265";
        break;
      default:
        return; // raw RGB/YUV frames are not supported in the browser
    }
    const chroma444 = this.settingsValue.trueColor && this.codecSupport.decode444.has(codec);
    for (const f of u.value.frames) this.video.push(codec, f.data, f.key, chroma444 && is444Frame(codec, f.data));
  }

  private requestKeyFrame(force: boolean): void {
    const now = performance.now();
    if (!force && now - this.keyFrameRequested < 1000) return;
    this.keyFrameRequested = now;
    if (versionNumber(this.peerInfo?.version ?? "") >= versionNumber("1.2.4")) {
      this.send({ union: { case: "misc", value: { union: { case: "refreshVideoDisplay", value: this.displayIndex } } } });
    } else {
      this.send({ union: { case: "misc", value: { union: { case: "refreshVideo", value: true } } } });
    }
  }

  private onClipboard(items: Clipboard[]): void {
    if (this.settingsValue.disableClipboard || this.settingsValue.viewOnly) return;
    for (const c of items) {
      if (c.format !== ClipboardFormat.Text) continue;
      try {
        const bytes = c.compress ? inflateCapped(c.content, MAX_CLIPBOARD) : c.content;
        if (bytes.length > MAX_CLIPBOARD) continue;
        this.events.emit("clipboard", { text: new TextDecoder().decode(bytes) });
      } catch {
        /* ignore malformed clipboard */
      }
      return;
    }
  }

  private emitStats(): void {
    const v = this.video?.stats();
    const stats: SessionStats = {
      codec: v?.codec ?? null,
      chroma444: v?.chroma444 ?? false,
      width: v?.width ?? 0,
      height: v?.height ?? 0,
      fps: v?.fps ?? 0,
      kbps: v?.kbps ?? 0,
      decoded: v?.decoded ?? 0,
      received: v?.received ?? 0,
      dropped: v?.dropped ?? 0,
      delayMs: this.lastDelay,
      targetKbps: this.targetKbps,
    };
    this.events.emit("stats", stats);
  }

  private loginOptions(s: SessionSettings): OptInit {
    const yes = BoolOption.Yes;
    const opt: OptInit = {
      ...this.qualityOptions(s, true),
      supportedDecoding: this.supportedDecoding(s),
    };
    if (s.viewOnly) {
      opt.disableKeyboard = yes;
      opt.showRemoteCursor = yes;
      opt.disableClipboard = yes;
      if (s.showMyCursor) opt.showMyCursor = yes;
    } else {
      if (s.showRemoteCursor) opt.showRemoteCursor = yes;
      if (s.disableClipboard) opt.disableClipboard = yes;
      if (s.lockAfterSessionEnd) opt.lockAfterSessionEnd = yes;
    }
    if (s.followRemoteCursor) opt.followRemoteCursor = yes;
    if (s.followRemoteWindow) opt.followRemoteWindow = yes;
    if (s.disableAudio) opt.disableAudio = yes;
    return opt;
  }

  private qualityOptions(s: SessionSettings, atLogin: boolean): OptInit {
    switch (s.imageQuality) {
      case "best":
        return { imageQuality: ImageQuality.Best, customFps: atLogin ? 0 : 30 };
      case "low":
        return { imageQuality: ImageQuality.Low, customFps: atLogin ? 0 : 30 };
      case "balanced":
        return atLogin ? {} : { imageQuality: ImageQuality.Balanced, customFps: 30 };
      case "custom": {
        const q = Math.round(Math.min(2000, Math.max(10, s.customQuality)));
        const fps = Math.round(Math.min(120, Math.max(5, s.customFps)));
        return { customImageQuality: q << 8, customFps: fps };
      }
    }
  }

  private supportedDecoding(s: SessionSettings) {
    return decodingOffer(this.codecSupport, s);
  }

  private sendMouse(mask: number, x: number, y: number): void {
    this.send({ union: { case: "mouseEvent", value: { mask, x, y, modifiers: this.legacyModifiers() } } });
  }

  private sendKeyEvent(ev: MessageInitShape<typeof KeyEventSchema>): void {
    this.send({ union: { case: "keyEvent", value: ev } });
  }

  private sendLegacyKey(code: string, key: string, down: boolean): void {
    const k = KEYMAP[code];
    const modifiers = this.legacyModifiers();
    if (k?.ctl !== undefined) {
      if (isModifierCode(code)) {
        this.sendKeyEvent({ union: { case: "controlKey", value: k.ctl }, down, mode: KeyboardMode.Legacy });
      } else {
        this.sendKeyEvent({ union: { case: "controlKey", value: k.ctl }, down, modifiers, mode: KeyboardMode.Legacy });
      }
      return;
    }
    const ch = legacyChar(code, key);
    if (ch === undefined) return;
    this.sendKeyEvent({ union: { case: "chr", value: ch }, down, modifiers, mode: KeyboardMode.Legacy });
  }

  private legacyModifiers(): ControlKey[] {
    const m: ControlKey[] = [];
    if (this.mods.alt) m.push(ControlKey.Alt);
    if (this.mods.ctrl) m.push(ControlKey.Control);
    if (this.mods.shift) m.push(ControlKey.Shift);
    if (this.mods.meta) m.push(ControlKey.Meta);
    return m;
  }

  private trackModifier(code: string, down: boolean): void {
    if (code.startsWith("Shift")) this.mods.shift = down;
    else if (code.startsWith("Control")) this.mods.ctrl = down;
    else if (code.startsWith("Alt")) this.mods.alt = down;
    else if (code.startsWith("Meta")) this.mods.meta = down;
  }
}

function isPrintable(key: string): boolean {
  return [...key].length === 1;
}

/** For legacy mode: the unshifted character a printable key produces. */
function legacyChar(code: string, key: string): number | undefined {
  const m = /^Key([A-Z])$/.exec(code);
  if (m) return m[1]!.toLowerCase().charCodeAt(0);
  const d = /^Digit(\d)$/.exec(code);
  if (d) return d[1]!.charCodeAt(0);
  if ([...key].length === 1) return key.toLowerCase().codePointAt(0);
  return undefined;
}

function swapCtrlMetaCode(code: string): string {
  switch (code) {
    case "ControlLeft":
      return "MetaLeft";
    case "ControlRight":
      return "MetaRight";
    case "MetaLeft":
      return "ControlLeft";
    case "MetaRight":
      return "ControlRight";
    default:
      return code;
  }
}

/**
 * Whether an encoded frame uses 4:4:4. VP9 carries it in the uncompressed
 * header profile bits; AV1 in the sequence header. We only need this to pick
 * the decoder configuration, and getting it wrong just costs a reconfigure,
 * so a cheap check is enough.
 */
function is444Frame(codec: Codec, data: Uint8Array): boolean {
  if (codec === "vp9" && data.length > 0) {
    const b = data[0]!;
    // frame_marker(2) profile_low_bit(1) profile_high_bit(1)
    const profile = ((b >> 5) & 1) | (((b >> 4) & 1) << 1);
    return profile === 1 || profile === 3;
  }
  // AV1: assume the negotiated chroma
  return codec === "av1";
}

function privacyMessage(s: PrivacyState, details: string): string {
  switch (s) {
    case PrivacyState.PrvOnSucceeded:
      return "Privacy mode is on";
    case PrivacyState.PrvOnByOther:
      return "Privacy mode was turned on by another session";
    case PrivacyState.PrvNotSupported:
      return "Privacy mode is not supported on the remote device";
    case PrivacyState.PrvOnFailedDenied:
      return "Privacy mode was denied";
    case PrivacyState.PrvOnFailedPlugin:
      return "Privacy mode needs a plugin that is not installed";
    case PrivacyState.PrvOnFailed:
      return details ? `Privacy mode failed: ${details}` : "Privacy mode failed";
    case PrivacyState.PrvOffSucceeded:
      return "Privacy mode is off";
    case PrivacyState.PrvOffByPeer:
      return "Privacy mode was turned off on the remote device";
    case PrivacyState.PrvOffFailed:
      return "Could not turn privacy mode off";
    default:
      return details;
  }
}

function blockMessage(s: BlockState): string {
  switch (s) {
    case BlockState.BlkOnSucceeded:
      return "Remote input is blocked";
    case BlockState.BlkOnFailed:
      return "Could not block remote input";
    case BlockState.BlkOffSucceeded:
      return "Remote input is unblocked";
    case BlockState.BlkOffFailed:
      return "Could not unblock remote input";
    default:
      return "";
  }
}

/**
 * What the browser tells the peer it can decode. H.265 only when chosen
 * explicitly: some browsers report it supported and then return cropped
 * frames (Edge on Windows decodes a 3420x2214 stream into its top-left
 * 1920x1080), and "auto" would let the peer pick it for being the cheapest.
 */
export function decodingOffer(support: CodecSupport, s: SessionSettings) {
  const dec = support.decode;
  const d444 = support.decode444;
  const prefer: Record<SessionSettings["codec"], PreferCodec> = {
    auto: PreferCodec.Auto,
    vp8: PreferCodec.VP8,
    vp9: PreferCodec.VP9,
    av1: PreferCodec.AV1,
    h264: PreferCodec.H264,
    h265: PreferCodec.H265,
  };
  return {
    abilityVp8: dec.has("vp8") ? 1 : 0,
    abilityVp9: dec.has("vp9") ? 1 : 0,
    abilityAv1: dec.has("av1") ? 1 : 0,
    abilityH264: dec.has("h264") ? 1 : 0,
    abilityH265: dec.has("h265") && s.codec === "h265" ? 1 : 0,
    prefer: prefer[s.codec],
    i444: { vp9: d444.has("vp9"), av1: d444.has("av1") },
    preferChroma: s.trueColor ? Chroma.I444 : Chroma.I420,
  };
}
