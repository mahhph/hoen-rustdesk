// DOM front end for a Session: renders frames, draws the remote cursor and
// turns mouse, touch and keyboard input into remote input.

import type { CursorShape } from "./cursor.js";
import { rgbaToDataUrl } from "./cursor.js";
import type { MouseButtonName, Session } from "./session.js";
import type { DisplayRect } from "./types.js";

export type ScaleMode = "fit" | "original" | "stretch";
/**
 * mouse    - a real pointer; the remote cursor follows it 1:1
 * trackpad - touch screen acts like a laptop touchpad (relative cursor)
 * touch    - touch screen taps/drags where you touch (absolute)
 */
export type InputMode = "mouse" | "trackpad" | "touch";

export interface ViewerOptions {
  scaleMode?: ScaleMode;
  /** Defaults to "trackpad" on touch-first devices and "mouse" otherwise. */
  inputMode?: InputMode;
  /** Scale the remote cursor with the view instead of showing it at native size. */
  zoomCursor?: boolean;
  /** Touchpad-mode pointer speed multiplier. */
  trackpadSpeed?: number;
}

export interface ViewerEventMap {
  /** Viewer-level zoom changed (pinch). */
  zoom: { zoom: number };
  /** The remote clipboard changed but we could not write the local one. */
  clipboardBlocked: { text: string };
  /** Keyboard capture state (focus) changed. */
  focus: { focused: boolean };
  /**
   * Files were pasted (Ctrl/Cmd+V) or dropped onto the screen; the host can
   * upload them. Handle a drop synchronously: its DataTransfer expires after the event.
   */
  files: { dataTransfer: DataTransfer };
}

const BUTTONS: Record<number, MouseButtonName> = { 0: "left", 1: "middle", 2: "right", 3: "back", 4: "forward" };
const TAP_MAX_MS = 250;
const TAP_SLOP = 10;
const LONG_PRESS_MS = 550;
const MAX_ZOOM = 6;

let styleInjected = false;
function injectStyle(): void {
  if (styleInjected || typeof document === "undefined") return;
  styleInjected = true;
  const css = `
.rdweb-root{position:relative;overflow:hidden;outline:none;background:#000;touch-action:none;user-select:none;-webkit-user-select:none;-webkit-touch-callout:none;-webkit-tap-highlight-color:transparent}
.rdweb-root[data-scale=original][data-input=mouse]{overflow:auto}
.rdweb-surface{position:absolute;left:0;top:0;transform-origin:0 0}
.rdweb-canvas{display:block;width:100%;height:100%;image-rendering:auto}
.rdweb-cursor{position:absolute;left:0;top:0;pointer-events:none;background-repeat:no-repeat;background-size:100% 100%;will-change:transform;display:none;z-index:2}
.rdweb-ime{position:absolute;left:0;bottom:0;width:1px;height:1px;opacity:0;border:0;padding:0;margin:0;resize:none;font-size:16px;color:transparent;background:transparent;caret-color:transparent;z-index:-1}
`;
  const el = document.createElement("style");
  el.dataset["rdweb"] = "";
  el.textContent = css;
  document.head.appendChild(el);
}

interface TouchPoint {
  id: number;
  x: number;
  y: number;
  startX: number;
  startY: number;
  t0: number;
}

export class Viewer {
  readonly root: HTMLDivElement;
  readonly canvas: HTMLCanvasElement;
  private readonly surface: HTMLDivElement;
  private readonly cursorEl: HTMLDivElement;
  private readonly ime: HTMLTextAreaElement;
  private softKeyHandler: ((input: string | { code: string; key: string }) => boolean) | null = null;
  private readonly ctx: CanvasRenderingContext2D;
  private readonly unsub: (() => void)[] = [];
  private readonly ro: ResizeObserver;
  private readonly listeners = new Map<keyof ViewerEventMap, Set<(ev: never) => void>>();

  private scaleMode: ScaleMode;
  private inputMode: InputMode;
  private zoomCursor: boolean;
  private trackpadSpeed: number;

  private pending: VideoFrame | null = null;
  private raf = 0;
  private videoW = 0;
  private videoH = 0;
  /** Base layout (before user zoom), CSS px relative to root. */
  private baseX = 0;
  private baseY = 0;
  private baseW = 0;
  private baseH = 0;
  /** User zoom and pan (touch modes). */
  private zoom = 1;
  private panX = 0;
  private panY = 0;

  /** Remote cursor position (remote screen coordinates). */
  private curX = 0;
  private curY = 0;
  private haveCursorPos = false;
  private cursorCssCache = new Map<string, string>();

  private touches = new Map<number, TouchPoint>();
  private gesture: "none" | "move" | "drag" | "pinch" | "scroll" | "twoFingerTap" = "none";
  private longPressTimer: ReturnType<typeof setTimeout> | null = null;
  private lastTapAt = 0;
  private pinchStart = { dist: 0, zoom: 1, midX: 0, midY: 0, panX: 0, panY: 0 };
  private scrollAcc = { x: 0, y: 0 };
  /** A Ctrl/Cmd+V waiting for the browser's paste event. */
  private pendingPaste: { timer: ReturnType<typeof setTimeout>; upSeen: boolean } | null = null;
  /** The V of a handled paste is still down locally: drop its keyup. */
  private swallowVUp = false;
  private heldButtons = new Set<MouseButtonName>();
  private destroyed = false;

  constructor(
    container: HTMLElement,
    private readonly session: Session,
    opts: ViewerOptions = {},
  ) {
    injectStyle();
    this.scaleMode = opts.scaleMode ?? "fit";
    this.inputMode = opts.inputMode ?? (isTouchFirst() ? "trackpad" : "mouse");
    this.zoomCursor = opts.zoomCursor ?? false;
    this.trackpadSpeed = opts.trackpadSpeed ?? 1.4;

    this.root = document.createElement("div");
    this.root.className = "rdweb-root";
    this.root.tabIndex = 0;
    this.root.style.width = "100%";
    this.root.style.height = "100%";
    this.root.dataset["scale"] = this.scaleMode;
    this.root.dataset["input"] = this.inputMode;

    this.surface = document.createElement("div");
    this.surface.className = "rdweb-surface";
    this.canvas = document.createElement("canvas");
    this.canvas.className = "rdweb-canvas";
    this.canvas.width = 16;
    this.canvas.height = 9;
    this.cursorEl = document.createElement("div");
    this.cursorEl.className = "rdweb-cursor";
    this.ime = document.createElement("textarea");
    this.ime.className = "rdweb-ime";
    this.ime.autocapitalize = "off";
    this.ime.autocomplete = "off";
    this.ime.spellcheck = false;
    this.ime.setAttribute("autocorrect", "off");
    this.ime.setAttribute("aria-label", "Remote keyboard input");
    this.ime.inputMode = "text";

    this.surface.append(this.canvas, this.cursorEl);
    this.root.append(this.surface, this.ime);
    container.appendChild(this.root);

    this.ctx = this.canvas.getContext("2d", { alpha: false, desynchronized: true })!;
    this.ctx.fillStyle = "#000";

    session.setFrameSink((f) => this.onFrame(f));
    this.unsub.push(
      session.on("display", ({ display }) => this.onDisplay(display)),
      session.on("cursorShape", () => this.applyCursorShape()),
      session.on("cursorPosition", ({ x, y }) => {
        this.curX = x;
        this.curY = y;
        this.haveCursorPos = true;
        this.positionCursor();
      }),
      session.on("clipboard", ({ text }) => void this.writeLocalClipboard(text)),
      session.on("close", () => this.releaseInput()),
    );

    this.ro = new ResizeObserver(() => this.layout());
    this.ro.observe(this.root);
    this.bindInput();
    this.layout();
    this.applyCursorShape();
  }

  // ------------------------------------------------------------------ public

  on<K extends keyof ViewerEventMap>(type: K, fn: (ev: ViewerEventMap[K]) => void): () => void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(fn as (ev: never) => void);
    return () => set!.delete(fn as (ev: never) => void);
  }

  getScaleMode(): ScaleMode {
    return this.scaleMode;
  }

  setScaleMode(mode: ScaleMode): void {
    this.scaleMode = mode;
    this.root.dataset["scale"] = mode;
    this.resetZoom();
    if (mode === "original" && this.inputMode !== "mouse") {
      // touch screens: "original" is a zoomed fit view (1 remote px = 1 device px)
      const dpr = window.devicePixelRatio || 1;
      const z = this.remoteSize().w / dpr / (this.baseW || 1);
      if (z > 1) {
        this.zoom = Math.min(MAX_ZOOM, z);
        this.layout();
        this.emit("zoom", { zoom: this.zoom });
      }
    }
  }

  getInputMode(): InputMode {
    return this.inputMode;
  }

  setInputMode(mode: InputMode): void {
    this.inputMode = mode;
    this.root.dataset["input"] = mode;
    if (mode !== "mouse" && !this.haveCursorPos) this.centerCursor();
    this.layout();
    this.cancelGesture();
    this.applyCursorShape();
  }

  setZoomCursor(on: boolean): void {
    this.zoomCursor = on;
    this.cursorCssCache.clear();
    this.applyCursorShape();
  }

  getZoom(): number {
    return this.zoom;
  }

  resetZoom(): void {
    this.zoom = 1;
    this.panX = this.panY = 0;
    this.layout();
    this.emit("zoom", { zoom: 1 });
  }

  focus(): void {
    // On touch devices focusing the textarea pops up the soft keyboard, so
    // only do that on request (showKeyboard).
    if (this.inputMode === "mouse") this.ime.focus({ preventScroll: true });
    else this.root.focus({ preventScroll: true });
  }

  /** Shows the on-screen keyboard on touch devices. */
  showKeyboard(): void {
    this.ime.focus({ preventScroll: true });
  }

  hideKeyboard(): void {
    this.ime.blur();
  }

  /**
   * Sees what the on-screen keyboard types first: text, or Enter / Backspace
   * / Delete as a key. Returning true consumes it, e.g. to press it with
   * modifiers latched on an extra keys bar. null removes the handler.
   */
  setSoftKeyHandler(fn: ((input: string | { code: string; key: string }) => boolean) | null): void {
    this.softKeyHandler = fn;
  }

  /** Fullscreen with keyboard lock (captures Esc, Alt+Tab, … where supported). */
  async enterFullscreen(el: HTMLElement = this.root): Promise<void> {
    try {
      await el.requestFullscreen({ navigationUI: "hide" });
      const kb = (navigator as Navigator & { keyboard?: { lock?: () => Promise<void> } }).keyboard;
      await kb?.lock?.().catch(() => {});
    } catch {
      /* not allowed */
    }
  }

  async exitFullscreen(): Promise<void> {
    const kb = (navigator as Navigator & { keyboard?: { unlock?: () => void } }).keyboard;
    kb?.unlock?.();
    if (document.fullscreenElement) await document.exitFullscreen().catch(() => {});
  }

  /** Captures the current frame as a PNG blob. */
  screenshot(): Promise<Blob | null> {
    return new Promise((resolve) => this.canvas.toBlob(resolve, "image/png"));
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.releaseInput();
    this.session.setFrameSink(null);
    for (const u of this.unsub) u();
    this.ro.disconnect();
    if (this.raf) cancelAnimationFrame(this.raf);
    this.pending?.close();
    this.pending = null;
    this.root.remove();
    this.listeners.clear();
  }

  // --------------------------------------------------------------- rendering

  private onFrame(frame: VideoFrame): void {
    if (this.destroyed) {
      frame.close();
      return;
    }
    // Keep only the newest frame; draw once per animation frame.
    this.pending?.close();
    this.pending = frame;
    if (!this.raf) this.raf = requestAnimationFrame(() => this.draw());
  }

  private draw(): void {
    this.raf = 0;
    const f = this.pending;
    this.pending = null;
    if (!f) return;
    try {
      const w = f.displayWidth;
      const h = f.displayHeight;
      if (w !== this.videoW || h !== this.videoH) {
        this.videoW = w;
        this.videoH = h;
        this.canvas.width = w;
        this.canvas.height = h;
        this.layout();
      }
      this.ctx.drawImage(f, 0, 0, w, h);
    } finally {
      f.close();
    }
  }

  private onDisplay(d: DisplayRect): void {
    this.cursorCssCache.clear();
    const inside = this.curX >= d.x && this.curX < d.x + d.width && this.curY >= d.y && this.curY < d.y + d.height;
    if ((!inside || !this.haveCursorPos) && this.inputMode !== "mouse") this.centerCursor();
    this.applyCursorShape();
    this.layout();
    this.positionCursor();
  }

  /** Remote display size used for input mapping and aspect ratio. */
  private remoteSize(): { w: number; h: number } {
    const d = this.session.display;
    const w = this.videoW || d?.width || 16;
    const h = this.videoH || d?.height || 9;
    return { w, h };
  }

  private layout(): void {
    const cw = this.root.clientWidth;
    const ch = this.root.clientHeight;
    const { w, h } = this.remoteSize();
    let bw: number;
    let bh: number;
    const mode = this.scaleMode === "original" && this.inputMode !== "mouse" ? "fit" : this.scaleMode;
    switch (mode) {
      case "original": {
        const dpr = window.devicePixelRatio || 1;
        bw = w / dpr;
        bh = h / dpr;
        break;
      }
      case "stretch":
        bw = cw;
        bh = ch;
        break;
      default: {
        const s = Math.min(cw / w, ch / h) || 1;
        bw = w * s;
        bh = h * s;
      }
    }
    this.baseW = bw;
    this.baseH = bh;
    this.baseX = mode === "original" ? Math.max(0, (cw - bw) / 2) : (cw - bw) / 2;
    this.baseY = mode === "original" ? Math.max(0, (ch - bh) / 2) : (ch - bh) / 2;
    this.clampPan();
    this.applyTransform();
  }

  private applyTransform(): void {
    const s = this.surface.style;
    s.width = `${this.baseW}px`;
    s.height = `${this.baseH}px`;
    const x = this.baseX * this.zoom + this.panX;
    const y = this.baseY * this.zoom + this.panY;
    if (this.zoom === 1 && this.panX === 0 && this.panY === 0) {
      s.transform = `translate(${this.baseX}px, ${this.baseY}px)`;
    } else {
      s.transform = `translate(${x}px, ${y}px) scale(${this.zoom})`;
    }
    this.positionCursor();
  }

  private clampPan(): void {
    if (this.zoom <= 1) {
      this.panX = this.panY = 0;
      return;
    }
    const cw = this.root.clientWidth;
    const ch = this.root.clientHeight;
    const w = this.baseW * this.zoom;
    const h = this.baseH * this.zoom;
    const x0 = this.baseX * this.zoom;
    const y0 = this.baseY * this.zoom;
    // keep the zoomed image covering the viewport where possible
    const minX = Math.min(0, cw - w) - x0;
    const maxX = Math.max(0, cw - w) - x0;
    const minY = Math.min(0, ch - h) - y0;
    const maxY = Math.max(0, ch - h) - y0;
    this.panX = Math.min(Math.max(this.panX, Math.min(minX, maxX)), Math.max(minX, maxX));
    this.panY = Math.min(Math.max(this.panY, Math.min(minY, maxY)), Math.max(minY, maxY));
  }

  // ----------------------------------------------------------------- cursor

  /** CSS px per remote px at the current zoom. */
  private viewScale(): number {
    const d = this.session.display;
    const rw = d?.width || this.remoteSize().w;
    return (this.baseW / rw) * this.zoom;
  }

  private applyCursorShape(): void {
    const shape = this.session.cursor;
    const overlay = this.overlayActive();
    if (this.inputMode === "mouse" && !this.session.settings.viewOnly) {
      this.canvas.style.cursor = overlay ? "default" : this.cssCursor(shape);
    } else {
      this.canvas.style.cursor = "default";
    }
    if (overlay && shape && !shape.empty) {
      const unit = this.cursorUnit();
      this.cursorEl.style.width = `${shape.width * unit}px`;
      this.cursorEl.style.height = `${shape.height * unit}px`;
      this.cursorEl.style.backgroundImage = `url("${shape.url()}")`;
      this.cursorEl.style.display = this.haveCursorPos || this.inputMode !== "mouse" ? "block" : "none";
    } else {
      this.cursorEl.style.display = "none";
    }
    this.positionCursor();
  }

  /**
   * Size of one cursor pixel in surface coordinates (before the user zoom).
   * Touch modes and "zoom cursor" draw the cursor at remote-screen scale;
   * otherwise it keeps its native size on screen.
   */
  private cursorUnit(): number {
    const d = this.session.display;
    const f = this.baseW / (d?.width || this.remoteSize().w || 1);
    if (this.zoomCursor) return f;
    // Touch modes draw the cursor with the remote screen, but never smaller
    // than 3/4 of its native size so it stays visible on phones.
    if (this.inputMode !== "mouse") return Math.max(f, 0.75 / this.zoom);
    return 1 / this.zoom;
  }

  /** Whether the remote cursor is drawn as an element instead of the local pointer. */
  private overlayActive(): boolean {
    if (this.inputMode !== "mouse") return true;
    const s = this.session.settings;
    return s.viewOnly || s.showRemoteCursor;
  }

  private cssCursor(shape: CursorShape | null): string {
    if (!shape) return "default";
    if (shape.empty) return "none";
    const scale = this.zoomCursor ? this.viewScale() : 1;
    const key = `${shape.id}@${scale.toFixed(2)}`;
    let css = this.cursorCssCache.get(key);
    if (!css) {
      const w = Math.round(shape.width * scale);
      const h = Math.round(shape.height * scale);
      if (w > 128 || h > 128 || w < 1 || h < 1) {
        css = "default";
      } else {
        const url = scale === 1 ? shape.url() : rgbaToDataUrl(shape.rgba, shape.width, shape.height, scale);
        const hx = Math.min(w - 1, Math.round(shape.hotX * scale));
        const hy = Math.min(h - 1, Math.round(shape.hotY * scale));
        css = `url("${url}") ${hx} ${hy}, default`;
      }
      if (this.cursorCssCache.size > 64) this.cursorCssCache.clear();
      this.cursorCssCache.set(key, css);
    }
    return css;
  }

  private positionCursor(): void {
    const shape = this.session.cursor;
    if (!shape || this.cursorEl.style.display === "none") return;
    const d = this.session.display;
    if (!d) return;
    const fx = this.baseW / (d.width || 1);
    const fy = this.baseH / (d.height || 1);
    const unit = this.cursorUnit();
    const x = (this.curX - d.x) * fx - shape.hotX * unit;
    const y = (this.curY - d.y) * fy - shape.hotY * unit;
    this.cursorEl.style.transform = `translate(${x}px, ${y}px)`;
  }

  // ------------------------------------------------------------------ input

  private bindInput(): void {
    const c = this.root;
    const opts = { passive: false } as AddEventListenerOptions;
    const add = <K extends keyof HTMLElementEventMap>(
      el: HTMLElement,
      type: K,
      fn: (e: HTMLElementEventMap[K]) => void,
      o?: AddEventListenerOptions,
    ) => {
      el.addEventListener(type, fn as EventListener, o);
      this.unsub.push(() => el.removeEventListener(type, fn as EventListener, o));
    };

    add(c, "pointerdown", (e) => this.onPointerDown(e), opts);
    add(c, "pointermove", (e) => this.onPointerMove(e), opts);
    add(c, "pointerup", (e) => this.onPointerUp(e), opts);
    add(c, "pointercancel", (e) => this.onPointerCancel(e), opts);
    add(c, "wheel", (e) => this.onWheel(e), opts);
    add(c, "contextmenu", (e) => e.preventDefault(), opts);
    add(c, "dragstart", (e) => e.preventDefault(), opts);
    add(c, "dragover", (e) => {
      if ([...(e.dataTransfer?.types ?? [])].includes("Files")) e.preventDefault();
    });
    add(c, "drop", (e) => {
      if (!e.dataTransfer?.files.length) return;
      e.preventDefault();
      this.emit("files", { dataTransfer: e.dataTransfer });
    });

    for (const el of [this.root, this.ime]) {
      add(el, "keydown", (e) => this.onKey(e, true), opts);
      add(el, "keyup", (e) => this.onKey(e, false), opts);
    }
    add(this.ime, "beforeinput", (e) => this.onBeforeInput(e), opts);
    add(this.ime, "compositionend", (e) => this.onCompositionEnd(e));
    add(this.ime, "paste", (e) => this.onPaste(e), opts);
    const onFocus = () => this.emit("focus", { focused: true });
    const onBlur = () => {
      // focus moving between root and ime is not a real blur
      setTimeout(() => {
        if (document.activeElement !== this.ime && document.activeElement !== this.root) {
          this.session.releaseAllKeys();
          this.releaseButtons();
          this.emit("focus", { focused: false });
        }
      }, 0);
    };
    add(this.ime, "focus", onFocus);
    add(this.root, "focus", onFocus);
    add(this.ime, "blur", onBlur);
    add(this.root, "blur", onBlur);
  }

  private toRemote(clientX: number, clientY: number): { x: number; y: number } {
    const d = this.session.display;
    const r = this.canvas.getBoundingClientRect();
    const u = Math.min(1, Math.max(0, (clientX - r.left) / (r.width || 1)));
    const v = Math.min(1, Math.max(0, (clientY - r.top) / (r.height || 1)));
    const w = d?.width || this.videoW;
    const h = d?.height || this.videoH;
    return { x: (d?.x ?? 0) + u * (w - 1), y: (d?.y ?? 0) + v * (h - 1) };
  }

  private onPointerDown(e: PointerEvent): void {
    this.session.resumeAudio();
    if (e.pointerType === "touch" || (e.pointerType === "pen" && this.inputMode !== "mouse")) {
      e.preventDefault();
      this.onTouchStart(e);
      return;
    }
    this.focus();
    if (this.scaleMode === "original" && e.target === this.root) return; // scrollbar
    e.preventDefault();
    const button = BUTTONS[e.button];
    if (!button) return;
    try {
      this.root.setPointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
    const p = this.toRemote(e.clientX, e.clientY);
    this.curX = p.x;
    this.curY = p.y;
    this.session.mouseMove(p.x, p.y);
    this.session.mouseButton(button, true, p.x, p.y);
    this.heldButtons.add(button);
  }

  private onPointerMove(e: PointerEvent): void {
    if (e.pointerType === "touch" || (e.pointerType === "pen" && this.inputMode !== "mouse")) {
      e.preventDefault();
      this.onTouchMove(e);
      return;
    }
    const p = this.toRemote(e.clientX, e.clientY);
    this.session.mouseMove(p.x, p.y);
    if (!this.session.settings.showRemoteCursor) {
      this.curX = p.x;
      this.curY = p.y;
    }
  }

  private onPointerUp(e: PointerEvent): void {
    if (e.pointerType === "touch" || (e.pointerType === "pen" && this.inputMode !== "mouse")) {
      e.preventDefault();
      this.onTouchEnd(e);
      return;
    }
    const button = BUTTONS[e.button];
    if (!button || !this.heldButtons.has(button)) return;
    e.preventDefault();
    const p = this.toRemote(e.clientX, e.clientY);
    this.session.mouseButton(button, false, p.x, p.y);
    this.heldButtons.delete(button);
  }

  private onPointerCancel(e: PointerEvent): void {
    if (e.pointerType === "touch") this.onTouchEnd(e, true);
    else this.releaseButtons();
  }

  private releaseButtons(): void {
    for (const b of this.heldButtons) this.session.mouseButton(b, false, this.curX, this.curY);
    this.heldButtons.clear();
  }

  private onWheel(e: WheelEvent): void {
    e.preventDefault();
    if (e.ctrlKey) return; // browser pinch-zoom gesture on touchpads: ignore
    const { dx, dy, smooth } = normalizeWheel(e);
    if (smooth) {
      this.session.trackpadScroll(-dx, -dy);
      return;
    }
    // discrete wheel: one step per notch (accumulate fractional notches)
    this.scrollAcc.x += dx / 100;
    this.scrollAcc.y += dy / 100;
    const sx = Math.trunc(this.scrollAcc.x);
    const sy = Math.trunc(this.scrollAcc.y);
    this.scrollAcc.x -= sx;
    this.scrollAcc.y -= sy;
    if (sx || sy) this.session.wheel(-sx, -sy);
  }

  // ----------------------------------------------------------------- touch

  private onTouchStart(e: PointerEvent): void {
    this.session.resumeAudio();
    this.touches.set(e.pointerId, {
      id: e.pointerId,
      x: e.clientX,
      y: e.clientY,
      startX: e.clientX,
      startY: e.clientY,
      t0: performance.now(),
    });
    try {
      this.root.setPointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
    if (this.touches.size === 1) {
      this.gesture = "none";
      if (this.inputMode === "touch") {
        const p = this.toRemote(e.clientX, e.clientY);
        this.setCursor(p.x, p.y);
        this.session.mouseMove(p.x, p.y);
      }
      // double-tap-and-hold starts a drag in trackpad mode
      const doubleTap = performance.now() - this.lastTapAt < 300;
      if (this.inputMode === "trackpad" && doubleTap) {
        this.gesture = "drag";
        this.session.mouseButton("left", true, this.curX, this.curY);
      }
      this.armLongPress();
    } else if (this.touches.size === 2) {
      this.disarmLongPress();
      if (this.gesture === "drag") this.session.mouseButton("left", false, this.curX, this.curY);
      const [a, b] = [...this.touches.values()] as [TouchPoint, TouchPoint];
      this.pinchStart = {
        dist: Math.hypot(a.x - b.x, a.y - b.y),
        zoom: this.zoom,
        midX: (a.x + b.x) / 2,
        midY: (a.y + b.y) / 2,
        panX: this.panX,
        panY: this.panY,
      };
      this.gesture = "none";
      this.scrollAcc = { x: 0, y: 0 };
    } else {
      this.disarmLongPress();
    }
  }

  private onTouchMove(e: PointerEvent): void {
    const t = this.touches.get(e.pointerId);
    if (!t) return;
    const dx = e.clientX - t.x;
    const dy = e.clientY - t.y;
    t.x = e.clientX;
    t.y = e.clientY;
    if (this.touches.size === 1) {
      const moved = Math.hypot(t.x - t.startX, t.y - t.startY) > TAP_SLOP;
      if (!moved && this.gesture === "none") return;
      this.disarmLongPress();
      if (this.inputMode === "trackpad") {
        if (this.gesture === "none") this.gesture = "move";
        const d = this.session.display;
        const scale = this.viewScale() || 1;
        const k = this.trackpadSpeed / scale;
        let x = this.curX + dx * k;
        let y = this.curY + dy * k;
        if (d) {
          x = Math.min(d.x + d.width - 1, Math.max(d.x, x));
          y = Math.min(d.y + d.height - 1, Math.max(d.y, y));
        }
        this.setCursor(x, y);
        this.session.mouseMove(x, y);
        this.followCursor();
      } else {
        const p = this.toRemote(e.clientX, e.clientY);
        if (this.gesture === "none") {
          this.gesture = "drag";
          const s = this.toRemote(t.startX, t.startY);
          this.session.mouseMove(s.x, s.y);
          this.session.mouseButton("left", true, s.x, s.y);
        }
        this.setCursor(p.x, p.y);
        this.session.mouseMove(p.x, p.y);
      }
      return;
    }
    if (this.touches.size === 2) {
      const [a, b] = [...this.touches.values()] as [TouchPoint, TouchPoint];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      const midX = (a.x + b.x) / 2;
      const midY = (a.y + b.y) / 2;
      const ratio = dist / (this.pinchStart.dist || 1);
      if (this.gesture === "none") {
        if (Math.abs(ratio - 1) > 0.12) this.gesture = "pinch";
        else if (Math.hypot(midX - this.pinchStart.midX, midY - this.pinchStart.midY) > TAP_SLOP) this.gesture = "scroll";
      }
      if (this.gesture === "pinch") {
        this.pinchTo(ratio, midX, midY);
      } else if (this.gesture === "scroll") {
        // two-finger drag scrolls the remote side; finger up = content up
        const ddy = dy / 2;
        const ddx = dx / 2;
        const os = this.session.peer?.os;
        if (os === "windows" || os === "macos") {
          this.session.trackpadScroll(ddx * 2, ddy * 2);
        } else {
          this.scrollAcc.x += ddx / 25;
          this.scrollAcc.y += ddy / 25;
          const sx = Math.trunc(this.scrollAcc.x);
          const sy = Math.trunc(this.scrollAcc.y);
          this.scrollAcc.x -= sx;
          this.scrollAcc.y -= sy;
          if (sx || sy) this.session.wheel(sx, sy);
        }
      }
    }
  }

  private onTouchEnd(e: PointerEvent, cancelled = false): void {
    const t = this.touches.get(e.pointerId);
    this.touches.delete(e.pointerId);
    if (!t) return;
    const count = this.touches.size;
    const elapsed = performance.now() - t.t0;
    const isTap = !cancelled && elapsed < TAP_MAX_MS && Math.hypot(t.x - t.startX, t.y - t.startY) <= TAP_SLOP;

    if (count === 0) {
      this.disarmLongPress();
      if (this.gesture === "drag") {
        this.session.mouseButton("left", false, this.curX, this.curY);
      } else if (this.gesture === "none" && isTap) {
        if (this.inputMode === "touch") {
          const p = this.toRemote(t.x, t.y);
          this.setCursor(p.x, p.y);
          this.click("left", p.x, p.y);
        } else {
          this.click("left", this.curX, this.curY);
        }
        this.lastTapAt = performance.now();
      } else if (this.gesture === "twoFingerTap") {
        this.click("right", this.curX, this.curY);
      }
      this.gesture = "none";
      return;
    }
    if (count === 1 && (this.gesture === "none" || this.gesture === "twoFingerTap") && isTap) {
      // second finger of a two-finger tap lifted first: right click when the other lifts
      this.gesture = "twoFingerTap";
      return;
    }
    if (count === 1) {
      // continuing with one finger after a pinch/scroll: ignore the rest
      const rest = [...this.touches.values()][0]!;
      rest.startX = rest.x;
      rest.startY = rest.y;
      if (this.gesture !== "twoFingerTap") this.gesture = "pinch";
    }
  }

  private cancelGesture(): void {
    this.disarmLongPress();
    if (this.gesture === "drag") this.session.mouseButton("left", false, this.curX, this.curY);
    this.touches.clear();
    this.gesture = "none";
  }

  private armLongPress(): void {
    this.disarmLongPress();
    this.longPressTimer = setTimeout(() => {
      this.longPressTimer = null;
      if (this.touches.size !== 1 || this.gesture !== "none") return;
      const t = [...this.touches.values()][0]!;
      const p = this.inputMode === "touch" ? this.toRemote(t.x, t.y) : { x: this.curX, y: this.curY };
      this.click("right", p.x, p.y);
      this.gesture = "move"; // swallow the rest of this touch
      navigator.vibrate?.(15);
    }, LONG_PRESS_MS);
  }

  private disarmLongPress(): void {
    if (this.longPressTimer) clearTimeout(this.longPressTimer);
    this.longPressTimer = null;
  }

  private click(button: MouseButtonName, x: number, y: number): void {
    this.session.mouseMove(x, y);
    this.session.mouseButton(button, true, x, y);
    this.session.mouseButton(button, false, x, y);
  }

  private centerCursor(): void {
    const d = this.session.display;
    if (!d) return;
    this.curX = d.x + d.width / 2;
    this.curY = d.y + d.height / 2;
    this.haveCursorPos = true;
  }

  private setCursor(x: number, y: number): void {
    this.curX = x;
    this.curY = y;
    this.haveCursorPos = true;
    if (this.cursorEl.style.display === "none" && this.overlayActive()) this.applyCursorShape();
    this.positionCursor();
  }

  private pinchTo(ratio: number, midX: number, midY: number): void {
    const r = this.root.getBoundingClientRect();
    const z0 = this.pinchStart.zoom;
    const z = Math.min(MAX_ZOOM, Math.max(1, z0 * ratio));
    // keep the point under the starting midpoint under the current midpoint
    const ox = this.pinchStart.midX - r.left;
    const oy = this.pinchStart.midY - r.top;
    const contentX = (ox - this.pinchStart.panX - this.baseX * z0) / z0;
    const contentY = (oy - this.pinchStart.panY - this.baseY * z0) / z0;
    this.zoom = z;
    this.panX = midX - r.left - contentX * z - this.baseX * z;
    this.panY = midY - r.top - contentY * z - this.baseY * z;
    this.clampPan();
    this.applyTransform();
    if (this.inputMode !== "mouse") this.applyCursorShape();
    this.emit("zoom", { zoom: z });
  }

  /** Pans a zoomed view so the trackpad cursor stays visible. */
  private followCursor(): void {
    if (this.zoom <= 1) return;
    const d = this.session.display;
    if (!d) return;
    const cw = this.root.clientWidth;
    const ch = this.root.clientHeight;
    const sx = (this.baseW / d.width) * this.zoom;
    const sy = (this.baseH / d.height) * this.zoom;
    const px = this.baseX * this.zoom + this.panX + (this.curX - d.x) * sx;
    const py = this.baseY * this.zoom + this.panY + (this.curY - d.y) * sy;
    const margin = 40;
    if (px < margin) this.panX += margin - px;
    else if (px > cw - margin) this.panX -= px - (cw - margin);
    if (py < margin) this.panY += margin - py;
    else if (py > ch - margin) this.panY -= py - (ch - margin);
    this.clampPan();
    this.applyTransform();
  }

  // --------------------------------------------------------------- keyboard

  private onKey(e: KeyboardEvent, down: boolean): void {
    if (down) this.session.resumeAudio();
    if (e.isComposing || e.keyCode === 229) return; // IME is composing; text arrives via input events
    if (!e.code || e.key === "Unidentified") return; // soft keyboards: handled by beforeinput
    // Ctrl/Cmd+V: let the browser fire "paste" so the remote clipboard is
    // updated first; then the remote side's own paste shortcut is pressed.
    if (down && (e.ctrlKey || e.metaKey) && e.code === "KeyV" && !e.altKey && document.activeElement === this.ime) {
      if (!this.pendingPaste) this.pendingPaste = { timer: setTimeout(() => this.endPaste(null), 150), upSeen: false };
      return;
    }
    if (!down && e.code === "KeyV" && (this.pendingPaste || this.swallowVUp)) {
      e.preventDefault();
      e.stopPropagation();
      if (this.pendingPaste) this.pendingPaste.upSeen = true;
      else this.swallowVUp = false;
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    if (e.repeat && !down) return;
    this.sendKey(e.code, e.key, down, e.repeat);
  }

  private sendKey(code: string, key: string, down: boolean, repeat = false): void {
    this.session.key({ code, key, down, repeat });
  }

  private onPaste(e: ClipboardEvent): void {
    e.preventDefault();
    if (e.clipboardData?.files.length) {
      // files: offered for upload instead of pasting remotely
      if (this.pendingPaste) {
        clearTimeout(this.pendingPaste.timer);
        this.swallowVUp = !this.pendingPaste.upSeen;
        this.pendingPaste = null;
      }
      this.emit("files", { dataTransfer: e.clipboardData });
      this.ime.value = "";
      return;
    }
    const text = e.clipboardData?.getData("text/plain") ?? "";
    if (this.pendingPaste) this.endPaste(text);
    else if (text) this.session.sendClipboard(text);
    this.ime.value = "";
  }

  /**
   * Finishes a Ctrl/Cmd+V. text: what the browser pasted (sent to the remote
   * clipboard, then the remote paste shortcut); null: no paste event came
   * (e.g. Ctrl+V on macOS), so the keystroke goes through as typed.
   */
  private endPaste(text: string | null): void {
    const p = this.pendingPaste;
    if (!p) return;
    clearTimeout(p.timer);
    this.pendingPaste = null;
    if (text === null) {
      this.sendKey("KeyV", "v", true);
      if (p.upSeen) this.sendKey("KeyV", "v", false);
      return;
    }
    if (text) this.session.sendClipboard(text);
    this.swallowVUp = !p.upSeen;
    // give the clipboard message a head start
    setTimeout(() => this.session.pasteShortcut(), 30);
  }

  private onBeforeInput(e: InputEvent): void {
    const t = e.inputType;
    if (t === "insertCompositionText") return; // wait for compositionend
    e.preventDefault();
    if (t === "insertText" || t === "insertReplacementText") {
      if (e.data) this.softText(e.data);
    } else if (t === "insertLineBreak" || t === "insertParagraph") {
      this.tapKey("Enter", "Enter");
    } else if (t === "deleteContentBackward") {
      this.tapKey("Backspace", "Backspace");
    } else if (t === "deleteContentForward") {
      this.tapKey("Delete", "Delete");
    }
    this.ime.value = "";
  }

  private onCompositionEnd(e: CompositionEvent): void {
    if (e.data) this.softText(e.data);
    this.ime.value = "";
  }

  private softText(text: string): void {
    if (!this.softKeyHandler?.(text)) this.session.typeText(text);
  }

  private tapKey(code: string, key: string): void {
    if (this.softKeyHandler?.({ code, key })) return;
    this.session.key({ code, key, down: true });
    this.session.key({ code, key, down: false });
  }

  // -------------------------------------------------------------- clipboard

  private async writeLocalClipboard(text: string): Promise<void> {
    try {
      if (!document.hasFocus()) throw new Error("not focused");
      await navigator.clipboard.writeText(text);
    } catch {
      this.emit("clipboardBlocked", { text });
    }
  }

  private releaseInput(): void {
    this.cancelGesture();
    this.releaseButtons();
  }

  private emit<K extends keyof ViewerEventMap>(type: K, ev: ViewerEventMap[K]): void {
    const set = this.listeners.get(type);
    if (!set) return;
    for (const fn of [...set]) {
      try {
        (fn as (ev: ViewerEventMap[K]) => void)(ev);
      } catch (err) {
        console.error(err);
      }
    }
  }
}

function isTouchFirst(): boolean {
  return typeof matchMedia === "function" && matchMedia("(pointer: coarse)").matches && !matchMedia("(pointer: fine)").matches;
}

/**
 * Splits wheel events into touchpad-style smooth deltas (pixels) and
 * notch-style mouse wheel deltas (100 per notch).
 */
export function normalizeWheel(e: WheelEvent): { dx: number; dy: number; smooth: boolean } {
  if (e.deltaMode === WheelEvent.DOM_DELTA_LINE) return { dx: e.deltaX * 33, dy: e.deltaY * 33, smooth: false };
  if (e.deltaMode === WheelEvent.DOM_DELTA_PAGE) return { dx: e.deltaX * 300, dy: e.deltaY * 300, smooth: false };
  const legacy = e as WheelEvent & { wheelDeltaY?: number; wheelDeltaX?: number };
  const wy = legacy.wheelDeltaY ?? 0;
  const wx = legacy.wheelDeltaX ?? 0;
  // Mouse wheels report multiples of 120 in wheelDelta; touchpads report small,
  // fractional pixel deltas.
  const notch = (wy !== 0 && wy % 120 === 0) || (wx !== 0 && wx % 120 === 0);
  if (notch) {
    const n = Math.abs(wy || wx) / 120;
    const scale = n > 0 ? 100 / (Math.abs(e.deltaY || e.deltaX) / n) : 1;
    return { dx: e.deltaX * scale, dy: e.deltaY * scale, smooth: false };
  }
  return { dx: e.deltaX, dy: e.deltaY, smooth: true };
}
