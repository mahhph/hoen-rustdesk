// Binary WebSocket transport. hbbs and hbbr carry exactly one protobuf
// message per WebSocket binary frame (no length prefix).

export class TransportError extends Error {
  constructor(
    message: string,
    readonly code: "connect" | "timeout" | "closed" | "aborted",
  ) {
    super(message);
    this.name = "TransportError";
  }
}

export interface OpenOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

type Waiter = { resolve: (m: Uint8Array) => void; reject: (e: Error) => void };

export class WsTransport {
  private queue: Uint8Array[] = [];
  private waiters: Waiter[] = [];
  private closedError: TransportError | null = null;
  private onMessageHandler: ((m: Uint8Array) => void) | null = null;
  private closeHandlers: ((reason: string) => void)[] = [];

  private constructor(private readonly ws: WebSocket) {
    ws.binaryType = "arraybuffer";
    ws.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return; // text frames are not part of the protocol
      const msg = new Uint8Array(ev.data);
      if (this.onMessageHandler) {
        this.onMessageHandler(msg);
        return;
      }
      const w = this.waiters.shift();
      if (w) w.resolve(msg);
      else this.queue.push(msg);
    };
    ws.onclose = (ev) => {
      const reason = ev.reason || (ev.wasClean ? "connection closed" : `connection lost (code ${ev.code})`);
      this.fail(new TransportError(reason, "closed"));
      for (const h of this.closeHandlers) h(reason);
    };
    ws.onerror = () => {
      // onclose follows with the details
    };
  }

  static open(url: string, opts: OpenOptions = {}): Promise<WsTransport> {
    const timeoutMs = opts.timeoutMs ?? 10_000;
    return new Promise((resolve, reject) => {
      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch (e) {
        reject(new TransportError(`cannot open ${redactUrl(url)}: ${String(e)}`, "connect"));
        return;
      }
      let settled = false;
      const done = (err: TransportError | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        opts.signal?.removeEventListener("abort", onAbort);
        if (err) {
          ws.onopen = ws.onerror = ws.onclose = null;
          try {
            ws.close();
          } catch {
            /* ignore */
          }
          reject(err);
        } else {
          resolve(new WsTransport(ws));
        }
      };
      const onAbort = () => done(new TransportError("aborted", "aborted"));
      const timer = setTimeout(
        () => done(new TransportError(`timed out connecting to ${redactUrl(url)}`, "timeout")),
        timeoutMs,
      );
      if (opts.signal?.aborted) {
        onAbort();
        return;
      }
      opts.signal?.addEventListener("abort", onAbort, { once: true });
      ws.onopen = () => done(null);
      ws.onerror = () => done(new TransportError(`cannot connect to ${redactUrl(url)}`, "connect"));
      ws.onclose = (ev) => done(new TransportError(`connection to ${redactUrl(url)} closed (code ${ev.code})`, "connect"));
    });
  }

  get isOpen(): boolean {
    return this.ws.readyState === WebSocket.OPEN && !this.closedError;
  }

  /** Bytes queued in the browser's send buffer (for backpressure decisions). */
  get bufferedAmount(): number {
    return this.ws.bufferedAmount;
  }

  send(data: Uint8Array): void {
    if (!this.isOpen) throw this.closedError ?? new TransportError("not connected", "closed");
    this.ws.send(data);
  }

  /** Waits for the next message (only before a message handler is installed). */
  next(timeoutMs: number, signal?: AbortSignal): Promise<Uint8Array> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closedError) return Promise.reject(this.closedError);
    return new Promise((resolve, reject) => {
      const w: Waiter = {
        resolve: (m) => {
          cleanup();
          resolve(m);
        },
        reject: (e) => {
          cleanup();
          reject(e);
        },
      };
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((x) => x !== w);
        w.reject(new TransportError("timed out waiting for the server", "timeout"));
      }, timeoutMs);
      const onAbort = () => {
        this.waiters = this.waiters.filter((x) => x !== w);
        w.reject(new TransportError("aborted", "aborted"));
      };
      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
      };
      if (signal?.aborted) {
        onAbort();
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.push(w);
    });
  }

  /** Switches to push mode: every queued and future message goes to `fn`. */
  onMessage(fn: (m: Uint8Array) => void): void {
    this.onMessageHandler = fn;
    const pending = this.queue;
    this.queue = [];
    for (const m of pending) fn(m);
  }

  onClose(fn: (reason: string) => void): void {
    this.closeHandlers.push(fn);
  }

  close(reason = "closed"): void {
    this.fail(new TransportError(reason, "closed"));
    this.onMessageHandler = null;
    this.closeHandlers = [];
    try {
      this.ws.close(1000, reason.slice(0, 120));
    } catch {
      /* ignore */
    }
  }

  private fail(err: TransportError): void {
    if (this.closedError) return;
    this.closedError = err;
    const waiters = this.waiters;
    this.waiters = [];
    for (const w of waiters) w.reject(err);
  }
}

/** Strips query strings from URLs before they end up in error messages. */
export function redactUrl(url: string): string {
  const i = url.indexOf("?");
  return i < 0 ? url : url.slice(0, i);
}
