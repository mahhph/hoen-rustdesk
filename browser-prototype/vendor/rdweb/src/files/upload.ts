// Upload job: announces the files, then for each one offers a digest, lets
// the peer (and, on a conflict, the host) decide between overwrite, skip and
// resume, and streams the data in blocks while respecting the WebSocket's
// send buffer.

import type {
  FileTransferDigest,
  FileTransferDone,
  FileTransferSendConfirmRequest,
  FileTransferError as WireFileError,
} from "../proto/session_pb.js";
import { FileType } from "../proto/session_pb.js";
import { versionNumber } from "../connector.js";
import { peerError, type JobHost, type MessageUnion, type TransferJob } from "./job.js";
import { Deferred, sleep } from "./queue.js";
import {
  FileTransferError,
  type ConflictAnswer,
  type TransferFileInfo,
  type TransferProgress,
  type TransferResult,
  type UploadOptions,
} from "./types.js";

/** Block size, as the desktop client reads files. */
export const UPLOAD_CHUNK = 128 * 1024;
const PROGRESS_INTERVAL_MS = 100;
/** Peers from this version announce existing files (digest negotiation). */
const DIGEST_SINCE = versionNumber("1.1.10");
/** Peers from this version can continue a partial upload. */
const RESUME_SINCE = versionNumber("1.4.2");

export interface UploadEntry extends TransferFileInfo {
  /** Path below the target folder with the peer's separator, as sent in the request. */
  wireName: string;
  source: Blob | ReadableStream<Uint8Array>;
}

type Reply = { kind: "confirm"; skip: boolean; offset: number } | { kind: "conflict"; digest: FileTransferDigest };

export class Upload implements TransferJob {
  readonly direction = "upload" as const;
  private readonly result = new Deferred<TransferResult>();
  /** Rejected as soon as the job fails; raced against every wait. */
  private readonly failed = new Deferred<never>();
  private failure: FileTransferError | null = null;
  private started = false;
  private over = false;
  private reply: { fileNum: number; deferred: Deferred<Reply> } | null = null;
  private echo: Deferred<"done" | "skipped"> | null = null;
  private remembered: "overwrite" | "skip" | null = null;
  private current: UploadEntry | null = null;
  private fileBytes = 0;
  private bytes = 0;
  private totalBytes: number;
  private filesDone = 0;
  private skipped = 0;
  private lastProgress = 0;
  private readonly onAbort = () => this.cancel();

  constructor(
    private readonly host: JobHost,
    readonly id: number,
    /** The remote folder the files go to. */
    readonly remoteDir: string,
    private readonly entries: UploadEntry[],
    private readonly opts: UploadOptions,
  ) {
    this.totalBytes = entries.reduce((n, e) => n + e.size, 0);
    if (opts.overwrite === "overwrite" || opts.overwrite === "skip") this.remembered = opts.overwrite;
    opts.signal?.addEventListener("abort", this.onAbort, { once: true });
  }

  /** Resolves once the peer confirmed the upload; rejects on error or cancel. */
  get done(): Promise<TransferResult> {
    return this.result.promise;
  }

  /** The files of this upload as announced to the peer. */
  get files(): TransferFileInfo[] {
    return this.entries.map(({ index, relativePath, remotePath, size, modified }) => ({
      index,
      relativePath,
      remotePath,
      size,
      modified,
    }));
  }

  cancel(): void {
    this.fail(new FileTransferError("upload cancelled", "cancelled", this.id, null, this.remoteDir));
  }

  // ------------------------------------------------------------- job hooks

  start(): void {
    if (this.over) return;
    this.started = true;
    void this.run();
  }

  onConfirm(c: FileTransferSendConfirmRequest): void {
    const r = this.reply;
    if (!r || c.fileNum !== r.fileNum) return;
    const skip = c.union.case === "skip" && c.union.value;
    const offset = c.union.case === "offsetBlk" ? c.union.value : 0;
    r.deferred.resolve({ kind: "confirm", skip, offset });
  }

  onDigest(d: FileTransferDigest): void {
    const r = this.reply;
    if (!r || d.fileNum !== r.fileNum) return;
    r.deferred.resolve({ kind: "conflict", digest: d });
  }

  onDone(_d: FileTransferDone): void {
    this.echo?.resolve("done");
  }

  onError(e: WireFileError): void {
    if (e.error === "skipped" && this.echo) {
      this.echo.resolve("skipped");
      return;
    }
    const entry = e.fileNum >= 0 ? this.entries[e.fileNum] : undefined;
    this.fail(peerError(e, entry?.remotePath ?? this.remoteDir, `upload to ${this.remoteDir} failed`));
  }

  abort(err: FileTransferError): void {
    // the session reports the reason itself
    this.fail(err, false);
  }

  // --------------------------------------------------------------- private

  private async run(): Promise<void> {
    try {
      this.send({
        case: "fileAction",
        value: {
          union: {
            case: "receive",
            value: {
              id: this.id,
              path: this.remoteDir,
              files: this.entries.map((e) => ({
                entryType: FileType.File,
                name: e.wireName,
                size: BigInt(e.size),
                modifiedTime: seconds(e.modified),
              })),
              fileNum: 0,
              totalSize: BigInt(this.totalBytes),
            },
          },
        },
      });
      this.progress(true);
      // An unknown version gets the digest dialogue too: never overwrite silently.
      const v = this.host.peerVersion;
      const digests = !v || v >= DIGEST_SINCE;
      for (const entry of this.entries) {
        this.check();
        this.current = entry;
        this.fileBytes = 0;
        let offset = 0;
        let skip = false;
        if (digests) ({ skip, offset } = await this.negotiate(entry));
        if (skip) {
          this.skipped++;
          this.totalBytes -= entry.size;
          this.progress(true);
          continue;
        }
        await this.sendFile(entry, offset);
        this.filesDone++;
        this.progress(true);
      }
      this.current = null;
      await this.finish();
    } catch (e) {
      const err =
        e instanceof FileTransferError
          ? e
          : new FileTransferError(`upload failed: ${(e as Error).message}`, "source", this.id, this.current?.index ?? null);
      this.fail(err);
    }
  }

  /** Offers the file's digest and settles overwrite / skip / resume. */
  private async negotiate(entry: UploadEntry): Promise<{ skip: boolean; offset: number }> {
    const resume = !!this.opts.resume && entry.index === 0 && this.host.peerVersion >= RESUME_SINCE;
    const reply = this.waitReply(entry.index);
    this.send({
      case: "fileResponse",
      value: {
        union: {
          case: "digest",
          value: {
            id: this.id,
            fileNum: entry.index,
            lastModified: seconds(entry.modified),
            fileSize: BigInt(entry.size),
            isResume: resume,
          },
        },
      },
    });
    const r = await reply;
    if (r.kind === "confirm") return { skip: r.skip, offset: 0 };

    // The peer has a copy already.
    const d = r.digest;
    const partial = Number(d.transferredSize);
    let skip: boolean;
    let offset = 0;
    // offset_blk is a 32-bit byte offset
    if (resume && d.isIdentical && partial > 0 && partial <= entry.size && partial <= 0xffff_ffff) {
      skip = false;
      offset = partial;
    } else {
      skip = (await this.decide(entry, d)) === "skip";
    }
    this.send({
      case: "fileAction",
      value: {
        union: {
          case: "sendConfirm",
          value: {
            id: this.id,
            fileNum: entry.index,
            union: skip ? { case: "skip", value: true } : { case: "offsetBlk", value: offset },
          },
        },
      },
    });
    return { skip, offset };
  }

  private async decide(entry: UploadEntry, d: FileTransferDigest): Promise<"overwrite" | "skip"> {
    if (this.remembered) return this.remembered;
    const { index, relativePath, remotePath, size, modified } = entry;
    let answer: ConflictAnswer;
    try {
      answer = await this.race(
        this.host.askConflict(
          {
            jobId: this.id,
            file: { index, relativePath, remotePath, size, modified },
            remote: { size: Number(d.fileSize), modified: Number(d.lastModified) * 1000 },
            identical: d.isIdentical,
          },
          this.opts.onConflict,
        ),
      );
    } catch (e) {
      if (e instanceof FileTransferError) throw e;
      throw new FileTransferError(`conflict handler failed: ${(e as Error)?.message ?? e}`, "cancelled", this.id, index, remotePath);
    }
    switch (answer) {
      case "overwriteAll":
        this.remembered = "overwrite";
        return "overwrite";
      case "skipAll":
        this.remembered = "skip";
        return "skip";
      case "overwrite":
        return "overwrite";
      default:
        return "skip";
    }
  }

  private async sendFile(entry: UploadEntry, offset: number): Promise<void> {
    this.fileBytes = offset;
    this.bytes += offset;
    const src = entry.source;
    if (src instanceof Blob) {
      for (let pos = offset; pos < src.size; ) {
        await this.drain();
        const end = Math.min(pos + UPLOAD_CHUNK, src.size);
        let chunk: Uint8Array;
        try {
          chunk = new Uint8Array(await src.slice(pos, end).arrayBuffer());
        } catch (e) {
          throw this.sourceError(entry, e);
        }
        this.check();
        this.sendBlock(entry.index, chunk);
        pos = end;
      }
    } else {
      await this.sendStream(entry, src, offset);
    }
    // An empty block ends the file (and creates it when it is empty).
    this.sendBlock(entry.index, new Uint8Array(0));
  }

  private async sendStream(entry: UploadEntry, stream: ReadableStream<Uint8Array>, offset: number): Promise<void> {
    const reader = stream.getReader();
    let toSkip = offset;
    let pending: Uint8Array[] = [];
    let pendingLen = 0;
    const flush = async (all: boolean) => {
      while (pendingLen >= UPLOAD_CHUNK || (all && pendingLen > 0)) {
        await this.drain();
        const n = Math.min(UPLOAD_CHUNK, pendingLen);
        const chunk = new Uint8Array(n);
        let off = 0;
        while (off < n) {
          const head = pending[0]!;
          const take = Math.min(head.length, n - off);
          chunk.set(head.subarray(0, take), off);
          off += take;
          if (take === head.length) pending.shift();
          else pending[0] = head.subarray(take);
        }
        pendingLen -= n;
        this.sendBlock(entry.index, chunk);
      }
    };
    try {
      for (;;) {
        let r: ReadableStreamReadResult<Uint8Array>;
        try {
          r = await this.race(reader.read());
        } catch (e) {
          if (e instanceof FileTransferError) throw e;
          throw this.sourceError(entry, e);
        }
        if (r.done) break;
        let data = r.value;
        if (toSkip > 0) {
          const s = Math.min(toSkip, data.length);
          toSkip -= s;
          data = data.subarray(s);
        }
        if (!data.length) continue;
        pending.push(data);
        pendingLen += data.length;
        await flush(false);
      }
      await flush(true);
    } catch (e) {
      void reader.cancel().catch(() => {});
      throw e;
    } finally {
      pending = [];
      try {
        reader.releaseLock();
      } catch {
        /* a read was still pending */
      }
    }
  }

  private sendBlock(fileNum: number, data: Uint8Array): void {
    this.check();
    this.send({
      case: "fileResponse",
      value: { union: { case: "block", value: { id: this.id, fileNum, data, compressed: false } } },
    });
    this.fileBytes += data.length;
    this.bytes += data.length;
    this.progress(false);
  }

  /** Tells the peer we are done and waits for it to confirm (it finalizes the last file then). */
  private async finish(): Promise<void> {
    this.echo = new Deferred();
    const n = this.entries.length;
    if (n === 1 && this.skipped === 1) {
      // A single skipped file is reported as such, so the peer leaves its copy untouched.
      this.send({ case: "fileResponse", value: { union: { case: "error", value: { id: this.id, error: "skipped", fileNum: 1 } } } });
    } else {
      this.send({ case: "fileResponse", value: { union: { case: "done", value: { id: this.id, fileNum: n } } } });
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<"timeout">((r) => (timer = setTimeout(() => r("timeout"), this.host.limits.requestTimeoutMs)));
    let answer: "done" | "skipped" | "timeout";
    try {
      answer = await this.race(Promise.race([this.echo.promise, timeout]));
    } finally {
      clearTimeout(timer);
    }
    // Everything was sent; a missing acknowledgement is reported, not failed.
    this.complete(answer !== "timeout");
  }

  private waitReply(fileNum: number): Promise<Reply> {
    const deferred = new Deferred<Reply>();
    this.reply = { fileNum, deferred };
    const timer = setTimeout(
      () =>
        deferred.reject(
          new FileTransferError(
            `the peer did not answer for ${this.entries[fileNum]?.relativePath}`,
            "timeout",
            this.id,
            fileNum,
            this.entries[fileNum]?.remotePath ?? null,
          ),
        ),
      this.host.limits.requestTimeoutMs,
    );
    return this.race(deferred.promise).finally(() => {
      clearTimeout(timer);
      if (this.reply?.deferred === deferred) this.reply = null;
    });
  }

  /** Waits for the WebSocket send buffer to drain below the high-water mark. */
  private async drain(): Promise<void> {
    for (;;) {
      this.check();
      if (!this.host.isOpen()) throw new FileTransferError("connection closed", "closed", this.id);
      if (this.host.bufferedAmount() <= this.host.limits.sendBufferHighWater) return;
      await sleep(5);
    }
  }

  private race<T>(p: Promise<T>): Promise<T> {
    return Promise.race([p, this.failed.promise]);
  }

  private check(): void {
    if (this.failure) throw this.failure;
  }

  private sourceError(entry: UploadEntry, e: unknown): FileTransferError {
    return new FileTransferError(
      `cannot read ${entry.relativePath}: ${(e as Error)?.message ?? String(e)}`,
      "source",
      this.id,
      entry.index,
      entry.remotePath,
    );
  }

  private send(union: MessageUnion): void {
    this.host.send({ union });
  }

  private complete(confirmed: boolean): void {
    if (this.over) return;
    this.over = true;
    this.cleanup();
    this.progress(true);
    this.result.resolve({
      jobId: this.id,
      direction: "upload",
      files: this.filesDone,
      skipped: this.skipped,
      bytes: this.bytes,
      confirmed,
    });
    this.host.finished(this);
  }

  private fail(err: FileTransferError, report = true): void {
    if (this.over) return;
    this.over = true;
    this.failure = err;
    this.cleanup();
    // Let the peer drop its job and partial file.
    if (this.started && err.code !== "closed" && this.host.isOpen()) {
      this.send({ case: "fileAction", value: { union: { case: "cancel", value: { id: this.id } } } });
    }
    this.failed.reject(err);
    this.reply?.deferred.reject(err);
    this.echo?.reject(err);
    this.result.reject(err);
    if (report && err.code !== "cancelled" && err.code !== "closed") this.host.reportError(err);
    this.host.finished(this);
  }

  private cleanup(): void {
    this.opts.signal?.removeEventListener("abort", this.onAbort);
  }

  private progress(force: boolean): void {
    const now = Date.now();
    if (!force && now - this.lastProgress < PROGRESS_INTERVAL_MS) return;
    this.lastProgress = now;
    const e = this.current;
    const p: TransferProgress = {
      jobId: this.id,
      direction: "upload",
      file: e
        ? {
            index: e.index,
            relativePath: e.relativePath,
            remotePath: e.remotePath,
            size: e.size,
            modified: e.modified,
            bytes: this.fileBytes,
          }
        : null,
      files: this.entries.length,
      filesDone: this.filesDone,
      skipped: this.skipped,
      bytes: this.bytes,
      totalBytes: Math.max(this.totalBytes, this.bytes),
    };
    this.host.progress(p, this.opts.onProgress);
  }
}

/** Milliseconds since the epoch to the protocol's seconds. */
function seconds(ms: number): bigint {
  return BigInt(Number.isFinite(ms) && ms > 0 ? Math.floor(ms / 1000) : 0);
}
