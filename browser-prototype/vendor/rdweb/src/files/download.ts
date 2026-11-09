// Download job: asks the peer to send a file or a folder and hands the files
// to the consumer one at a time, as async iterables of chunks.
//
// Peers announce each file with a digest and wait for our answer before
// sending its data; the answer is given when the consumer starts reading the
// file (or skips it), so at most one file is in flight. Blocks are handled in
// arrival order; compressed ones are inflated with a hard size cap, and what
// the consumer has not read yet is bounded by maxBufferedBytes.

import type {
  FileDirectory,
  FileTransferBlock,
  FileTransferDigest,
  FileTransferDone,
  FileTransferError as WireFileError,
} from "../proto/session_pb.js";
import { FileTransferSendRequest_FileType } from "../proto/session_pb.js";
import { inflateCapped } from "../zstd.js";
import { peerError, type JobHost, type TransferJob } from "./job.js";
import { baseNameRemote, joinRemote, safeRelativeSegments } from "./paths.js";
import { AsyncQueue, Deferred } from "./queue.js";
import {
  FileTransferError,
  type DownloadOptions,
  type TransferFileInfo,
  type TransferProgress,
  type TransferResult,
} from "./types.js";

type FileState = "announced" | "accepted" | "skipped" | "discarded" | "finished";

const PROGRESS_INTERVAL_MS = 100;

/** One file of a download. Read it (iterate, stream() or blob()) or skip() it before asking for the next file. */
export class IncomingFile implements TransferFileInfo, AsyncIterable<Uint8Array> {
  readonly index: number;
  readonly relativePath: string;
  readonly remotePath: string;
  readonly size: number;
  readonly modified: number;
  /** @internal */
  readonly chunks = new AsyncQueue<Uint8Array>();
  /** @internal */
  state: FileState;
  /** @internal bytes received from the peer */
  received = 0;
  /** @internal the consumer started reading */
  touched = false;

  constructor(
    private readonly job: Download,
    info: TransferFileInfo,
    state: FileState,
  ) {
    this.index = info.index;
    this.relativePath = info.relativePath;
    this.remotePath = info.remotePath;
    this.size = info.size;
    this.modified = info.modified;
    this.state = state;
  }

  /** The last component of relativePath. */
  get name(): string {
    return this.relativePath.slice(this.relativePath.lastIndexOf("/") + 1);
  }

  [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    this.touched = true;
    this.job.accept(this);
    return {
      next: async () => {
        const r = await this.chunks.next();
        if (!r.done) this.job.consumed(r.value.length);
        return r;
      },
      return: async () => {
        this.job.discard(this);
        return { value: undefined, done: true };
      },
    };
  }

  /** The data as a ReadableStream (pull-based, e.g. for pipeTo a FileSystemWritableFileStream). */
  stream(): ReadableStream<Uint8Array> {
    const it = this[Symbol.asyncIterator]();
    return new ReadableStream<Uint8Array>(
      {
        async pull(controller) {
          const r = await it.next();
          if (r.done) controller.close();
          else controller.enqueue(r.value);
        },
        async cancel() {
          await it.return?.();
        },
      },
      { highWaterMark: 0 },
    );
  }

  /** Collects the file into a Blob; fails with "too-large" beyond maxBytes. */
  async blob(maxBytes = Number.POSITIVE_INFINITY, type = ""): Promise<Blob> {
    const parts: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of this) {
      total += chunk.length;
      if (total > maxBytes) {
        throw new FileTransferError(
          `${this.relativePath} is larger than ${maxBytes} bytes`,
          "too-large",
          this.job.id,
          this.index,
          this.remotePath,
        );
      }
      parts.push(chunk);
    }
    return new Blob(parts as BlobPart[], { type });
  }

  /** Do not transfer this file (or drop the rest of it if it is already arriving). */
  skip(): void {
    this.job.skip(this);
  }
}

export class Download implements TransferJob, AsyncIterable<IncomingFile> {
  readonly direction = "download" as const;
  private readonly queue = new AsyncQueue<IncomingFile>();
  private readonly list = new Deferred<TransferFileInfo[]>();
  private readonly result = new Deferred<TransferResult>();
  private infos: TransferFileInfo[] | null = null;
  private current: IncomingFile | null = null;
  private yielded: IncomingFile | null = null;
  private open: IncomingFile[] = [];
  /** Highest file index announced so far. */
  private seen = -1;
  private started = false;
  private over = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private bytes = 0;
  private totalBytes = 0;
  private filesDone = 0;
  private skipped = 0;
  private lastSkipped = -1;
  private buffered = 0;
  private lastProgress = 0;
  private readonly onAbort = () => this.cancel();

  constructor(
    private readonly host: JobHost,
    readonly id: number,
    /** The remote file or folder being downloaded. */
    readonly remotePath: string,
    private readonly opts: DownloadOptions,
  ) {
    opts.signal?.addEventListener("abort", this.onAbort, { once: true });
  }

  /**
   * Resolves when every file arrived (or was skipped); rejects on error or
   * cancel. Files are only requested as they are consumed, so iterate the
   * job (or use saveTo / downloadBlob): awaiting this alone waits forever.
   */
  get done(): Promise<TransferResult> {
    return this.result.promise;
  }

  /** The job's file list, once the peer sent it. */
  get files(): Promise<TransferFileInfo[]> {
    return this.list.promise;
  }

  /**
   * Iterates the files in order. Handle each file before asking for the
   * next: a file nobody started reading by then is skipped. Leaving the loop
   * early cancels the download.
   */
  [Symbol.asyncIterator](): AsyncIterator<IncomingFile> {
    return {
      next: async () => {
        const prev = this.yielded;
        // a file the consumer passed over without reading is not wanted
        if (prev && !prev.touched) this.skip(prev);
        const r = await this.queue.next();
        this.yielded = r.done ? null : r.value;
        return r;
      },
      return: async () => {
        this.cancel();
        return { value: undefined, done: true };
      },
    };
  }

  /**
   * Writes every file to the stream `open` returns for it (null/undefined
   * skips the file), e.g. a FileSystemWritableFileStream.
   */
  async saveTo(
    open: (file: IncomingFile) => WritableStream<Uint8Array> | null | undefined | Promise<WritableStream<Uint8Array> | null | undefined>,
  ): Promise<TransferResult> {
    for await (const file of this) {
      const sink = await open(file);
      if (!sink) {
        file.skip();
        continue;
      }
      await file.stream().pipeTo(sink);
    }
    return this.done;
  }

  cancel(): void {
    if (this.over) return;
    this.fail(new FileTransferError("download cancelled", "cancelled", this.id, null, this.remotePath));
  }

  // ------------------------------------------------------------- job hooks

  start(): void {
    if (this.over) return;
    this.started = true;
    this.host.send({
      union: {
        case: "fileAction",
        value: {
          union: {
            case: "send",
            value: {
              id: this.id,
              path: this.remotePath,
              includeHidden: this.opts.showHidden ?? false,
              fileNum: 0,
              fileType: FileTransferSendRequest_FileType.Generic,
            },
          },
        },
      },
    });
    this.timer = setTimeout(
      () => this.fail(new FileTransferError(`no answer for ${this.remotePath}`, "timeout", this.id, null, this.remotePath)),
      this.host.limits.requestTimeoutMs,
    );
    this.progress(true);
  }

  onDir(fd: FileDirectory): void {
    if (this.over || this.infos) return;
    this.clearTimer();
    const sep = this.host.sep;
    const single = fd.entries.length === 1 && fd.entries[0]!.name === "";
    const base = localName(baseNameRemote(this.remotePath, sep));
    const infos: TransferFileInfo[] = [];
    try {
      fd.entries.forEach((e, index) => {
        if (single) {
          infos.push({
            index,
            relativePath: base,
            remotePath: this.remotePath,
            size: Number(e.size),
            modified: Number(e.modifiedTime) * 1000,
          });
          return;
        }
        const segs = safeRelativeSegments(e.name);
        if (!segs.length) throw new FileTransferError("the peer sent an empty file name", "invalid-name");
        infos.push({
          index,
          relativePath: [base, ...segs].filter(Boolean).join("/"),
          remotePath: joinRemote(this.remotePath, e.name, sep),
          size: Number(e.size),
          modified: Number(e.modifiedTime) * 1000,
        });
      });
    } catch (e) {
      const err = e as FileTransferError;
      this.fail(new FileTransferError(err.message, err.code, this.id, null, this.remotePath));
      return;
    }
    this.infos = infos;
    this.totalBytes = infos.reduce((n, f) => n + f.size, 0);
    this.list.resolve(infos);
    this.progress(true);
  }

  onDigest(d: FileTransferDigest): void {
    if (this.over) return;
    const info = this.fileInfo(d.fileNum);
    if (!info) return;
    if (this.current?.index === d.fileNum) return; // repeated digest
    if (d.fileNum <= this.seen) {
      this.protocolError(`file ${d.fileNum} announced again`);
      return;
    }
    this.finishCurrent();
    const size = Number(d.fileSize);
    this.totalBytes += size - info.size;
    const f = new IncomingFile(this, { ...info, size, modified: Number(d.lastModified) * 1000 || info.modified }, "announced");
    this.announce(f);
  }

  onBlock(b: FileTransferBlock): void {
    if (this.over) return;
    const info = this.fileInfo(b.fileNum);
    if (!info) return;
    const max = this.host.limits.maxBlockSize;
    if (b.data.length > max) {
      this.fail(
        new FileTransferError(
          `the peer sent a ${b.data.length} byte block (limit ${max})`,
          "oversize-block",
          this.id,
          b.fileNum,
          info.remotePath,
        ),
      );
      return;
    }
    let f = this.current;
    if (!f || f.index !== b.fileNum) {
      if (b.fileNum <= this.seen) {
        this.protocolError(`data for file ${b.fileNum}, which is not the current one`);
        return;
      }
      // Peers that do not announce files with a digest just start sending.
      this.finishCurrent();
      f = new IncomingFile(this, info, "accepted");
      this.announce(f);
    }
    // Data without our go-ahead: take it rather than lose it.
    if (f.state === "announced") f.state = "accepted";
    if (b.data.length === 0) {
      this.finishCurrent();
      return;
    }
    let chunk = b.data;
    if (b.compressed) {
      try {
        chunk = inflateCapped(b.data, max);
      } catch (e) {
        this.fail(
          new FileTransferError(
            `bad compressed block: ${(e as Error).message}`,
            "decompress",
            this.id,
            b.fileNum,
            info.remotePath,
          ),
        );
        return;
      }
    }
    this.bytes += chunk.length;
    f.received += chunk.length;
    if (f.state === "accepted") {
      f.chunks.push(chunk);
      this.buffered += chunk.length;
      if (this.buffered > this.host.limits.maxBufferedBytes) {
        this.fail(
          new FileTransferError(
            `more than ${this.host.limits.maxBufferedBytes} bytes received but not read`,
            "overflow",
            this.id,
            f.index,
            f.remotePath,
          ),
        );
        return;
      }
    }
    this.progress(false);
  }

  onDone(_d: FileTransferDone): void {
    if (this.over) return;
    if (!this.infos) {
      this.protocolError("the transfer ended before its file list");
      return;
    }
    this.finishCurrent();
    this.complete();
  }

  onError(e: WireFileError): void {
    if (this.over) return;
    // A single-file job whose file we skipped ends with "skipped".
    if (e.error === "skipped" && this.lastSkipped >= 0 && this.infos?.length === 1) {
      this.complete();
      return;
    }
    // Peers move past a file before reporting that it could not be read.
    const index =
      this.current?.index ??
      (this.infos && e.fileNum >= 1 && e.fileNum <= this.infos.length ? e.fileNum - 1 : null);
    const path = (index !== null && this.infos?.[index]?.remotePath) || this.remotePath;
    this.fail(peerError(e, path, `download of ${this.remotePath} failed`, index));
  }

  abort(err: FileTransferError): void {
    // the session reports the reason itself
    this.fail(err, false);
  }

  // ------------------------------------------------------- consumer hooks

  /** @internal The consumer started reading `f`. */
  accept(f: IncomingFile): void {
    if (f.state !== "announced" || this.over) return;
    f.state = "accepted";
    this.confirm(f.index, false);
  }

  /** @internal */
  consumed(n: number): void {
    this.buffered = Math.max(0, this.buffered - n);
  }

  /** @internal The consumer stopped reading `f`. */
  discard(f: IncomingFile): void {
    if (f.state === "announced") {
      this.skip(f);
      return;
    }
    if (f.state !== "accepted" && f.state !== "finished") return;
    if (f.state === "accepted") f.state = "discarded";
    else if (!f.touched) {
      // arrived completely but passed over unread
      this.filesDone--;
      this.skipped++;
    }
    for (const c of f.chunks.drain()) this.consumed(c.length);
    f.chunks.end();
  }

  /** @internal */
  skip(f: IncomingFile): void {
    if (this.over) return;
    if (f.state === "announced") {
      f.state = "skipped";
      f.chunks.end();
      this.skipped++;
      this.lastSkipped = f.index;
      this.totalBytes -= f.size;
      this.confirm(f.index, true);
      this.progress(true);
      return;
    }
    this.discard(f);
  }

  // --------------------------------------------------------------- private

  private announce(f: IncomingFile): void {
    this.current = f;
    this.seen = f.index;
    this.open.push(f);
    this.queue.push(f);
    this.progress(true);
  }

  private finishCurrent(): void {
    const f = this.current;
    this.current = null;
    if (!f) return;
    if (f.state === "accepted") {
      f.state = "finished";
      f.chunks.end();
      this.filesDone++;
      this.progress(true, f);
    } else if (f.state === "discarded" || f.state === "announced") {
      // abandoned by the consumer, or passed over by the peer without our go-ahead
      f.state = f.state === "announced" ? "skipped" : "discarded";
      f.chunks.end();
      this.skipped++;
      this.progress(true);
    }
    this.open = this.open.filter((x) => x !== f);
  }

  private confirm(fileNum: number, skip: boolean): void {
    this.host.send({
      union: {
        case: "fileAction",
        value: {
          union: {
            case: "sendConfirm",
            value: {
              id: this.id,
              fileNum,
              union: skip ? { case: "skip", value: true } : { case: "offsetBlk", value: 0 },
            },
          },
        },
      },
    });
  }

  private fileInfo(fileNum: number): TransferFileInfo | null {
    if (!this.infos) {
      this.protocolError("file data before the file list");
      return null;
    }
    const info = this.infos[fileNum];
    if (!info) {
      this.protocolError(`file number ${fileNum} is not in the file list`);
      return null;
    }
    return info;
  }

  private protocolError(what: string): void {
    this.fail(new FileTransferError(`protocol error: ${what}`, "protocol", this.id, null, this.remotePath));
  }

  private complete(): void {
    if (this.over) return;
    this.over = true;
    this.cleanup();
    this.queue.end();
    this.progress(true);
    this.result.resolve({
      jobId: this.id,
      direction: "download",
      files: this.filesDone,
      skipped: this.skipped,
      bytes: this.bytes,
      confirmed: true,
    });
    this.host.finished(this);
  }

  private fail(err: FileTransferError, report = true): void {
    if (this.over) return;
    this.over = true;
    this.cleanup();
    if (this.started && err.code !== "closed" && this.host.isOpen()) {
      this.host.send({ union: { case: "fileAction", value: { union: { case: "cancel", value: { id: this.id } } } } });
    }
    for (const f of this.open) if (f.state === "accepted" || f.state === "announced") f.chunks.fail(err);
    this.open = [];
    this.current = null;
    this.queue.fail(err);
    this.list.reject(err);
    this.result.reject(err);
    if (report && err.code !== "cancelled" && err.code !== "closed") this.host.reportError(err);
    this.host.finished(this);
  }

  private cleanup(): void {
    this.clearTimer();
    this.opts.signal?.removeEventListener("abort", this.onAbort);
  }

  private clearTimer(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private progress(force: boolean, file: IncomingFile | null = this.current): void {
    const now = Date.now();
    if (!force && now - this.lastProgress < PROGRESS_INTERVAL_MS) return;
    this.lastProgress = now;
    const f = file && file.state !== "skipped" ? file : null;
    const p: TransferProgress = {
      jobId: this.id,
      direction: "download",
      file: f
        ? {
            index: f.index,
            relativePath: f.relativePath,
            remotePath: f.remotePath,
            size: f.size,
            modified: f.modified,
            bytes: f.received,
          }
        : null,
      files: this.infos?.length ?? 0,
      filesDone: this.filesDone,
      skipped: this.skipped,
      bytes: this.bytes,
      totalBytes: Math.max(this.totalBytes, this.bytes),
    };
    this.host.progress(p, this.opts.onProgress);
  }
}

/** The downloaded item's own name as a local folder/file name ("C:" -> "C", ".." -> "download"). */
function localName(name: string): string {
  const clean = name.replace(/[\u0000-\u001f<>:"/\\|?*]/g, "").trim();
  return clean && clean !== "." && clean !== ".." ? clean : "download";
}
