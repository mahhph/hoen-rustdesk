// A file transfer session with one peer: same rendezvous, authentication and
// login as a remote desktop session (conn_type FILE_TRANSFER), then remote
// listings, downloads, uploads and file operations.
//
// Transfers run one at a time in the order they were started (the peer works
// through its jobs one by one as well); listings and file operations are
// independent of them. Listings carry no job id on the wire, so they are
// serialized and matched by path.

import {
  isRetryable,
  PeerConnector,
  SessionError,
  toSessionError,
  versionNumber,
} from "../connector.js";
import { parseServerKey } from "../crypto.js";
import { Emitter } from "../emitter.js";
import { peerOsFromPlatform } from "../keymap.js";
import { ConnType } from "../proto/rendezvous_pb.js";
import {
  FileType,
  PermissionInfo_Permission as Permission,
  type FileDirectory,
  type FileEntry,
  type FileResponse,
  type FileTransferError as WireFileError,
  type Message,
  type PeerInfo,
} from "../proto/session_pb.js";
import type { CloseInfo, PermissionName, SessionState } from "../types.js";
import { Download } from "./download.js";
import {
  peerError,
  type FileActionUnion,
  type FileJob,
  type JobHost,
  type JobLimits,
  type MessageInit,
  type TransferJob,
} from "./job.js";
import { checkPlainName, joinRemote, parentRemote, safeRelativeSegments, type Separator } from "./paths.js";
import { Deferred } from "./queue.js";
import { Upload, type UploadEntry } from "./upload.js";
import {
  FileTransferError,
  type ConflictAnswer,
  type DownloadOptions,
  type FilePeerSummary,
  type FileTransferEventMap,
  type FileTransferOptions,
  type RemoteDirectory,
  type RemoteEntry,
  type RemoteEntryType,
  type RemoveOptions,
  type TransferFileInfo,
  type TransferProgress,
  type UploadConflict,
  type UploadItem,
  type UploadOptions,
} from "./types.js";

const DEFAULT_LIMITS: JobLimits = {
  requestTimeoutMs: 30_000,
  maxBlockSize: 1 << 20,
  maxBufferedBytes: 32 << 20,
  sendBufferHighWater: 1 << 20,
};

const NO_USER = "no user is logged on at the remote device; log on there first";
/** How long connect() waits for the peer's first listing. */
const INITIAL_LISTING_MS = 10_000;

export class FileTransferSession {
  readonly peerId: string;
  private readonly events = new Emitter<FileTransferEventMap>();
  private stateValue: SessionState = "idle";
  private readonly abort = new AbortController();
  private readonly link: PeerConnector;
  private readonly limits: JobLimits;
  private readonly showHidden: boolean;
  private peerInfo: FilePeerSummary | null = null;
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
  private closedInfo: CloseInfo | null = null;
  private problem: SessionError | null = null;
  private home: RemoteDirectory | null = null;
  /** The remote user's home folder, once a listing of "" told us. */
  private homePath: string | null = null;
  private readonly initialDir: string;
  private readonly initial = new Deferred<RemoteDirectory | null>();
  private initialSeen = false;

  private nextId = 1;
  private readonly jobs = new Map<number, FileJob>();
  private readonly queue: TransferJob[] = [];
  private active: TransferJob | null = null;
  private listChain: Promise<unknown> = Promise.resolve();
  private listing: { path: string; deferred: Deferred<RemoteDirectory> } | null = null;
  private readonly host: JobHost;

  constructor(opts: FileTransferOptions) {
    this.peerId = opts.peerId.replace(/\s+/g, "");
    if (!this.peerId) throw new SessionError("peer id is empty", "bad-config");
    // fail early on a missing/bad key: we never connect unauthenticated
    if (!opts.hoen) parseServerKey(opts.server.key);
    this.limits = {
      requestTimeoutMs: opts.requestTimeoutMs ?? DEFAULT_LIMITS.requestTimeoutMs,
      maxBlockSize: opts.maxBlockSize ?? DEFAULT_LIMITS.maxBlockSize,
      maxBufferedBytes: opts.maxBufferedBytes ?? DEFAULT_LIMITS.maxBufferedBytes,
      sendBufferHighWater: opts.sendBufferHighWater ?? DEFAULT_LIMITS.sendBufferHighWater,
    };
    this.showHidden = opts.showHidden ?? false;
    this.initialDir = opts.initialDir ?? "";
    this.link = new PeerConnector(
      {
        peerId: this.peerId,
        server: opts.server,
        hoen: opts.hoen,
        connType: ConnType.FILE_TRANSFER,
        rememberedHash: opts.rememberedHash,
        myName: opts.myName,
        myId: opts.myId,
        clientVersion: opts.clientVersion,
        loginExtras: () => ({
          union: { case: "fileTransfer", value: { dir: this.initialDir, showHidden: this.showHidden } },
        }),
        loginErrorCode: (e) => (/no permission/i.test(e) ? "permission-denied" : "login"),
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
    const self = this; // for the getters below
    this.host = {
      limits: this.limits,
      get sep() {
        return self.separator;
      },
      get peerVersion() {
        return versionNumber(self.peerInfo?.version ?? "");
      },
      send: (init: MessageInit) => this.link.send(init),
      isOpen: () => this.link.isOpen,
      bufferedAmount: () => this.link.bufferedAmount,
      progress: (p, cb) => this.emitProgress(p, cb),
      reportError: (err) => this.reportError(err),
      askConflict: (c, cb) => this.askConflict(c, cb),
      finished: (job) => this.jobFinished(job),
    };
  }

  // ------------------------------------------------------------------ state

  get state(): SessionState {
    return this.stateValue;
  }

  get peer(): FilePeerSummary | null {
    return this.peerInfo;
  }

  /** The folder the peer listed first (the remote user's home unless initialDir was given). */
  get homeDir(): string {
    return this.home?.path ?? "";
  }

  /** Path separator of the remote file system ("\" on Windows). */
  get separator(): Separator {
    return this.peerInfo?.separator ?? "/";
  }

  get permission(): Readonly<Record<PermissionName, boolean>> {
    return this.permissions;
  }

  /** Why the session closed, once it has. */
  get closeInfo(): CloseInfo | null {
    return this.closedInfo;
  }

  on<K extends keyof FileTransferEventMap>(type: K, fn: (ev: FileTransferEventMap[K]) => void): () => void {
    return this.events.on(type, fn);
  }

  /**
   * Connects, logs in and waits for the first listing (see homeDir). While
   * waiting it may emit `password`, `twoFactor` or `waitingForApproval`.
   */
  async connect(): Promise<void> {
    if (this.stateValue !== "idle") throw new SessionError("connect() can only be called once", "state");
    try {
      await this.link.connect(this.abort.signal);
      if (this.problem) throw this.problem;
      const home = await this.waitInitialListing();
      this.home = home;
      this.setState("connected");
      this.events.emit("connected", { peer: this.peerInfo!, rememberedHash: this.link.rememberedHash, home });
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
        this.link.send({ union: { case: "misc", value: { union: { case: "closeReason", value: reason } } } });
      } catch {
        /* ignore */
      }
    }
    this.shutdown({ reason, remote: false, retryable: false });
  }

  // ------------------------------------------------------------------ paths

  /** Joins a remote folder and a name ("/" + "C:" gives "C:\" on Windows). */
  joinPath(dir: string, name: string): string {
    return joinRemote(dir, name, this.separator);
  }

  /** The parent folder; on Windows a drive root's parent is the drive list "/". */
  parentPath(path: string): string {
    return parentRemote(path, this.separator);
  }

  // --------------------------------------------------------------- listings

  /**
   * Lists a remote folder. An empty path lists the remote user's home; on
   * Windows peers "/" lists the drives.
   */
  listDir(path: string, opts: { showHidden?: boolean } = {}): Promise<RemoteDirectory> {
    const blocked = this.blocked(path);
    if (blocked) return Promise.reject(blocked);
    const showHidden = opts.showHidden ?? this.showHidden;
    const task = this.listChain.then(() => this.readDir(path, showHidden));
    this.listChain = task.catch(() => {});
    return task;
  }

  // -------------------------------------------------------------- transfers

  /**
   * Downloads a remote file or folder (recursively). Iterate the returned
   * job to receive the files; see Download.
   */
  download(remotePath: string, opts: DownloadOptions = {}): Download {
    const blocked = this.blocked(remotePath);
    if (blocked) throw blocked;
    const job = new Download(this.host, this.allocId(), remotePath, opts);
    if (opts.signal?.aborted) job.cancel();
    else this.enqueue(job);
    return job;
  }

  /** Downloads one remote file into a Blob (for small files). */
  async downloadBlob(
    remotePath: string,
    opts: DownloadOptions & { maxBytes?: number; type?: string } = {},
  ): Promise<{ file: TransferFileInfo; blob: Blob }> {
    const job = this.download(remotePath, opts);
    const files = await job.files;
    if (files.length !== 1 || files[0]!.remotePath !== remotePath) {
      job.cancel();
      throw new FileTransferError(`${remotePath} is not a file`, "not-a-file", job.id, null, remotePath);
    }
    let out: { file: TransferFileInfo; blob: Blob } | null = null;
    for await (const file of job) {
      const { index, relativePath, size, modified } = file;
      out = { file: { index, relativePath, remotePath: file.remotePath, size, modified }, blob: await file.blob(opts.maxBytes ?? 64 << 20, opts.type) };
    }
    await job.done;
    if (!out) throw new FileTransferError(`${remotePath} was skipped`, "not-a-file", job.id, null, remotePath);
    return out;
  }

  /**
   * Uploads files into a remote folder; relative paths create sub-folders.
   * Accepts File objects (webkitRelativePath is honoured) or UploadItem.
   */
  upload(files: Iterable<File | UploadItem>, remoteDir: string, opts: UploadOptions = {}): Upload {
    const blocked = this.blocked(remoteDir);
    if (blocked) throw blocked;
    if (!remoteDir) throw new FileTransferError("the target folder is empty", "invalid-name");
    const sep = this.separator;
    const entries: UploadEntry[] = [];
    let index = 0;
    for (const item of files) {
      const isFile = typeof File !== "undefined" && item instanceof File;
      const data = isFile ? (item as File) : (item as UploadItem).data;
      const rel =
        (isFile ? (item as File).webkitRelativePath : (item as UploadItem).relativePath) || item.name;
      const segs = safeRelativeSegments(rel);
      if (!segs.length) throw new FileTransferError(`invalid upload name ${JSON.stringify(rel)}`, "invalid-name");
      let size: number;
      if (data instanceof Blob) size = data.size;
      else if (typeof (item as UploadItem).size === "number") size = (item as UploadItem).size!;
      else throw new TypeError(`upload ${rel}: size is required for a stream`);
      const lastModified = isFile ? (item as File).lastModified : ((item as UploadItem).lastModified ?? Date.now());
      const wireName = segs.join(sep);
      entries.push({
        index: index++,
        relativePath: segs.join("/"),
        remotePath: joinRemote(remoteDir, wireName, sep),
        size,
        modified: lastModified,
        wireName,
        source: data,
      });
    }
    const job = new Upload(this.host, this.allocId(), remoteDir, entries, opts);
    if (opts.signal?.aborted) job.cancel();
    else this.enqueue(job);
    return job;
  }

  // -------------------------------------------------------- file operations

  /** Creates a remote folder (with missing parents). */
  async mkdir(path: string): Promise<void> {
    await this.operation(path, `cannot create ${path}`, async (op) => {
      await op.request({ case: "create", value: { id: op.id, path } }, "done");
    });
  }

  /** Renames a remote file or folder within its folder. */
  async rename(path: string, newName: string): Promise<void> {
    checkPlainName(newName);
    await this.operation(path, `cannot rename ${path}`, async (op) => {
      await op.request({ case: "rename", value: { id: op.id, path, newName } }, "done");
    });
  }

  /**
   * Removes a remote file, or a folder with `dir`. A non-empty folder needs
   * `recursive`: its files are removed one by one, then the empty folders.
   */
  async remove(path: string, opts: RemoveOptions = {}): Promise<void> {
    await this.operation(path, `cannot remove ${path}`, async (op) => {
      if (!opts.dir) {
        await op.request({ case: "removeFile", value: { id: op.id, path, fileNum: 0 } }, "done");
        return;
      }
      if (opts.recursive) {
        const fd = await op.request({ case: "allFiles", value: { id: op.id, path, includeHidden: true } }, "dir");
        const files = fd?.entries ?? [];
        for (let i = 0; i < files.length; i++) {
          const name = files[i]!.name;
          const filePath = name ? this.joinPath(path, name) : path;
          await op.request({ case: "removeFile", value: { id: op.id, path: filePath, fileNum: i } }, "done");
          opts.onProgress?.(i + 1, files.length);
        }
      }
      await op.request({ case: "removeDir", value: { id: op.id, path, recursive: !!opts.recursive } }, "done");
    });
  }

  // ---------------------------------------------------------------- private

  private setState(state: SessionState): void {
    if (this.stateValue === state) return;
    this.stateValue = state;
    this.events.emit("state", { state });
  }

  private blocked(path: string | null): FileTransferError | null {
    if (this.stateValue !== "connected") return new FileTransferError("not connected", "closed", null, null, path);
    if (!this.permissions.file) {
      return new FileTransferError("file transfer is disabled on the remote side", "permission-denied", null, null, path);
    }
    return null;
  }

  private allocId(): number {
    const id = this.nextId;
    this.nextId = this.nextId >= 0x7fff_ffff ? 1 : this.nextId + 1;
    return id;
  }

  private enqueue(job: TransferJob): void {
    this.jobs.set(job.id, job);
    this.queue.push(job);
    this.pump();
  }

  private pump(): void {
    if (this.active || this.stateValue === "closed") return;
    const next = this.queue.shift();
    if (!next) return;
    this.active = next;
    next.start();
  }

  private jobFinished(job: FileJob): void {
    if (this.jobs.get(job.id) === job) this.jobs.delete(job.id);
    const i = this.queue.indexOf(job as TransferJob);
    if (i >= 0) this.queue.splice(i, 1);
    if (this.active === job) {
      this.active = null;
      queueMicrotask(() => this.pump());
    }
  }

  private async operation(path: string, what: string, fn: (op: Operation) => Promise<void>): Promise<void> {
    const blocked = this.blocked(path);
    if (blocked) throw blocked;
    const op = new Operation(this.host, this.allocId(), path, what);
    this.jobs.set(op.id, op);
    try {
      await fn(op);
    } catch (e) {
      if (e instanceof FileTransferError && e.code !== "cancelled" && e.code !== "closed") this.reportError(e);
      throw e;
    } finally {
      this.jobFinished(op);
    }
  }

  private readDir(path: string, showHidden: boolean): Promise<RemoteDirectory> {
    const blocked = this.blocked(path);
    if (blocked) return Promise.reject(blocked);
    const deferred = new Deferred<RemoteDirectory>();
    this.listing = { path, deferred };
    const timer = setTimeout(
      () => deferred.reject(new FileTransferError(`listing ${path || "home"} timed out`, "timeout", null, null, path)),
      this.limits.requestTimeoutMs,
    );
    this.link.send({
      union: { case: "fileAction", value: { union: { case: "readDir", value: { path, includeHidden: showHidden } } } },
    });
    return deferred.promise.finally(() => {
      clearTimeout(timer);
      if (this.listing?.deferred === deferred) this.listing = null;
    });
  }

  private waitInitialListing(): Promise<RemoteDirectory | null> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    return Promise.race([
      this.initial.promise,
      new Promise<null>(
        (resolve) =>
          (timer = setTimeout(
            () => {
              // give up on it; a late one must not be mistaken for an answer
              this.initialSeen = true;
              resolve(null);
            },
            Math.min(this.limits.requestTimeoutMs, INITIAL_LISTING_MS),
          )),
      ),
    ]).finally(() => clearTimeout(timer));
  }

  private onLoggedIn(pi: PeerInfo): void {
    this.applyPeerInfo(pi);
    const sessions = pi.windowsSessions?.sessions ?? [];
    if (!pi.username && sessions.length === 0) {
      this.problem = new SessionError(NO_USER, "no-user");
      return;
    }
    // A Windows host with several user sessions waits for us to pick one
    // before it lists anything; stay in the session it runs in.
    if (sessions.length > 0) {
      this.link.send({
        union: { case: "misc", value: { union: { case: "selectedSid", value: pi.windowsSessions!.currentSid } } },
      });
    }
  }

  private applyPeerInfo(pi: PeerInfo): void {
    const os = peerOsFromPlatform(pi.platform);
    this.peerInfo = {
      id: this.peerId,
      username: pi.username,
      hostname: pi.hostname,
      platform: pi.platform,
      os,
      version: pi.version,
      separator: os === "windows" ? "\\" : "/",
      windowsSessions: (pi.windowsSessions?.sessions ?? []).map((s) => ({ sid: s.sid, name: s.name })),
      currentWindowsSession: pi.windowsSessions?.currentSid ?? 0,
    };
  }

  private onMessage(msg: Message): void {
    const u = msg.union;
    switch (u.case) {
      case "fileResponse":
        this.onFileResponse(u.value);
        return;
      case "fileAction":
        // The peer confirms our upload digests with a send confirmation.
        if (u.value.union.case === "sendConfirm") this.jobs.get(u.value.union.value.id)?.onConfirm?.(u.value.union.value);
        return;
      case "testDelay":
        if (!u.value.fromClient) this.link.send({ union: { case: "testDelay", value: u.value } });
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
      case "misc": {
        const m = u.value.union;
        if (m.case === "permissionInfo") this.onPermission(m.value.permission, m.value.enabled);
        else if (m.case === "closeReason") {
          this.link.rejectLogin(new SessionError(m.value, "remote-closed"));
          this.shutdown({ reason: m.value || "closed by the remote side", remote: true, retryable: false });
        }
        return;
      }
      default:
        return;
    }
  }

  private onFileResponse(r: FileResponse): void {
    const u = r.union;
    switch (u.case) {
      case "dir": {
        const job = u.value.id ? this.jobs.get(u.value.id) : undefined;
        if (job) job.onDir?.(u.value);
        else if (!u.value.id) this.onListing(u.value);
        return;
      }
      case "block":
        this.jobs.get(u.value.id)?.onBlock?.(u.value);
        return;
      case "digest":
        this.jobs.get(u.value.id)?.onDigest?.(u.value);
        return;
      case "done":
        this.jobs.get(u.value.id)?.onDone(u.value);
        return;
      case "error": {
        const job = u.value.id ? this.jobs.get(u.value.id) : undefined;
        if (job) job.onError(u.value);
        else if (!u.value.id) this.onListingError(u.value);
        return;
      }
      default:
        return;
    }
  }

  private onListing(fd: FileDirectory): void {
    const dir = toDirectory(fd);
    if (!this.initialSeen) {
      this.initialSeen = true;
      if (!this.initialDir) this.homePath = fd.path;
      this.initial.resolve(dir);
      return;
    }
    const p = this.listing;
    if (!p) return;
    // "" asks for home: once home is known, accept only that (not a late answer to an older request)
    if (samePath(p.path || this.homePath || "", fd.path, this.separator)) {
      if (!p.path) this.homePath = fd.path;
      p.deferred.resolve(dir);
    }
    // anything else answers a listing that already timed out
  }

  private onListingError(e: WireFileError): void {
    if (!this.initialSeen) {
      this.initialSeen = true;
      this.initial.resolve(null);
      this.reportError(peerError(e, null, "the first listing failed"));
      return;
    }
    const p = this.listing;
    const err = peerError(e, p?.path ?? null, `cannot list ${p ? p.path || "home" : "a folder"}`);
    this.reportError(err);
    p?.deferred.reject(err);
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
    const was = this.permissions[name];
    this.permissions = { ...this.permissions, [name]: enabled };
    this.events.emit("permission", { name, enabled });
    if (name === "file" && was && !enabled) {
      const err = new FileTransferError("file transfer was disabled on the remote side", "permission-denied");
      this.reportError(err);
      this.abortAll(err);
    }
  }

  private abortAll(err: FileTransferError): void {
    for (const job of [...this.jobs.values()]) job.abort(err);
    this.listing?.deferred.reject(err);
  }

  private emitProgress(p: TransferProgress, cb: ((p: TransferProgress) => void) | undefined): void {
    if (cb) {
      try {
        cb(p);
      } catch (e) {
        console.error("rdweb: onProgress failed", e);
      }
    }
    this.events.emit("progress", p);
  }

  private reportError(err: FileTransferError): void {
    this.events.emit("error", {
      code: err.code,
      message: err.message,
      jobId: err.jobId,
      fileIndex: err.fileIndex,
      path: err.path,
      remoteMessage: err.remoteMessage,
    });
  }

  private askConflict(
    c: UploadConflict,
    cb: ((c: UploadConflict) => ConflictAnswer | Promise<ConflictAnswer>) | undefined,
  ): Promise<ConflictAnswer> {
    if (cb) return Promise.resolve().then(() => cb(c));
    if (this.events.listenerCount("conflict") === 0) return Promise.resolve("skip");
    return new Promise((resolve) => {
      let answered = false;
      this.events.emit("conflict", {
        conflict: c,
        answer: (a) => {
          if (answered) return;
          answered = true;
          resolve(a);
        },
      });
    });
  }

  private shutdown(info: CloseInfo): void {
    if (this.stateValue === "closed") return;
    this.closedInfo = info;
    this.abort.abort();
    this.link.close(info.reason);
    this.setState("closed");
    const err = new FileTransferError(info.reason, "closed");
    this.queue.length = 0;
    this.abortAll(err);
    this.jobs.clear();
    this.active = null;
    this.initial.reject(new SessionError(info.reason, "closed"));
    this.events.emit("close", info);
  }
}

/** A mkdir / rename / remove request; steps share the job id and are answered with done or error. */
class Operation implements FileJob {
  private step: { expect: "done" | "dir"; deferred: Deferred<FileDirectory | null> } | null = null;

  constructor(
    private readonly host: JobHost,
    readonly id: number,
    private readonly path: string,
    private readonly what: string,
  ) {}

  request(action: FileActionUnion, expect: "done" | "dir"): Promise<FileDirectory | null> {
    const deferred = new Deferred<FileDirectory | null>();
    this.step = { expect, deferred };
    const timer = setTimeout(
      () => deferred.reject(new FileTransferError(`${this.what}: no answer`, "timeout", this.id, null, this.path)),
      this.host.limits.requestTimeoutMs,
    );
    if (!this.host.isOpen()) deferred.reject(new FileTransferError("not connected", "closed", this.id, null, this.path));
    else this.host.send({ union: { case: "fileAction", value: { union: action } } });
    return deferred.promise.finally(() => {
      clearTimeout(timer);
      if (this.step?.deferred === deferred) this.step = null;
    });
  }

  onDir(fd: FileDirectory): void {
    if (this.step?.expect === "dir") this.step.deferred.resolve(fd);
  }

  onDone(): void {
    if (this.step?.expect === "done") this.step.deferred.resolve(null);
  }

  onError(e: WireFileError): void {
    this.step?.deferred.reject(peerError(e, this.path, this.what));
  }

  abort(err: FileTransferError): void {
    this.step?.deferred.reject(err);
  }
}

function entryType(t: FileType): RemoteEntryType {
  switch (t) {
    case FileType.Dir:
      return "dir";
    case FileType.DirLink:
      return "dirLink";
    case FileType.DirDrive:
      return "drive";
    case FileType.File:
      return "file";
    case FileType.FileLink:
      return "fileLink";
    default:
      return "unknown";
  }
}

function toEntry(e: FileEntry): RemoteEntry {
  return {
    name: e.name,
    type: entryType(e.entryType),
    size: Number(e.size),
    modified: Number(e.modifiedTime) * 1000,
    hidden: e.isHidden,
  };
}

function toDirectory(fd: FileDirectory): RemoteDirectory {
  return { path: fd.path, entries: fd.entries.map(toEntry) };
}

/** Whether a listing for `got` answers a request for `asked` ("" asks for home, which can be anything). */
function samePath(asked: string, got: string, sep: Separator): boolean {
  if (asked === "" || asked === got) return true;
  const norm = (p: string) => {
    const t = p.replace(sep === "\\" ? /[\\/]+$/ : /\/+$/, "");
    return sep === "\\" ? t.replace(/\//g, "\\").toLowerCase() : t;
  };
  return norm(asked) === norm(got);
}

