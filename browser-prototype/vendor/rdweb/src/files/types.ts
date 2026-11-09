// Public types of the file transfer API.

import type { PeerOs } from "../keymap.js";
import type { CloseInfo, PermissionName, ServerConfig, SessionState } from "../types.js";

export type RemoteEntryType = "dir" | "dirLink" | "drive" | "file" | "fileLink" | "unknown";

export interface RemoteEntry {
  name: string;
  type: RemoteEntryType;
  /** Bytes (0 for folders and links). */
  size: number;
  /** Last modification, milliseconds since the epoch (like File.lastModified); 0 if unknown. */
  modified: number;
  hidden: boolean;
}

export interface RemoteDirectory {
  /** The listed folder as the peer reports it (an empty request path is answered with the home folder). */
  path: string;
  entries: RemoteEntry[];
}

export interface FilePeerSummary {
  id: string;
  username: string;
  hostname: string;
  platform: string;
  os: PeerOs;
  version: string;
  /** Path separator of the remote file system. */
  separator: "/" | "\\";
  windowsSessions: { sid: number; name: string }[];
  currentWindowsSession: number;
}

export interface FileTransferOptions {
  hoen?: import("../types.js").SessionOptions["hoen"];
  server: ServerConfig;
  peerId: string;
  /** Stored SHA256(password || salt) from an earlier "remember password". */
  rememberedHash?: Uint8Array;
  /** Shown to the remote user in the connection request. */
  myName?: string;
  /** Our id as shown on the remote side; defaults to a web-specific marker. */
  myId?: string;
  /** Version string announced to the peer. */
  clientVersion?: string;
  /** Folder the peer lists first; empty (default) means the remote user's home. */
  initialDir?: string;
  /** Include hidden entries in the first listing. */
  showHidden?: boolean;
  /** How long to wait for a listing or a file operation to be answered (default 30 s). */
  requestTimeoutMs?: number;
  /**
   * Largest file data block accepted from the peer, before and after zstd
   * decompression (default 1 MiB; peers send at most 128 KiB).
   */
  maxBlockSize?: number;
  /**
   * Received data a download may hold that the consumer has not read yet
   * (default 32 MiB). The protocol has no way to pause the sender within a
   * file, so a consumer slower than the network fails the download with
   * code "overflow" instead of growing memory without bound.
   */
  maxBufferedBytes?: number;
  /** Upload backpressure: pause while the WebSocket send buffer holds more than this (default 1 MiB). */
  sendBufferHighWater?: number;
}

export type FileErrorCode =
  /** The peer refused access (OS permission, file transfer disabled). */
  | "permission-denied"
  | "not-found"
  | "exists"
  | "not-empty"
  /** The peer's file count limit for one transfer was exceeded. */
  | "too-many-files"
  /** A path or name is not acceptable (traversal, absolute, separators in a name). */
  | "invalid-name"
  /** The peer only allows transfers towards us ("one-way file transfer"). */
  | "one-way"
  | "cancelled"
  | "timeout"
  /** The session is not connected or was closed. */
  | "closed"
  /** The peer sent something that breaks the protocol. */
  | "protocol"
  | "oversize-block"
  /** A compressed block did not inflate (corrupt, or larger than maxBlockSize). */
  | "decompress"
  | "overflow"
  /** More data than the caller allowed (e.g. downloadBlob maxBytes). */
  | "too-large"
  /** downloadBlob: the path is a folder, not a file. */
  | "not-a-file"
  /** Reading a local upload source failed. */
  | "source"
  /** Any other error reported by the peer; see `remoteMessage`. */
  | "remote";

export class FileTransferError extends Error {
  constructor(
    message: string,
    readonly code: FileErrorCode,
    readonly jobId: number | null = null,
    readonly fileIndex: number | null = null,
    readonly path: string | null = null,
    /** The peer's own error text, when the error came from the peer. */
    readonly remoteMessage: string | null = null,
  ) {
    super(message);
    this.name = "FileTransferError";
  }
}

export interface FileErrorEvent {
  code: FileErrorCode;
  message: string;
  jobId: number | null;
  fileIndex: number | null;
  path: string | null;
  remoteMessage: string | null;
}

export type TransferDirection = "download" | "upload";

export interface TransferFileInfo {
  /** Index in the job's file list. */
  index: number;
  /** "/"-separated path relative to the job's parent folder, e.g. "docs/a/b.txt". */
  relativePath: string;
  /** Full path on the remote side. */
  remotePath: string;
  /** Size in bytes as announced (the peer's file may change while it is read). */
  size: number;
  /** Milliseconds since the epoch, 0 if unknown. */
  modified: number;
}

export interface TransferProgress {
  jobId: number;
  direction: TransferDirection;
  /** The file being transferred, null before the file list is known or after the last file. */
  file: (TransferFileInfo & { bytes: number }) | null;
  /** Number of files in the job (0 until known). */
  files: number;
  filesDone: number;
  skipped: number;
  /** Bytes transferred so far in the job. */
  bytes: number;
  /** Bytes the job will transfer (skipped files are subtracted). */
  totalBytes: number;
}

export interface TransferResult {
  jobId: number;
  direction: TransferDirection;
  /** Files transferred completely. */
  files: number;
  /** Files skipped (by choice, or abandoned by the consumer while arriving). */
  skipped: number;
  bytes: number;
  /**
   * The peer acknowledged the end of the job. Always true for downloads; an
   * upload whose acknowledgement did not arrive in time (slow remote disk, or
   * a lost peer job) resolves with false.
   */
  confirmed: boolean;
}

export interface DownloadOptions {
  showHidden?: boolean;
  signal?: AbortSignal;
  onProgress?: (p: TransferProgress) => void;
}

export interface UploadItem {
  /** File name, used when relativePath is empty. */
  name: string;
  /** "/"-separated path below the target folder (e.g. File.webkitRelativePath); defaults to name. */
  relativePath?: string;
  /** Bytes; required for streams, taken from the Blob otherwise. */
  size?: number;
  /** Milliseconds since the epoch (File.lastModified); defaults to now. */
  lastModified?: number;
  data: Blob | ReadableStream<Uint8Array>;
}

export type ConflictAnswer = "overwrite" | "skip" | "overwriteAll" | "skipAll";

export interface UploadConflict {
  jobId: number;
  file: TransferFileInfo;
  /** The copy that already exists on the remote side. */
  remote: { size: number; modified: number };
  /** Same size and modification time as the file being uploaded. */
  identical: boolean;
}

export interface UploadOptions {
  /**
   * What to do with files that already exist remotely: "ask" (default) asks
   * `onConflict`, or the session's `conflict` event listeners; with neither
   * the file is skipped.
   */
  overwrite?: "ask" | "overwrite" | "skip";
  onConflict?: (c: UploadConflict) => ConflictAnswer | Promise<ConflictAnswer>;
  /**
   * Continue an interrupted upload of the first file when the peer still has
   * its partial copy from an earlier, dropped connection (peers 1.4.2+).
   */
  resume?: boolean;
  signal?: AbortSignal;
  onProgress?: (p: TransferProgress) => void;
}

export interface RemoveOptions {
  /** The path is a folder. */
  dir?: boolean;
  /** Remove the folder with everything in it (files first, then empty folders). */
  recursive?: boolean;
  /** Recursive removal: called after each removed file. */
  onProgress?: (removed: number, total: number) => void;
}

export interface FileTransferEventMap {
  state: { state: SessionState };
  password: { wrong: boolean };
  twoFactor: { wrong: boolean };
  waitingForApproval: Record<string, never>;
  /** Logged in and the first listing arrived (home is null if the peer sent none). */
  connected: { peer: FilePeerSummary; rememberedHash: Uint8Array | null; home: RemoteDirectory | null };
  peer: { peer: FilePeerSummary };
  permission: { name: PermissionName; enabled: boolean };
  message: { type: string; title: string; text: string; link: string };
  progress: TransferProgress;
  /** An upload found an existing remote file; call `answer` once (the upload waits for it, or for cancel()). */
  conflict: { conflict: UploadConflict; answer: (a: ConflictAnswer) => void };
  /** Errors reported by the peer or detected locally, also for jobs whose promise rejects. */
  error: FileErrorEvent;
  close: CloseInfo;
}

