// What file jobs need from the session, and what the session routes to them.

import type { MessageInitShape } from "@bufbuild/protobuf";
import type {
  FileActionSchema,
  FileDirectory,
  FileTransferBlock,
  FileTransferDigest,
  FileTransferDone,
  FileTransferError as WireFileError,
  FileTransferSendConfirmRequest,
  MessageSchema,
} from "../proto/session_pb.js";
import type { Separator } from "./paths.js";
import {
  FileTransferError,
  type ConflictAnswer,
  type FileErrorCode,
  type TransferProgress,
  type UploadConflict,
} from "./types.js";

export type MessageInit = MessageInitShape<typeof MessageSchema>;
/** The oneof of a Message, as accepted by create(). */
export type MessageUnion = NonNullable<MessageInit["union"]>;
/** The oneof of a FileAction, as accepted by create(). */
export type FileActionUnion = NonNullable<MessageInitShape<typeof FileActionSchema>["union"]>;

export interface JobLimits {
  requestTimeoutMs: number;
  maxBlockSize: number;
  maxBufferedBytes: number;
  sendBufferHighWater: number;
}

export interface JobHost {
  readonly limits: JobLimits;
  readonly sep: Separator;
  /** The peer's version as a number (see versionNumber). */
  readonly peerVersion: number;
  send(init: MessageInit): void;
  isOpen(): boolean;
  bufferedAmount(): number;
  progress(p: TransferProgress, cb: ((p: TransferProgress) => void) | undefined): void;
  reportError(err: FileTransferError): void;
  askConflict(c: UploadConflict, cb: ((c: UploadConflict) => ConflictAnswer | Promise<ConflictAnswer>) | undefined): Promise<ConflictAnswer>;
  /** The job is over (any outcome); frees its id and starts the next transfer. */
  finished(job: FileJob): void;
}

export interface FileJob {
  readonly id: number;
  onDir?(fd: FileDirectory): void;
  onBlock?(b: FileTransferBlock): void;
  onDigest?(d: FileTransferDigest): void;
  onConfirm?(c: FileTransferSendConfirmRequest): void;
  onDone(d: FileTransferDone): void;
  onError(e: WireFileError): void;
  /** Ends the job from outside (session closed, permission revoked). */
  abort(err: FileTransferError): void;
}

export interface TransferJob extends FileJob {
  readonly direction: "download" | "upload";
  start(): void;
}

/** Classifies an error text from the peer (io::Error strings on any OS, or its own messages). */
export function classifyPeerError(text: string): FileErrorCode {
  const t = text.toLowerCase();
  const os = /\(os error (\d+)\)/.exec(t)?.[1];
  if (t.includes("one-way-file-transfer")) return "one-way";
  if (t.includes("too many files")) return "too-many-files";
  if (
    t.includes("permission denied") ||
    t.includes("access is denied") ||
    t.includes("no permission") ||
    os === "1" ||
    os === "5" ||
    os === "13"
  ) {
    return "permission-denied";
  }
  if (t.includes("not empty") || os === "39" || os === "66" || os === "145") return "not-empty";
  if (t.includes("exists") && !t.includes("not exist")) return "exists";
  if (os === "17" || os === "80" || os === "183") return "exists";
  if (
    t.includes("no such file") ||
    t.includes("not exist") ||
    t.includes("cannot find") ||
    t.includes("not found") ||
    os === "2" ||
    os === "3"
  ) {
    return "not-found";
  }
  if (t.includes("traversal") || t.includes("absolute path") || t.includes("null byte") || t.includes("invalid")) {
    return "invalid-name";
  }
  return "remote";
}

export function peerError(
  e: WireFileError,
  path: string | null,
  what: string,
  fileIndex: number | null = e.fileNum >= 0 ? e.fileNum : null,
): FileTransferError {
  const code = classifyPeerError(e.error);
  return new FileTransferError(`${what}: ${e.error}`, code, e.id || null, fileIndex, path, e.error);
}
