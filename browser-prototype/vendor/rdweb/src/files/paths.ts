// Remote path helpers. Windows peers use "\" and list their drives at "/";
// everything else uses "/". Names that come from the peer are untrusted and
// are checked before they become local relative paths.

import { FileTransferError } from "./types.js";

export type Separator = "/" | "\\";

/** Joins a remote folder and a name with the peer's separator. */
export function joinRemote(dir: string, name: string, sep: Separator): string {
  if (!name) return dir;
  if (!dir) return name;
  // On Windows the drive list lives at "/": "/" + "C:" is the root of C:.
  if (sep === "\\" && dir === "/") return /^[A-Za-z]:$/.test(name) ? `${name}\\` : name;
  if (dir.endsWith(sep) || dir.endsWith("/")) return dir + name;
  return dir + sep + name;
}

/** The parent of a remote path; Windows drive roots go up to the drive list "/". */
export function parentRemote(path: string, sep: Separator): string {
  if (sep === "\\") {
    if (path === "/" || /^[A-Za-z]:[\\/]?$/.test(path)) return "/";
    const trimmed = path.replace(/[\\/]+$/, "");
    const i = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
    if (i < 0) return "/";
    const parent = trimmed.slice(0, i);
    return /^[A-Za-z]:$/.test(parent) ? `${parent}\\` : parent || "/";
  }
  const trimmed = path.replace(/\/+$/, "");
  const i = trimmed.lastIndexOf("/");
  if (i <= 0) return "/";
  return trimmed.slice(0, i);
}

/** The last component of a remote path ("C:" for "C:\"). */
export function baseNameRemote(path: string, sep: Separator): string {
  const trimmed = sep === "\\" ? path.replace(/[\\/]+$/, "") : path.replace(/\/+$/, "");
  const i = sep === "\\" ? Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/")) : trimmed.lastIndexOf("/");
  return trimmed.slice(i + 1);
}

/**
 * Turns a relative name from the peer (or the host) into "/"-separated
 * segments, refusing anything that could leave the target folder: "..",
 * absolute paths, drive letters, NUL bytes.
 */
export function safeRelativeSegments(name: string): string[] {
  if (name.includes("\0")) throw new FileTransferError(`invalid file name ${JSON.stringify(name)}`, "invalid-name");
  if (/^[\\/]/.test(name) || /^[A-Za-z]:/.test(name)) {
    throw new FileTransferError(`absolute path not allowed: ${JSON.stringify(name)}`, "invalid-name");
  }
  const parts = name.split(/[\\/]+/).filter((p) => p !== "" && p !== ".");
  if (parts.some((p) => p === "..")) {
    throw new FileTransferError(`path traversal not allowed: ${JSON.stringify(name)}`, "invalid-name");
  }
  return parts;
}

/** A plain file name for rename (no separators, not "." or ".."). */
export function checkPlainName(name: string): void {
  if (!name || name === "." || name === ".." || /[\\/\0]/.test(name)) {
    throw new FileTransferError(`invalid name ${JSON.stringify(name)}`, "invalid-name");
  }
}
