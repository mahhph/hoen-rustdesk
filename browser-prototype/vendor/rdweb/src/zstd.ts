import { Decompress } from "fzstd";

/** Largest window a frame may declare beyond the output cap (fzstd allocates the window up front). */
const MAX_EXTRA_WINDOW = 8 << 20;

/**
 * Inflates zstd data, refusing to produce more than `max` bytes so a
 * malicious peer cannot make us allocate unbounded memory.
 */
export function inflateCapped(data: Uint8Array, max: number): Uint8Array {
  checkFrames(data, Math.max(max, MAX_EXTRA_WINDOW), max);
  const chunks: Uint8Array[] = [];
  let total = 0;
  const d = new Decompress((chunk) => {
    total += chunk.length;
    if (total > max) throw new Error(`zstd: inflated size exceeds ${max} bytes`);
    chunks.push(chunk.slice());
  });
  d.push(data, true);
  if (chunks.length === 1) return chunks[0]!;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** Inflates zstd data that must decompress to exactly `expected` bytes. */
export function inflateExact(data: Uint8Array, expected: number): Uint8Array {
  const out = inflateCapped(data, expected);
  if (out.length !== expected) throw new Error(`zstd: expected ${expected} bytes, got ${out.length}`);
  return out;
}

/**
 * Walks the frame and block headers (RFC 8878) without decompressing and
 * rejects frames whose window, which the decoder allocates before producing
 * any output, is larger than `maxWindow`, or whose declared content size
 * exceeds `maxContent`.
 */
function checkFrames(data: Uint8Array, maxWindow: number, maxContent: number): void {
  const n = data.length;
  let p = 0;
  const need = (k: number) => {
    if (p + k > n) throw new Error("zstd: truncated frame");
  };
  const le = (at: number, len: number) => {
    let v = 0;
    for (let i = len - 1; i >= 0; i--) v = v * 256 + data[at + i]!;
    return v;
  };
  while (p < n) {
    need(4);
    const magic = le(p, 4);
    p += 4;
    if (magic >= 0x184d2a50 && magic <= 0x184d2a5f) {
      // skippable frame
      need(4);
      const len = le(p, 4);
      p += 4;
      need(len);
      p += len;
      continue;
    }
    if (magic !== 0xfd2fb528) throw new Error("zstd: bad frame magic");
    need(1);
    const fhd = data[p++]!;
    if (fhd & 8) throw new Error("zstd: reserved header bit set");
    const fcsFlag = fhd >> 6;
    const singleSegment = (fhd >> 5) & 1;
    const checksum = (fhd >> 2) & 1;
    let window = 0;
    if (!singleSegment) {
      need(1);
      const wd = data[p++]!;
      const base = 2 ** (10 + (wd >> 3));
      window = base + (base / 8) * (wd & 7);
    }
    const dictLen = [0, 1, 2, 4][fhd & 3]!;
    need(dictLen);
    p += dictLen;
    const fcsLen = fcsFlag === 0 ? singleSegment : [0, 2, 4, 8][fcsFlag]!;
    need(fcsLen);
    const contentSize = fcsLen ? le(p, fcsLen) + (fcsLen === 2 ? 256 : 0) : -1;
    p += fcsLen;
    if (singleSegment) window = contentSize;
    if (window > maxWindow) throw new Error(`zstd: frame window of ${window} bytes exceeds ${maxWindow}`);
    if (contentSize > maxContent) throw new Error(`zstd: inflated size exceeds ${maxContent} bytes`);
    for (;;) {
      need(3);
      const bh = le(p, 3);
      p += 3;
      const type = (bh >> 1) & 3;
      if (type === 3) throw new Error("zstd: reserved block type");
      const len = type === 1 ? 1 : bh >>> 3; // RLE blocks carry one byte
      need(len);
      p += len;
      if (bh & 1) break;
    }
    if (checksum) {
      need(4);
      p += 4;
    }
  }
}
