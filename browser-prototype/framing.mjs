// RustDesk's native TCP stream prefixes each frame with a 1–4 byte little-endian length.
export const MAX_FRAME = 16 * 1024 * 1024;

export function encodeFrame(data, maxFrame = MAX_FRAME) {
  const payload = Buffer.from(data);
  const n = payload.length;
  if (n > maxFrame || n > 0x3fffffff) throw new Error('Frame exceeds limit');
  const bytes = n <= 0x3f ? 1 : n <= 0x3fff ? 2 : n <= 0x3fffff ? 3 : 4;
  let header = n * 4 + bytes - 1;
  const output = Buffer.allocUnsafe(bytes + n);
  for (let i = 0; i < bytes; i++) { output[i] = header % 256; header = Math.floor(header / 256); }
  payload.copy(output, bytes);
  return output;
}

export class FrameDecoder {
  constructor(maxFrame = MAX_FRAME) { this.maxFrame = maxFrame; this.pending = Buffer.alloc(0); }
  push(chunk) {
    this.pending = Buffer.concat([this.pending, chunk]);
    const frames = [];
    while (this.pending.length) {
      const headerLength = (this.pending[0] & 3) + 1;
      if (this.pending.length < headerLength) break;
      let header = 0;
      for (let i = 0; i < headerLength; i++) header += this.pending[i] * (256 ** i);
      const length = Math.floor(header / 4);
      if (length > this.maxFrame) throw new Error('Frame exceeds limit');
      if (this.pending.length < headerLength + length) break;
      frames.push(Buffer.from(this.pending.subarray(headerLength, headerLength + length)));
      this.pending = this.pending.subarray(headerLength + length);
    }
    return frames;
  }
}
