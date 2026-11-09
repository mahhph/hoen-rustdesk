// Remote cursor shapes. Peers send each shape once (CursorData, zstd RGBA)
// and afterwards refer to it by id (CursorId).

import type { CursorData } from "./proto/session_pb.js";
import { inflateExact } from "./zstd.js";

export interface CursorShape {
  id: string;
  width: number;
  height: number;
  hotX: number;
  hotY: number;
  /** Straight (non-premultiplied) RGBA pixels. */
  rgba: Uint8ClampedArray;
  /** PNG data URL, built lazily. */
  url(): string;
  /** True when the shape has no visible pixels (the peer hid the cursor). */
  readonly empty: boolean;
}

/** Peers clamp shapes to 128 px but accept some slack for HiDPI. */
const MAX_CURSOR_SIDE = 512;
/** Keep at most this many shapes; peers resend unknown ones when asked. */
const MAX_SHAPES = 64;

export class CursorStore {
  private shapes = new Map<string, CursorShape>();

  decode(cd: CursorData): CursorShape {
    const { width, height } = cd;
    if (!(width >= 1 && width <= MAX_CURSOR_SIDE && height >= 1 && height <= MAX_CURSOR_SIDE)) {
      throw new Error(`invalid cursor size ${width}x${height}`);
    }
    const hotX = clamp(cd.hotx, 0, width - 1);
    const hotY = clamp(cd.hoty, 0, height - 1);
    const rgba = new Uint8ClampedArray(inflateExact(cd.colors, width * height * 4).buffer);
    let empty = true;
    for (let i = 3; i < rgba.length; i += 4) {
      if (rgba[i] !== 0) {
        empty = false;
        break;
      }
    }
    let cachedUrl: string | null = null;
    const shape: CursorShape = {
      id: cd.id,
      width,
      height,
      hotX,
      hotY,
      rgba,
      empty,
      url: () => (cachedUrl ??= rgbaToDataUrl(rgba, width, height)),
    };
    this.shapes.delete(cd.id);
    this.shapes.set(cd.id, shape);
    while (this.shapes.size > MAX_SHAPES) {
      const oldest = this.shapes.keys().next().value as string;
      this.shapes.delete(oldest);
    }
    return shape;
  }

  get(id: string): CursorShape | undefined {
    const s = this.shapes.get(id);
    if (s) {
      // keep recently used shapes alive
      this.shapes.delete(id);
      this.shapes.set(id, s);
    }
    return s;
  }

  clear(): void {
    this.shapes.clear();
  }
}

function clamp(v: number, lo: number, hi: number): number {
  return v < lo ? lo : v > hi ? hi : v;
}

export function rgbaToDataUrl(rgba: Uint8ClampedArray, width: number, height: number, scale = 1): string {
  const w = Math.max(1, Math.round(width * scale));
  const h = Math.max(1, Math.round(height * scale));
  const src = document.createElement("canvas");
  src.width = width;
  src.height = height;
  const sctx = src.getContext("2d")!;
  sctx.putImageData(new ImageData(new Uint8ClampedArray(rgba), width, height), 0, 0);
  if (w === width && h === height) return src.toDataURL("image/png");
  const dst = document.createElement("canvas");
  dst.width = w;
  dst.height = h;
  const dctx = dst.getContext("2d")!;
  dctx.imageSmoothingEnabled = true;
  dctx.imageSmoothingQuality = "high";
  dctx.drawImage(src, 0, 0, w, h);
  return dst.toDataURL("image/png");
}
