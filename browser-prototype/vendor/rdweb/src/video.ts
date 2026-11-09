// Video decoding with WebCodecs. Peers send Annex-B H.264/H.265 and raw
// VP8/VP9/AV1 frames, which VideoDecoder takes without a description.

export type Codec = "vp8" | "vp9" | "av1" | "h264" | "h265";

export const ALL_CODECS: readonly Codec[] = ["vp9", "av1", "h264", "h265", "vp8"];

export interface CodecSupport {
  /** Codecs this browser can decode (4:2:0). */
  decode: Set<Codec>;
  /** Codecs this browser can decode in 4:4:4 ("true color"). */
  decode444: Set<Codec>;
}

const CODEC_STRING: Record<Codec, string> = {
  vp8: "vp8",
  vp9: "vp09.00.51.08",
  av1: "av01.0.12M.08",
  h264: "avc1.640034",
  h265: "hev1.1.6.L153.B0",
};

const CODEC_STRING_444: Partial<Record<Codec, string>> = {
  vp9: "vp09.01.51.08.03",
  av1: "av01.1.12M.08",
};

export function codecString(codec: Codec, chroma444: boolean): string {
  return (chroma444 && CODEC_STRING_444[codec]) || CODEC_STRING[codec];
}

let probed: Promise<CodecSupport> | null = null;

/** Probes WebCodecs once per page; safe to call repeatedly. */
export function probeCodecs(): Promise<CodecSupport> {
  if (!probed) probed = doProbe();
  return probed;
}

async function supported(codec: string): Promise<boolean> {
  try {
    const r = await VideoDecoder.isConfigSupported({ codec, optimizeForLatency: true });
    return r.supported === true;
  } catch {
    return false;
  }
}

async function doProbe(): Promise<CodecSupport> {
  const out: CodecSupport = { decode: new Set(), decode444: new Set() };
  if (!isWebCodecsAvailable()) return out;
  await Promise.all(
    ALL_CODECS.map(async (c) => {
      if (await supported(CODEC_STRING[c])) out.decode.add(c);
      const s444 = CODEC_STRING_444[c];
      if (s444 && (await supported(s444))) out.decode444.add(c);
    }),
  );
  return out;
}

export function isWebCodecsAvailable(): boolean {
  return typeof globalThis.VideoDecoder === "function" && typeof globalThis.EncodedVideoChunk === "function";
}

export interface DecodedFrameSink {
  (frame: VideoFrame): void;
}

export interface DecoderStats {
  codec: Codec | null;
  chroma444: boolean;
  width: number;
  height: number;
  /** Frames decoded in the last full second. */
  fps: number;
  /** Received video bitrate over the last full second, kbit/s. */
  kbps: number;
  decoded: number;
  /** Encoded frames received. */
  received: number;
  dropped: number;
  queue: number;
  hardware: boolean | null;
}

/** Above this many frames waiting in the decoder we drop until the next key frame. */
const MAX_QUEUE = 8;

export class VideoPipeline {
  private decoder: VideoDecoder | null = null;
  private codec: Codec | null = null;
  private chroma444 = false;
  private needKey = true;
  private closed = false;
  private ts = 0;

  private decoded = 0;
  private received = 0;
  private dropped = 0;
  private winFrames = 0;
  private winBytes = 0;
  private winStart = performance.now();
  private lastFps = 0;
  private lastKbps = 0;
  private width = 0;
  private height = 0;

  constructor(
    private readonly sink: DecodedFrameSink,
    /** Called when we need a key frame (decoder reset, overload, error). */
    private readonly requestKeyFrame: () => void,
    private readonly onError: (err: Error) => void = () => {},
  ) {}

  /** Feeds one encoded frame. */
  push(codec: Codec, data: Uint8Array, key: boolean, chroma444: boolean): void {
    if (this.closed) return;
    this.winBytes += data.byteLength;
    this.received++;
    this.rollWindow();
    if (!isWebCodecsAvailable()) return;
    if (!this.decoder || this.decoder.state === "closed" || codec !== this.codec || chroma444 !== this.chroma444) {
      this.configure(codec, chroma444);
    }
    const dec = this.decoder!;
    if (!key && this.needKey) {
      this.dropped++;
      return;
    }
    if (!key && dec.decodeQueueSize > MAX_QUEUE) {
      // The decoder cannot keep up: skip ahead to the next key frame rather
      // than building latency.
      this.dropped++;
      this.needKey = true;
      this.requestKeyFrame();
      return;
    }
    try {
      dec.decode(new EncodedVideoChunk({ type: key ? "key" : "delta", timestamp: (this.ts += 16_666), data }));
      this.needKey = false;
    } catch (e) {
      this.dropped++;
      this.needKey = true;
      this.onError(e instanceof Error ? e : new Error(String(e)));
      this.reset();
    }
  }

  /** Drops decoder state, e.g. after a display switch; waits for a key frame. */
  reset(): void {
    if (this.decoder && this.decoder.state !== "closed") {
      try {
        this.decoder.close();
      } catch {
        /* ignore */
      }
    }
    this.decoder = null;
    this.needKey = true;
    this.requestKeyFrame();
  }

  stats(): DecoderStats {
    this.rollWindow();
    return {
      codec: this.codec,
      chroma444: this.chroma444,
      width: this.width,
      height: this.height,
      fps: this.lastFps,
      kbps: this.lastKbps,
      decoded: this.decoded,
      received: this.received,
      dropped: this.dropped,
      queue: this.decoder?.decodeQueueSize ?? 0,
      hardware: null,
    };
  }

  close(): void {
    this.closed = true;
    if (this.decoder && this.decoder.state !== "closed") {
      try {
        this.decoder.close();
      } catch {
        /* ignore */
      }
    }
    this.decoder = null;
  }

  private configure(codec: Codec, chroma444: boolean): void {
    if (this.decoder && this.decoder.state !== "closed") {
      try {
        this.decoder.close();
      } catch {
        /* ignore */
      }
    }
    this.codec = codec;
    this.chroma444 = chroma444;
    this.needKey = true;
    const decoder = new VideoDecoder({
      output: (frame) => {
        if (this.closed || decoder !== this.decoder) {
          frame.close();
          return;
        }
        this.decoded++;
        this.winFrames++;
        this.width = frame.displayWidth;
        this.height = frame.displayHeight;
        this.sink(frame);
      },
      error: (e) => {
        if (decoder !== this.decoder) return;
        this.onError(new Error(`video decoder: ${e.message}`));
        this.decoder = null;
        this.needKey = true;
        this.requestKeyFrame();
      },
    });
    decoder.configure({ codec: codecString(codec, chroma444), optimizeForLatency: true });
    this.decoder = decoder;
  }

  private rollWindow(): void {
    const now = performance.now();
    const dt = now - this.winStart;
    if (dt < 1000) return;
    this.lastFps = Math.round((this.winFrames * 1000) / dt);
    this.lastKbps = Math.round((this.winBytes * 8) / dt);
    this.winFrames = 0;
    this.winBytes = 0;
    this.winStart = now;
  }
}
