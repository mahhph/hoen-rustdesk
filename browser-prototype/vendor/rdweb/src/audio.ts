// Remote audio: Opus packets decoded with WebCodecs (or a WebAssembly Opus
// decoder where WebCodecs audio is missing, e.g. older Safari) and played
// through a small jitter buffer on an AudioContext.

const TARGET_LATENCY = 0.08; // seconds of audio queued ahead after a (re)start
const MAX_LATENCY = 0.35; // more than this queued: drop packets to catch up

/**
 * off         - no audio stream (yet), or muted
 * blocked     - the browser did not let audio start: needs a user gesture
 * playing     - audio is running
 * unsupported - this browser can decode neither with WebCodecs nor WebAssembly
 */
export type AudioState = "off" | "blocked" | "playing" | "unsupported";

export function isAudioDecodingAvailable(): boolean {
  return typeof globalThis.AudioContext === "function" || typeof (globalThis as { webkitAudioContext?: unknown }).webkitAudioContext === "function";
}

interface Pcm {
  channels: Float32Array[];
  sampleRate: number;
}

interface Backend {
  decode(packet: Uint8Array): void;
  close(): void;
}

async function webCodecsSupported(sampleRate: number, channels: number): Promise<boolean> {
  if (typeof globalThis.AudioDecoder !== "function") return false;
  try {
    const r = await AudioDecoder.isConfigSupported({ codec: "opus", sampleRate, numberOfChannels: channels });
    return r.supported === true;
  } catch {
    return false;
  }
}

function webCodecsBackend(sampleRate: number, channels: number, out: (pcm: Pcm) => void, fail: () => void): Backend {
  let ts = 0;
  const decoder = new AudioDecoder({
    output: (data) => {
      try {
        const frames = data.numberOfFrames;
        const chans: Float32Array[] = [];
        for (let c = 0; c < data.numberOfChannels; c++) {
          const plane = new Float32Array(frames);
          data.copyTo(plane, { planeIndex: c, format: "f32-planar" });
          chans.push(plane);
        }
        out({ channels: chans, sampleRate: data.sampleRate });
      } finally {
        data.close();
      }
    },
    error: fail,
  });
  decoder.configure({ codec: "opus", sampleRate, numberOfChannels: channels });
  return {
    decode(packet) {
      if (decoder.state !== "configured") return;
      decoder.decode(new EncodedAudioChunk({ type: "key", timestamp: (ts += 10_000), data: packet }));
    },
    close() {
      if (decoder.state !== "closed") decoder.close();
    },
  };
}

async function wasmBackend(sampleRate: number, channels: number, out: (pcm: Pcm) => void): Promise<Backend> {
  const { OpusDecoder } = await import("opus-decoder");
  const decoder = new OpusDecoder({ sampleRate: sampleRate as 48000, channels });
  await decoder.ready;
  return {
    decode(packet) {
      const r = decoder.decodeFrame(packet);
      if (r.samplesDecoded > 0) out({ channels: r.channelData, sampleRate: r.sampleRate });
    },
    close() {
      decoder.free();
    },
  };
}

export class AudioPlayer {
  private ctx: AudioContext | null = null;
  private gain: GainNode | null = null;
  private backend: Backend | null = null;
  /** Bumped per configure(); a slow backend set-up for an older format is discarded. */
  private generation = 0;
  private loading = false;
  private sampleRate = 0;
  private channels = 0;
  private nextTime = 0;
  private muted = false;
  private volume = 1;
  private stateValue: AudioState = "off";
  private closed = false;

  constructor(private readonly onState: (s: AudioState) => void = () => {}) {}

  get state(): AudioState {
    return this.stateValue;
  }

  /** Applies a new stream format announced by the peer. */
  configure(sampleRate: number, channels: number): void {
    if (this.closed) return;
    if (sampleRate === this.sampleRate && channels === this.channels && (this.backend || this.loading)) return;
    this.sampleRate = sampleRate;
    this.channels = channels;
    this.closeBackend();
    if (!isAudioDecodingAvailable()) {
      this.setState("unsupported");
      return;
    }
    if (!this.ctx) {
      const Ctx = globalThis.AudioContext ?? (globalThis as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      this.ctx = new Ctx({ latencyHint: "interactive" });
      this.gain = this.ctx.createGain();
      this.gain.connect(this.ctx.destination);
      this.ctx.onstatechange = () => this.refreshState();
      this.applyGain();
    }
    const out = (pcm: Pcm) => this.play(pcm);
    const gen = ++this.generation;
    this.loading = true;
    void (async () => {
      let backend: Backend | null = null;
      try {
        if (await webCodecsSupported(sampleRate, channels)) {
          backend = webCodecsBackend(sampleRate, channels, out, () => {
            if (this.backend === backend) this.backend = null;
          });
        } else {
          backend = await wasmBackend(sampleRate, channels, out);
        }
      } catch {
        backend = null;
      }
      if (gen !== this.generation || this.closed) {
        backend?.close();
        return;
      }
      this.loading = false;
      this.backend = backend;
      if (!backend) this.setState("unsupported");
      else this.refreshState();
    })();
  }

  push(packet: Uint8Array): void {
    if (this.muted || !this.backend) return;
    try {
      this.backend.decode(packet);
    } catch {
      /* a broken packet is not worth tearing the session down for */
    }
  }

  /** Browsers only start audio after a user gesture; call this from one. */
  resume(): void {
    const ctx = this.ctx;
    if (!ctx || ctx.state === "running") return;
    void ctx.resume().then(
      () => this.refreshState(),
      () => {},
    );
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
    this.applyGain();
    if (muted) this.nextTime = 0;
    this.refreshState();
  }

  setVolume(v: number): void {
    this.volume = Math.min(1, Math.max(0, v));
    this.applyGain();
  }

  close(): void {
    this.closed = true;
    this.generation++;
    this.loading = false;
    this.closeBackend();
    void this.ctx?.close().catch(() => {});
    this.ctx = null;
    this.gain = null;
    this.setState("off");
  }

  private setState(s: AudioState): void {
    if (s === this.stateValue) return;
    this.stateValue = s;
    this.onState(s);
  }

  private refreshState(): void {
    if (this.closed || this.stateValue === "unsupported") return;
    if (!this.ctx || !this.backend || this.muted) this.setState("off");
    else this.setState(this.ctx.state === "running" ? "playing" : "blocked");
  }

  private applyGain(): void {
    if (this.gain) this.gain.gain.value = this.muted ? 0 : this.volume;
  }

  private closeBackend(): void {
    try {
      this.backend?.close();
    } catch {
      /* ignore */
    }
    this.backend = null;
  }

  private play(pcm: Pcm): void {
    const ctx = this.ctx;
    if (!ctx || !this.gain || this.muted || ctx.state !== "running") return;
    const frames = pcm.channels[0]?.length ?? 0;
    if (!frames) return;
    const now = ctx.currentTime;
    if (this.nextTime < now) this.nextTime = now + TARGET_LATENCY;
    // Too much queued (a burst after a network stall): drop instead of
    // stacking latency; the next packets play on time again.
    if (this.nextTime - now > MAX_LATENCY) return;
    try {
      const buf = ctx.createBuffer(pcm.channels.length, frames, pcm.sampleRate);
      pcm.channels.forEach((ch, i) => buf.copyToChannel(ch as Float32Array<ArrayBuffer>, i));
      const src = ctx.createBufferSource();
      src.buffer = buf;
      src.connect(this.gain);
      src.start(this.nextTime);
      this.nextTime += buf.duration;
    } catch {
      /* ignore */
    }
  }
}
