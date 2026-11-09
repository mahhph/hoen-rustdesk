// A small single-consumer async queue: producers push, the consumer awaits
// next(); end() finishes it after the queued items, fail() drops them.

export class AsyncQueue<T> {
  private items: T[] = [];
  private waiters: { resolve: (r: IteratorResult<T>) => void; reject: (e: Error) => void }[] = [];
  private ended = false;
  private error: Error | null = null;

  get length(): number {
    return this.items.length;
  }

  get closed(): boolean {
    return this.ended;
  }

  push(item: T): void {
    if (this.ended) return;
    const w = this.waiters.shift();
    if (w) w.resolve({ value: item, done: false });
    else this.items.push(item);
  }

  end(): void {
    if (this.ended) return;
    this.ended = true;
    if (this.items.length) return;
    for (const w of this.waiters.splice(0)) w.resolve({ value: undefined, done: true });
  }

  fail(err: Error): void {
    if (this.error) return;
    this.error = err;
    this.ended = true;
    this.items = [];
    for (const w of this.waiters.splice(0)) w.reject(err);
  }

  /** Drops queued items; returns them. */
  drain(): T[] {
    return this.items.splice(0);
  }

  next(): Promise<IteratorResult<T>> {
    if (this.items.length) {
      const value = this.items.shift()!;
      if (this.ended && !this.items.length) {
        for (const w of this.waiters.splice(0)) w.resolve({ value: undefined, done: true });
      }
      return Promise.resolve({ value, done: false });
    }
    if (this.error) return Promise.reject(this.error);
    if (this.ended) return Promise.resolve({ value: undefined, done: true });
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
}

/** A promise with its resolve/reject at hand; rejections are never reported as unhandled. */
export class Deferred<T> {
  readonly promise: Promise<T>;
  resolve!: (v: T) => void;
  reject!: (e: Error) => void;
  settled = false;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.resolve = (v) => {
        if (this.settled) return;
        this.settled = true;
        resolve(v);
      };
      this.reject = (e) => {
        if (this.settled) return;
        this.settled = true;
        reject(e);
      };
    });
    this.promise.catch(() => {});
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
