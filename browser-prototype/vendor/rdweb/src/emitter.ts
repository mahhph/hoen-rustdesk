/** Minimal typed event emitter; listener errors never break the session. */
export class Emitter<M> {
  private listeners = new Map<keyof M, Set<(ev: never) => void>>();

  on<K extends keyof M>(type: K, fn: (ev: M[K]) => void): () => void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(fn as (ev: never) => void);
    return () => set!.delete(fn as (ev: never) => void);
  }

  listenerCount<K extends keyof M>(type: K): number {
    return this.listeners.get(type)?.size ?? 0;
  }

  emit<K extends keyof M>(type: K, ev: M[K]): void {
    const set = this.listeners.get(type);
    if (!set) return;
    for (const fn of [...set]) {
      try {
        (fn as (ev: M[K]) => void)(ev);
      } catch (e) {
        console.error(`rdweb: "${String(type)}" listener failed`, e);
      }
    }
  }

  clear(): void {
    this.listeners.clear();
  }
}
