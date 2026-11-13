import { useCallback, useRef } from "react";

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
    .join(",")}}`;
}

export class StableMutationIntentKeys {
  private readonly keys = new Map<string, string>();

  constructor(
    private readonly prefix: string,
    private readonly maximumEntries = 64,
  ) {}

  key(intent: unknown): string {
    const signature = canonical(intent);
    const existing = this.keys.get(signature);
    if (existing) return existing;
    const value = `${this.prefix}-${crypto.randomUUID()}`;
    this.keys.set(signature, value);
    if (this.keys.size > this.maximumEntries) {
      const oldest = this.keys.keys().next().value;
      if (oldest !== undefined) this.keys.delete(oldest);
    }
    return value;
  }

  clear(): void {
    this.keys.clear();
  }
}

export function useStableMutationIntentKey(prefix: string) {
  const store = useRef<StableMutationIntentKeys | null>(null);
  if (!store.current) store.current = new StableMutationIntentKeys(prefix);
  return useCallback((intent: unknown) => store.current!.key(intent), []);
}
