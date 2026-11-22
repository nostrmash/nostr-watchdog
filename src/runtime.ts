const REDACTED_KEY = /token|secret|nsec|authorization|password|seed|api[-_]?key|credential|cookie/i;

export function readString(env: Env, key: keyof Env): string {
  const value = env[key];
  return typeof value === "string" ? value.trim() : "";
}

export function readInt(env: Env, key: keyof Env, fallback: number): number {
  const raw = readString(env, key);
  if (raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value)) return fallback;
  return value;
}

export function flagEnabled(env: Env, key: keyof Env): boolean {
  return readString(env, key) === "true";
}

export function log(
  level: "info" | "error",
  event: string,
  fields: Record<string, string | number | boolean | null> = {},
): void {
  const safe: Record<string, string | number | boolean | null> = { level, event };
  for (const [key, value] of Object.entries(fields)) {
    if (REDACTED_KEY.test(key)) continue;
    safe[key] = typeof value === "string" ? value.slice(0, 200) : value;
  }
  const line = JSON.stringify(safe);
  if (level === "error") console.error(line);
  else console.log(line);
}

export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  if (items.length === 0) return [];
  const results = new Array<PromiseSettledResult<R>>(items.length);
  let cursor = 0;
  const workers = Math.max(1, Math.min(limit, items.length));
  await Promise.all(
    Array.from({ length: workers }, async () => {
      for (;;) {
        const index = cursor;
        cursor += 1;
        if (index >= items.length) return;
        const item = items[index];
        if (item === undefined) return;
        try {
          results[index] = { status: "fulfilled", value: await fn(item) };
        } catch (reason) {
          results[index] = { status: "rejected", reason };
        }
      }
    }),
  );
  return results;
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
