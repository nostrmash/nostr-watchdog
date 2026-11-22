export function readPointer(value: unknown, pointer: string): unknown {
  if (pointer === "" || pointer === "/") return value;
  if (!pointer.startsWith("/")) return undefined;
  let current = value;
  for (const raw of pointer.slice(1).split("/")) {
    if (current === null || typeof current !== "object") return undefined;
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      const index = Number(key);
      if (!Number.isInteger(index)) return undefined;
      current = current[index];
    } else {
      current = (current as Record<string, unknown>)[key];
    }
  }
  return current;
}
