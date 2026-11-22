const PATTERNS = [
  /nsec1[0-9a-z]+/gi,
  /npub1[0-9a-z]+/gi,
  /bearer\s+\S+/gi,
  /\b(?:token|secret|password|authorization)\b\s*[:=]\s*\S+/gi,
  /[a-f0-9]{32,}/gi,
  /[a-z]+:\/\/[^/\s:@]+:[^/\s@]+@/gi,
];

export function sanitizeText(value: string, max = 180): string {
  let text = value.replace(/\s+/g, " ").trim();
  for (const pattern of PATTERNS) text = text.replace(pattern, "[redacted]");
  if (text.length > max) text = `${text.slice(0, max - 1)}…`;
  return text;
}

export function safeVersion(value: string | null): string | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (!/^[0-9A-Za-z._+-]{1,40}$/.test(trimmed)) return null;
  return trimmed;
}
