export class UrlPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UrlPolicyError";
  }
}

export interface UrlPolicy {
  allowHosts: string[];
  privateNetwork: boolean;
}

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata.internal",
  "metadata",
]);

export function assertProbeUrl(raw: string, policy: UrlPolicy): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UrlPolicyError("The probe URL is not a valid absolute URL.");
  }
  if (url.username !== "" || url.password !== "") {
    throw new UrlPolicyError("The probe URL must not include credentials.");
  }
  if (url.protocol !== "https:" && !(policy.privateNetwork && url.protocol === "http:")) {
    throw new UrlPolicyError("The probe URL must use HTTPS.");
  }
  const host = url.hostname.replace(/\.$/, "").toLowerCase();
  if (host === "") throw new UrlPolicyError("The probe URL is missing a host.");
  const allowed = new Set(policy.allowHosts.map((item) => item.toLowerCase()));
  if (!allowed.has(host)) {
    throw new UrlPolicyError("The probe host is not on the configured allowlist.");
  }
  const defaultPort = url.protocol === "https:" ? "443" : "80";
  if (url.port !== "" && url.port !== defaultPort) {
    throw new UrlPolicyError("The probe URL uses a non-default port.");
  }
  if (
    BLOCKED_HOSTS.has(host) ||
    host.endsWith(".local") ||
    host.endsWith(".localhost") ||
    host.endsWith(".internal") ||
    host.endsWith(".home.arpa")
  ) {
    if (!policy.privateNetwork)
      throw new UrlPolicyError("The probe host is not a public destination.");
  }
  if (isBlockedAddress(host) && !policy.privateNetwork) {
    throw new UrlPolicyError(
      "The probe address is a private, link-local, or metadata destination.",
    );
  }
  if (looksLikeAddress(host) && parseAddress(host) === "invalid") {
    throw new UrlPolicyError("The probe address could not be validated.");
  }
  return url;
}

export function assertWssUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UrlPolicyError("The relay URL is invalid.");
  }
  if (url.protocol !== "wss:" || url.username !== "" || url.password !== "") {
    throw new UrlPolicyError("Relay URLs must be wss and must not include credentials.");
  }
  if (url.port !== "" && url.port !== "443") {
    throw new UrlPolicyError("Relay URLs must use the default TLS port.");
  }
  const host = url.hostname.toLowerCase();
  if (
    isBlockedAddress(host) ||
    BLOCKED_HOSTS.has(host) ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    throw new UrlPolicyError("The relay host is not a public destination.");
  }
  return url;
}

export function isBlockedAddress(hostname: string): boolean {
  const parsed = parseAddress(hostname);
  if (parsed === "public" || parsed === "name") return false;
  return true;
}

function looksLikeAddress(hostname: string): boolean {
  return (
    hostname.includes(":") || /^\d+(\.\d+){0,3}$/.test(hostname) || /^0x[0-9a-f]+$/i.test(hostname)
  );
}

function parseAddress(hostname: string): "public" | "blocked" | "invalid" | "name" {
  if (hostname.includes(":")) {
    const v6 = parseIPv6(hostname);
    if (v6 === null) return "invalid";
    return ipv6Blocked(v6) ? "blocked" : "public";
  }
  if (/^0x[0-9a-f]+$/i.test(hostname) || /^\d+$/.test(hostname)) return "blocked";
  const v4 = ipv4ToInt(hostname);
  if (v4 === null) {
    if (/^\d+(\.\d+){1,3}$/.test(hostname)) return "invalid";
    return "name";
  }
  return privateV4(v4) ? "blocked" : "public";
}

export function ipv4ToInt(hostname: string): number | null {
  const parts = hostname.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

function privateV4(value: number): boolean {
  const a = (value >>> 24) & 255;
  const b = (value >>> 16) & 255;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51) return true;
  if (a === 203 && b === 0) return true;
  if (a >= 224) return true;
  return false;
}

export function parseIPv6(input: string): bigint | null {
  let value = input.toLowerCase();
  const zone = value.indexOf("%");
  if (zone !== -1) value = value.slice(0, zone);
  const dotted = value.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted?.[1]) {
    const v4 = ipv4ToInt(dotted[1]);
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    value = `${value.slice(0, value.length - dotted[1].length)}${hi}:${lo}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (halves.length === 2 && missing < 1) return null;
  if (missing < 0) return null;
  const groups = [...left, ...Array.from({ length: Math.max(0, missing) }, () => "0"), ...right];
  if (groups.length !== 8) return null;
  let out = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    out = (out << 16n) + BigInt(Number.parseInt(group, 16));
  }
  return out;
}

function ipv6Blocked(value: bigint): boolean {
  if (value === 0n || value === 1n) return true;
  const first = Number((value >> 112n) & 0xffffn);
  if ((first & 0xfe00) === 0xfc00) return true;
  if ((first & 0xffc0) === 0xfe80) return true;
  if ((first & 0xff00) === 0xff00) return true;
  if (value >> 96n === 0x20010db8n) return true;
  const v4Mapped = value >> 32n === 0xffffn;
  if (v4Mapped) return privateV4(Number(value & 0xffffffffn));
  const sixToFour = first === 0x2002;
  if (sixToFour) return privateV4(Number((value >> 80n) & 0xffffffffn));
  return false;
}
