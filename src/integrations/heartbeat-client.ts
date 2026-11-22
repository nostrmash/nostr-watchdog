import {
  canonicalHeartbeat,
  encodeHeartbeatBody,
  type HeartbeatPayload,
} from "../security/canonical";
import { hmacSha256Hex } from "../security/hmac";

export async function createHeartbeatRequest(input: {
  url: string;
  secret: string;
  payload: HeartbeatPayload;
  now?: number;
  nonce?: string;
}): Promise<{ url: string; method: "POST"; headers: Record<string, string>; body: string }> {
  const target = new URL(input.url);
  if (
    target.protocol !== "https:" ||
    target.search !== "" ||
    target.username !== "" ||
    target.password !== ""
  ) {
    throw new Error("heartbeat_url_invalid");
  }
  const body = encodeHeartbeatBody(input.payload);
  const bytes = new TextEncoder().encode(body);
  const timestamp = String(Math.floor((input.now ?? Date.now()) / 1000));
  const nonce = input.nonce ?? crypto.randomUUID().replace(/-/g, "");
  const canonical = await canonicalHeartbeat({
    timestamp,
    nonce,
    method: "POST",
    path: target.pathname,
    body: bytes,
  });
  return {
    url: target.toString(),
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-watchdog-timestamp": timestamp,
      "x-watchdog-nonce": nonce,
      "x-watchdog-signature": await hmacSha256Hex(input.secret, canonical),
    },
    body,
  };
}
