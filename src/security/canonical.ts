import { sha256Hex } from "./hmac";

export async function canonicalHeartbeat(input: {
  timestamp: string;
  nonce: string;
  method: string;
  path: string;
  body: Uint8Array;
}): Promise<string> {
  const bodyHash = await sha256Hex(input.body);
  return `${input.timestamp}\n${input.nonce}\n${input.method.toUpperCase()}\n${input.path}\n${bodyHash}`;
}

export interface HeartbeatPayload {
  progress?: string;
  idle?: boolean;
  loopAt?: number;
}

export function encodeHeartbeatBody(payload: HeartbeatPayload): string {
  const body: Record<string, string | boolean | number> = {};
  if (payload.progress !== undefined) body.progress = payload.progress;
  if (payload.idle !== undefined) body.idle = payload.idle;
  if (payload.loopAt !== undefined) body.loopAt = payload.loopAt;
  return JSON.stringify(body);
}
