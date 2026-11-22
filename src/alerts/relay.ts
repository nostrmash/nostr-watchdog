import { getEventHash, verifyEvent, type Event, type NostrEvent } from "nostr-tools/pure";

import { sanitizeText } from "../security/redact";
import { assertWssUrl } from "../security/url-policy";
import type { FetchLike } from "../types";

const MAX_FRAME_CHARS = 65_536;
const FUTURE_SKEW_SECONDS = 15 * 60;

export interface JsonSocket {
  send(data: string): void;
  close(): void;
  onMessage(handler: (data: string) => void): void;
  onClose(handler: () => void): void;
  onError(handler: () => void): void;
}

export interface VerifiedInbox {
  id: string;
  pubkey: string;
  createdAt: number;
  relays: string[];
}

/**
 * Cloudflare's fetch WebSocket upgrade accepts http(s) URLs, not ws(s).
 * Relay configuration stays wss://. The transport URL is https:// on port 443.
 * ws:// is never produced.
 */
export function workersWebSocketUrl(wssUrl: string): string {
  const url = assertWssUrl(wssUrl);
  url.protocol = "https:";
  return url.toString();
}

export async function connectRelay(
  url: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
): Promise<JsonSocket> {
  const transport = workersWebSocketUrl(url);
  if (!transport.startsWith("https://")) throw new Error("relay_transport_invalid");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetchImpl(transport, {
      headers: { Upgrade: "websocket" },
      redirect: "manual",
      signal: controller.signal,
    });
  } catch (error) {
    clearTimeout(timer);
    const name = error instanceof Error ? error.name : "";
    if (name === "AbortError" || name === "TimeoutError") {
      throw new Error("relay_timeout", { cause: error });
    }
    throw new Error("relay_connect_failed", { cause: error });
  }
  clearTimeout(timer);
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new Error("relay_redirect_refused");
  }
  const socket = response.webSocket;
  if (!socket || response.status !== 101) {
    await response.body?.cancel();
    throw new Error("relay_upgrade_failed");
  }
  socket.accept();
  const messageHandlers: Array<(data: string) => void> = [];
  const closeHandlers: Array<() => void> = [];
  const errorHandlers: Array<() => void> = [];
  let closed = false;
  const finishClose = () => {
    if (closed) return;
    closed = true;
    for (const handler of closeHandlers) handler();
  };
  socket.addEventListener("message", (event) => {
    const data = typeof event.data === "string" ? event.data : "";
    if (data.length > MAX_FRAME_CHARS) return;
    for (const handler of messageHandlers) handler(data);
  });
  socket.addEventListener("close", finishClose);
  socket.addEventListener("error", () => {
    for (const handler of errorHandlers) handler();
    finishClose();
  });
  return {
    send(data) {
      if (closed) throw new Error("relay_closed");
      socket.send(data);
    },
    close() {
      if (closed) return;
      try {
        socket.close(1000, "done");
      } catch {
        finishClose();
        return;
      }
      finishClose();
    },
    onMessage(handler) {
      messageHandlers.push(handler);
    },
    onClose(handler) {
      closeHandlers.push(handler);
    },
    onError(handler) {
      errorHandlers.push(handler);
    },
  };
}

export function relayTags(tags: string[][]): string[] {
  const relays: string[] = [];
  for (const tag of tags) {
    if (tag[0] === "relay" && tag[1]) relays.push(tag[1]);
  }
  return relays;
}

export function validateInboxRelays(relays: string[]): string[] {
  const unique: string[] = [];
  for (const relay of relays) {
    try {
      const normalized = assertWssUrl(relay).toString().replace(/\/$/, "");
      if (!unique.includes(normalized)) unique.push(normalized);
    } catch {
      continue;
    }
    if (unique.length >= 5) break;
  }
  return unique;
}

export function verifyInboxEvent(
  value: unknown,
  author: string,
  nowSec: number,
): VerifiedInbox | null {
  if (!isEvent(value)) return null;
  if (value.kind !== 10050 || value.pubkey !== author) return null;
  if (!Number.isInteger(value.created_at) || value.created_at <= 0) return null;
  if (value.created_at > nowSec + FUTURE_SKEW_SECONDS) return null;
  if (value.tags.length > 50) return null;
  if (value.content.length > 4096) return null;
  const fresh: Event = {
    id: value.id,
    pubkey: value.pubkey,
    created_at: value.created_at,
    kind: value.kind,
    tags: value.tags,
    content: value.content,
    sig: value.sig,
  };
  try {
    if (getEventHash(fresh) !== fresh.id || !verifyEvent(fresh)) return null;
  } catch {
    return null;
  }
  return {
    id: value.id,
    pubkey: value.pubkey,
    createdAt: value.created_at,
    relays: validateInboxRelays(relayTags(value.tags)),
  };
}

/** Newest created_at wins. Equal timestamps keep the lowest event id, per NIP-01. */
export function selectInbox(events: VerifiedInbox[]): VerifiedInbox | null {
  let best: VerifiedInbox | null = null;
  for (const event of events) {
    if (!best) {
      best = event;
      continue;
    }
    if (
      event.createdAt > best.createdAt ||
      (event.createdAt === best.createdAt && event.id < best.id)
    ) {
      best = event;
    }
  }
  return best;
}

export async function queryKind10050(
  socket: JsonSocket,
  author: string,
  timeoutMs: number,
  nowSec: number,
): Promise<{ events: VerifiedInbox[]; sawEose: boolean }> {
  const sub = crypto.randomUUID();
  const events: VerifiedInbox[] = [];
  let sawEose = false;
  let settled = false;
  const done = new Promise<"ok" | "closed">((resolve) => {
    const finish = (value: "ok" | "closed") => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    socket.onMessage((data) => {
      const parsed = parseRelayMessage(data);
      if (!parsed) return;
      if (parsed[0] === "EVENT" && parsed[1] === sub) {
        const verified = verifyInboxEvent(parsed[2], author, nowSec);
        if (verified) events.push(verified);
      }
      if (parsed[0] === "EOSE" && parsed[1] === sub) {
        sawEose = true;
        finish("ok");
      }
    });
    socket.onClose(() => finish("closed"));
    socket.onError(() => finish("closed"));
  });
  try {
    socket.send(JSON.stringify(["REQ", sub, { kinds: [10050], authors: [author], limit: 5 }]));
  } catch {
    socket.close();
    return { events, sawEose: false };
  }
  await Promise.race([done, sleep(timeoutMs)]);
  try {
    socket.send(JSON.stringify(["CLOSE", sub]));
  } catch {
    // The socket may already be closed after a timeout or relay hang-up.
  }
  socket.close();
  return { events, sawEose };
}

export async function publishToSocket(
  socket: JsonSocket,
  event: NostrEvent,
  timeoutMs: number,
): Promise<{ accepted: boolean; message: string }> {
  let settled = false;
  const done = new Promise<{ accepted: boolean; message: string } | "closed">((resolve) => {
    const finish = (value: { accepted: boolean; message: string } | "closed") => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    socket.onMessage((data) => {
      const parsed = parseRelayMessage(data);
      if (!parsed || parsed[0] !== "OK" || parsed[1] !== event.id) return;
      const message = typeof parsed[3] === "string" ? sanitizeText(parsed[3], 120) : "";
      finish({ accepted: parsed[2] === true, message });
    });
    socket.onClose(() => finish("closed"));
    socket.onError(() => finish("closed"));
  });
  try {
    socket.send(JSON.stringify(["EVENT", event]));
  } catch {
    socket.close();
    return { accepted: false, message: "closed" };
  }
  const result = await Promise.race([done, sleep(timeoutMs).then(() => "timeout" as const)]);
  socket.close();
  if (result === "timeout" || result === "closed") return { accepted: false, message: result };
  return result;
}

export function parseRelayMessage(data: string): unknown[] | null {
  if (data.length > MAX_FRAME_CHARS) return null;
  try {
    const parsed = JSON.parse(data) as unknown;
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function isEvent(value: unknown): value is Event {
  if (!value || typeof value !== "object") return false;
  const event = value as Record<string, unknown>;
  if (typeof event.id !== "string" || !/^[0-9a-f]{64}$/.test(event.id)) return false;
  if (typeof event.pubkey !== "string" || !/^[0-9a-f]{64}$/.test(event.pubkey)) return false;
  if (typeof event.sig !== "string" || !/^[0-9a-f]{128}$/.test(event.sig)) return false;
  if (typeof event.content !== "string" || typeof event.kind !== "number") return false;
  if (typeof event.created_at !== "number") return false;
  if (!Array.isArray(event.tags)) return false;
  for (const tag of event.tags) {
    if (!Array.isArray(tag) || tag.some((item) => typeof item !== "string")) return false;
  }
  return true;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
