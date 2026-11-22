import type { NostrEvent } from "nostr-tools/pure";

import { sanitizeText } from "../security/redact";
import { assertWssUrl } from "../security/url-policy";
import type { FetchLike } from "../types";

export interface JsonSocket {
  send(data: string): void;
  close(): void;
  onMessage(handler: (data: string) => void): void;
  onClose(handler: () => void): void;
}

export async function connectRelay(
  url: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
): Promise<JsonSocket> {
  assertWssUrl(url);
  const response = await fetchImpl(url, {
    headers: { Upgrade: "websocket" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  const socket = response.webSocket;
  if (!socket) throw new Error("relay_upgrade_failed");
  socket.accept();
  return {
    send: (data) => socket.send(data),
    close: () => socket.close(),
    onMessage: (handler) => {
      socket.addEventListener("message", (event) => {
        handler(typeof event.data === "string" ? event.data : "");
      });
    },
    onClose: (handler) => {
      socket.addEventListener("close", () => handler());
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

export async function queryKind10050(
  socket: JsonSocket,
  author: string,
  timeoutMs: number,
): Promise<{ relays: string[]; sawEose: boolean }> {
  const sub = crypto.randomUUID();
  const events: Array<{ created_at: number; tags: string[][] }> = [];
  let sawEose = false;
  const done = new Promise<"ok" | "closed">((resolve) => {
    socket.onMessage((data) => {
      const parsed = parseRelayMessage(data);
      if (!parsed) return;
      if (parsed[0] === "EVENT" && parsed[1] === sub && isRecord(parsed[2])) {
        const event = parsed[2];
        const tags = stringTags(event.tags);
        if (
          event.kind === 10050 &&
          event.pubkey === author &&
          typeof event.created_at === "number" &&
          tags
        ) {
          events.push({ created_at: event.created_at, tags });
        }
      }
      if (parsed[0] === "EOSE" && parsed[1] === sub) {
        sawEose = true;
        resolve("ok");
      }
    });
    socket.onClose(() => resolve("closed"));
  });
  socket.send(JSON.stringify(["REQ", sub, { kinds: [10050], authors: [author], limit: 5 }]));
  await Promise.race([done, sleep(timeoutMs)]);
  socket.send(JSON.stringify(["CLOSE", sub]));
  socket.close();
  const newest = events.sort((left, right) => right.created_at - left.created_at)[0];
  return { relays: newest ? validateInboxRelays(relayTags(newest.tags)) : [], sawEose };
}

export async function publishToSocket(
  socket: JsonSocket,
  event: NostrEvent,
  timeoutMs: number,
): Promise<{ accepted: boolean; message: string }> {
  const done = new Promise<{ accepted: boolean; message: string } | "closed">((resolve) => {
    socket.onMessage((data) => {
      const parsed = parseRelayMessage(data);
      if (!parsed || parsed[0] !== "OK" || parsed[1] !== event.id) return;
      const message = typeof parsed[3] === "string" ? sanitizeText(parsed[3], 120) : "";
      resolve({ accepted: parsed[2] === true, message });
    });
    socket.onClose(() => resolve("closed"));
  });
  socket.send(JSON.stringify(["EVENT", event]));
  const result = await Promise.race([done, sleep(timeoutMs).then(() => "timeout" as const)]);
  socket.close();
  if (result === "timeout" || result === "closed") return { accepted: false, message: result };
  return result;
}

export function parseRelayMessage(data: string): unknown[] | null {
  try {
    const parsed = JSON.parse(data) as unknown;
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object";
}

function stringTags(value: unknown): string[][] | null {
  if (!Array.isArray(value)) return null;
  const tags: string[][] = [];
  for (const tag of value) {
    if (!Array.isArray(tag) || tag.some((item) => typeof item !== "string")) return null;
    tags.push(tag);
  }
  return tags;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
