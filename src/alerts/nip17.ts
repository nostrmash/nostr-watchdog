import { unwrapEvent, wrapEvent } from "nostr-tools/nip17";
import { decode } from "nostr-tools/nip19";
import { getPublicKey, type NostrEvent } from "nostr-tools/pure";

import { mapLimit } from "../runtime";
import type { FetchLike } from "../types";
import {
  connectRelay,
  queryKind10050,
  publishToSocket,
  selectInbox,
  type JsonSocket,
  type VerifiedInbox,
} from "./relay";

const PUBLISH_CONCURRENCY = 3;
const DISCOVERY_CONCURRENCY = 4;

export function senderKeyFromNsec(nsec: string): Uint8Array {
  const decoded = decode(nsec.trim());
  if (decoded.type !== "nsec") throw new Error("sender_key_invalid");
  return decoded.data;
}

export function recipientPubkey(value: string): string {
  const trimmed = value.trim();
  if (/^[0-9a-f]{64}$/i.test(trimmed)) return trimmed.toLowerCase();
  const decoded = decode(trimmed);
  if (decoded.type !== "npub") throw new Error("recipient_invalid");
  return decoded.data;
}

export function publicKeyOf(secret: Uint8Array): string {
  return getPublicKey(secret);
}

export function buildGiftWrap(input: {
  senderSecret: Uint8Array;
  recipient: string;
  message: string;
  title: string;
  createdAt: number;
}): NostrEvent {
  return wrapEvent(
    input.senderSecret,
    { publicKey: input.recipient },
    input.message,
    input.title,
    undefined,
    input.createdAt,
  );
}

export function openGiftWrap(
  event: NostrEvent,
  recipientSecret: Uint8Array,
): { content: string; pubkey: string } {
  const rumor = unwrapEvent(event, recipientSecret);
  return { content: rumor.content, pubkey: rumor.pubkey };
}

export async function discoverInbox(input: {
  author: string;
  bootstrap: string[];
  connect: (url: string) => Promise<JsonSocket>;
  timeoutMs: number;
  nowMs: number;
}): Promise<{ relays: string[]; definitiveEmpty: boolean; event: VerifiedInbox | null }> {
  if (input.bootstrap.length === 0) return { relays: [], definitiveEmpty: false, event: null };
  const nowSec = Math.floor(input.nowMs / 1000);
  const settled = await mapLimit(input.bootstrap, DISCOVERY_CONCURRENCY, async (relay) => {
    const socket = await input.connect(relay);
    return queryKind10050(socket, input.author, input.timeoutMs, nowSec);
  });
  const events: VerifiedInbox[] = [];
  let completed = 0;
  let failures = 0;
  for (const item of settled) {
    if (item.status === "rejected") {
      failures += 1;
      continue;
    }
    events.push(...item.value.events);
    if (item.value.sawEose) completed += 1;
    else failures += 1;
  }
  const selected = selectInbox(events);
  if (selected && selected.relays.length > 0) {
    return { relays: selected.relays, definitiveEmpty: false, event: selected };
  }
  const definitiveEmpty = completed > 0 && failures === 0;
  return { relays: [], definitiveEmpty, event: selected };
}

export async function publishGiftWrap(input: {
  event: NostrEvent;
  relays: string[];
  connect: (url: string) => Promise<JsonSocket>;
  timeoutMs: number;
}): Promise<{ accepted: string[]; failed: string[] }> {
  const settled = await mapLimit(input.relays, PUBLISH_CONCURRENCY, async (relay) => {
    const socket = await input.connect(relay);
    const result = await publishToSocket(socket, input.event, input.timeoutMs);
    return { relay, accepted: result.accepted };
  });
  const accepted: string[] = [];
  const failed: string[] = [];
  input.relays.forEach((relay, index) => {
    const item = settled[index];
    if (item?.status === "fulfilled" && item.value.accepted) accepted.push(relay);
    else failed.push(relay);
  });
  return { accepted, failed };
}

export function workersRelayConnect(
  fetchImpl: FetchLike,
  timeoutMs: number,
): (url: string) => Promise<JsonSocket> {
  return (url) => connectRelay(url, fetchImpl, timeoutMs);
}
