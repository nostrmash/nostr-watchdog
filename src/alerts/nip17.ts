import { unwrapEvent, wrapEvent } from "nostr-tools/nip17";
import { decode } from "nostr-tools/nip19";
import { getPublicKey, type NostrEvent } from "nostr-tools/pure";

import type { FetchLike } from "../types";
import { connectRelay, queryKind10050, publishToSocket, type JsonSocket } from "./relay";

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
}): Promise<{ relays: string[]; definitiveEmpty: boolean }> {
  let emptyResponses = 0;
  let failures = 0;
  for (const relay of input.bootstrap) {
    try {
      const socket = await input.connect(relay);
      const found = await queryKind10050(socket, input.author, input.timeoutMs);
      if (found.relays.length > 0) return { relays: found.relays, definitiveEmpty: false };
      if (found.sawEose) emptyResponses += 1;
      else failures += 1;
    } catch {
      failures += 1;
    }
  }
  return { relays: [], definitiveEmpty: emptyResponses > 0 && failures === 0 };
}

export async function publishGiftWrap(input: {
  event: NostrEvent;
  relays: string[];
  connect: (url: string) => Promise<JsonSocket>;
  timeoutMs: number;
}): Promise<{ accepted: string[]; failed: string[] }> {
  const accepted: string[] = [];
  const failed: string[] = [];
  for (const relay of input.relays) {
    try {
      const socket = await input.connect(relay);
      const result = await publishToSocket(socket, input.event, input.timeoutMs);
      if (result.accepted) accepted.push(relay);
      else failed.push(relay);
    } catch {
      failed.push(relay);
    }
  }
  return { accepted, failed };
}

export function workersRelayConnect(
  fetchImpl: FetchLike,
  timeoutMs: number,
): (url: string) => Promise<JsonSocket> {
  return (url) => connectRelay(url, fetchImpl, timeoutMs);
}
