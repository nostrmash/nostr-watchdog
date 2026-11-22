import { SELF } from "cloudflare:test";
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";

import { discoverInbox, publishGiftWrap, buildGiftWrap } from "../../src/alerts/nip17";
import { connectRelay } from "../../src/alerts/relay";
import { signedInbox } from "../relay-pair";
import type { FetchLike } from "../../src/types";

const fetchImpl: FetchLike = (input, init) => SELF.fetch(input as RequestInfo, init);

async function configure(mode: string, events: unknown[] = []): Promise<void> {
  const response = await SELF.fetch("https://watchdog.test/__test_relay/config", {
    method: "POST",
    body: JSON.stringify({ mode, events }),
  });
  expect(response.status).toBe(200);
}

describe("workers websocket relay", () => {
  it("upgrades https, discovers a signed inbox, publishes kind 1059, and handles rejection and timeout", async () => {
    const secret = generateSecretKey();
    const author = getPublicKey(secret);
    const sender = generateSecretKey();
    const inbox = signedInbox(secret, 1_700_000_010, [
      ["relay", "wss://watchdog.test/__test_relay"],
    ]);
    await configure("inbox", [inbox]);
    const discovered = await discoverInbox({
      author,
      bootstrap: ["wss://watchdog.test/__test_relay"],
      connect: (url) => connectRelay(url, fetchImpl, 2_000),
      timeoutMs: 2_000,
      nowMs: 1_700_000_100_000,
    });
    expect(discovered.relays).toEqual(["wss://watchdog.test/__test_relay"]);
    const seen = await SELF.fetch("https://watchdog.test/__test_relay/last");
    const last = (await seen.json()) as { url: string };
    expect(last.url.startsWith("https://")).toBe(true);
    expect(last.url.includes("wss://")).toBe(false);

    await configure("publish-ok");
    const event = buildGiftWrap({
      senderSecret: sender,
      recipient: author,
      message: "workers runtime",
      title: "Watchdog",
      createdAt: 1_700_000_100,
    });
    const published = await publishGiftWrap({
      event,
      relays: ["wss://watchdog.test/__test_relay"],
      connect: (url) => connectRelay(url, fetchImpl, 2_000),
      timeoutMs: 2_000,
    });
    expect(published.accepted).toEqual(["wss://watchdog.test/__test_relay"]);

    await configure("publish-reject");
    const rejected = await publishGiftWrap({
      event,
      relays: ["wss://watchdog.test/__test_relay"],
      connect: (url) => connectRelay(url, fetchImpl, 2_000),
      timeoutMs: 2_000,
    });
    expect(rejected.accepted).toEqual([]);
    expect(rejected.failed).toEqual(["wss://watchdog.test/__test_relay"]);

    await configure("silent");
    const hung = await discoverInbox({
      author,
      bootstrap: ["wss://watchdog.test/__test_relay"],
      connect: (url) => connectRelay(url, fetchImpl, 300),
      timeoutMs: 300,
      nowMs: 1_700_000_100_000,
    });
    expect(hung.definitiveEmpty).toBe(false);
    expect(hung.relays).toEqual([]);

    await configure("refuse");
    await expect(
      connectRelay("wss://watchdog.test/__test_relay", fetchImpl, 1_000),
    ).rejects.toThrow("relay_upgrade_failed");

    await configure("malformed", [inbox]);
    const messy = await discoverInbox({
      author,
      bootstrap: ["wss://watchdog.test/__test_relay"],
      connect: (url) => connectRelay(url, fetchImpl, 2_000),
      timeoutMs: 2_000,
      nowMs: 1_700_000_100_000,
    });
    expect(messy.relays).toEqual(["wss://watchdog.test/__test_relay"]);
  });
});
