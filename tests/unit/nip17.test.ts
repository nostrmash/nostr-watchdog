import { describe, expect, it } from "vitest";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { npubEncode } from "nostr-tools/nip19";

import {
  buildGiftWrap,
  discoverInbox,
  openGiftWrap,
  publishGiftWrap,
  recipientPubkey,
} from "../../src/alerts/nip17";
import { verifyInboxEvent, workersWebSocketUrl } from "../../src/alerts/relay";
import { serveInbox, signedInbox, socketPair } from "../relay-pair";

describe("nip17", () => {
  it("round-trips a gift wrap for two different senders and only the recipient", () => {
    const recipient = generateSecretKey();
    const first = generateSecretKey();
    const second = generateSecretKey();
    expect(getPublicKey(first)).not.toBe(getPublicKey(second));
    const message = "SmartFlowSocial watchdog test";
    const wrapped = buildGiftWrap({
      senderSecret: first,
      recipient: getPublicKey(recipient),
      message,
      title: "SmartFlowSocial Watchdog",
      createdAt: 1_700_000_000,
    });
    expect(wrapped.kind).toBe(1059);
    expect(openGiftWrap(wrapped, recipient).content).toBe(message);
    expect(openGiftWrap(wrapped, recipient).pubkey).toBe(getPublicKey(first));
    expect(() => openGiftWrap(wrapped, second)).toThrow();
    expect(recipientPubkey(npubEncode(getPublicKey(recipient)))).toBe(getPublicKey(recipient));
  });

  it("publishes only to the newest valid kind 10050 inbox", async () => {
    const inboxSecret = generateSecretKey();
    const author = getPublicKey(inboxSecret);
    const sender = generateSecretKey();
    const discovered = await discoverInbox({
      author,
      bootstrap: ["wss://bootstrap.example"],
      timeoutMs: 1000,
      nowMs: 1_700_000_100_000,
      connect: async (url) => {
        expect(url).toBe("wss://bootstrap.example");
        const { client, server } = socketPair();
        serveInbox(server, [
          signedInbox(inboxSecret, 1_700_000_001, [["relay", "wss://old.example"]]),
          signedInbox(inboxSecret, 1_700_000_002, [
            ["relay", "https://bad.example"],
            ["relay", "wss://inbox.example"],
          ]),
        ]);
        return client;
      },
    });
    expect(discovered.relays).toEqual(["wss://inbox.example"]);
    const event = buildGiftWrap({
      senderSecret: sender,
      recipient: author,
      message: "hello",
      title: "Watchdog",
      createdAt: 1_700_000_000,
    });
    const published = await publishGiftWrap({
      event,
      relays: discovered.relays,
      timeoutMs: 1000,
      connect: async (url) => {
        expect(url).toBe("wss://inbox.example");
        const { client, server } = socketPair();
        server.onMessage((data) => {
          const message = JSON.parse(data) as [string, { id: string }];
          expect(message[1].id).toBe(event.id);
          server.send(JSON.stringify(["OK", message[1].id, true, ""]));
        });
        return client;
      },
    });
    expect(published.accepted).toEqual(["wss://inbox.example"]);
    const again = await publishGiftWrap({
      event,
      relays: ["wss://inbox.example"],
      timeoutMs: 1000,
      connect: async () => {
        const { client, server } = socketPair();
        server.onMessage((data) => {
          const message = JSON.parse(data) as [string, { id: string }];
          expect(message[1].id).toBe(event.id);
          server.send(JSON.stringify(["OK", message[1].id, true, ""]));
        });
        return client;
      },
    });
    expect(again.accepted).toEqual(["wss://inbox.example"]);
  });

  it("fails closed when every responding relay has no inbox and does not treat a timeout as definitive", async () => {
    const author = getPublicKey(generateSecretKey());
    const empty = await discoverInbox({
      author,
      bootstrap: ["wss://bootstrap.example"],
      timeoutMs: 1000,
      nowMs: 1_700_000_100_000,
      connect: async () => {
        const { client, server } = socketPair();
        serveInbox(server, []);
        return client;
      },
    });
    expect(empty.relays).toEqual([]);
    expect(empty.definitiveEmpty).toBe(true);
    const mixed = await discoverInbox({
      author,
      bootstrap: ["wss://down.example", "wss://empty.example"],
      timeoutMs: 1000,
      nowMs: 1_700_000_100_000,
      connect: async (url) => {
        if (url.endsWith("down.example")) throw new Error("timeout");
        const { client, server } = socketPair();
        serveInbox(server, []);
        return client;
      },
    });
    expect(mixed.definitiveEmpty).toBe(false);
  });

  it("rejects forged inbox events and keeps the newest valid event across relays", async () => {
    const secret = generateSecretKey();
    const author = getPublicKey(secret);
    const other = generateSecretKey();
    const valid = signedInbox(secret, 1_700_000_010, [["relay", "wss://new.example"]]);
    const older = signedInbox(secret, 1_700_000_001, [["relay", "wss://old.example"]]);
    const forged = { ...valid, sig: "ab".repeat(64), id: "cd".repeat(32) };
    expect(verifyInboxEvent(forged, author, 1_700_000_100)).toBeNull();
    const wrongAuthor = finalizeEvent(
      {
        kind: 10050,
        created_at: 1_700_000_050,
        tags: [["relay", "wss://attacker.example"]],
        content: "",
      },
      other,
    );
    expect(verifyInboxEvent(wrongAuthor, author, 1_700_000_100)).toBeNull();
    const discovered = await discoverInbox({
      author,
      bootstrap: ["wss://a.example", "wss://b.example"],
      timeoutMs: 1000,
      nowMs: 1_700_000_100_000,
      connect: async (url) => {
        const { client, server } = socketPair();
        serveInbox(server, url.endsWith("a.example") ? [older, forged as typeof valid] : [valid]);
        return client;
      },
    });
    expect(discovered.relays).toEqual(["wss://new.example"]);
    expect(discovered.event?.id).toBe(valid.id);
  });

  it("converts relay URLs to https for the Workers fetch upgrade and rejects ws", () => {
    expect(workersWebSocketUrl("wss://relay.example/path")).toBe("https://relay.example/path");
    expect(() => workersWebSocketUrl("ws://relay.example")).toThrow();
    expect(() => workersWebSocketUrl("https://relay.example")).toThrow();
  });

  it("builds a gift wrap within a local execution budget", () => {
    const started = performance.now();
    buildGiftWrap({
      senderSecret: generateSecretKey(),
      recipient: getPublicKey(generateSecretKey()),
      message: "budget",
      title: "Watchdog",
      createdAt: 1_700_000_000,
    });
    expect(performance.now() - started).toBeLessThan(2000);
  });
});
