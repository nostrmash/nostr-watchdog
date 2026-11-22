import { describe, expect, it } from "vitest";
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { npubEncode } from "nostr-tools/nip19";

import {
  buildGiftWrap,
  discoverInbox,
  openGiftWrap,
  publishGiftWrap,
  recipientPubkey,
} from "../../src/alerts/nip17";
import { serveInbox, socketPair } from "../relay-pair";

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
    const author = getPublicKey(generateSecretKey());
    const sender = generateSecretKey();
    const discovered = await discoverInbox({
      author,
      bootstrap: ["wss://bootstrap.example"],
      timeoutMs: 1000,
      connect: async (url) => {
        expect(url).toBe("wss://bootstrap.example");
        const { client, server } = socketPair();
        serveInbox(server, author, [
          { created_at: 1, tags: [["relay", "wss://old.example"]] },
          {
            created_at: 2,
            tags: [
              ["relay", "https://bad.example"],
              ["relay", "wss://inbox.example"],
            ],
          },
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
      connect: async () => {
        const { client, server } = socketPair();
        serveInbox(server, author, []);
        return client;
      },
    });
    expect(empty).toEqual({ relays: [], definitiveEmpty: true });
    const mixed = await discoverInbox({
      author,
      bootstrap: ["wss://down.example", "wss://empty.example"],
      timeoutMs: 1000,
      connect: async (url) => {
        if (url.endsWith("down.example")) throw new Error("timeout");
        const { client, server } = socketPair();
        serveInbox(server, author, []);
        return client;
      },
    });
    expect(mixed.definitiveEmpty).toBe(false);
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
