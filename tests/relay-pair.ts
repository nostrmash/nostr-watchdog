import { finalizeEvent, type Event } from "nostr-tools/pure";

import type { JsonSocket } from "../src/alerts/relay";

export function socketPair(): { client: JsonSocket; server: JsonSocket } {
  const handlers = {
    client: [] as Array<(data: string) => void>,
    server: [] as Array<(data: string) => void>,
    clientClose: [] as Array<() => void>,
    serverClose: [] as Array<() => void>,
  };
  const socket = (name: "client" | "server"): JsonSocket => ({
    send(data) {
      const target = name === "client" ? handlers.server : handlers.client;
      queueMicrotask(() => {
        for (const handler of [...target]) handler(data);
      });
    },
    close() {
      const target = name === "client" ? handlers.serverClose : handlers.clientClose;
      for (const handler of target) handler();
    },
    onMessage(handler) {
      handlers[name].push(handler);
    },
    onClose(handler) {
      (name === "client" ? handlers.clientClose : handlers.serverClose).push(handler);
    },
    onError(handler) {
      (name === "client" ? handlers.clientClose : handlers.serverClose).push(handler);
    },
  });
  return { client: socket("client"), server: socket("server") };
}

export function signedInbox(secret: Uint8Array, createdAt: number, tags: string[][]): Event {
  return finalizeEvent({ kind: 10050, created_at: createdAt, tags, content: "" }, secret);
}

export function serveInbox(server: JsonSocket, events: Event[]): void {
  server.onMessage((data) => {
    const message = JSON.parse(data) as unknown[];
    if (message[0] === "REQ") {
      for (const event of events) {
        server.send(JSON.stringify(["EVENT", message[1], event]));
      }
      server.send(JSON.stringify(["EOSE", message[1]]));
    }
    if (message[0] === "EVENT") {
      const event = message[1] as { id?: string };
      server.send(JSON.stringify(["OK", event.id, true, ""]));
    }
  });
}
