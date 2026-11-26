// Copy of scripts/fixture-relay.mjs so Node resolves `ws` from this package.
// In-memory NIP-01 relay for local Marmot tests. It stores events and answers
// REQ with EVENT then EOSE. It does not check signatures. It is not a public
// relay and it listens on loopback only.

import { createServer } from "node:http";
import { WebSocketServer } from "ws";

const port = Number(process.env.PORT || 0);
const events = new Map();

function address(event) {
  const d = (event.tags || []).find((tag) => tag[0] === "d");
  const replaceable =
    event.kind === 0 ||
    event.kind === 3 ||
    (event.kind >= 10000 && event.kind < 20000) ||
    (event.kind >= 30000 && event.kind < 40000);
  if (!replaceable) return null;
  return `${event.pubkey}:${event.kind}:${d ? d[1] : ""}`;
}

function matches(filter, event) {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.since != null && event.created_at < filter.since) return false;
  if (filter.until != null && event.created_at > filter.until) return false;
  for (const [key, values] of Object.entries(filter)) {
    if (!key.startsWith("#") || !Array.isArray(values)) continue;
    const tag = key.slice(1);
    const present = (event.tags || [])
      .filter((item) => item[0] === tag)
      .map((item) => item[1]);
    if (!values.some((value) => present.includes(value))) return false;
  }
  return true;
}

function matching(filters, event) {
  return filters.length === 0 || filters.some((filter) => matches(filter, event));
}

function limited(filters, found) {
  found.sort((left, right) => right.created_at - left.created_at);
  const limit = filters.reduce(
    (bound, filter) =>
      typeof filter.limit === "number" ? Math.min(bound, filter.limit) : bound,
    found.length,
  );
  return found.slice(0, limit);
}

const server = createServer();
const sockets = new WebSocketServer({ server });
const clients = new Set();
sockets.on("connection", (socket) => {
  socket.subs = new Map();
  clients.add(socket);
  socket.on("close", () => clients.delete(socket));
  socket.on("message", (data) => {
    let message;
    try {
      message = JSON.parse(data.toString());
    } catch {
      return;
    }
    if (!Array.isArray(message) || message.length === 0) return;
    const [type, ...rest] = message;
    if (type === "EVENT" && rest[0] && typeof rest[0].id === "string") {
      const event = rest[0];
      const key = address(event);
      if (key) {
        for (const [id, stored] of events) {
          if (address(stored) === key && stored.created_at <= event.created_at) {
            events.delete(id);
          }
        }
      }
      events.set(event.id, event);
      socket.send(JSON.stringify(["OK", event.id, true, ""]));
      for (const client of clients) {
        for (const [sub, filters] of client.subs) {
          if (matching(filters, event)) {
            client.send(JSON.stringify(["EVENT", sub, event]));
          }
        }
      }
      return;
    }
    if (type === "REQ" && typeof rest[0] === "string") {
      const sub = rest[0];
      const filters = rest.slice(1).filter((item) => item && typeof item === "object");
      socket.subs.set(sub, filters);
      const found = [...events.values()].filter((event) => matching(filters, event));
      for (const event of limited(filters, found)) {
        socket.send(JSON.stringify(["EVENT", sub, event]));
      }
      socket.send(JSON.stringify(["EOSE", sub]));
      return;
    }
    if (type === "CLOSE" && typeof rest[0] === "string") {
      socket.subs.delete(rest[0]);
    }
  });
});

server.on("request", (request, response) => {
  if (request.url !== "/stats") {
    response.statusCode = 404;
    response.end();
    return;
  }
  const counts = {};
  const giftWraps = [];
  for (const event of events.values()) {
    const kind = String(event.kind);
    counts[kind] = (counts[kind] || 0) + 1;
    if (event.kind === 1059) {
      const target = (event.tags || []).find((tag) => tag[0] === "p");
      giftWraps.push({
        idPrefix: String(event.id).slice(0, 12),
        recipientPrefix: target ? String(target[1]).slice(0, 12) : "",
      });
    }
  }
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify({ counts, giftWraps }));
});

server.listen(port, "127.0.0.1", () => {
  const bound = server.address();
  process.stdout.write(`ws://127.0.0.1:${bound.port}\n`);
});
