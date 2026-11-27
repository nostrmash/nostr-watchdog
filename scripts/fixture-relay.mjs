// Loopback NIP-01 relay for local Marmot tests. It stores events and answers
// REQ with EVENT then EOSE. Signature checks happen in the Rust test, which
// holds the notification server's key. This process checks event shape only.
// It listens on 127.0.0.1 and has no package dependency.

import { createHash } from "node:crypto";
import { createServer } from "node:http";

const port = Number(process.env.PORT || 0);
const events = new Map();
const clients = new Set();
const rejectKinds = new Set();
let seq = 0;

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

function compareStored(left, right) {
  return right.event.created_at - left.event.created_at ||
    left.event.id.localeCompare(right.event.id);
}

function backlog(filters) {
  const storedEvents = [...events.values()];
  const selected = new Map();
  for (const filter of filters.length ? filters : [{}]) {
    const found = storedEvents.filter((stored) => matches(filter, stored.event));
    found.sort(compareStored);
    const limit = filter.limit ?? found.length;
    for (const stored of found.slice(0, limit)) {
      selected.set(stored.event.id, stored);
    }
  }
  return [...selected.values()].sort(compareStored);
}

function hex(value, length) {
  return typeof value === "string" && value.length === length && /^[0-9a-f]+$/i.test(value);
}

function structurallyValid(event) {
  return (
    event &&
    typeof event === "object" &&
    hex(event.id, 64) &&
    hex(event.pubkey, 64) &&
    hex(event.sig, 128) &&
    Number.isInteger(event.kind) &&
    Number.isInteger(event.created_at) &&
    typeof event.content === "string" &&
    Array.isArray(event.tags)
  );
}

function broadcast(stored) {
  const event = stored.event;
  for (const client of clients) {
    for (const [sub, filters] of client.subs) {
      if (matching(filters, event)) {
        client.send(JSON.stringify(["EVENT", sub, event]));
      }
    }
  }
}

function acceptEvent(event) {
  if (!structurallyValid(event)) {
    return { ok: false, message: "invalid: event shape" };
  }
  if (rejectKinds.has(event.kind)) {
    return { ok: false, message: "blocked: kind" };
  }
  const key = address(event);
  if (key) {
    for (const [id, stored] of events) {
      if (address(stored.event) === key && stored.event.created_at <= event.created_at) {
        events.delete(id);
      }
    }
  }
  seq += 1;
  const stored = { seq, event };
  events.set(event.id, stored);
  broadcast(stored);
  return { ok: true, message: "" };
}

function encodeFrame(opcode, payload) {
  const body = Buffer.from(payload);
  let header;
  if (body.length < 126) {
    header = Buffer.alloc(2);
    header[1] = body.length;
  } else if (body.length < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(body.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(body.length), 2);
  }
  header[0] = 0x80 | opcode;
  return Buffer.concat([header, body]);
}

class Client {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.subs = new Map();
    this.fragments = [];
    this.fragmentOpcode = 1;
    clients.add(this);
  }

  send(text) {
    if (!this.socket.destroyed) this.socket.write(encodeFrame(1, text));
  }

  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.consume()) {}
  }

  consume() {
    if (this.buffer.length < 2) return false;
    const first = this.buffer[0];
    const second = this.buffer[1];
    const fin = (first & 0x80) !== 0;
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let offset = 2;
    if (length === 126) {
      if (this.buffer.length < 4) return false;
      length = this.buffer.readUInt16BE(2);
      offset = 4;
    } else if (length === 127) {
      if (this.buffer.length < 10) return false;
      const wide = this.buffer.readBigUInt64BE(2);
      if (wide > BigInt(1_000_000)) {
        this.socket.destroy();
        return false;
      }
      length = Number(wide);
      offset = 10;
    }
    if (length > 1_000_000) {
      this.socket.destroy();
      return false;
    }
    const maskLength = masked ? 4 : 0;
    if (this.buffer.length < offset + maskLength + length) return false;
    let payload = this.buffer.subarray(offset + maskLength, offset + maskLength + length);
    if (masked) {
      const mask = this.buffer.subarray(offset, offset + 4);
      payload = Buffer.from(payload);
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % 4];
      }
    }
    this.buffer = this.buffer.subarray(offset + maskLength + length);
    this.frame(fin, opcode, payload);
    return true;
  }

  frame(fin, opcode, payload) {
    if (opcode === 0 || opcode === 1 || opcode === 2) {
      const kind = opcode === 0 ? this.fragmentOpcode : opcode;
      if (opcode !== 0) {
        this.fragments = [];
        this.fragmentOpcode = kind;
      }
      this.fragments.push(Buffer.from(payload));
      if (!fin) return;
      const message = Buffer.concat(this.fragments);
      this.fragments = [];
      if (kind === 1) this.message(message.toString("utf8"));
      return;
    }
    if (opcode === 8) {
      if (!this.socket.destroyed) this.socket.write(encodeFrame(8, payload));
      this.socket.end();
      return;
    }
    if (opcode === 9) {
      if (!this.socket.destroyed) this.socket.write(encodeFrame(10, payload));
    }
  }

  message(text) {
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      return;
    }
    if (!Array.isArray(message) || message.length === 0) return;
    const [type, ...rest] = message;
    if (type === "EVENT" && rest[0] && typeof rest[0] === "object") {
      const result = acceptEvent(rest[0]);
      const id = typeof rest[0].id === "string" ? rest[0].id : "";
      this.send(JSON.stringify(["OK", id, result.ok, result.message]));
      return;
    }
    if (type === "REQ" && typeof rest[0] === "string") {
      const sub = rest[0];
      const filters = rest.slice(1).filter((item) => item && typeof item === "object");
      this.subs.set(sub, filters);
      for (const stored of backlog(filters)) {
        this.send(JSON.stringify(["EVENT", sub, stored.event]));
      }
      this.send(JSON.stringify(["EOSE", sub]));
      return;
    }
    if (type === "CLOSE" && typeof rest[0] === "string") {
      this.subs.delete(rest[0]);
    }
  }
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new Error("too_large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

let healthReady = false;
const server = createServer(async (request, response) => {
  const url = new URL(request.url || "/", "http://127.0.0.1");
  if (request.method === "POST" && url.pathname === "/telegram") {
    const message = JSON.parse(await readBody(request));
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ ok: message.chat_id === "1" && Boolean(message.text) }));
    return;
  }
  if (request.method === "GET" && url.pathname === "/healthcheck") {
    response.statusCode = healthReady ? 200 : 503;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ status: healthReady ? "ok" : "down" }));
    return;
  }
  if (request.method === "GET" && url.pathname === "/stats") {
    const counts = {};
    const giftWraps = [];
    for (const stored of events.values()) {
      const kind = String(stored.event.kind);
      counts[kind] = (counts[kind] || 0) + 1;
      if (stored.event.kind === 1059) {
        const target = (stored.event.tags || []).find((tag) => tag[0] === "p");
        giftWraps.push({
          idPrefix: String(stored.event.id).slice(0, 12),
          recipientPrefix: target ? String(target[1]).slice(0, 12) : "",
        });
      }
    }
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ counts, giftWraps }));
    return;
  }
  if (request.method === "GET" && url.pathname === "/order") {
    const order = [...events.values()]
      .map((stored) => ({ seq: stored.seq, kind: stored.event.kind }))
      .sort((left, right) => left.seq - right.seq);
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify(order));
    return;
  }
  if (request.method === "GET" && url.pathname === "/events") {
    const kind = Number(url.searchParams.get("kind"));
    const selected = [...events.values()]
      .filter((stored) => stored.event.kind === kind)
      .sort((left, right) => left.seq - right.seq)
      .map((stored) => ({ seq: stored.seq, event: stored.event }));
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify(selected));
    return;
  }
  if (request.method === "POST" && url.pathname === "/event") {
    try {
      const event = JSON.parse(await readBody(request));
      const result = acceptEvent(event);
      response.statusCode = result.ok ? 200 : 400;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(result));
    } catch {
      response.statusCode = 400;
      response.end();
    }
    return;
  }
  if (request.method === "POST" && url.pathname === "/control") {
    try {
      const body = JSON.parse(await readBody(request));
      if (typeof body.healthReady === "boolean") healthReady = body.healthReady;
      rejectKinds.clear();
      for (const kind of body.rejectKinds || []) rejectKinds.add(kind);
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ rejectKinds: [...rejectKinds] }));
    } catch {
      response.statusCode = 400;
      response.end();
    }
    return;
  }
  response.statusCode = 404;
  response.end();
});

server.on("upgrade", (request, socket, head) => {
  const key = request.headers["sec-websocket-key"];
  if (!key || request.headers.upgrade?.toLowerCase() !== "websocket") {
    socket.destroy();
    return;
  }
  const accept = createHash("sha1")
    .update(String(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    .digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  const client = new Client(socket);
  socket.on("data", (chunk) => client.push(chunk));
  socket.on("close", () => clients.delete(client));
  socket.on("error", () => clients.delete(client));
  if (head.length) client.push(head);
});

server.listen(port, "127.0.0.1", () => {
  const bound = server.address();
  process.stdout.write(`ws://127.0.0.1:${bound.port}\n`);
});
