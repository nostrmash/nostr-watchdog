export type RelayFixtureMode =
  "inbox" | "publish-ok" | "publish-reject" | "silent" | "refuse" | "malformed";

let mode: RelayFixtureMode = "inbox";
let events: unknown[] = [];
let lastUrl = "";

export function testRelayAllowed(env: Env): boolean {
  return env.ENVIRONMENT === "development" && Reflect.get(env, "TEST_RELAY") === "enabled";
}

export async function handleTestRelay(request: Request): Promise<Response> {
  const url = new URL(request.url);
  lastUrl = url.toString();
  if (request.method === "POST" && url.pathname === "/__test_relay/config") {
    let body: { mode?: RelayFixtureMode; events?: unknown[] };
    try {
      body = (await request.json()) as { mode?: RelayFixtureMode; events?: unknown[] };
    } catch {
      return new Response(JSON.stringify({ error: "bad_request" }), { status: 400 });
    }
    if (!body.mode) return new Response(JSON.stringify({ error: "bad_request" }), { status: 400 });
    mode = body.mode;
    events = Array.isArray(body.events) ? body.events : [];
    return Response.json({ ok: true });
  }
  if (request.method === "GET" && url.pathname === "/__test_relay/last") {
    return Response.json({ url: lastUrl });
  }
  if (url.pathname !== "/__test_relay") return new Response(null, { status: 404 });
  if (mode === "refuse") return new Response("refused", { status: 200 });
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("expected upgrade", { status: 426 });
  }
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();
  const active = mode;
  const canned = events;
  server.addEventListener("message", (event) => {
    const data = typeof event.data === "string" ? event.data : "";
    if (active === "silent") return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(data) as unknown;
    } catch {
      return;
    }
    if (!Array.isArray(parsed)) return;
    if (parsed[0] === "REQ") {
      if (active === "malformed") server.send("{{{");
      for (const item of canned) server.send(JSON.stringify(["EVENT", parsed[1], item]));
      server.send(JSON.stringify(["EOSE", parsed[1]]));
    }
    if (parsed[0] === "EVENT") {
      const published = parsed[1] as { id?: string; kind?: number };
      const ok = active !== "publish-reject" && published.kind === 1059;
      server.send(JSON.stringify(["OK", published.id, ok, ok ? "" : "rejected"]));
    }
  });
  return new Response(null, { status: 101, webSocket: client });
}
