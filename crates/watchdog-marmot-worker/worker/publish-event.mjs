// Publish one signed Nostr event and wait for the OK that names its id.
import { readFileSync } from "node:fs";
import { WebSocket } from "ws";

const [url, file] = process.argv.slice(2);
const event = JSON.parse(readFileSync(file, "utf8"));
const ws = new WebSocket(url);
const timer = setTimeout(() => {
  process.stderr.write("publication_timeout\n");
  process.exit(3);
}, 8000);
ws.on("open", () => ws.send(JSON.stringify(["EVENT", event])));
ws.on("message", (data) => {
  const text = data.toString();
  process.stdout.write(`${text}\n`);
  let frame;
  try {
    frame = JSON.parse(text);
  } catch {
    return;
  }
  if (!Array.isArray(frame) || frame[0] !== "OK" || frame[1] !== event.id) {
    return;
  }
  clearTimeout(timer);
  ws.close();
  process.exit(frame[2] === true ? 0 : 2);
});
ws.on("error", (error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
