// Publish one Nostr event to the loopback fixture. Used by the workerd test.
import { readFileSync } from "node:fs";
import { WebSocket } from "ws";

const [url, file] = process.argv.slice(2);
const event = JSON.parse(readFileSync(file, "utf8"));
const ws = new WebSocket(url);
ws.on("open", () => ws.send(JSON.stringify(["EVENT", event])));
ws.on("message", (data) => {
  process.stdout.write(`${data.toString()}\n`);
  ws.close();
});
ws.on("error", (error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
