import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { dispatchDue } from "../../src/cycles/dispatch";
import { loadSettings } from "../../src/config/settings";
import { claimOutbox, finishDelivery, insertAlert } from "../../src/state/store";
import type { AlertDraft } from "../../src/types";
import { bind, binding, jsonResponse } from "../helpers";
import { serveInbox, signedInbox, socketPair } from "../relay-pair";
import { decode } from "nostr-tools/nip19";

afterEach(() => {
  bind({
    BOOTSTRAP_RELAYS: "",
    TELEGRAM_BOT_TOKEN: "",
    TELEGRAM_CHAT_IDS: "",
    TELEGRAM_CRITICAL_MODE: "dual",
    ALERTS_ENABLED: "true",
  });
});

function alert(
  id: string,
  destination: "nostr" | "telegram" = "nostr",
  severity: "critical" | "info" = "info",
): AlertDraft {
  return {
    id,
    alertClass: "test",
    incidentId: null,
    monitorId: "sfs-web",
    projectId: "smartflowsocial",
    dedupeKey: id,
    destination,
    severity,
    text: `SmartFlowSocial test ${id}`,
  };
}

describe("delivery", () => {
  it("accepts a gift wrap on the discovered inbox and republishes the same event after a retry", async () => {
    const recipient = decode(binding("TEST_RECIPIENT_NSEC"));
    if (recipient.type !== "nsec") throw new Error("recipient");
    bind({ BOOTSTRAP_RELAYS: "wss://bootstrap.example" });
    const now = { value: 1_700_000_000_000 };
    let attempt = 0;
    const ids: string[] = [];
    const deps = {
      now: () => now.value,
      fetch: async () => jsonResponse({}),
      connectRelay: async (url: string) => {
        const { client, server } = socketPair();
        if (url === "wss://bootstrap.example")
          serveInbox(server, [
            signedInbox(recipient.data, 1_700_000_001, [["relay", "wss://inbox.example"]]),
          ]);
        else {
          attempt += 1;
          server.onMessage((data) => {
            const message = JSON.parse(data) as [string, { id: string }];
            ids.push(message[1].id);
            if (attempt === 1)
              server.send(JSON.stringify(["OK", message[1].id, false, "rejected"]));
            else server.send(JSON.stringify(["OK", message[1].id, true, ""]));
          });
        }
        return client;
      },
    };
    await insertAlert(env.DB, alert("alt_retry"), now.value);
    await dispatchDue(env, deps, loadSettings(env));
    const retrying = await env.DB.prepare(
      "SELECT state, envelope_json FROM alert_outbox WHERE id = ?",
    )
      .bind("alt_retry")
      .first<{ state: string; envelope_json: string }>();
    expect(retrying?.state).toBe("retrying");
    expect(retrying?.envelope_json).toContain(ids[0]);
    now.value += 60_000;
    await dispatchDue(env, deps, loadSettings(env));
    const accepted = await env.DB.prepare("SELECT state FROM alert_outbox WHERE id = ?")
      .bind("alt_retry")
      .first<{ state: string }>();
    expect(accepted?.state).toBe("relay_accepted");
    expect(ids[0]).toBe(ids[1]);
  });

  it("keeps the nostr alert when telegram fails and falls back only in nostr_fallback mode", async () => {
    const recipient = decode(binding("TEST_RECIPIENT_NSEC"));
    if (recipient.type !== "nsec") throw new Error("recipient");
    bind({
      BOOTSTRAP_RELAYS: "wss://bootstrap.example",
      TELEGRAM_BOT_TOKEN: "telegram-token",
      TELEGRAM_CHAT_IDS: JSON.stringify({ smartflowsocial: "12345" }),
      TELEGRAM_CRITICAL_MODE: "dual",
    });
    const now = { value: 1_710_000_000_000 };
    const deps = {
      now: () => now.value,
      fetch: async () => {
        throw new Error("telegram down");
      },
      connectRelay: async (url: string) => {
        const { client, server } = socketPair();
        if (url === "wss://bootstrap.example")
          serveInbox(server, [
            signedInbox(recipient.data, 1_700_000_001, [["relay", "wss://inbox.example"]]),
          ]);
        else
          server.onMessage((data) => {
            const message = JSON.parse(data) as [string, { id: string }];
            server.send(JSON.stringify(["OK", message[1].id, true, ""]));
          });
        return client;
      },
    };
    await insertAlert(env.DB, alert("alt_tg", "telegram", "critical"), now.value);
    await insertAlert(env.DB, alert("alt_nostr", "nostr", "critical"), now.value);
    await dispatchDue(env, deps, loadSettings(env));
    const rows = await env.DB.prepare(
      "SELECT id, state FROM alert_outbox WHERE id IN ('alt_tg', 'alt_nostr')",
    ).all<{ id: string; state: string }>();
    const byId = new Map(rows.results.map((row) => [row.id, row.state]));
    expect(byId.get("alt_nostr")).toBe("relay_accepted");
    expect(byId.get("alt_tg")).toBe("retrying");

    bind({ TELEGRAM_CRITICAL_MODE: "nostr_fallback" });
    let failNostr = true;
    await insertAlert(env.DB, alert("alt_fallback", "nostr", "critical"), now.value);
    await dispatchDue(
      env,
      {
        ...deps,
        connectRelay: async (url: string) => {
          const { client, server } = socketPair();
          if (url === "wss://bootstrap.example")
            serveInbox(server, [
              signedInbox(recipient.data, 1_700_000_001, [["relay", "wss://inbox.example"]]),
            ]);
          else
            server.onMessage((data) => {
              const message = JSON.parse(data) as [string, { id: string }];
              server.send(JSON.stringify(["OK", message[1].id, !failNostr, ""]));
              failNostr = false;
            });
          return client;
        },
      },
      loadSettings(env),
    );
    const fallback = await env.DB.prepare(
      "SELECT destination FROM alert_outbox WHERE dedupe_key = ?",
    )
      .bind("fallback:alt_fallback")
      .first<{ destination: string }>();
    expect(fallback?.destination).toBe("telegram");
  });

  it("records a terminal failure when the recipient has no inbox", async () => {
    await env.DB.prepare("DELETE FROM relay_list_cache").run();
    bind({ BOOTSTRAP_RELAYS: "wss://bootstrap.example" });
    const recipient = decode(binding("TEST_RECIPIENT_NSEC"));
    if (recipient.type !== "nsec") throw new Error("recipient");
    const now = 1_720_000_000_000;
    await insertAlert(env.DB, alert("alt_empty"), now);
    await dispatchDue(
      env,
      {
        now: () => now,
        fetch: async () => jsonResponse({}),
        connectRelay: async () => {
          const { client, server } = socketPair();
          serveInbox(server, []);
          return client;
        },
      },
      loadSettings(env),
    );
    const row = await env.DB.prepare("SELECT state, last_error FROM alert_outbox WHERE id = ?")
      .bind("alt_empty")
      .first<{ state: string; last_error: string }>();
    expect(row).toEqual({ state: "failed", last_error: "recipient_inbox_missing" });
  });

  it("drops a finish from a claimant whose lease was replaced", async () => {
    const now = 1_730_000_000_000;
    await insertAlert(env.DB, alert("alt_fence"), now);
    const claimed = await claimOutbox(env.DB, now, now + 1_000);
    expect(claimed).toHaveLength(1);
    const token = claimed[0]?.claim_token ?? "";
    await env.DB.prepare("UPDATE alert_outbox SET claim_token = ? WHERE id = ?")
      .bind("newer-token", "alt_fence")
      .run();
    const owned = await finishDelivery(env.DB, {
      id: "alt_fence",
      token,
      state: "relay_accepted",
      attemptCount: 1,
      nextAttemptAt: now,
      error: null,
      acceptedRelays: ["wss://inbox.example"],
      failedRelays: [],
      now,
    });
    expect(owned).toBe(false);
    const row = await env.DB.prepare("SELECT state, claim_token FROM alert_outbox WHERE id = ?")
      .bind("alt_fence")
      .first<{ state: string; claim_token: string }>();
    expect(row).toEqual({ state: "retrying", claim_token: "newer-token" });
  });
});
