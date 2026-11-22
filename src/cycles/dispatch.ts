import type { NostrEvent } from "nostr-tools/pure";

import {
  buildGiftWrap,
  discoverInbox,
  publishGiftWrap,
  recipientPubkey,
  senderKeyFromNsec,
  workersRelayConnect,
} from "../alerts/nip17";
import { sendTelegram, telegramChat } from "../alerts/telegram";
import { projectById, projectRecipient } from "../config/projects";
import type { Settings } from "../config/settings";
import type { Dependencies } from "../deps";
import { log, readString } from "../runtime";
import {
  claimOutbox,
  claimRow,
  extendClaim,
  finishDelivery,
  insertAlert,
  readEnvelope,
  relayCache,
  saveEnvelope,
  saveRelayCache,
} from "../state/store";
import type { AlertDraft, OutboxRow } from "../types";

const MAX_ATTEMPTS = 8;

export async function dispatchDue(env: Env, deps: Dependencies, settings: Settings): Promise<void> {
  if (!settings.alertsEnabled) return;
  const now = deps.now();
  const rows = await claimOutbox(env.DB, now, now + settings.deliveryClaimMs);
  for (const row of rows) {
    try {
      await deliver(env, deps, settings, row);
    } catch {
      const token = row.claim_token;
      if (!token) continue;
      const owned = await finishDelivery(env.DB, {
        id: row.id,
        token,
        state: nextState(row.attempt_count + 1),
        attemptCount: row.attempt_count + 1,
        nextAttemptAt: now + backoff(row.attempt_count + 1),
        error: "delivery_failed",
        acceptedRelays: null,
        failedRelays: null,
        now,
      });
      if (owned) log("error", "delivery_failed", { alert: row.id, destination: row.destination });
    }
  }
}

export async function deliver(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  row: OutboxRow,
): Promise<OutboxRow["state"]> {
  const now = deps.now();
  const attempt = row.attempt_count + 1;
  const token =
    row.claim_token ?? (await claimRow(env.DB, row.id, now, now + settings.deliveryClaimMs)) ?? "";
  if (token === "") return row.state;
  if (row.destination === "telegram") {
    const chat = telegramChat(readString(env, "TELEGRAM_CHAT_IDS"), row.project_id);
    const tokenMissing = readString(env, "TELEGRAM_BOT_TOKEN") === "";
    const sent =
      chat && !tokenMissing
        ? await sendTelegram({
            token: readString(env, "TELEGRAM_BOT_TOKEN"),
            chatId: chat,
            text: row.payload_text,
            fetch: deps.fetch,
            timeoutMs: settings.timeoutMs,
          })
        : "failed";
    const error =
      sent === "accepted"
        ? null
        : tokenMissing || !chat
          ? "telegram_unavailable"
          : "telegram_failed";
    const state =
      sent === "accepted" ? "relay_accepted" : nextState(attempt, tokenMissing || !chat);
    await finishDelivery(env.DB, {
      id: row.id,
      token,
      state,
      attemptCount: attempt,
      nextAttemptAt: now + backoff(attempt),
      error,
      acceptedRelays: null,
      failedRelays: null,
      now,
    });
    return state;
  }
  const outcome = await deliverNostr(env, deps, settings, { ...row, claim_token: token });
  const state = outcome.accepted ? "relay_accepted" : nextState(attempt, outcome.terminal === true);
  const owned = await finishDelivery(env.DB, {
    id: row.id,
    token,
    state,
    attemptCount: attempt,
    nextAttemptAt: now + backoff(attempt),
    error: outcome.error,
    acceptedRelays: outcome.acceptedRelays,
    failedRelays: outcome.failedRelays,
    now,
  });
  if (
    owned &&
    !outcome.accepted &&
    settings.telegramMode === "nostr_fallback" &&
    row.severity === "critical"
  ) {
    await enqueueFallback(env, row, now);
  }
  return owned ? state : row.state;
}

async function deliverNostr(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  row: OutboxRow,
): Promise<{
  accepted: boolean;
  error: string | null;
  terminal?: boolean;
  acceptedRelays: string[];
  failedRelays: string[];
}> {
  const none = { acceptedRelays: [] as string[], failedRelays: [] as string[] };
  const project = projectById(row.project_id);
  if (!project) return { accepted: false, error: "project_invalid", terminal: true, ...none };
  const claim = row.claim_token ?? "";
  const now = deps.now();
  if (!(await extendClaim(env.DB, row.id, claim, now + settings.deliveryClaimMs))) {
    return { accepted: false, error: "claim_lost", ...none };
  }
  const nsec = readString(env, project.senderSecret);
  if (nsec === "") return { accepted: false, error: "sender_key_missing", terminal: true, ...none };
  let secret: Uint8Array;
  try {
    secret = senderKeyFromNsec(nsec);
  } catch {
    return { accepted: false, error: "sender_key_invalid", terminal: true, ...none };
  }
  const recipientRaw = projectRecipient(env, project.id);
  if (!recipientRaw)
    return { accepted: false, error: "recipient_missing", terminal: true, ...none };
  let recipient: string;
  try {
    recipient = recipientPubkey(recipientRaw);
  } catch {
    return { accepted: false, error: "recipient_invalid", terminal: true, ...none };
  }
  const cached = await relayCache(env.DB, recipient, now);
  let relays = cached && !cached.negative ? cached.relays : null;
  if (cached?.negative) {
    return { accepted: false, error: "recipient_inbox_missing", terminal: true, ...none };
  }
  const connect = deps.connectRelay ?? workersRelayConnect(deps.fetch, settings.timeoutMs);
  if (!relays) {
    if (settings.bootstrap.length === 0) {
      return { accepted: false, error: "bootstrap_relays_missing", terminal: true, ...none };
    }
    const found = await discoverInbox({
      author: recipient,
      bootstrap: settings.bootstrap,
      connect,
      timeoutMs: settings.timeoutMs,
      nowMs: now,
    });
    if (found.relays.length === 0) {
      if (found.definitiveEmpty) {
        await saveRelayCache(
          env.DB,
          recipient,
          [],
          true,
          now,
          now + Math.min(settings.relayTtlSeconds, 300) * 1000,
        );
        return { accepted: false, error: "recipient_inbox_missing", terminal: true, ...none };
      }
      return { accepted: false, error: "inbox_discovery_failed", ...none };
    }
    relays = found.relays;
    await saveRelayCache(
      env.DB,
      recipient,
      relays,
      false,
      now,
      now + settings.relayTtlSeconds * 1000,
    );
  }
  if (!(await extendClaim(env.DB, row.id, claim, deps.now() + settings.deliveryClaimMs))) {
    return { accepted: false, error: "claim_lost", ...none };
  }
  const event = await envelopeFor(env, row, secret, recipient, project.contactName, claim);
  if (!event) return { accepted: false, error: "envelope_invalid", terminal: true, ...none };
  const published = await publishGiftWrap({
    event,
    relays,
    connect,
    timeoutMs: settings.timeoutMs,
  });
  if (published.accepted.length === 0) {
    return {
      accepted: false,
      error: "relay_rejected",
      acceptedRelays: [],
      failedRelays: published.failed,
    };
  }
  return {
    accepted: true,
    error: published.failed.length > 0 ? "partial_relay_acceptance" : null,
    acceptedRelays: published.accepted,
    failedRelays: published.failed,
  };
}

async function envelopeFor(
  env: Env,
  row: OutboxRow,
  secret: Uint8Array,
  recipient: string,
  title: string,
  claim: string,
): Promise<NostrEvent | null> {
  const stored = row.envelope_json ?? (await readEnvelope(env.DB, row.id));
  if (stored) {
    try {
      const parsed = JSON.parse(stored) as NostrEvent;
      if (parsed.kind !== 1059 || typeof parsed.id !== "string") return null;
      return parsed;
    } catch {
      return null;
    }
  }
  const event = buildGiftWrap({
    senderSecret: secret,
    recipient,
    message: row.payload_text,
    title,
    createdAt: Math.floor(row.created_at / 1000),
  });
  const saved = await saveEnvelope(env.DB, row.id, claim, JSON.stringify(event), Date.now());
  if (saved === "lost") return null;
  if (saved === "exists") {
    const again = await readEnvelope(env.DB, row.id);
    if (!again) return null;
    try {
      return JSON.parse(again) as NostrEvent;
    } catch {
      return null;
    }
  }
  return event;
}

async function enqueueFallback(env: Env, row: OutboxRow, now: number): Promise<void> {
  if (!projectById(row.project_id)) return;
  const chat = telegramChat(readString(env, "TELEGRAM_CHAT_IDS"), row.project_id);
  if (!chat || readString(env, "TELEGRAM_BOT_TOKEN") === "") return;
  const alert: AlertDraft = {
    id: `alt_${crypto.randomUUID()}`,
    alertClass: row.alert_class as AlertDraft["alertClass"],
    incidentId: row.incident_id,
    monitorId: row.monitor_id,
    projectId: row.project_id,
    dedupeKey: `fallback:${row.dedupe_key}`,
    destination: "telegram",
    severity: "critical",
    text: row.payload_text,
  };
  await insertAlert(env.DB, alert, now);
}

function nextState(attempt: number, terminal = false): "retrying" | "failed" {
  return terminal || attempt >= MAX_ATTEMPTS ? "failed" : "retrying";
}

function backoff(attempt: number): number {
  return Math.min(3_600_000, 30_000 * 2 ** Math.max(0, attempt - 1));
}
