import { clamp, readInt, readString } from "../runtime";

export interface Settings {
  enabled: boolean;
  alertsEnabled: boolean;
  concurrency: number;
  timeoutMs: number;
  failureThreshold: number | null;
  recoveryThreshold: number | null;
  relayTtlSeconds: number;
  skewSeconds: number;
  maxBody: number;
  staleSeconds: number;
  progressSeconds: number;
  reminderSeconds: number;
  unknownThreshold: number;
  deliveryClaimMs: number;
  schedulerStaleSeconds: number;
  telegramMode: "dual" | "nostr_fallback";
  bootstrap: string[];
  githubApi: string;
  privateNetwork: boolean;
  runbookBase: string | null;
  environment: string;
}

export function loadSettings(env: Env): Settings {
  const failure = readString(env, "FAILURE_THRESHOLD");
  const recovery = readString(env, "RECOVERY_THRESHOLD");
  const mode = readString(env, "TELEGRAM_CRITICAL_MODE");
  return {
    enabled: readString(env, "WATCHDOG_ENABLED") !== "false",
    alertsEnabled: readString(env, "ALERTS_ENABLED") !== "false",
    concurrency: clamp(readInt(env, "CHECK_CONCURRENCY", 4), 1, 6),
    timeoutMs: clamp(readInt(env, "CHECK_TIMEOUT_MS", 5000), 1000, 15000),
    failureThreshold: failure === "" ? null : clamp(readInt(env, "FAILURE_THRESHOLD", 2), 1, 10),
    recoveryThreshold: recovery === "" ? null : clamp(readInt(env, "RECOVERY_THRESHOLD", 2), 1, 10),
    relayTtlSeconds: clamp(readInt(env, "RELAY_LIST_TTL_SECONDS", 3600), 60, 86_400),
    skewSeconds: clamp(readInt(env, "HEARTBEAT_MAX_SKEW_SECONDS", 300), 30, 900),
    maxBody: clamp(readInt(env, "HEARTBEAT_MAX_BODY_BYTES", 4096), 256, 16_384),
    staleSeconds: clamp(readInt(env, "HEARTBEAT_STALE_SECONDS", 180), 30, 86_400),
    progressSeconds: clamp(readInt(env, "HEARTBEAT_PROGRESS_SECONDS", 600), 30, 86_400),
    reminderSeconds: clamp(readInt(env, "CRITICAL_REMINDER_SECONDS", 0), 0, 604_800),
    unknownThreshold: clamp(readInt(env, "UNKNOWN_THRESHOLD", 5), 2, 100),
    deliveryClaimMs: clamp(readInt(env, "DELIVERY_CLAIM_MS", 120_000), 30_000, 300_000),
    schedulerStaleSeconds: clamp(readInt(env, "SCHEDULER_STALE_SECONDS", 180), 90, 3600),
    telegramMode: mode === "nostr_fallback" ? "nostr_fallback" : "dual",
    bootstrap: readString(env, "BOOTSTRAP_RELAYS")
      .split(",")
      .map((item) => item.trim())
      .filter((item) => item !== ""),
    githubApi: readString(env, "GITHUB_API_BASE") || "https://api.github.com",
    privateNetwork: readString(env, "PRIVATE_NETWORK_PROFILE") === "true",
    runbookBase: httpsOrigin(readString(env, "RUNBOOK_BASE_URL")),
    environment: readString(env, "ENVIRONMENT") || "development",
  };
}

function httpsOrigin(value: string): string | null {
  if (value === "") return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "") return null;
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}
