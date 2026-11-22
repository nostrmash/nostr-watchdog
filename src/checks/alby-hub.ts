import { readResponseLimited } from "../security/body";
import { safeVersion } from "../security/redact";
import { assertProbeUrl, UrlPolicyError } from "../security/url-policy";
import type { CheckResult, FetchLike } from "../types";
import { misconfigured, networkFailure, result, unknownResult } from "./result";

const SHARED_ALBY_HOSTS = new Set(["my.albyhub.com"]);
const KNOWN_ALARMS = new Set([
  "alby_service",
  "node_not_ready",
  "channels_offline",
  "nostr_relay_offline",
  "vss_no_subscription",
]);

export interface AlbyInput {
  baseUrl: string;
  routingProfile: string;
  hubName: string;
  hubRegion: string;
  token: string;
  privateNetwork: boolean;
  timeoutMs: number;
  fetch: FetchLike;
}

interface InfoBody {
  version: string;
  running: boolean;
  unlocked: boolean;
  startupError: boolean;
}

export async function runAlbyHubCheck(input: AlbyInput): Promise<CheckResult> {
  if (input.baseUrl === "") return misconfigured("The Alby Hub base URL is not configured.");
  let target: URL;
  try {
    target = assertProbeUrl(input.baseUrl, {
      allowHosts: [new URL(input.baseUrl).hostname],
      privateNetwork: input.privateNetwork,
    });
  } catch (error) {
    if (error instanceof UrlPolicyError || error instanceof TypeError) {
      return misconfigured("The Alby Hub URL failed the outbound policy.");
    }
    throw error;
  }
  const shared = SHARED_ALBY_HOSTS.has(target.hostname);
  if (shared && input.routingProfile !== "alby_cloud") {
    return misconfigured("The shared Alby Cloud origin requires routing profile alby_cloud.");
  }
  if (input.routingProfile === "alby_cloud" && input.hubName === "") {
    return misconfigured("Alby Cloud routing requires ALBY_HUB_NAME.");
  }
  if (
    input.routingProfile !== "" &&
    input.routingProfile !== "self_hosted" &&
    input.routingProfile !== "alby_cloud"
  ) {
    return misconfigured("ALBY_ROUTING_PROFILE must be self_hosted or alby_cloud.");
  }
  const started = Date.now();
  const headers = routingHeaders(input);
  let infoResponse: Response;
  try {
    infoResponse = await vendorGet(
      input,
      new URL("/api/info", target),
      headers,
      Boolean(input.token),
    );
  } catch (error) {
    return vendorError(error, Date.now() - started);
  }
  const infoParsed = await parseResponse(infoResponse, 32_768);
  const latency = Date.now() - started;
  if (infoParsed.kind === "network") return networkFailure(infoParsed.error, latency);
  if (infoResponse.status === 401 || infoResponse.status === 403) {
    return misconfigured("The Alby Hub rejected the read-only token.", latency);
  }
  if (infoParsed.kind === "too_large" || infoParsed.kind === "json") {
    return unknownResult(
      "The Alby Hub info response did not match the expected schema.",
      "schema",
      latency,
    );
  }
  if (infoResponse.status < 200 || infoResponse.status >= 300) {
    return result({
      status: "down",
      errorClass: "http_status",
      summary: "The Alby Hub info endpoint failed.",
      latencyMs: latency,
    });
  }
  const info = parseInfo(infoParsed.value);
  if (!info)
    return unknownResult(
      "The Alby Hub info response did not match the expected schema.",
      "schema",
      latency,
    );
  const version = safeVersion(info.version);
  if (input.token === "") {
    return result({
      status: "misconfigured",
      errorClass: "misconfigured",
      summary: "The Alby Hub read-only token is not configured, so node health was not checked.",
      latencyMs: latency,
      observedVersion: version,
    });
  }
  let healthResponse: Response;
  let nodeResponse: Response;
  try {
    [healthResponse, nodeResponse] = await Promise.all([
      vendorGet(input, new URL("/api/health", target), headers, true),
      vendorGet(input, new URL("/api/node/status", target), headers, true),
    ]);
  } catch (error) {
    return vendorError(error, Date.now() - started);
  }
  const done = Date.now() - started;
  if (
    healthResponse.status === 401 ||
    healthResponse.status === 403 ||
    nodeResponse.status === 401 ||
    nodeResponse.status === 403
  ) {
    return result({
      status: "misconfigured",
      errorClass: "unauthorized",
      summary: "The Alby Hub read-only token was rejected or has expired.",
      latencyMs: done,
      observedVersion: version,
    });
  }
  const healthParsed = await parseResponse(healthResponse, 16_384);
  const nodeParsed = await parseResponse(nodeResponse, 16_384);
  if (healthParsed.kind !== "ok" || nodeParsed.kind !== "ok") {
    return unknownResult(
      "The Alby Hub health response did not match the expected schema.",
      "schema",
      done,
    );
  }
  if (
    healthResponse.status < 200 ||
    healthResponse.status >= 300 ||
    nodeResponse.status < 200 ||
    nodeResponse.status >= 300
  ) {
    return result({
      status: "degraded",
      errorClass: "http_status",
      summary: "The Alby Hub API responded, but the health or node status endpoint failed.",
      latencyMs: done,
      observedVersion: version,
    });
  }
  const alarms = parseAlarms(healthParsed.value);
  if (alarms === "drift") {
    return unknownResult(
      "The Alby Hub health response did not match the expected schema.",
      "schema",
      done,
    );
  }
  const nodeReady = parseNodeReady(nodeParsed.value);
  if (nodeReady === "drift") {
    return unknownResult(
      "The Alby Hub node status response did not match the expected schema.",
      "schema",
      done,
    );
  }
  return classifyAlby({ info, alarms, nodeReady, version, latencyMs: done });
}

export function classifyAlby(input: {
  info: InfoBody;
  alarms: string[];
  nodeReady: boolean;
  version: string | null;
  latencyMs: number;
}): CheckResult {
  for (const alarm of input.alarms) {
    if (!KNOWN_ALARMS.has(alarm)) {
      return unknownResult(
        "The Alby Hub returned an unrecognized health alarm.",
        "schema",
        input.latencyMs,
      );
    }
  }
  const base = { latencyMs: input.latencyMs, observedVersion: input.version };
  if (!input.info.running || input.alarms.includes("node_not_ready") || !input.nodeReady) {
    return result({
      ...base,
      status: "degraded",
      errorClass: "node_not_ready",
      summary: input.info.running
        ? "The Alby Hub is up and the Lightning node is not ready."
        : "The Alby Hub API is up and the node is not running.",
    });
  }
  if (input.alarms.includes("alby_service")) {
    return result({
      ...base,
      status: "degraded",
      errorClass: "health_alarm",
      summary: "The Alby Hub reported an Alby service alarm.",
    });
  }
  if (input.alarms.includes("channels_offline")) {
    return result({
      ...base,
      status: "degraded",
      errorClass: "channels_offline",
      summary: "The Alby Hub reported offline channels.",
    });
  }
  if (input.alarms.includes("nostr_relay_offline")) {
    return result({
      ...base,
      status: "degraded",
      errorClass: "relay_offline",
      summary: "The Alby Hub reported an offline Nostr relay.",
    });
  }
  if (input.alarms.includes("vss_no_subscription")) {
    return result({
      ...base,
      status: "degraded",
      errorClass: "subscription",
      summary: "The Alby Hub reported that VSS has no subscription.",
    });
  }
  if (input.info.startupError) {
    return result({
      ...base,
      status: "degraded",
      errorClass: "startup",
      summary: "The Alby Hub recorded a startup error.",
    });
  }
  return result({
    ...base,
    status: "healthy",
    summary: "The Alby Hub info, health, and node status checks passed.",
  });
}

function vendorError(error: unknown, latencyMs: number): CheckResult {
  if (error instanceof Error && error.message === "vendor redirect refused") {
    return misconfigured(
      "The Alby Hub endpoint redirected. The probe did not follow it.",
      latencyMs,
    );
  }
  return networkFailure(error, latencyMs);
}

function routingHeaders(input: AlbyInput): Headers {
  const headers = new Headers({ accept: "application/json", "cache-control": "no-cache" });
  if (input.routingProfile === "alby_cloud") {
    headers.set("AlbyHub-Name", input.hubName);
    if (input.hubRegion !== "") headers.set("AlbyHub-Region", input.hubRegion);
  }
  return headers;
}

async function vendorGet(
  input: AlbyInput,
  url: URL,
  headers: Headers,
  authorized: boolean,
): Promise<Response> {
  const requestHeaders = new Headers(headers);
  if (authorized) requestHeaders.set("authorization", `Bearer ${input.token}`);
  const response = await input.fetch(url.toString(), {
    method: "GET",
    redirect: "manual",
    signal: AbortSignal.timeout(input.timeoutMs),
    headers: requestHeaders,
  });
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new Error("vendor redirect refused");
  }
  return response;
}

async function parseResponse(
  response: Response,
  maxBytes: number,
): Promise<
  | { kind: "ok"; value: unknown }
  | { kind: "json" }
  | { kind: "too_large" }
  | { kind: "network"; error: unknown }
> {
  try {
    const text = await readResponseLimited(response, maxBytes);
    if (text === "too_large") return { kind: "too_large" };
    if (text === "") return { kind: "ok", value: null };
    return { kind: "ok", value: JSON.parse(text) as unknown };
  } catch (error) {
    if (error instanceof SyntaxError) return { kind: "json" };
    return { kind: "network", error };
  }
}

function parseInfo(value: unknown): InfoBody | null {
  if (!value || typeof value !== "object") return null;
  const body = value as Record<string, unknown>;
  if (
    typeof body.running !== "boolean" ||
    typeof body.unlocked !== "boolean" ||
    typeof body.version !== "string"
  ) {
    return null;
  }
  if (body.startupState !== undefined && typeof body.startupState !== "string") return null;
  return {
    version: body.version,
    running: body.running,
    unlocked: body.unlocked,
    startupError: typeof body.startupError === "string" && body.startupError.trim() !== "",
  };
}

function parseAlarms(value: unknown): string[] | "drift" {
  if (!value || typeof value !== "object") return "drift";
  const alarms = (value as { alarms?: unknown }).alarms;
  if (alarms === undefined) return [];
  if (!Array.isArray(alarms)) return "drift";
  const kinds: string[] = [];
  for (const alarm of alarms) {
    if (
      !alarm ||
      typeof alarm !== "object" ||
      typeof (alarm as { kind?: unknown }).kind !== "string"
    )
      return "drift";
    kinds.push((alarm as { kind: string }).kind);
  }
  return kinds;
}

function parseNodeReady(value: unknown): boolean | "drift" {
  if (
    !value ||
    typeof value !== "object" ||
    typeof (value as { isReady?: unknown }).isReady !== "boolean"
  )
    return "drift";
  return (value as { isReady: boolean }).isReady;
}
