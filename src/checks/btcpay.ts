import { readResponseLimited } from "../security/body";
import { safeVersion } from "../security/redact";
import { assertProbeUrl, UrlPolicyError } from "../security/url-policy";
import type { CheckResult, FetchLike } from "../types";
import { misconfigured, networkFailure, result, unknownResult } from "./result";

export interface BtcPayInput {
  baseUrl: string;
  apiKey: string;
  privateNetwork: boolean;
  timeoutMs: number;
  fetch: FetchLike;
}

export async function runBtcpayCheck(input: BtcPayInput): Promise<CheckResult> {
  if (input.baseUrl === "") return misconfigured("The BTCPay base URL is not configured.");
  let target: URL;
  try {
    target = assertProbeUrl(input.baseUrl, {
      allowHosts: [new URL(input.baseUrl).hostname],
      privateNetwork: input.privateNetwork,
    });
  } catch (error) {
    if (error instanceof UrlPolicyError || error instanceof TypeError) {
      return misconfigured("The BTCPay URL failed the outbound policy.");
    }
    throw error;
  }
  const started = Date.now();
  let healthResponse: Response;
  try {
    healthResponse = await vendorGet(input, new URL("/api/v1/health", target), false);
  } catch (error) {
    return vendorError(error, Date.now() - started);
  }
  const healthLatency = Date.now() - started;
  if (healthResponse.status === 401 || healthResponse.status === 403) {
    return misconfigured("The BTCPay health endpoint rejected the request.", healthLatency);
  }
  const healthBody = await readJson(healthResponse, 16_384);
  if (healthBody === "too_large" || healthBody === "json") {
    return unknownResult(
      "The BTCPay health response did not match the expected schema.",
      "schema",
      healthLatency,
    );
  }
  if (healthResponse.status < 200 || healthResponse.status >= 300) {
    return result({
      status: "down",
      errorClass: "http_status",
      summary: "The BTCPay health endpoint failed.",
      latencyMs: healthLatency,
    });
  }
  const synchronized = readSynchronized(healthBody);
  if (synchronized === "drift") {
    return unknownResult(
      "The BTCPay health response did not match the expected schema.",
      "schema",
      healthLatency,
    );
  }
  if (input.apiKey === "") {
    return result({
      status: synchronized ? "healthy" : "degraded",
      errorClass: synchronized ? null : "unsynchronized",
      summary: synchronized
        ? "BTCPay public health passed. Server info was not checked because no read-only key is configured."
        : "BTCPay is up but not synchronized. Server info was not checked because no read-only key is configured.",
      latencyMs: healthLatency,
    });
  }
  let infoResponse: Response;
  try {
    infoResponse = await vendorGet(input, new URL("/api/v1/server/info", target), true);
  } catch (error) {
    return vendorError(error, Date.now() - started);
  }
  const latencyMs = Date.now() - started;
  if (infoResponse.status === 401 || infoResponse.status === 403) {
    return result({
      status: "misconfigured",
      errorClass: "unauthorized",
      summary: synchronized
        ? "BTCPay is up, but the server info key was rejected or lacks access."
        : "BTCPay is up but not synchronized, and the server info key was rejected.",
      latencyMs,
    });
  }
  const infoBody = await readJson(infoResponse, 32_768);
  if (
    infoBody === "too_large" ||
    infoBody === "json" ||
    infoResponse.status < 200 ||
    infoResponse.status >= 300
  ) {
    return unknownResult(
      "The BTCPay server info response did not match the expected schema.",
      "schema",
      latencyMs,
    );
  }
  const info = parseServerInfo(infoBody);
  if (!info)
    return unknownResult(
      "The BTCPay server info response did not match the expected schema.",
      "schema",
      latencyMs,
    );
  return classifyBtcpay({ synchronized, info, latencyMs });
}

export function classifyBtcpay(input: {
  synchronized: boolean;
  info: { version: string | null; fullySynched: boolean | null; processorUnavailable: boolean };
  latencyMs: number;
}): CheckResult {
  const version = input.info.version;
  const unsynced = !input.synchronized || input.info.fullySynched === false;
  if (input.info.processorUnavailable) {
    return result({
      status: "degraded",
      errorClass: "processor_unavailable",
      summary: unsynced
        ? "BTCPay is up, a payment processor is unavailable, and chain sync is incomplete."
        : "BTCPay is up and a payment processor is unavailable.",
      latencyMs: input.latencyMs,
      observedVersion: version,
    });
  }
  if (unsynced) {
    return result({
      status: "degraded",
      errorClass: "unsynchronized",
      summary: "BTCPay is up but not synchronized.",
      latencyMs: input.latencyMs,
      observedVersion: version,
    });
  }
  return result({
    status: "healthy",
    summary: "BTCPay health and server info checks passed.",
    latencyMs: input.latencyMs,
    observedVersion: version,
  });
}

function vendorError(error: unknown, latencyMs: number): CheckResult {
  if (error instanceof Error && error.message === "vendor redirect refused") {
    return misconfigured("The BTCPay endpoint redirected. The probe did not follow it.", latencyMs);
  }
  return networkFailure(error, latencyMs);
}

async function vendorGet(input: BtcPayInput, url: URL, authorized: boolean): Promise<Response> {
  const headers = new Headers({ accept: "application/json", "cache-control": "no-cache" });
  if (authorized) headers.set("authorization", `token ${input.apiKey}`);
  const response = await input.fetch(url.toString(), {
    method: "GET",
    redirect: "manual",
    signal: AbortSignal.timeout(input.timeoutMs),
    headers,
  });
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new Error("vendor redirect refused");
  }
  return response;
}

async function readJson(
  response: Response,
  maxBytes: number,
): Promise<unknown | "too_large" | "json"> {
  const text = await readResponseLimited(response, maxBytes);
  if (text === "too_large") return "too_large";
  if (text === "") return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return "json";
  }
}

function readSynchronized(value: unknown): boolean | "drift" {
  if (
    !value ||
    typeof value !== "object" ||
    typeof (value as { synchronized?: unknown }).synchronized !== "boolean"
  ) {
    return "drift";
  }
  return (value as { synchronized: boolean }).synchronized;
}

function parseServerInfo(
  value: unknown,
): { version: string | null; fullySynched: boolean | null; processorUnavailable: boolean } | null {
  if (!value || typeof value !== "object") return null;
  const body = value as Record<string, unknown>;
  if (typeof body.version !== "string") return null;
  if (body.fullySynched !== undefined && typeof body.fullySynched !== "boolean") return null;
  if (body.syncStatus !== undefined && !Array.isArray(body.syncStatus)) return null;
  let processorUnavailable = false;
  if (Array.isArray(body.syncStatus)) {
    for (const entry of body.syncStatus) {
      if (!entry || typeof entry !== "object") return null;
      const available = (entry as { available?: unknown }).available;
      if (available !== undefined && typeof available !== "boolean") return null;
      if (available === false) processorUnavailable = true;
    }
  }
  return {
    version: safeVersion(body.version),
    fullySynched: typeof body.fullySynched === "boolean" ? body.fullySynched : null,
    processorUnavailable,
  };
}
