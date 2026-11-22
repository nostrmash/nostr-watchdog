import { readResponseLimited } from "../security/body";
import { assertProbeUrl, UrlPolicyError } from "../security/url-policy";
import type { CheckResult, FetchLike, HttpCheckSpec } from "../types";
import { readPointer } from "./json-pointer";
import { misconfigured, networkFailure, result, unknownResult } from "./result";

export async function runHttpJsonCheck(input: {
  spec: HttpCheckSpec;
  url: string;
  privateNetwork: boolean;
  timeoutMs: number;
  fetch: FetchLike;
  bearerToken?: string;
}): Promise<CheckResult> {
  if (input.url === "") return misconfigured("The readiness URL is not configured.");
  let target: URL;
  try {
    target = assertProbeUrl(input.url, {
      allowHosts: [new URL(input.url).hostname],
      privateNetwork: input.privateNetwork,
    });
  } catch (error) {
    if (error instanceof UrlPolicyError || error instanceof TypeError) {
      return misconfigured("The readiness URL failed the outbound policy.");
    }
    throw error;
  }
  if (target.pathname !== input.spec.expectedPath) {
    return misconfigured(`The readiness URL must use ${input.spec.expectedPath}.`);
  }
  const started = Date.now();
  try {
    return await fetchChecked(target, input, started, 0);
  } catch (error) {
    return networkFailure(error, Date.now() - started);
  }
}

async function fetchChecked(
  target: URL,
  input: {
    spec: HttpCheckSpec;
    privateNetwork: boolean;
    timeoutMs: number;
    fetch: FetchLike;
    bearerToken?: string;
  },
  started: number,
  hop: number,
): Promise<CheckResult> {
  const headers: Record<string, string> = {
    accept: "application/json",
    "cache-control": "no-cache",
    pragma: "no-cache",
    ...input.spec.headers,
  };
  if (input.bearerToken) headers.authorization = `Bearer ${input.bearerToken}`;
  const response = await input.fetch(target.toString(), {
    method: "GET",
    redirect: "manual",
    signal: AbortSignal.timeout(input.timeoutMs),
    headers,
  });
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    if (input.bearerToken) {
      return misconfigured(
        "The readiness endpoint redirected. The authenticated probe did not follow it.",
        Date.now() - started,
      );
    }
    if (hop >= 2)
      return misconfigured(
        "The readiness endpoint redirected too many times.",
        Date.now() - started,
      );
    const location = response.headers.get("location");
    if (!location)
      return misconfigured(
        "The readiness endpoint returned a redirect without a location.",
        Date.now() - started,
      );
    let next: URL;
    try {
      next = assertProbeUrl(new URL(location, target).toString(), {
        allowHosts: [target.hostname],
        privateNetwork: input.privateNetwork,
      });
    } catch {
      return misconfigured(
        "The readiness endpoint redirected outside its allowlist.",
        Date.now() - started,
      );
    }
    return fetchChecked(next, input, started, hop + 1);
  }
  const latencyMs = Date.now() - started;
  const text = await readResponseLimited(response, input.spec.maxBytes);
  if (text === "too_large") {
    return unknownResult("The readiness response exceeded the size limit.", "schema", latencyMs);
  }
  if (response.status === 401 || response.status === 403) {
    return misconfigured("The readiness endpoint rejected the request.", latencyMs);
  }
  if (response.status === 404) {
    return misconfigured("The readiness endpoint was not found.", latencyMs);
  }
  if (response.status === 429) {
    return unknownResult("The readiness endpoint was rate limited.", "rate_limit", latencyMs);
  }
  let body: unknown = null;
  if (text !== "") {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      return unknownResult("The readiness response was not JSON.", "schema", latencyMs);
    }
  }
  if (input.spec.statusFromBody) {
    return (
      statusFromBody(body, response.status, input.spec, latencyMs) ??
      result({
        status: "down",
        errorClass: "predicate",
        summary: "The readiness response did not match its status contract.",
        latencyMs,
      })
    );
  }
  if (!input.spec.expectedStatuses.includes(response.status)) {
    return result({
      status: "down",
      errorClass: "http_status",
      summary: "The readiness endpoint returned an unexpected status.",
      latencyMs,
    });
  }
  for (const predicate of input.spec.predicates) {
    if (readPointer(body, predicate.pointer) !== predicate.equals) {
      return result({
        status: "down",
        errorClass: "predicate",
        summary: "The readiness response did not match its success contract.",
        latencyMs,
      });
    }
  }
  return result({ status: "healthy", summary: "The readiness contract passed.", latencyMs });
}

function statusFromBody(
  body: unknown,
  httpStatus: number,
  spec: HttpCheckSpec,
  latencyMs: number,
): CheckResult | null {
  const map = spec.statusFromBody;
  if (!map) return null;
  const value = readPointer(body, map.pointer);
  if (value === map.healthy && spec.expectedStatuses.includes(httpStatus)) {
    return result({ status: "healthy", summary: "The readiness contract passed.", latencyMs });
  }
  if (map.degraded && value === map.degraded && httpStatus === 200) {
    return result({
      status: "degraded",
      errorClass: "partial",
      summary: "The endpoint is only partly available.",
      latencyMs,
    });
  }
  if (map.down && value === map.down) {
    return result({
      status: "down",
      errorClass: "http_status",
      summary: "The endpoint reported that it is down.",
      latencyMs,
    });
  }
  if (map.misconfigured && value === map.misconfigured) {
    return misconfigured("The endpoint reported that it is misconfigured.", latencyMs);
  }
  return null;
}
