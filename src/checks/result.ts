import type { CheckResult } from "../types";

export function result(partial: {
  status: CheckResult["status"];
  errorClass?: string | null;
  summary: string;
  latencyMs?: number | null;
  observedVersion?: string | null;
}): CheckResult {
  return {
    status: partial.status,
    errorClass: partial.errorClass ?? null,
    summary: partial.summary,
    latencyMs: partial.latencyMs ?? null,
    observedVersion: partial.observedVersion ?? null,
  };
}

export function networkFailure(error: unknown, latencyMs: number): CheckResult {
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (
    name === "AbortError" ||
    name === "TimeoutError" ||
    message.includes("timeout") ||
    message.includes("aborted")
  ) {
    return result({
      status: "down",
      errorClass: "timeout",
      summary: "The probe timed out.",
      latencyMs,
    });
  }
  if (message.includes("cert") || message.includes("tls") || message.includes("ssl")) {
    return result({
      status: "down",
      errorClass: "tls",
      summary: "The probe failed TLS validation.",
      latencyMs,
    });
  }
  if (message.includes("dns") || message.includes("enotfound") || message.includes("getaddrinfo")) {
    return result({
      status: "down",
      errorClass: "dns",
      summary: "The probe could not resolve the host.",
      latencyMs,
    });
  }
  return result({
    status: "down",
    errorClass: "network",
    summary: "The probe could not connect.",
    latencyMs,
  });
}

export function misconfigured(summary: string, latencyMs: number | null = null): CheckResult {
  return result({ status: "misconfigured", errorClass: "misconfigured", summary, latencyMs });
}

export function unknownResult(
  summary: string,
  errorClass = "schema",
  latencyMs: number | null = null,
): CheckResult {
  return result({ status: "unknown", errorClass, summary, latencyMs });
}
