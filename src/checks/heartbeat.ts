import type { CheckResult } from "../types";
import { result } from "./result";

export interface HeartbeatRow {
  receivedAt: number;
  progressToken: string | null;
  progressChangedAt: number;
  idle: boolean;
  loopAt: number | null;
}

export function evaluateHeartbeat(input: {
  row: HeartbeatRow | null;
  now: number;
  staleSeconds: number;
  progressSeconds: number;
}): CheckResult {
  if (!input.row) {
    return result({
      status: "down",
      errorClass: "stale",
      summary: "No heartbeat has been received.",
    });
  }
  const ageMs = input.now - input.row.receivedAt;
  if (ageMs > input.staleSeconds * 1000) {
    return result({ status: "down", errorClass: "stale", summary: "The heartbeat is stale." });
  }
  const loopAge = input.row.loopAt === null ? null : input.now - input.row.loopAt;
  if (loopAge !== null && loopAge > input.staleSeconds * 1000) {
    return result({
      status: "down",
      errorClass: "stale",
      summary: "A heartbeat arrived, but the job loop timestamp is stale.",
    });
  }
  if (!input.row.idle && input.now - input.row.progressChangedAt > input.progressSeconds * 1000) {
    return result({
      status: "degraded",
      errorClass: "not_progressing",
      summary: "The process is alive, but reported work has not progressed.",
    });
  }
  return result({
    status: "healthy",
    summary: input.row.idle
      ? "The heartbeat is fresh and the loop reported idle."
      : "The heartbeat is fresh and progress is current.",
  });
}
