import { describe, expect, it } from "vitest";

import { emptyMemory, transition } from "../../src/state/transition";
import type { CheckResult } from "../../src/types";
import { formatIncidentMessage } from "../../src/alerts/format";

const monitor = {
  failureThreshold: 2,
  recoveryThreshold: 2,
  severity: "critical" as const,
  incidentOnDegraded: true,
};

function check(status: CheckResult["status"], summary = status): CheckResult {
  return {
    status,
    errorClass: status === "healthy" ? null : status,
    summary,
    latencyMs: 12,
    observedVersion: null,
  };
}

function step(
  memory: ReturnType<typeof emptyMemory>,
  status: CheckResult["status"],
  now: number,
  reminderSeconds = 0,
) {
  return transition({
    memory,
    result: check(status),
    now,
    monitor,
    reminderSeconds,
    newIncidentId: `inc_${now}`,
  });
}

describe("incident transitions", () => {
  it("opens after two failures and closes after two successes", () => {
    let memory = emptyMemory();
    memory = step(memory, "down", 1).memory;
    expect(memory.openIncident).toBeNull();
    const opened = step(memory, "down", 2);
    expect(opened.notice?.event).toBe("open");
    memory = step(opened.memory, "healthy", 3).memory;
    expect(memory.openIncident).not.toBeNull();
    const closed = step(memory, "healthy", 4);
    expect(closed.notice?.event).toBe("close");
    expect(closed.memory.openIncident).toBeNull();
  });

  it("does not open while flapping below the threshold", () => {
    let memory = emptyMemory();
    for (const [status, now] of [
      ["down", 1],
      ["healthy", 2],
      ["down", 3],
      ["healthy", 4],
    ] as const) {
      memory = step(memory, status, now).memory;
    }
    expect(memory.openIncident).toBeNull();
  });

  it("does not recover or count a skipped unknown sample", () => {
    const opened = step(step(emptyMemory(), "down", 1).memory, "down", 2);
    const unknown = transition({
      memory: opened.memory,
      result: check("unknown"),
      now: 3,
      monitor,
      reminderSeconds: 0,
      newIncidentId: "inc_ignored",
    });
    expect(unknown.memory.openIncident?.id).toBe(opened.memory.openIncident?.id);
    expect(unknown.memory.consecutiveFailures).toBe(2);
    expect(unknown.notice).toBeNull();
  });

  it("keeps a degraded incident at warning severity and reminds only when configured", () => {
    const first = step(emptyMemory(), "degraded", 1);
    const opened = step(first.memory, "degraded", 2);
    expect(opened.notice?.severity).toBe("warning");
    const quiet = step(opened.memory, "degraded", 10_000, 0);
    expect(quiet.notice).toBeNull();
    const reminded = step(opened.memory, "degraded", 10_000, 5);
    expect(reminded.notice).toBeNull();
    const critical = step(step(emptyMemory(), "down", 1).memory, "down", 2);
    const reminder = step(critical.memory, "down", 8_000, 5);
    expect(reminder.notice?.event).toBe("remind");
  });

  it("redacts secrets from alert text", () => {
    const text = formatIncidentMessage({
      projectName: "SmartFlowSocial",
      displayName: "App",
      severity: "critical",
      kind: "outage",
      event: "open",
      state: "down",
      incidentId: "inc_00000000-0000-4000-8000-000000000001",
      occurredAt: 1_700_000_000_000,
      reason:
        "failed token=abc nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
      observedVersion: null,
      runbookUrl: null,
    });
    expect(text).not.toContain("nsec1");
    expect(text).not.toContain("token=abc");
    expect(text).toContain("inc_00000000-0000-4000-8000-000000000001");
  });
});
