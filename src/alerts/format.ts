import { sanitizeText, safeVersion } from "../security/redact";
import type { IncidentKind, Severity } from "../types";

export function formatIncidentMessage(input: {
  projectName: string;
  displayName: string;
  severity: Severity;
  kind: IncidentKind;
  event: "open" | "close" | "remind";
  state: string;
  incidentId: string;
  occurredAt: number;
  reason: string;
  observedVersion: string | null;
  runbookUrl: string | null;
}): string {
  const label =
    input.event === "close" ? "recovery" : input.event === "remind" ? "reminder" : input.kind;
  const lines = [
    `[${input.projectName}] ${input.severity.toUpperCase()} ${label}`,
    `Service: ${input.displayName}`,
    `State: ${input.state}`,
    `Incident: ${input.incidentId}`,
    `Time: ${new Date(input.occurredAt).toISOString()}`,
    `Reason: ${sanitizeText(input.reason)}`,
  ];
  const version = safeVersion(input.observedVersion);
  if (version) lines.push(`Observed version: ${version}`);
  if (input.runbookUrl) lines.push(`Runbook: ${input.runbookUrl}`);
  lines.push("Relay acceptance does not confirm that a person or phone received this message.");
  return lines.join("\n");
}

export function formatVersionMessage(input: {
  projectName: string;
  displayName: string;
  installed: string;
  latest: string;
  url: string;
  occurredAt: number;
}): string {
  return [
    `[${input.projectName}] INFO update_available`,
    `Service: ${input.displayName}`,
    `State: update_available`,
    `Time: ${new Date(input.occurredAt).toISOString()}`,
    `Installed version: ${input.installed}`,
    `Latest version: ${input.latest}`,
    `Reference: ${input.url}`,
    "No upgrade was performed.",
  ].join("\n");
}

export function formatSecurityMessage(input: {
  projectName: string;
  displayName: string;
  severity: Severity;
  installed: string | null;
  summary: string;
  url: string | null;
  occurredAt: number;
  classification?: string;
}): string {
  const lines = [
    `[${input.projectName}] ${input.severity.toUpperCase()} security_update`,
    `Service: ${input.displayName}`,
    `State: ${input.classification ?? (input.severity === "critical" ? "affected" : "review_recommended")}`,
    `Time: ${new Date(input.occurredAt).toISOString()}`,
    `Reason: ${sanitizeText(input.summary, 300)}`,
  ];
  const version = safeVersion(input.installed);
  if (version) lines.push(`Installed version: ${version}`);
  if (input.url) lines.push(`Reference: ${input.url}`);
  lines.push("No upgrade was performed. This is not a claim about unrelated vulnerabilities.");
  return lines.join("\n");
}

export function formatTestMessage(input: { projectName: string; occurredAt: number }): string {
  return [
    `[${input.projectName}] INFO test`,
    "State: test",
    `Time: ${new Date(input.occurredAt).toISOString()}`,
    "Reason: Operator requested a test alert.",
    "Relay acceptance does not confirm phone delivery.",
  ].join("\n");
}
