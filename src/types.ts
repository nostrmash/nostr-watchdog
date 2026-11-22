export type MonitorStatus = "healthy" | "degraded" | "down" | "unknown" | "misconfigured";

export type Severity = "info" | "warning" | "critical";

export type IncidentKind = "outage" | "degraded" | "misconfigured" | "inconclusive";

export type ProjectId = "smartflowsocial" | "nostrmash";

export type Destination = "nostr" | "telegram";

export type AlertClass = "outage" | "recovery" | "reminder" | "update" | "security" | "test";

export type DeliveryState = "queued" | "relay_accepted" | "retrying" | "failed";

export type CheckKind = "http_json" | "signed_heartbeat" | "alby_hub" | "btcpay";

export type VendorId = "getAlby/hub" | "btcpayserver/btcpayserver";

export interface CheckResult {
  status: MonitorStatus;
  errorClass: string | null;
  summary: string;
  latencyMs: number | null;
  observedVersion: string | null;
}

export interface JsonPredicate {
  pointer: string;
  equals: string | number | boolean;
}

export interface HttpCheckSpec {
  urlVar: keyof Env;
  expectedPath: string;
  headers: Record<string, string>;
  expectedStatuses: number[];
  predicates: JsonPredicate[];
  maxBytes: number;
}

export interface MonitorDefinition {
  id: string;
  projectId: ProjectId;
  kind: CheckKind;
  displayName: string;
  enableVar: keyof Env;
  intervalSeconds: number;
  failureThreshold: number;
  recoveryThreshold: number;
  severity: Severity;
  incidentOnDegraded: boolean;
  runbookPath: string;
  http?: HttpCheckSpec;
  versionVendor?: VendorId;
}

export interface OpenIncident {
  id: string;
  kind: IncidentKind;
  severity: Severity;
  openedAt: number;
  reminderCount: number;
  lastReminderAt: number | null;
  silencedUntil: number | null;
  ackedAt: number | null;
}

export interface MonitorMemory {
  status: MonitorStatus;
  consecutiveSuccesses: number;
  consecutiveFailures: number;
  failureKind: MonitorStatus | null;
  openIncident: OpenIncident | null;
  observedVersion: string | null;
}

export interface Notice {
  event: "open" | "close" | "remind";
  incidentId: string;
  kind: IncidentKind;
  severity: Severity;
  reason: string;
  occurredAt: number;
  monitorStatus: MonitorStatus;
}

export interface TransitionResult {
  memory: MonitorMemory;
  notice: Notice | null;
  changed: boolean;
}

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface AlertDraft {
  id: string;
  alertClass: AlertClass;
  incidentId: string | null;
  monitorId: string;
  projectId: ProjectId;
  dedupeKey: string;
  destination: Destination;
  severity: Severity;
  text: string;
}

export interface OutboxRow {
  id: string;
  alert_class: string;
  incident_id: string | null;
  monitor_id: string;
  project_id: string;
  dedupe_key: string;
  destination: string;
  severity: string;
  state: string;
  payload_text: string;
  envelope_json: string | null;
  attempt_count: number;
  next_attempt_at: number;
  claim_until: number | null;
  last_error: string | null;
  created_at: number;
  updated_at: number;
}
