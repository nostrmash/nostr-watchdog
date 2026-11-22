export const OPERATOR_TOKEN = "test-operator-token";
export const STATUS_SIGNING_SECRET = "status-signing-secret-value-0001";

export const HEARTBEAT_KEYS = {
  "sfs-worker": "current-heartbeat-secret-value-32b",
  "nostrmash-ingestor": "ingestor-heartbeat-secret-value-01",
  "nostrmash-worker": "worker-heartbeat-secret-value-0001",
} as const;

export const HEARTBEAT_KEYS_PREVIOUS = {
  "sfs-worker": "previous-heartbeat-secret-value-01",
} as const;
