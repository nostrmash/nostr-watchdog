import type { ProjectId } from "../types";

export interface ProjectDefinition {
  id: ProjectId;
  displayName: string;
  contactName: string;
  senderSecret: "SFS_BOT_NSEC" | "NOSTRMASH_BOT_NSEC";
}

export const PROJECTS: Record<ProjectId, ProjectDefinition> = {
  smartflowsocial: {
    id: "smartflowsocial",
    displayName: "SmartFlowSocial",
    contactName: "SmartFlowSocial Watchdog",
    senderSecret: "SFS_BOT_NSEC",
  },
  nostrmash: {
    id: "nostrmash",
    displayName: "NostrMash",
    contactName: "NostrMash Watchdog",
    senderSecret: "NOSTRMASH_BOT_NSEC",
  },
};

export function projectRecipient(env: Env, projectId: ProjectId): string | null {
  const raw = env.PROJECT_RECIPIENTS.trim();
  if (raw !== "" && raw !== "{}") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object") return null;
      const value = (parsed as Record<string, unknown>)[projectId];
      if (typeof value === "string" && value.trim() !== "") return value.trim();
    } catch {
      return null;
    }
  }
  const admin = env.ADMIN_NPUB.trim();
  return admin === "" ? null : admin;
}
