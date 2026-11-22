import { readResponseLimited } from "../security/body";
import type { FetchLike } from "../types";

export async function sendTelegram(input: {
  token: string;
  chatId: string;
  text: string;
  fetch: FetchLike;
  timeoutMs: number;
}): Promise<"accepted" | "failed"> {
  if (!/^-?\d+$/.test(input.chatId) || input.token === "") return "failed";
  const url = `https://api.telegram.org/bot${encodeURIComponent(input.token)}/sendMessage`;
  try {
    const response = await input.fetch(url, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(input.timeoutMs),
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: input.chatId,
        text: input.text,
        disable_web_page_preview: true,
      }),
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      return "failed";
    }
    const text = await readResponseLimited(response, 8_192);
    if (text === "too_large") return "failed";
    if (response.status < 200 || response.status >= 300) return "failed";
    const body = JSON.parse(text) as { ok?: unknown };
    return body.ok === true ? "accepted" : "failed";
  } catch {
    return "failed";
  }
}

export function telegramChat(raw: string, projectId: string): string | null {
  if (raw.trim() === "") return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const value = (parsed as Record<string, unknown>)[projectId];
    return typeof value === "string" && /^-?\d+$/.test(value) ? value : null;
  } catch {
    return null;
  }
}
