import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { sendTelegram, telegramChat } from "../../src/alerts/telegram";
import { readPointer } from "../../src/checks/json-pointer";
import { projectRecipient } from "../../src/config/projects";
import { loadSettings } from "../../src/config/settings";
import worker from "../../src/index";
import { bind, jsonResponse } from "../helpers";

afterEach(() => {
  bind({
    PROJECT_RECIPIENTS: "{}",
    ADMIN_NPUB: "",
    RUNBOOK_BASE_URL: "",
  });
});

describe("project recipients", () => {
  it("uses a project recipient, then the admin npub, and fails closed on invalid JSON", () => {
    bind({
      PROJECT_RECIPIENTS: JSON.stringify({ smartflowsocial: "ab".repeat(32) }),
      ADMIN_NPUB: "cd".repeat(32),
    });
    expect(projectRecipient(env, "smartflowsocial")).toBe("ab".repeat(32));
    expect(projectRecipient(env, "nostrmash")).toBe("cd".repeat(32));
    bind({ PROJECT_RECIPIENTS: "{", ADMIN_NPUB: "cd".repeat(32) });
    expect(projectRecipient(env, "smartflowsocial")).toBeNull();
  });
});

describe("settings", () => {
  it("accepts an https runbook origin and rejects credentials", () => {
    bind({ RUNBOOK_BASE_URL: "https://runbooks.example/docs/" });
    expect(loadSettings(env).runbookBase).toBe("https://runbooks.example/docs");
    bind({ RUNBOOK_BASE_URL: "https://user:secret@runbooks.example" });
    expect(loadSettings(env).runbookBase).toBeNull();
    bind({ RUNBOOK_BASE_URL: "not a url" });
    expect(loadSettings(env).runbookBase).toBeNull();
  });
});

describe("json pointer", () => {
  it("reads nested fields and escaped keys", () => {
    const body = { status: "ok", list: [{ "a/b": 1 }], "~n": 2 };
    expect(readPointer(body, "/status")).toBe("ok");
    expect(readPointer(body, "/list/0/a~1b")).toBe(1);
    expect(readPointer(body, "/~0n")).toBe(2);
    expect(readPointer(body, "status")).toBeUndefined();
    expect(readPointer(null, "/status")).toBeUndefined();
  });
});

describe("telegram", () => {
  it("parses chat ids and accepts only an ok response from api.telegram.org", async () => {
    expect(telegramChat("", "smartflowsocial")).toBeNull();
    expect(telegramChat("{", "smartflowsocial")).toBeNull();
    expect(telegramChat(JSON.stringify({ smartflowsocial: "123" }), "smartflowsocial")).toBe("123");
    expect(telegramChat(JSON.stringify({ smartflowsocial: "abc" }), "smartflowsocial")).toBeNull();
    const accepted = await sendTelegram({
      token: "bot-token",
      chatId: "123",
      text: "hello",
      timeoutMs: 1000,
      fetch: async (input) => {
        expect(String(input)).toBe("https://api.telegram.org/botbot-token/sendMessage");
        return jsonResponse({ ok: true });
      },
    });
    expect(accepted).toBe("accepted");
    const failed = await sendTelegram({
      token: "bot-token",
      chatId: "nope",
      text: "hello",
      timeoutMs: 1000,
      fetch: async () => jsonResponse({ ok: true }),
    });
    expect(failed).toBe("failed");
  });
});

describe("worker entry", () => {
  it("answers liveness through the default fetch handler", async () => {
    const response = await worker.fetch(new Request("https://watchdog.example/healthz"), env);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "ok", service: "nostr-watchdog" });
  });
});
