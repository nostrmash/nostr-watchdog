// Wrangler prints a secrets.required warning here because the test process has
// no .dev.vars. The miniflare bindings below supply the Worker, and they are
// generated keys or the fixed non-production values in tests/secrets.ts.
import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { npubEncode, nsecEncode } from "nostr-tools/nip19";
import { defineConfig } from "vitest/config";

import {
  HEARTBEAT_KEYS,
  HEARTBEAT_KEYS_PREVIOUS,
  OPERATOR_TOKEN,
  STATUS_SIGNING_SECRET,
} from "./tests/secrets.ts";

export default defineConfig({
  plugins: [
    cloudflareTest(async () => {
      const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
      const smartflow = generateSecretKey();
      const nostrmash = generateSecretKey();
      const recipient = generateSecretKey();
      return {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            OPERATOR_TOKEN,
            STATUS_SIGNING_SECRET,
            SFS_BOT_NSEC: nsecEncode(smartflow),
            NOSTRMASH_BOT_NSEC: nsecEncode(nostrmash),
            TEST_RECIPIENT_NSEC: nsecEncode(recipient),
            ADMIN_NPUB: npubEncode(getPublicKey(recipient)),
            HEARTBEAT_KEYS: JSON.stringify(HEARTBEAT_KEYS),
            HEARTBEAT_KEYS_PREVIOUS: JSON.stringify(HEARTBEAT_KEYS_PREVIOUS),
            ALBY_AUTH_TOKEN: "",
            BTCPAY_API_KEY: "",
            TELEGRAM_BOT_TOKEN: "",
            TELEGRAM_CHAT_IDS: "",
            GITHUB_TOKEN: "",
            TEST_RELAY: "enabled",
          },
        },
      };
    }),
  ],
  test: {
    setupFiles: ["./tests/apply-migrations.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      reportOnFailure: true,
      include: ["src/**/*.ts"],
      exclude: ["**/*.d.ts"],
      thresholds: {
        statements: 74,
        branches: 68,
        functions: 85,
        lines: 80,
      },
    },
  },
});
