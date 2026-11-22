import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { env } from "cloudflare:workers";

const migrations = Reflect.get(env, "TEST_MIGRATIONS");
if (!Array.isArray(migrations)) throw new Error("TEST_MIGRATIONS missing");
await applyD1Migrations(env.DB, migrations as D1Migration[]);
