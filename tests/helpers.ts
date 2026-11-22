import { env } from "cloudflare:workers";

import type { FetchLike } from "../src/types";

export function bind(values: Record<string, string>): void {
  for (const [key, value] of Object.entries(values)) Reflect.set(env, key, value);
}

export function binding(name: string): string {
  const value = Reflect.get(env, name);
  if (typeof value !== "string" || value === "") throw new Error(`missing test binding ${name}`);
  return value;
}

export function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export function routed(
  routes: Record<string, (init?: RequestInit) => Response | Promise<Response>>,
): FetchLike {
  return async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const handler = routes[url];
    if (!handler) throw new Error(`unexpected fetch ${url}`);
    return handler(init);
  };
}
