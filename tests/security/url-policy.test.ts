import { describe, expect, it } from "vitest";

import {
  assertProbeUrl,
  assertWssUrl,
  isBlockedAddress,
  UrlPolicyError,
} from "../../src/security/url-policy";

const allow = (host: string, privateNetwork = false) => ({ allowHosts: [host], privateNetwork });

describe("url policy", () => {
  it("accepts an allowlisted https origin", () => {
    expect(assertProbeUrl("https://app.example/healthcheck", allow("app.example")).pathname).toBe(
      "/healthcheck",
    );
  });

  it("rejects credentials, http, other ports, and hosts outside the allowlist", () => {
    expect(() =>
      assertProbeUrl("https://user:secret@app.example/healthcheck", allow("app.example")),
    ).toThrow(UrlPolicyError);
    expect(() => assertProbeUrl("http://app.example/healthcheck", allow("app.example"))).toThrow(
      UrlPolicyError,
    );
    expect(() =>
      assertProbeUrl("https://app.example:8443/healthcheck", allow("app.example")),
    ).toThrow(UrlPolicyError);
    expect(() => assertProbeUrl("https://other.example/healthcheck", allow("app.example"))).toThrow(
      UrlPolicyError,
    );
  });

  it("blocks loopback, private, link-local, metadata, and decimal address literals", () => {
    expect(isBlockedAddress("127.0.0.1")).toBe(true);
    expect(isBlockedAddress("10.1.2.3")).toBe(true);
    expect(isBlockedAddress("169.254.169.254")).toBe(true);
    expect(isBlockedAddress("192.168.1.1")).toBe(true);
    expect(isBlockedAddress("2130706433")).toBe(true);
    expect(isBlockedAddress("::1")).toBe(true);
    expect(isBlockedAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isBlockedAddress("2001:db8::1")).toBe(true);
    expect(isBlockedAddress("1.1.1.1")).toBe(false);
    expect(() => assertProbeUrl("https://127.0.0.1/health", allow("127.0.0.1"))).toThrow(
      UrlPolicyError,
    );
    expect(() =>
      assertProbeUrl("https://metadata.google.internal/", allow("metadata.google.internal")),
    ).toThrow(UrlPolicyError);
  });

  it("allows a private destination only in the explicit private-network profile", () => {
    expect(assertProbeUrl("http://10.1.2.3/health", allow("10.1.2.3", true)).hostname).toBe(
      "10.1.2.3",
    );
  });

  it("requires public wss relay urls", () => {
    expect(assertWssUrl("wss://relay.example").protocol).toBe("wss:");
    expect(() => assertWssUrl("ws://relay.example")).toThrow(UrlPolicyError);
    expect(() => assertWssUrl("wss://127.0.0.1")).toThrow(UrlPolicyError);
  });
});
