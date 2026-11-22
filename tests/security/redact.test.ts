import { describe, expect, it } from "vitest";

import { sanitizeText, safeVersion } from "../../src/security/redact";

describe("alert redaction", () => {
  it("removes key material and URL userinfo from text that might be sent", () => {
    const text = sanitizeText(
      "bearer abc.def token=secret nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq https://user:pass@example.com/path",
    );
    expect(text).not.toContain("nsec1");
    expect(text).not.toContain("token=secret");
    expect(text).not.toContain("bearer abc");
    expect(text).not.toContain("user:pass");
  });

  it("keeps ordinary version strings and drops values that are not versions", () => {
    expect(safeVersion("v1.2.3-rc.1")).toBe("v1.2.3-rc.1");
    expect(safeVersion("not a version")).toBeNull();
    expect(safeVersion("")).toBeNull();
  });
});
