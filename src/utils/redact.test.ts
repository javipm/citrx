import { describe, expect, it } from "vitest";

import { isSensitiveParamName, redactSecretPairs } from "./redact.js";

const SENSITIVE_KEYS = [
  "token",
  "_token",
  "sid",
  "session",
  "password",
  "passwd",
  "key",
  "secret",
  "jwt",
  "auth",
  "authorization",
  "credential"
];

describe("isSensitiveParamName", () => {
  it("flags every documented sensitive key", () => {
    for (const key of SENSITIVE_KEYS) {
      expect(isSensitiveParamName(key)).toBe(true);
    }
  });

  it("is case-insensitive", () => {
    expect(isSensitiveParamName("TOKEN")).toBe(true);
    expect(isSensitiveParamName("Api_Key")).toBe(true);
    expect(isSensitiveParamName("PassWord")).toBe(true);
  });

  it("does not flag unrelated names", () => {
    for (const name of ["q", "page", "next", "camper", "utm_source", "id"]) {
      expect(isSensitiveParamName(name)).toBe(false);
    }
  });
});

describe("redactSecretPairs", () => {
  it("redacts every documented sensitive key in a key=value pair", () => {
    for (const key of SENSITIVE_KEYS) {
      expect(redactSecretPairs(`${key}=abc123`)).toBe(`${key}=[REDACTED]`);
    }
  });

  it("is case-insensitive on the key", () => {
    expect(redactSecretPairs("TOKEN=abc123")).toBe("TOKEN=[REDACTED]");
  });

  it("stops the value at &", () => {
    expect(redactSecretPairs("token=abc&next=/admin")).toBe("token=[REDACTED]&next=/admin");
  });

  it("stops the value at whitespace", () => {
    expect(redactSecretPairs('GET /x?token=abc HTTP/1.1')).toBe(
      "GET /x?token=[REDACTED] HTTP/1.1"
    );
  });

  it("stops the value at a double quote and does not consume it", () => {
    expect(redactSecretPairs('"token=abc"')).toBe('"token=[REDACTED]"');
  });

  it("leaves non-sensitive keys intact", () => {
    expect(redactSecretPairs("q=camper&page=1")).toBe("q=camper&page=1");
  });

  it("redacts multiple sensitive params in a single line", () => {
    expect(redactSecretPairs("token=abc&password=hunter2&q=camper")).toBe(
      "token=[REDACTED]&password=[REDACTED]&q=camper"
    );
  });
});
