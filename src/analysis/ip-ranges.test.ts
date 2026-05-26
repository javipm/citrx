import { describe, expect, it } from "vitest";

import {
  ipInPreparedRanges,
  ipv4ToBigInt,
  ipv6ToBigInt,
  isIpInCidr,
  parseCidr,
  prepareRanges
} from "./ip-ranges.js";
import { GOOGLEBOT_RANGES } from "../rules/data/googlebot-ranges.js";

describe("IP ranges", () => {
  it("parses IPv4 addresses to bigint", () => {
    expect(ipv4ToBigInt("66.249.64.10")).toBe(1123631114n);
    expect(ipv4ToBigInt("999.1.1.1")).toBeNull();
  });

  it("parses compact IPv6 addresses to bigint", () => {
    expect(ipv6ToBigInt("::1")).toBe(1n);
    expect(ipv6ToBigInt("not-ipv6")).toBeNull();
  });

  it("parses CIDR ranges", () => {
    expect(parseCidr("66.249.64.0/27")).toEqual(
      expect.objectContaining({ kind: "ipv4", mask: 27 })
    );
    expect(parseCidr("2001:4860:4801::/48")).toEqual(
      expect.objectContaining({ kind: "ipv6", mask: 48 })
    );
  });

  it("checks CIDR membership", () => {
    const cidr = parseCidr("66.249.64.0/27");

    expect(cidr && isIpInCidr("66.249.64.10", cidr)).toBe(true);
    expect(cidr && isIpInCidr("66.249.64.40", cidr)).toBe(false);
  });

  it("prepares snapshot ranges", () => {
    const ranges = prepareRanges(GOOGLEBOT_RANGES);

    expect(ranges.ipv4.length).toBeGreaterThan(0);
    expect(ipInPreparedRanges("66.249.64.10", ranges)).toBe(true);
  });
});
