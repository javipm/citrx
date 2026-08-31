import { expandIPv6 } from "../analysis/ip-ranges.js";

/**
 * Groups an IP into the subnet used for coordinated-source analysis: /24 for
 * IPv4, /48 for IPv6. Shared by the behavior tracker and the path-level
 * aggregate rules so both report the same grouping. Returns `null` for
 * addresses that do not parse.
 */
export function extractSubnetPrefix(ip: string): string | null {
  if (ip.includes(":")) {
    const expanded = expandIPv6(ip);

    if (!expanded) {
      return null;
    }

    const groups = expanded.split(":");
    return `${groups.slice(0, 3).join(":")}::/48`;
  }

  const parts = ip.split(".");

  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    return null;
  }

  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}
