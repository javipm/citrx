/** A parsed CIDR block with its network base address and prefix length. */
export interface ParsedCidr {
  /** IP version of the CIDR block. */
  kind: "ipv4" | "ipv6";
  /** Network base address as a bigint (32-bit for IPv4, 128-bit for IPv6). */
  base: bigint;
  /** Prefix length (0–32 for IPv4, 0–128 for IPv6). */
  mask: number;
}

/** Pre-parsed CIDR lists split by IP version for efficient lookup. */
export interface PreparedRanges {
  /** Parsed IPv4 CIDR blocks. */
  ipv4: ParsedCidr[];
  /** Parsed IPv6 CIDR blocks. */
  ipv6: ParsedCidr[];
}

/**
 * Converts a dotted-decimal IPv4 address to a 32-bit bigint.
 *
 * @param ip - IPv4 address string (e.g. `"192.168.1.1"`).
 * @returns The address as a bigint, or `null` if the input is invalid.
 */
export function ipv4ToBigInt(ip: string): bigint | null {
  const parts = ip.split(".");

  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    return null;
  }

  return parts.reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n);
}

/**
 * Converts an IPv6 address (including compressed `::` notation) to a 128-bit bigint.
 *
 * Internally calls `expandIPv6` to normalise the address before conversion.
 *
 * @param ip - IPv6 address string (e.g. `"2001:db8::1"`).
 * @returns The address as a bigint, or `null` if the input is invalid.
 */
export function ipv6ToBigInt(ip: string): bigint | null {
  const expanded = expandIPv6(ip);

  if (!expanded) {
    return null;
  }

  return expanded
    .split(":")
    .reduce((value, group) => (value << 16n) + BigInt(Number.parseInt(group, 16)), 0n);
}

/**
 * Parses a CIDR string into a `ParsedCidr` object.
 *
 * Detects IP version by the presence of `.` (IPv4) or `:` (IPv6) in the
 * address portion and validates the prefix length against the version's range.
 *
 * @param cidr - CIDR notation string (e.g. `"10.0.0.0/8"` or `"2001:db8::/32"`).
 * @returns A `ParsedCidr` on success, or `null` if the input is malformed.
 */
export function parseCidr(cidr: string): ParsedCidr | null {
  const [ip, maskValue] = cidr.split("/");
  const mask = Number(maskValue);

  if (!ip || !Number.isInteger(mask)) {
    return null;
  }

  if (ip.includes(".")) {
    const base = ipv4ToBigInt(ip);
    return base !== null && mask >= 0 && mask <= 32 ? { kind: "ipv4", base, mask } : null;
  }

  if (ip.includes(":")) {
    const base = ipv6ToBigInt(ip);
    return base !== null && mask >= 0 && mask <= 128 ? { kind: "ipv6", base, mask } : null;
  }

  return null;
}

/**
 * Tests whether a single IP address falls within a parsed CIDR block.
 *
 * Uses a right-shift comparison: both the candidate IP and the CIDR base are
 * shifted right by `(totalBits - mask)` bits, then compared. A mask of 0
 * matches every address of the corresponding IP version.
 *
 * @param ip - IP address string to test.
 * @param cidr - Pre-parsed CIDR block to test against.
 * @returns `true` if the IP is within the CIDR range, `false` otherwise.
 */
export function isIpInCidr(ip: string, cidr: ParsedCidr): boolean {
  const totalBits = cidr.kind === "ipv4" ? 32 : 128;
  const value = cidr.kind === "ipv4" ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);

  if (value === null) {
    return false;
  }

  if (cidr.mask === 0) {
    return true;
  }

  const shift = BigInt(totalBits - cidr.mask);
  return value >> shift === cidr.base >> shift;
}

/**
 * Parses and separates raw CIDR strings into a `PreparedRanges` structure for
 * fast repeated lookups. Invalid CIDR strings are silently dropped.
 *
 * @param ranges - Object with separate `ipv4` and `ipv6` CIDR string arrays.
 * @returns A `PreparedRanges` object with all valid CIDRs pre-parsed.
 */
export function prepareRanges(ranges: {
  ipv4: readonly string[];
  ipv6: readonly string[];
}): PreparedRanges {
  return {
    ipv4: ranges.ipv4.map(parseCidr).filter((cidr): cidr is ParsedCidr => cidr !== null),
    ipv6: ranges.ipv6.map(parseCidr).filter((cidr): cidr is ParsedCidr => cidr !== null)
  };
}

/**
 * Tests whether an IP address matches any CIDR block in a `PreparedRanges` set.
 *
 * Selects the IPv4 or IPv6 list automatically based on the presence of `:` in
 * the address string.
 *
 * @param ip - IP address string to test.
 * @param ranges - Pre-parsed ranges produced by `prepareRanges`.
 * @returns `true` if the IP matches at least one CIDR block, `false` otherwise.
 */
export function ipInPreparedRanges(ip: string, ranges: PreparedRanges): boolean {
  const cidrs = ip.includes(":") ? ranges.ipv6 : ranges.ipv4;
  return cidrs.some((cidr) => isIpInCidr(ip, cidr));
}

/**
 * Expands a compressed IPv6 address into its full 8-group colon-separated form.
 *
 * Handles `::` zero-compression by computing the number of missing groups and
 * inserting `"0"` groups accordingly. Returns `null` for any invalid input
 * (bad characters, multiple `::`, wrong group count, or out-of-range groups).
 *
 * @param ip - IPv6 address string, possibly compressed (e.g. `"::1"`, `"fe80::1"`).
 * @returns The fully expanded address (e.g. `"0:0:0:0:0:0:0:1"`), or `null` if invalid.
 */
export function expandIPv6(ip: string): string | null {
  if (!/^[0-9a-f:.]+$/i.test(ip)) {
    return null;
  }

  const doubleColonCount = ip.split("::").length - 1;

  if (doubleColonCount > 1) {
    return null;
  }

  const [head = "", tail = ""] = ip.split("::");
  const headGroups = head ? head.split(":") : [];
  const tailGroups = tail ? tail.split(":") : [];

  if ([...headGroups, ...tailGroups].some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) {
    return null;
  }

  const missing = doubleColonCount === 1 ? 8 - headGroups.length - tailGroups.length : 0;

  if (
    missing < 0 ||
    (doubleColonCount === 0 && headGroups.length !== 8) ||
    (doubleColonCount === 1 && headGroups.length + tailGroups.length >= 8)
  ) {
    return null;
  }

  const groups = [...headGroups, ...Array.from({ length: missing }, () => "0"), ...tailGroups];

  if (groups.length !== 8) {
    return null;
  }

  return groups.map((group) => Number.parseInt(group, 16).toString(16)).join(":");
}
