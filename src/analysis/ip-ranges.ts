export interface ParsedCidr {
  kind: "ipv4" | "ipv6";
  base: bigint;
  mask: number;
}

export interface PreparedRanges {
  ipv4: ParsedCidr[];
  ipv6: ParsedCidr[];
}

export function ipv4ToBigInt(ip: string): bigint | null {
  const parts = ip.split(".");

  if (
    parts.length !== 4 ||
    parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)
  ) {
    return null;
  }

  return parts.reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n);
}

export function ipv6ToBigInt(ip: string): bigint | null {
  const expanded = expandIPv6(ip);

  if (!expanded) {
    return null;
  }

  return expanded
    .split(":")
    .reduce((value, group) => (value << 16n) + BigInt(Number.parseInt(group, 16)), 0n);
}

export function parseCidr(cidr: string): ParsedCidr | null {
  const [ip, maskValue] = cidr.split("/");
  const mask = Number(maskValue);

  if (!ip || !Number.isInteger(mask)) {
    return null;
  }

  if (ip.includes(".")) {
    const base = ipv4ToBigInt(ip);
    return base !== null && mask >= 0 && mask <= 32
      ? { kind: "ipv4", base, mask }
      : null;
  }

  if (ip.includes(":")) {
    const base = ipv6ToBigInt(ip);
    return base !== null && mask >= 0 && mask <= 128
      ? { kind: "ipv6", base, mask }
      : null;
  }

  return null;
}

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
  return (value >> shift) === (cidr.base >> shift);
}

export function prepareRanges(ranges: {
  ipv4: readonly string[];
  ipv6: readonly string[];
}): PreparedRanges {
  return {
    ipv4: ranges.ipv4.map(parseCidr).filter((cidr): cidr is ParsedCidr => cidr !== null),
    ipv6: ranges.ipv6.map(parseCidr).filter((cidr): cidr is ParsedCidr => cidr !== null)
  };
}

export function ipInPreparedRanges(ip: string, ranges: PreparedRanges): boolean {
  const cidrs = ip.includes(":") ? ranges.ipv6 : ranges.ipv4;
  return cidrs.some((cidr) => isIpInCidr(ip, cidr));
}

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

  if (
    [...headGroups, ...tailGroups].some(
      (group) => !/^[0-9a-f]{1,4}$/i.test(group)
    )
  ) {
    return null;
  }

  const missing = doubleColonCount === 1
    ? 8 - headGroups.length - tailGroups.length
    : 0;

  if (
    missing < 0 ||
    (doubleColonCount === 0 && headGroups.length !== 8) ||
    (doubleColonCount === 1 && headGroups.length + tailGroups.length >= 8)
  ) {
    return null;
  }

  const groups = [
    ...headGroups,
    ...Array.from({ length: missing }, () => "0"),
    ...tailGroups
  ];

  if (groups.length !== 8) {
    return null;
  }

  return groups.map((group) => Number.parseInt(group, 16).toString(16)).join(":");
}
