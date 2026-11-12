/**
 * IPv4 subnet arithmetic for the subnet calculator. Pure and synchronous: the
 * calculator runs it in the browser, the CIDR table on the server, and the
 * unit tests in plain Node.
 */
import { classifyIPv4, formatIPv4, parseIPv4, prefixMask, type AddressInfo } from "./ip.js";

export type SubnetResult = {
  /** the address as entered, canonicalised */
  address: string;
  prefix: number;
  cidr: string;
  netmask: string;
  wildcard: string;
  network: string;
  /** null for /31 and /32, which have no broadcast address */
  broadcast: string | null;
  firstHost: string;
  lastHost: string;
  totalAddresses: number;
  usableHosts: number;
  /** a sentence on how /31 and /32 are counted, otherwise null */
  note: string | null;
  ipClass: "A" | "B" | "C" | "D" | "E";
  type: AddressInfo;
  /** the address as one 32-bit integer and in hex: handy for firewall rules and databases */
  integer: number;
  hex: string;
  binary: { address: string; netmask: string; network: string; broadcast: string };
  /** the in-addr.arpa zone that covers the network (on an octet boundary) */
  reverseZone: string;
};

export function prefixToMask(prefix: number): string {
  return formatIPv4(prefixMask(prefix));
}

export function wildcardOf(prefix: number): string {
  return formatIPv4(~prefixMask(prefix) >>> 0);
}

/** A dotted netmask to its prefix length; null unless the ones are contiguous. */
export function maskToPrefix(mask: string): number | null {
  const n = parseIPv4(mask.trim());
  if (n === null) return null;
  for (let p = 0; p <= 32; p++) if (prefixMask(p) === n) return p;
  return null;
}

/** A wildcard (inverse) mask such as 0.0.0.255 to its prefix length. */
export function wildcardToPrefix(mask: string): number | null {
  const n = parseIPv4(mask.trim());
  if (n === null) return null;
  return maskToPrefix(formatIPv4(~n >>> 0));
}

export function ipClassOf(ip: number): SubnetResult["ipClass"] {
  const first = ip >>> 24;
  if (first < 128) return "A";
  if (first < 192) return "B";
  if (first < 224) return "C";
  if (first < 240) return "D";
  return "E";
}

export function toBinary(n: number): string {
  const bits = (n >>> 0).toString(2).padStart(32, "0");
  return [bits.slice(0, 8), bits.slice(8, 16), bits.slice(16, 24), bits.slice(24)].join(".");
}

export function totalAddresses(prefix: number): number {
  return 2 ** (32 - prefix);
}

/** Usable host addresses: /31 counts both (RFC 3021), /32 is one host. */
export function usableHosts(prefix: number): number {
  if (prefix === 32) return 1;
  if (prefix === 31) return 2;
  return 2 ** (32 - prefix) - 2;
}

export function calculateSubnet(address: string, prefix: number): SubnetResult {
  const ip = parseIPv4(address.trim());
  if (ip === null) throw new RangeError("invalid IPv4 address");
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new RangeError("prefix must be 0-32");

  const mask = prefixMask(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;

  let first = network;
  let last = broadcast;
  let note: string | null = null;
  if (prefix <= 30) {
    first = network + 1;
    last = broadcast - 1;
  } else if (prefix === 31) {
    note = "A /31 has no network or broadcast address: both addresses are usable on a point-to-point link (RFC 3021).";
  } else {
    note = "A /32 is a single host route: the network, first and last address are the same.";
  }

  // A zone exists per whole octet: a /20 is covered by its /16 zone, anything shorter than /8 by the root.
  const octets = Math.floor(prefix / 8);
  const reverseZone = octets === 0 ? "in-addr.arpa" : `${formatIPv4(network).split(".").slice(0, octets).reverse().join(".")}.in-addr.arpa`;

  return {
    address: formatIPv4(ip),
    prefix,
    cidr: `${formatIPv4(network)}/${prefix}`,
    netmask: formatIPv4(mask),
    wildcard: formatIPv4(~mask >>> 0),
    network: formatIPv4(network),
    broadcast: prefix >= 31 ? null : formatIPv4(broadcast),
    firstHost: formatIPv4(first),
    lastHost: formatIPv4(last),
    totalAddresses: totalAddresses(prefix),
    usableHosts: usableHosts(prefix),
    note,
    ipClass: ipClassOf(ip),
    type: classifyIPv4(ip),
    integer: ip,
    hex: `0x${ip.toString(16).padStart(8, "0").toUpperCase()}`,
    binary: {
      address: toBinary(ip),
      netmask: toBinary(mask),
      network: toBinary(network),
      broadcast: toBinary(broadcast),
    },
    reverseZone,
  };
}

export type SubnetInput = { ok: true; address: string; prefix: number } | { ok: false; field: "address" | "prefix"; error: string };

/**
 * Read the two form fields. The address field may already carry the prefix
 * ("10.0.0.7/8" or "10.0.0.7 255.0.0.0"); then the second field is ignored.
 * The prefix field takes "24", "/24", a netmask or a wildcard mask.
 */
export function parseSubnetInput(addressField: string, prefixField: string): SubnetInput {
  let addr = addressField.trim();
  let pre = prefixField.trim();
  const inline = /^(\S+?)\s*(?:\/\s*|\s+)(\S+)$/.exec(addr);
  if (inline) {
    addr = inline[1];
    pre = inline[2];
  }
  if (!addr) return { ok: false, field: "address", error: "Enter an IPv4 address, for example 192.168.1.10." };
  if (parseIPv4(addr) === null) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) {
      return { ok: false, field: "address", error: "Each of the four numbers must be 0-255, without leading zeros." };
    }
    if (addr.includes(":")) return { ok: false, field: "address", error: "This calculator handles IPv4. Enter an address like 10.0.0.1." };
    return { ok: false, field: "address", error: "That is not an IPv4 address. Use four numbers separated by dots, like 10.0.0.1." };
  }
  const prefix = parsePrefixOrMask(pre);
  if (prefix === null) {
    return {
      ok: false,
      field: "prefix",
      error: pre
        ? "Use a prefix from /0 to /32 or a contiguous netmask such as 255.255.255.0."
        : "Enter a prefix such as /24 or a netmask such as 255.255.255.0.",
    };
  }
  return { ok: true, address: addr, prefix };
}

/** "24", "/24", "255.255.255.0" or "0.0.0.255" to a prefix length; null if none of these. */
export function parsePrefixOrMask(raw: string): number | null {
  const s = raw.trim().replace(/^\//, "");
  if (/^\d{1,2}$/.test(s)) {
    const p = Number(s);
    return p >= 0 && p <= 32 ? p : null;
  }
  if (s.includes(".")) {
    const m = maskToPrefix(s);
    if (m !== null) return m;
    return wildcardToPrefix(s);
  }
  return null;
}

export type CidrRow = { prefix: number; netmask: string; wildcard: string; total: number; usable: number };

export function cidrTable(from = 8, to = 32): CidrRow[] {
  const rows: CidrRow[] = [];
  for (let p = from; p <= to; p++) {
    rows.push({ prefix: p, netmask: prefixToMask(p), wildcard: wildcardOf(p), total: totalAddresses(p), usable: usableHosts(p) });
  }
  return rows;
}
