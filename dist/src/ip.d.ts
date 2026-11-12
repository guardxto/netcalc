/**
 * IP address parsing and classification, shared by the free tools.
 *
 * Pure TypeScript with no Node or browser APIs, so the subnet calculator can
 * run it in the browser and the server routes can use the same code for their
 * private-address checks. Parsing is strict on purpose: four decimal octets
 * for IPv4 (no octal, hex or shortened forms) and RFC 4291 text for IPv6. URL
 * hostnames are canonicalised by the WHATWG URL parser before they get here,
 * which is what turns tricks like `0x7f.1` or `2130706433` into `127.0.0.1`.
 */
/** Strict dotted-quad IPv4 to an unsigned 32-bit integer, or null. */
export declare function parseIPv4(input: string): number | null;
export declare function formatIPv4(n: number): string;
/** IPv6 text (RFC 4291, optional trailing dotted IPv4) to 16 bytes, or null. Zone ids are refused. */
export declare function parseIPv6(input: string): Uint8Array | null;
/** RFC 5952 text: lowercase, longest zero run compressed, IPv4-mapped in mixed notation. */
export declare function formatIPv6(bytes: Uint8Array): string;
export type ParsedIp = {
    version: 4;
    value: number;
    text: string;
} | {
    version: 6;
    bytes: Uint8Array;
    text: string;
};
/**
 * Parse either family and return the canonical text. An IPv4-mapped IPv6
 * address (`::ffff:1.2.3.4`, as Node reports IPv4 peers on a dual-stack
 * socket) is unwrapped to plain IPv4 so both spellings classify the same way.
 */
export declare function parseIp(input: string): ParsedIp | null;
/** Like parseIp, but keeps IPv4-mapped IPv6 as IPv6 (for the SSRF check, which must see what will be dialled). */
export declare function parseIpExact(input: string): ParsedIp | null;
export declare function prefixMask(prefix: number): number;
export declare function inV4Cidr(ip: number, base: number, prefix: number): boolean;
export declare function inV6Cidr(ip: Uint8Array, base: Uint8Array, prefix: number): boolean;
/** Parse "a.b.c.d/n" or "x::/n". Throws on a malformed literal: these tables are static. */
export declare function parseCidr(cidr: string): {
    version: 4;
    base: number;
    prefix: number;
} | {
    version: 6;
    base: Uint8Array;
    prefix: number;
};
export type AddressKind = "public" | "private" | "cgnat" | "loopback" | "link-local" | "multicast" | "broadcast" | "unspecified" | "documentation" | "benchmarking" | "reserved" | "unique-local" | "ipv4-mapped" | "translation" | "tunnel";
export type AddressInfo = {
    kind: AddressKind;
    /** human label, e.g. "Private network (RFC 1918)" */
    label: string;
    /** the matching special-purpose block, if any */
    range?: string;
    /** true only for ordinary globally routable unicast */
    isPublic: boolean;
};
export declare function classifyIPv4(ip: number): AddressInfo;
export declare function classifyIPv6(ip: Uint8Array): AddressInfo;
export declare function classifyIp(ip: ParsedIp): AddressInfo;
