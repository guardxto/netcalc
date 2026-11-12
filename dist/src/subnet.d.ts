/**
 * IPv4 subnet arithmetic for the subnet calculator. Pure and synchronous: the
 * calculator runs it in the browser, the CIDR table on the server, and the
 * unit tests in plain Node.
 */
import { type AddressInfo } from "./ip.js";
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
    binary: {
        address: string;
        netmask: string;
        network: string;
        broadcast: string;
    };
    /** the in-addr.arpa zone that covers the network (on an octet boundary) */
    reverseZone: string;
};
export declare function prefixToMask(prefix: number): string;
export declare function wildcardOf(prefix: number): string;
/** A dotted netmask to its prefix length; null unless the ones are contiguous. */
export declare function maskToPrefix(mask: string): number | null;
/** A wildcard (inverse) mask such as 0.0.0.255 to its prefix length. */
export declare function wildcardToPrefix(mask: string): number | null;
export declare function ipClassOf(ip: number): SubnetResult["ipClass"];
export declare function toBinary(n: number): string;
export declare function totalAddresses(prefix: number): number;
/** Usable host addresses: /31 counts both (RFC 3021), /32 is one host. */
export declare function usableHosts(prefix: number): number;
export declare function calculateSubnet(address: string, prefix: number): SubnetResult;
export type SubnetInput = {
    ok: true;
    address: string;
    prefix: number;
} | {
    ok: false;
    field: "address" | "prefix";
    error: string;
};
/**
 * Read the two form fields. The address field may already carry the prefix
 * ("10.0.0.7/8" or "10.0.0.7 255.0.0.0"); then the second field is ignored.
 * The prefix field takes "24", "/24", a netmask or a wildcard mask.
 */
export declare function parseSubnetInput(addressField: string, prefixField: string): SubnetInput;
/** "24", "/24", "255.255.255.0" or "0.0.0.255" to a prefix length; null if none of these. */
export declare function parsePrefixOrMask(raw: string): number | null;
export type CidrRow = {
    prefix: number;
    netmask: string;
    wildcard: string;
    total: number;
    usable: number;
};
export declare function cidrTable(from?: number, to?: number): CidrRow[];
