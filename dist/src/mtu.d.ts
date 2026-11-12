/**
 * Tunnel MTU and TCP MSS arithmetic for the tunnel MTU calculator, and the
 * configuration snippets built from the result. Pure and synchronous: the
 * calculator runs it in the browser and the unit tests in plain Node.
 */
export type IpVersion = 4 | 6;
/** Outer IP header without options: RFC 791 (IPv4), RFC 8200 (IPv6). */
export declare const IP_HEADER: Record<IpVersion, number>;
/** TCP header without options (RFC 9293): MSS = MTU - IP header - 20. */
export declare const TCP_HEADER = 20;
/** Smallest MTU an IPv4 link may have (RFC 791). */
export declare const IPV4_MIN_MTU = 68;
/** Smallest MTU an IPv6 link may have (RFC 8200, section 5). */
export declare const IPV6_MIN_MTU = 1280;
export declare const MAX_LAYERS = 6;
export type LayerKind = "pppoe" | "gre" | "gre-key" | "ipip" | "wireguard" | "vxlan" | "esp" | "esp-natt";
export type LayerDef = {
    kind: LayerKind;
    name: string;
    /** the encapsulation's own bytes, part by part, without the outer IP header */
    parts: [string, number][];
    /** carried in an outer IPv4 or IPv6 header of its own */
    overIp: boolean;
    /** a typical value, not a constant of the protocol */
    estimate: boolean;
    /** where the sizes come from */
    source: string;
    /** default Linux interface name (without the number) and the number it starts at */
    iface: (v: IpVersion) => [string, number];
};
export declare const LAYERS: Record<LayerKind, LayerDef>;
export declare const LAYER_KINDS: LayerKind[];
export type Layer = {
    kind: LayerKind;
    ip: IpVersion;
};
/** Bytes one layer adds: its own headers plus its outer IP header. */
export declare function layerBytes(l: Layer): number;
export type LayerRow = {
    kind: LayerKind;
    name: string;
    /** outer IP version, or null for a layer without one (PPPoE) */
    ip: IpVersion | null;
    parts: [string, number][];
    bytes: number;
    /** the MTU left inside this layer: what its interface should be set to */
    mtu: number;
    estimate: boolean;
    source: string;
};
export type MtuNote = {
    tone: "warn" | "info";
    title: string;
    text: string;
};
export type MtuResult = {
    underlay: number;
    rows: LayerRow[];
    overhead: number;
    innerMtu: number;
    /** an IPv4 packet still fits (68 bytes or more) */
    fits: boolean;
    /** IPv6 can run inside (1,280 bytes or more) */
    ipv6: boolean;
    /** TCP MSS over IPv4 and IPv6 inside the tunnel; null when that family cannot run */
    mss4: number | null;
    mss6: number | null;
    /** at least one layer is an estimate (IPsec) */
    estimate: boolean;
    notes: MtuNote[];
};
/**
 * The stack is ordered from the underlay inwards: the first layer sits on
 * the physical link, the last one is the tunnel the traffic enters.
 */
export declare function calculateMtu(underlay: number, layers: Layer[]): MtuResult;
export declare const UNDERLAY_PRESETS: {
    mtu: number;
    label: string;
}[];
/** An underlay MTU as typed ("1500" or "1,500"); an error sentence otherwise. */
export declare function parseUnderlay(raw: string): {
    ok: true;
    mtu: number;
} | {
    ok: false;
    error: string;
};
/** Linux interface names: at most 15 characters; kept to a set that is safe in every snippet. */
export declare function isValidIfName(name: string): boolean;
/** Default interface names for each layer, outermost first, numbered so repeats do not collide. */
export declare function defaultIfNames(layers: Layer[], underlay: number): string[];
export type Snippet = {
    id: "linux" | "iptables" | "nftables" | "mikrotik";
    title: string;
    code: string;
};
/**
 * Copy-paste configuration for the result. `names` holds one interface per
 * layer (outermost first); the clamp rules use the innermost one, the
 * interface the traffic enters. The iptables and nftables forms are checked
 * with iptables-restore --test and nft -c in an isolated network namespace.
 */
export declare function buildSnippets(result: MtuResult, names: string[]): Snippet[];
export type MtuFields = {
    underlay: string;
    layers: Layer[];
    iface: string | null;
};
export declare const MTU_DEFAULT: MtuFields;
/** The form as a URL fragment: it stays in the browser and never reaches a server log. */
export declare function mtuToHash(f: MtuFields): Record<string, string>;
/** A fragment from a shared link back to form fields; null unless it holds a complete, valid state. */
export declare function mtuFromHash(hash: string | null): MtuFields | null;
