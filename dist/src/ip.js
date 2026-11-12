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
export function parseIPv4(input) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(input);
    if (!m)
        return null;
    let n = 0;
    for (let i = 1; i <= 4; i++) {
        const part = m[i];
        // "010" is octal to some parsers and decimal to others: refuse to guess.
        if (part.length > 1 && part[0] === "0")
            return null;
        const v = Number(part);
        if (v > 255)
            return null;
        n = n * 256 + v;
    }
    return n;
}
export function formatIPv4(n) {
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
/** IPv6 text (RFC 4291, optional trailing dotted IPv4) to 16 bytes, or null. Zone ids are refused. */
export function parseIPv6(input) {
    let s = input.trim();
    if (s.startsWith("[") && s.endsWith("]"))
        s = s.slice(1, -1);
    if (!s || s.length > 45 || s.includes("%"))
        return null;
    const halves = s.split("::");
    if (halves.length > 2)
        return null;
    const groupsOf = (part, mayEndInV4) => {
        if (part === "")
            return [];
        const raw = part.split(":");
        const out = [];
        for (let i = 0; i < raw.length; i++) {
            const g = raw[i];
            if (g.includes(".")) {
                if (!mayEndInV4 || i !== raw.length - 1)
                    return null;
                const v4 = parseIPv4(g);
                if (v4 === null)
                    return null;
                out.push(v4 >>> 16, v4 & 0xffff);
            }
            else {
                if (!/^[0-9a-fA-F]{1,4}$/.test(g))
                    return null;
                out.push(parseInt(g, 16));
            }
        }
        return out;
    };
    let groups;
    if (halves.length === 2) {
        const head = groupsOf(halves[0], false);
        const tail = groupsOf(halves[1], true);
        if (!head || !tail)
            return null;
        const missing = 8 - head.length - tail.length;
        if (missing < 1)
            return null;
        groups = [...head, ...new Array(missing).fill(0), ...tail];
    }
    else {
        const all = groupsOf(s, true);
        if (!all || all.length !== 8)
            return null;
        groups = all;
    }
    const bytes = new Uint8Array(16);
    groups.forEach((g, i) => {
        bytes[i * 2] = g >> 8;
        bytes[i * 2 + 1] = g & 255;
    });
    return bytes;
}
/** RFC 5952 text: lowercase, longest zero run compressed, IPv4-mapped in mixed notation. */
export function formatIPv6(bytes) {
    const g = [];
    for (let i = 0; i < 16; i += 2)
        g.push((bytes[i] << 8) | bytes[i + 1]);
    if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
        return `::ffff:${formatIPv4(((g[6] << 16) | g[7]) >>> 0)}`;
    }
    let bestAt = -1;
    let bestLen = 0;
    for (let i = 0; i < 8;) {
        if (g[i] !== 0) {
            i++;
            continue;
        }
        let j = i;
        while (j < 8 && g[j] === 0)
            j++;
        if (j - i > bestLen && j - i >= 2) {
            bestAt = i;
            bestLen = j - i;
        }
        i = j;
    }
    const hex = g.map((x) => x.toString(16));
    if (bestAt < 0)
        return hex.join(":");
    const left = hex.slice(0, bestAt).join(":");
    const right = hex.slice(bestAt + bestLen).join(":");
    return `${left}::${right}`;
}
/**
 * Parse either family and return the canonical text. An IPv4-mapped IPv6
 * address (`::ffff:1.2.3.4`, as Node reports IPv4 peers on a dual-stack
 * socket) is unwrapped to plain IPv4 so both spellings classify the same way.
 */
export function parseIp(input) {
    const s = input.trim();
    const v4 = parseIPv4(s);
    if (v4 !== null)
        return { version: 4, value: v4, text: formatIPv4(v4) };
    const v6 = parseIPv6(s);
    if (!v6)
        return null;
    if (v6.slice(0, 10).every((b) => b === 0) && v6[10] === 0xff && v6[11] === 0xff) {
        const value = ((v6[12] << 24) | (v6[13] << 16) | (v6[14] << 8) | v6[15]) >>> 0;
        return { version: 4, value, text: formatIPv4(value) };
    }
    return { version: 6, bytes: v6, text: formatIPv6(v6) };
}
/** Like parseIp, but keeps IPv4-mapped IPv6 as IPv6 (for the SSRF check, which must see what will be dialled). */
export function parseIpExact(input) {
    const s = input.trim();
    const v4 = parseIPv4(s);
    if (v4 !== null)
        return { version: 4, value: v4, text: formatIPv4(v4) };
    const v6 = parseIPv6(s);
    return v6 ? { version: 6, bytes: v6, text: formatIPv6(v6) } : null;
}
/* ---------------- CIDR matching ---------------- */
export function prefixMask(prefix) {
    return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}
export function inV4Cidr(ip, base, prefix) {
    const mask = prefixMask(prefix);
    return ((ip & mask) >>> 0) === ((base & mask) >>> 0);
}
export function inV6Cidr(ip, base, prefix) {
    const full = prefix >> 3;
    for (let i = 0; i < full; i++)
        if (ip[i] !== base[i])
            return false;
    const rest = prefix & 7;
    if (rest === 0)
        return true;
    const mask = (0xff << (8 - rest)) & 0xff;
    return (ip[full] & mask) === (base[full] & mask);
}
/** Parse "a.b.c.d/n" or "x::/n". Throws on a malformed literal: these tables are static. */
export function parseCidr(cidr) {
    const [addr, len] = cidr.split("/");
    const prefix = Number(len);
    const v4 = parseIPv4(addr);
    if (v4 !== null && prefix >= 0 && prefix <= 32)
        return { version: 4, base: v4, prefix };
    const v6 = parseIPv6(addr);
    if (v6 && prefix >= 0 && prefix <= 128)
        return { version: 6, base: v6, prefix };
    throw new Error(`bad CIDR ${cidr}`);
}
// IANA IPv4 Special-Purpose Address Registry plus multicast and class E.
// Order matters: the most specific block comes first.
const V4_SPECIAL = [
    { cidr: "255.255.255.255/32", kind: "broadcast", label: "Limited broadcast (RFC 919)" },
    { cidr: "0.0.0.0/32", kind: "unspecified", label: "Unspecified address" },
    { cidr: "0.0.0.0/8", kind: "reserved", label: "\"This network\" (RFC 791)" },
    { cidr: "10.0.0.0/8", kind: "private", label: "Private network (RFC 1918)" },
    { cidr: "100.64.0.0/10", kind: "cgnat", label: "Shared address space / carrier-grade NAT (RFC 6598)" },
    { cidr: "127.0.0.0/8", kind: "loopback", label: "Loopback (RFC 1122)" },
    { cidr: "169.254.0.0/16", kind: "link-local", label: "Link-local (RFC 3927)" },
    { cidr: "172.16.0.0/12", kind: "private", label: "Private network (RFC 1918)" },
    { cidr: "192.0.0.0/24", kind: "reserved", label: "IETF protocol assignments (RFC 6890)" },
    { cidr: "192.0.2.0/24", kind: "documentation", label: "Documentation, TEST-NET-1 (RFC 5737)" },
    { cidr: "192.88.99.0/24", kind: "reserved", label: "Deprecated 6to4 relay anycast (RFC 7526)" },
    { cidr: "192.168.0.0/16", kind: "private", label: "Private network (RFC 1918)" },
    { cidr: "198.18.0.0/15", kind: "benchmarking", label: "Network benchmarking (RFC 2544)" },
    { cidr: "198.51.100.0/24", kind: "documentation", label: "Documentation, TEST-NET-2 (RFC 5737)" },
    { cidr: "203.0.113.0/24", kind: "documentation", label: "Documentation, TEST-NET-3 (RFC 5737)" },
    { cidr: "233.252.0.0/24", kind: "documentation", label: "Multicast documentation, MCAST-TEST-NET (RFC 6676)" },
    { cidr: "224.0.0.0/4", kind: "multicast", label: "Multicast (RFC 5771)" },
    { cidr: "240.0.0.0/4", kind: "reserved", label: "Reserved for future use (RFC 1112)" },
];
// IANA IPv6 Special-Purpose Address Registry. Anything outside 2000::/3 is not
// allocated as global unicast, so it is reserved unless listed here.
const V6_SPECIAL = [
    { cidr: "::/128", kind: "unspecified", label: "Unspecified address" },
    { cidr: "::1/128", kind: "loopback", label: "Loopback (RFC 4291)" },
    { cidr: "::ffff:0:0/96", kind: "ipv4-mapped", label: "IPv4-mapped address (RFC 4291)" },
    { cidr: "::/96", kind: "reserved", label: "Deprecated IPv4-compatible address (RFC 4291)" },
    { cidr: "64:ff9b::/96", kind: "translation", label: "IPv4/IPv6 translation (RFC 6052)" },
    { cidr: "64:ff9b:1::/48", kind: "translation", label: "Local-use IPv4/IPv6 translation (RFC 8215)" },
    { cidr: "100::/64", kind: "reserved", label: "Discard-only (RFC 6666)" },
    { cidr: "2001:db8::/32", kind: "documentation", label: "Documentation (RFC 3849)" },
    { cidr: "3fff::/20", kind: "documentation", label: "Documentation (RFC 9637)" },
    { cidr: "2001::/32", kind: "tunnel", label: "Teredo tunnelling (RFC 4380)" },
    { cidr: "2001:2::/48", kind: "benchmarking", label: "Benchmarking (RFC 5180)" },
    { cidr: "2001:10::/28", kind: "reserved", label: "Deprecated ORCHID (RFC 4843)" },
    { cidr: "2001:20::/28", kind: "reserved", label: "ORCHIDv2 (RFC 7343)" },
    { cidr: "2001::/23", kind: "reserved", label: "IETF protocol assignments (RFC 2928)" },
    { cidr: "2002::/16", kind: "tunnel", label: "6to4 (RFC 3056)" },
    { cidr: "5f00::/16", kind: "reserved", label: "Segment routing SIDs (RFC 9602)" },
    { cidr: "fc00::/7", kind: "unique-local", label: "Unique local address (RFC 4193)" },
    { cidr: "fe80::/10", kind: "link-local", label: "Link-local (RFC 4291)" },
    { cidr: "fec0::/10", kind: "reserved", label: "Deprecated site-local (RFC 3879)" },
    { cidr: "ff00::/8", kind: "multicast", label: "Multicast (RFC 4291)" },
];
const V4_TABLE = V4_SPECIAL.map((s) => ({ ...s, net: parseCidr(s.cidr) }));
const V6_TABLE = V6_SPECIAL.map((s) => ({ ...s, net: parseCidr(s.cidr) }));
const GLOBAL_UNICAST = parseCidr("2000::/3");
export function classifyIPv4(ip) {
    for (const s of V4_TABLE) {
        if (inV4Cidr(ip, s.net.base, s.net.prefix))
            return { kind: s.kind, label: s.label, range: s.cidr, isPublic: false };
    }
    return { kind: "public", label: "Public (globally routable)", isPublic: true };
}
export function classifyIPv6(ip) {
    for (const s of V6_TABLE) {
        if (inV6Cidr(ip, s.net.base, s.net.prefix))
            return { kind: s.kind, label: s.label, range: s.cidr, isPublic: false };
    }
    if (!inV6Cidr(ip, GLOBAL_UNICAST.base, GLOBAL_UNICAST.prefix)) {
        return { kind: "reserved", label: "Reserved by IETF (outside 2000::/3)", isPublic: false };
    }
    return { kind: "public", label: "Public (globally routable)", isPublic: true };
}
export function classifyIp(ip) {
    return ip.version === 4 ? classifyIPv4(ip.value) : classifyIPv6(ip.bytes);
}
