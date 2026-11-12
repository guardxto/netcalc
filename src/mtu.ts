/**
 * Tunnel MTU and TCP MSS arithmetic for the tunnel MTU calculator, and the
 * configuration snippets built from the result. Pure and synchronous: the
 * calculator runs it in the browser and the unit tests in plain Node.
 */

export type IpVersion = 4 | 6;

/** Outer IP header without options: RFC 791 (IPv4), RFC 8200 (IPv6). */
export const IP_HEADER: Record<IpVersion, number> = { 4: 20, 6: 40 };
/** TCP header without options (RFC 9293): MSS = MTU - IP header - 20. */
export const TCP_HEADER = 20;
/** Smallest MTU an IPv4 link may have (RFC 791). */
export const IPV4_MIN_MTU = 68;
/** Smallest MTU an IPv6 link may have (RFC 8200, section 5). */
export const IPV6_MIN_MTU = 1280;
export const MAX_LAYERS = 6;

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

const ESP_PARTS: [string, number][] = [
  ["ESP header (SPI, sequence number)", 8],
  ["AES-GCM IV", 8],
  ["padding at worst", 3],
  ["pad length and next header", 2],
  ["GCM integrity check value", 16],
];

export const LAYERS: Record<LayerKind, LayerDef> = {
  pppoe: {
    kind: "pppoe",
    name: "PPPoE",
    parts: [
      ["PPPoE header", 6],
      ["PPP protocol field", 2],
    ],
    overIp: false,
    estimate: false,
    source: "RFC 2516",
    iface: () => ["ppp", 0],
  },
  gre: {
    kind: "gre",
    name: "GRE",
    parts: [["GRE header", 4]],
    overIp: true,
    estimate: false,
    source: "RFC 2784",
    iface: (v) => (v === 4 ? ["gre", 1] : ["ip6gre", 1]),
  },
  "gre-key": {
    kind: "gre-key",
    name: "GRE with key",
    parts: [
      ["GRE header", 4],
      ["key field", 4],
    ],
    overIp: true,
    estimate: false,
    source: "RFC 2784, RFC 2890",
    iface: (v) => (v === 4 ? ["gre", 1] : ["ip6gre", 1]),
  },
  ipip: {
    kind: "ipip",
    name: "IP-in-IP",
    parts: [],
    overIp: true,
    estimate: false,
    source: "RFC 2003 (IPv4 outer), RFC 2473 (IPv6 outer)",
    iface: (v) => (v === 4 ? ["ipip", 1] : ["ip6tnl", 1]),
  },
  wireguard: {
    kind: "wireguard",
    name: "WireGuard",
    parts: [
      ["UDP header", 8],
      ["WireGuard data header", 16],
      ["Poly1305 tag", 16],
    ],
    overIp: true,
    estimate: false,
    source: "WireGuard protocol and whitepaper",
    iface: () => ["wg", 0],
  },
  vxlan: {
    kind: "vxlan",
    name: "VXLAN",
    parts: [
      ["UDP header", 8],
      ["VXLAN header", 8],
      ["inner Ethernet header", 14],
    ],
    overIp: true,
    estimate: false,
    source: "RFC 7348",
    iface: () => ["vxlan", 100],
  },
  esp: {
    kind: "esp",
    name: "IPsec ESP",
    parts: ESP_PARTS,
    overIp: true,
    estimate: true,
    source: "RFC 4303, RFC 4106 (tunnel mode, AES-GCM)",
    iface: () => ["ipsec", 0],
  },
  "esp-natt": {
    kind: "esp-natt",
    name: "IPsec ESP with NAT-T",
    parts: [["UDP header for NAT traversal", 8], ...ESP_PARTS],
    overIp: true,
    estimate: true,
    source: "RFC 4303, RFC 4106, RFC 3948",
    iface: () => ["ipsec", 0],
  },
};

export const LAYER_KINDS = Object.keys(LAYERS) as LayerKind[];

export type Layer = { kind: LayerKind; ip: IpVersion };

/** Bytes one layer adds: its own headers plus its outer IP header. */
export function layerBytes(l: Layer): number {
  const d = LAYERS[l.kind];
  return d.parts.reduce((s, [, b]) => s + b, 0) + (d.overIp ? IP_HEADER[l.ip] : 0);
}

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

export type MtuNote = { tone: "warn" | "info"; title: string; text: string };

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

const n = (x: number) => x.toLocaleString("en-US");

/**
 * The stack is ordered from the underlay inwards: the first layer sits on
 * the physical link, the last one is the tunnel the traffic enters.
 */
export function calculateMtu(underlay: number, layers: Layer[]): MtuResult {
  let mtu = underlay;
  const rows: LayerRow[] = layers.map((l) => {
    const d = LAYERS[l.kind];
    const bytes = layerBytes(l);
    mtu -= bytes;
    return { kind: l.kind, name: d.name, ip: d.overIp ? l.ip : null, parts: d.parts, bytes, mtu, estimate: d.estimate, source: d.source };
  });
  const overhead = underlay - mtu;
  const fits = mtu >= IPV4_MIN_MTU;
  const ipv6 = mtu >= IPV6_MIN_MTU;
  const notes: MtuNote[] = [];

  if (!fits) {
    notes.push({
      tone: "warn",
      title: "The layers do not fit",
      text: `The stack needs ${n(overhead)} bytes, which leaves less than the 68 bytes every IPv4 link must carry (RFC 791). Remove a layer or raise the underlay MTU.`,
    });
  } else if (!ipv6) {
    notes.push({
      tone: "warn",
      title: "Too small for IPv6",
      text: `${n(mtu)} bytes is below 1,280, the minimum link MTU for IPv6 (RFC 8200). The tunnel can carry IPv4 only unless the underlay MTU grows.`,
    });
  }
  if (underlay === 1492 && layers.some((l) => l.kind === "pppoe")) {
    notes.push({
      tone: "warn",
      title: "PPPoE counted twice",
      text: "1,492 is already the MTU inside PPPoE. With the PPPoE layer added as well, its 8 bytes are subtracted twice: use 1,500 with the layer, or 1,492 without it.",
    });
  }
  if (layers.some((l, i) => l.kind === "pppoe" && i > 0 && layers[i - 1].kind !== "vxlan")) {
    notes.push({
      tone: "warn",
      title: "PPPoE runs on Ethernet",
      text: "PPPoE belongs at the bottom of the stack, directly on the Ethernet link, or inside a layer that carries Ethernet frames such as VXLAN.",
    });
  }
  if (layers.some((l) => (l.kind === "gre" || l.kind === "gre-key" || l.kind === "ipip") && l.ip === 6)) {
    notes.push({
      tone: "info",
      title: "Linux IPv6 tunnels add 8 bytes by default",
      text: "Linux ip6gre and ip6tnl tunnels insert an 8-byte tunnel encapsulation limit option (RFC 2473) unless created with encaplimit none, so their default MTU is 8 bytes lower than the figure here.",
    });
  }
  if (layers.some((l) => l.kind === "wireguard")) {
    notes.push({
      tone: "info",
      title: "WireGuard's own default",
      text: "wg-quick and the Linux driver default to 1,420 on a 1,500-byte path: the IPv6 figure, so one MTU works whichever address family the peer uses. Over IPv4 only, 1,440 is safe.",
    });
  }
  if (layers.some((l) => l.kind === "vxlan")) {
    notes.push({
      tone: "info",
      title: "VXLAN carries Ethernet frames",
      text: "The VXLAN figure includes the 14-byte inner Ethernet header. An 802.1Q VLAN tag on the inner frame takes 4 bytes more.",
    });
  }
  if (layers.some((l) => l.kind === "esp" || l.kind === "esp-natt")) {
    notes.push({
      tone: "info",
      title: "IPsec ESP is an estimate",
      text: "ESP overhead depends on the cipher, the integrity check, the mode and NAT traversal. This figure assumes tunnel mode with AES-GCM and a 16-byte ICV, with padding at its 3-byte worst case. CBC ciphers need more: up to 73 bytes over IPv4 for AES-CBC with HMAC-SHA1-96. Confirm with a ping that sets the don't-fragment bit.",
    });
  }

  return {
    underlay,
    rows,
    overhead,
    innerMtu: mtu,
    fits,
    ipv6,
    mss4: fits ? mtu - IP_HEADER[4] - TCP_HEADER : null,
    mss6: ipv6 ? mtu - IP_HEADER[6] - TCP_HEADER : null,
    estimate: rows.some((r) => r.estimate),
    notes,
  };
}

/* ---------------- form input ---------------- */

export const UNDERLAY_PRESETS: { mtu: number; label: string }[] = [
  { mtu: 1500, label: "Ethernet" },
  { mtu: 1492, label: "PPPoE" },
  { mtu: 9000, label: "Jumbo" },
];

/** An underlay MTU as typed ("1500" or "1,500"); an error sentence otherwise. */
export function parseUnderlay(raw: string): { ok: true; mtu: number } | { ok: false; error: string } {
  const s = raw.trim();
  if (!s) return { ok: false, error: "Enter the MTU of the link the tunnel runs over, for example 1500." };
  if (!/^(?:\d{1,5}|\d{1,2},\d{3})$/.test(s)) return { ok: false, error: "Enter a whole number of bytes, for example 1500." };
  const mtu = Number(s.replace(",", ""));
  if (mtu < IPV4_MIN_MTU || mtu > 65535) return { ok: false, error: "Enter an MTU between 68 and 65,535 bytes." };
  return { ok: true, mtu };
}

/** Linux interface names: at most 15 characters; kept to a set that is safe in every snippet. */
export function isValidIfName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/.test(name);
}

/** Default interface names for each layer, outermost first, numbered so repeats do not collide. */
export function defaultIfNames(layers: Layer[], underlay: number): string[] {
  const used = new Map<string, number>();
  const names = layers.map((l) => {
    const [base, start] = LAYERS[l.kind].iface(l.ip);
    const k = used.get(base) ?? start;
    used.set(base, k + 1);
    return `${base}${k}`;
  });
  return names.length ? names : [underlay === 1492 ? "ppp0" : "eth0"];
}

/* ---------------- snippets ---------------- */

export type Snippet = { id: "linux" | "iptables" | "nftables" | "mikrotik"; title: string; code: string };

/**
 * Copy-paste configuration for the result. `names` holds one interface per
 * layer (outermost first); the clamp rules use the innermost one, the
 * interface the traffic enters. The iptables and nftables forms are checked
 * with iptables-restore --test and nft -c in an isolated network namespace.
 */
export function buildSnippets(result: MtuResult, names: string[]): Snippet[] {
  const inner = names[names.length - 1];
  const mtus = result.rows.length ? result.rows.map((r) => r.mtu) : [result.underlay];
  const { mss4, mss6 } = result;

  const linux = [
    "# set the MTU of each interface, outermost first",
    ...names.map((name, i) => `ip link set dev ${name} mtu ${mtus[i]}`),
  ];

  const ipt: string[] = [];
  if (mss4 !== null) {
    ipt.push(
      "# IPv4: clamp SYN and SYN-ACK in both directions",
      `iptables -t mangle -A FORWARD -o ${inner} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${mss4}`,
      `iptables -t mangle -A FORWARD -i ${inner} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${mss4}`,
    );
  }
  if (mss6 !== null) {
    ipt.push(
      "# IPv6",
      `ip6tables -t mangle -A FORWARD -o ${inner} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${mss6}`,
      `ip6tables -t mangle -A FORWARD -i ${inner} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${mss6}`,
    );
  } else if (mss4 !== null) {
    ipt.push("# IPv6 needs a tunnel MTU of at least 1280");
  }
  if (mss4 !== null) {
    ipt.push(
      "# or follow the route MTU instead of a fixed value (outgoing direction)",
      `iptables -t mangle -A FORWARD -o ${inner} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`,
    );
  }

  const nft: string[] = ["table inet mss_clamp {", "\tchain forward {", "\t\ttype filter hook forward priority mangle; policy accept;"];
  if (mss4 !== null) {
    nft.push(
      `\t\toifname "${inner}" meta nfproto ipv4 tcp flags syn tcp option maxseg size set ${mss4}`,
      `\t\tiifname "${inner}" meta nfproto ipv4 tcp flags syn tcp option maxseg size set ${mss4}`,
    );
  }
  if (mss6 !== null) {
    nft.push(
      `\t\toifname "${inner}" meta nfproto ipv6 tcp flags syn tcp option maxseg size set ${mss6}`,
      `\t\tiifname "${inner}" meta nfproto ipv6 tcp flags syn tcp option maxseg size set ${mss6}`,
    );
  }
  nft.push(
    "\t\t# or follow the route MTU (outgoing direction):",
    `\t\t# oifname "${inner}" tcp flags syn tcp option maxseg size set rt mtu`,
    "\t}",
    "}",
  );

  const mk: string[] = [];
  if (mss4 !== null) {
    mk.push(
      "/ip firewall mangle",
      `add chain=forward out-interface=${inner} protocol=tcp tcp-flags=syn tcp-mss=${mss4 + 1}-65535 action=change-mss new-mss=${mss4} passthrough=yes`,
      `add chain=forward in-interface=${inner} protocol=tcp tcp-flags=syn tcp-mss=${mss4 + 1}-65535 action=change-mss new-mss=${mss4} passthrough=yes`,
    );
  }
  if (mss6 !== null) {
    mk.push(
      "/ipv6 firewall mangle",
      `add chain=forward out-interface=${inner} protocol=tcp tcp-flags=syn tcp-mss=${mss6 + 1}-65535 action=change-mss new-mss=${mss6} passthrough=yes`,
      `add chain=forward in-interface=${inner} protocol=tcp tcp-flags=syn tcp-mss=${mss6 + 1}-65535 action=change-mss new-mss=${mss6} passthrough=yes`,
    );
  }

  const out: Snippet[] = [{ id: "linux", title: "Linux interface MTU (iproute2)", code: linux.join("\n") }];
  if (mss4 !== null) {
    out.push(
      { id: "iptables", title: "MSS clamping with iptables", code: ipt.join("\n") },
      { id: "nftables", title: "MSS clamping with nftables", code: nft.join("\n") },
      { id: "mikrotik", title: "MSS clamping on MikroTik RouterOS", code: mk.join("\n") },
    );
  }
  return out;
}

/* ---------------- shareable state (URL fragment) ---------------- */

export type MtuFields = { underlay: string; layers: Layer[]; iface: string | null };

export const MTU_DEFAULT: MtuFields = { underlay: "1500", layers: [{ kind: "gre", ip: 4 }], iface: null };

const token = (l: Layer) => (LAYERS[l.kind].overIp ? `${l.kind}${l.ip}` : l.kind);

/** The form as a URL fragment: it stays in the browser and never reaches a server log. */
export function mtuToHash(f: MtuFields): Record<string, string> {
  const h: Record<string, string> = { mtu: f.underlay.trim(), stack: f.layers.map(token).join(".") };
  if (f.iface) h.if = f.iface;
  return h;
}

/** A fragment from a shared link back to form fields; null unless it holds a complete, valid state. */
export function mtuFromHash(hash: string | null): MtuFields | null {
  if (!hash || !hash.includes("=")) return null;
  const p = new URLSearchParams(hash);
  const underlay = p.get("mtu") ?? "";
  if (!parseUnderlay(underlay).ok) return null;
  const stack = p.get("stack") ?? "";
  const layers: Layer[] = [];
  for (const t of stack ? stack.split(".") : []) {
    const m = /^([a-z-]+?)([46])?$/.exec(t);
    if (!m || !(LAYER_KINDS as string[]).includes(m[1])) return null;
    const kind = m[1] as LayerKind;
    if (LAYERS[kind].overIp !== Boolean(m[2])) return null;
    layers.push({ kind, ip: m[2] === "6" ? 6 : 4 });
  }
  if (layers.length > MAX_LAYERS) return null;
  const iface = p.get("if");
  if (iface !== null && !isValidIfName(iface)) return null;
  return { underlay, layers, iface };
}
