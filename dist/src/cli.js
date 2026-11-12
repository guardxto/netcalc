/**
 * netcalc: the command-line front end to the subnet, bandwidth-to-PPS and
 * tunnel MTU/MSS maths. No dependencies beyond Node itself.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { calculateBandwidth, ETHERNET, formatBps, formatDuration, formatNumber, formatPps, MAX_BPS, MAX_PPS, parseDecimal } from "./bandwidth.js";
import { buildSnippets, calculateMtu, defaultIfNames, isValidIfName, LAYER_KINDS, LAYERS, MAX_LAYERS, parseUnderlay } from "./mtu.js";
import { calculateSubnet, cidrTable, parseSubnetInput } from "./subnet.js";
const WEB = {
    subnet: "https://guardx.to/tools/subnet-calculator",
    pps: "https://guardx.to/tools/bandwidth-pps-calculator",
    mtu: "https://guardx.to/tools/mtu-mss-calculator",
};
const HELP = `netcalc: subnet, bandwidth-to-PPS and tunnel MTU/MSS maths

Usage
  netcalc subnet <address>/<prefix>        e.g. 192.168.1.10/24
  netcalc subnet <address> <netmask>       e.g. 10.0.0.7 255.255.252.0
  netcalc subnet --table                   netmasks and host counts for /8 to /32

  netcalc pps <bit rate>                   e.g. 10G, 2.5Gbps, 500M
  netcalc bps <packet rate>                e.g. 14.88M, 1.5Mpps, 250k
      --frame <bytes>                      Ethernet frame size, 64 to 9216 (default 64)
      --no-wire                            leave out preamble, SFD and inter-frame gap

  netcalc mtu <layer> [<layer> ...]        layers from the link inwards, e.g. pppoe gre4 wireguard6
      --underlay <bytes>                   MTU of the link the stack runs over (default 1500)
      --iface <name,name,...>              interface names for the snippets, one per layer
      --snippets                           print iproute2, iptables, nftables and MikroTik config
  layers: ${LAYER_KINDS.map((k) => (LAYERS[k].overIp ? `${k}4|${k}6` : k)).join(", ")}

Options
  --json       machine-readable output
  -h, --help   this help
  -v, --version

The same calculators run in the browser at https://guardx.to/tools`;
class UsageError extends Error {
}
function version() {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
    return pkg.version;
}
const pad = (rows) => {
    const w = Math.max(...rows.map(([k]) => k.length));
    return rows.map(([k, v]) => `  ${k.padEnd(w)}  ${v}`).join("\n");
};
/* ---------------- subnet ---------------- */
function subnet(args, table, json) {
    if (table) {
        const rows = cidrTable();
        if (json)
            return JSON.stringify(rows, null, 2);
        const lines = rows.map((r) => `  /${String(r.prefix).padEnd(3)} ${r.netmask.padEnd(16)} ${r.wildcard.padEnd(16)} ${formatNumber(r.total).padStart(14)} ${formatNumber(r.usable).padStart(14)}`);
        return [`  ${"pfx".padEnd(4)} ${"netmask".padEnd(16)} ${"wildcard".padEnd(16)} ${"addresses".padStart(14)} ${"usable".padStart(14)}`, ...lines].join("\n");
    }
    if (args.length === 0 || args.length > 2)
        throw new UsageError("netcalc subnet needs an address with a prefix, e.g. 192.168.1.10/24");
    const input = parseSubnetInput(args[0], args[1] ?? "");
    if (!input.ok)
        throw new UsageError(input.error);
    const r = calculateSubnet(input.address, input.prefix);
    if (json)
        return JSON.stringify(r, null, 2);
    const rows = [
        ["Network", r.cidr],
        ["Netmask", `${r.netmask}  (wildcard ${r.wildcard})`],
        ["First host", r.firstHost],
        ["Last host", r.lastHost],
        ["Broadcast", r.broadcast ?? "none"],
        ["Addresses", formatNumber(r.totalAddresses)],
        ["Usable hosts", formatNumber(r.usableHosts)],
        ["Address type", r.type.label],
        ["Class", r.ipClass],
        ["Reverse zone", r.reverseZone],
        ["As integer", `${r.integer}  (${r.hex})`],
    ];
    return [pad(rows), r.note ? `\n\n  ${r.note}` : "", `\n\n  In the browser: ${WEB.subnet}`].join("");
}
/* ---------------- bandwidth ---------------- */
const RATE_SUFFIX = { "": 1, k: 1e3, m: 1e6, g: 1e9, t: 1e12 };
/** "10G", "2.5Gbps", "500 M", "14.88Mpps", "250k" to a plain number. */
function parseRate(raw, kind) {
    const m = /^\s*([\d.]+)\s*([kmgt]?)(bps|bit\/s|b\/s|pps)?\s*$/i.exec(raw);
    const v = m ? parseDecimal(m[1]) : null;
    if (!m || v === null) {
        throw new UsageError(kind === "bps" ? `"${raw}" is not a bit rate. Try 10G, 2.5Gbps or 500M.` : `"${raw}" is not a packet rate. Try 14.88M, 1.5Mpps or 250k.`);
    }
    const unit = (m[3] ?? "").toLowerCase();
    if (unit && (unit === "pps") !== (kind === "pps")) {
        throw new UsageError(kind === "bps" ? "netcalc pps takes a bit rate; use netcalc bps for a packet rate." : "netcalc bps takes a packet rate; use netcalc pps for a bit rate.");
    }
    const value = v * RATE_SUFFIX[m[2].toLowerCase()];
    if (value <= 0)
        throw new UsageError("Enter a rate above zero.");
    if (kind === "bps" && value > MAX_BPS)
        throw new UsageError("netcalc goes up to 1,000 Tbps.");
    if (kind === "pps" && value > MAX_PPS)
        throw new UsageError("netcalc goes up to 1,000,000 Mpps.");
    return value;
}
function parseFrame(raw) {
    if (raw === undefined)
        return ETHERNET.minFrame;
    const frame = parseDecimal(raw);
    if (frame === null || !Number.isInteger(frame))
        throw new UsageError("--frame takes the frame size in whole bytes, for example 64 or 1518.");
    if (frame < ETHERNET.minFrame)
        throw new UsageError("Ethernet frames are at least 64 bytes: shorter packets are padded to 64.");
    if (frame > ETHERNET.maxJumbo)
        throw new UsageError("--frame goes up to 9,216 bytes, the largest jumbo frame most switches accept.");
    return frame;
}
function bandwidth(mode, args, frameRaw, wire, json) {
    if (args.length !== 1)
        throw new UsageError(mode === "rate" ? "netcalc pps needs one bit rate, e.g. 10G" : "netcalc bps needs one packet rate, e.g. 14.88M");
    const value = parseRate(args[0], mode === "rate" ? "bps" : "pps");
    const frame = parseFrame(frameRaw);
    const r = calculateBandwidth(mode === "rate" ? { ok: true, mode, bps: value, pps: null, frame, wire } : { ok: true, mode, bps: null, pps: value, frame, wire });
    if (json)
        return JSON.stringify(r, null, 2);
    const rows = [
        ["Packet rate", `${formatPps(r.pps)}  (${formatNumber(r.pps)} pps)`],
        ["Bit rate", `${formatBps(r.bps)}  (${wire ? "on the wire" : "frames only"})`],
        ["Frame", `${formatNumber(frame)} bytes, ${formatNumber(r.ipPacket)}-byte IP packet inside`],
        ["On the wire", formatBps(r.wireBps)],
        ["Frames only", formatBps(r.frameBps)],
        ["IP packets", formatBps(r.ipBps)],
        ["Frame interval", formatDuration(r.interval)],
    ];
    return [pad(rows), "", ...r.steps.map((s) => `  ${s}`), "", `  In the browser: ${WEB.pps}`].join("\n");
}
/* ---------------- mtu ---------------- */
/** "gre", "gre4", "wireguard6", "pppoe": the notation of the shared links on guardx.to. */
function parseLayer(token) {
    const m = /^([a-z-]+?)([46])?$/.exec(token.toLowerCase());
    if (!m || !LAYER_KINDS.includes(m[1])) {
        throw new UsageError(`Unknown layer "${token}". Layers: ${LAYER_KINDS.join(", ")} (add 4 or 6 for the outer IP version, e.g. gre6).`);
    }
    const kind = m[1];
    if (!LAYERS[kind].overIp && m[2])
        throw new UsageError(`${LAYERS[kind].name} has no outer IP header; write ${kind} without 4 or 6.`);
    return { kind, ip: m[2] === "6" ? 6 : 4 };
}
function mtu(args, underlayRaw, ifaceRaw, snippets, json) {
    if (args.length === 0)
        throw new UsageError("netcalc mtu needs at least one layer, e.g. netcalc mtu gre4");
    if (args.length > MAX_LAYERS)
        throw new UsageError(`netcalc mtu takes at most ${MAX_LAYERS} layers.`);
    const layers = args.map(parseLayer);
    const u = parseUnderlay(underlayRaw ?? "1500");
    if (!u.ok)
        throw new UsageError(u.error);
    const r = calculateMtu(u.mtu, layers);
    let names = defaultIfNames(layers, u.mtu);
    if (ifaceRaw !== undefined) {
        names = ifaceRaw.split(",").map((s) => s.trim());
        if (names.length !== layers.length)
            throw new UsageError(`--iface needs ${layers.length} name(s), one per layer.`);
        const bad = names.find((n) => !isValidIfName(n));
        if (bad !== undefined)
            throw new UsageError(`"${bad}" is not a usable Linux interface name (at most 15 letters, digits, dots, dashes or underscores).`);
    }
    const code = snippets ? buildSnippets(r, names) : [];
    if (json)
        return JSON.stringify(snippets ? { ...r, snippets: code } : r, null, 2);
    const out = [`  Underlay MTU   ${r.underlay}`];
    r.rows.forEach((row, i) => {
        const label = row.ip ? `${row.name} over IPv${row.ip}` : row.name;
        out.push(`  ${label.padEnd(24)} -${String(row.bytes).padStart(3)} bytes  ->  MTU ${String(row.mtu).padStart(4)}  (${names[i]})${row.estimate ? "  estimate" : ""}`);
    });
    out.push("", `  Tunnel MTU     ${r.fits ? r.innerMtu : "does not fit"}`, `  TCP MSS IPv4   ${r.mss4 ?? "n/a"}`, `  TCP MSS IPv6   ${r.mss6 ?? "n/a (needs a tunnel MTU of 1,280 or more)"}`);
    for (const n of r.notes)
        out.push("", `  ${n.tone === "warn" ? "!" : "i"} ${n.title}`, `    ${n.text}`);
    for (const s of code)
        out.push("", `# ${s.title}`, s.code);
    out.push("", `  In the browser: ${WEB.mtu}`);
    return out.join("\n");
}
/* ---------------- main ---------------- */
export function run(argv) {
    const { values, positionals } = parseArgs({
        args: argv,
        allowPositionals: true,
        options: {
            json: { type: "boolean", default: false },
            help: { type: "boolean", short: "h", default: false },
            version: { type: "boolean", short: "v", default: false },
            table: { type: "boolean", default: false },
            frame: { type: "string" },
            "no-wire": { type: "boolean", default: false },
            underlay: { type: "string" },
            iface: { type: "string" },
            snippets: { type: "boolean", default: false },
        },
    });
    const [cmd, ...rest] = positionals;
    if (values.version)
        return version();
    if (values.help || !cmd)
        return HELP;
    switch (cmd) {
        case "subnet":
            return subnet(rest, values.table, values.json);
        case "pps":
            return bandwidth("rate", rest, values.frame, !values["no-wire"], values.json);
        case "bps":
            return bandwidth("pps", rest, values.frame, !values["no-wire"], values.json);
        case "mtu":
            return mtu(rest, values.underlay, values.iface, values.snippets, values.json);
        default:
            throw new UsageError(`Unknown command "${cmd}". Run netcalc --help.`);
    }
}
/** Prints the result or the error and returns the exit code: 0, 2 for a usage error, 1 otherwise. */
export function main(argv) {
    try {
        process.stdout.write(run(argv) + "\n");
        return 0;
    }
    catch (e) {
        const usage = e instanceof UsageError || (e instanceof TypeError && "code" in e && String(e.code).startsWith("ERR_PARSE_ARGS"));
        process.stderr.write(`netcalc: ${e.message}\n`);
        return usage ? 2 : 1;
    }
}
