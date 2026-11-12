/**
 * Bit rate and packet rate arithmetic for the bandwidth to PPS calculator,
 * plus the 95th percentile of a list of samples. Pure and synchronous: the
 * calculator runs it in the browser, the line-rate table on the server and
 * the unit tests in plain Node.
 */
/**
 * Ethernet sizes in bytes (IEEE 802.3). RFC 2544 appendix B builds its
 * maximum frame rates from the same 64-bit preamble and 96-bit gap.
 */
export const ETHERNET = {
    /** preamble (7) and start frame delimiter (1) */
    preamble: 8,
    /** minimum inter-frame gap: 96 bit times */
    gap: 12,
    /** destination MAC, source MAC, EtherType */
    header: 14,
    fcs: 4,
    minFrame: 64,
    /** a 1,500-byte payload with header and FCS, no VLAN tag */
    maxFrame: 1518,
    /** the largest jumbo frame most switches accept; jumbo frames are outside IEEE 802.3 */
    maxJumbo: 9216,
};
/** What a frame costs on the line beyond its own bytes: preamble, SFD and gap. */
export const WIRE_OVERHEAD = ETHERNET.preamble + ETHERNET.gap;
/** What an untagged frame adds around an IP packet: header and FCS. */
export const FRAMING = ETHERNET.header + ETHERNET.fcs;
export const RATE_UNITS = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
export const PPS_UNITS = ["pps", "Kpps", "Mpps"];
/** Decimal (SI) prefixes, as link speeds are quoted: 1 Gbps is 10^9 bits per second. */
const RATE_SCALE = [
    ["bps", 1],
    ["Kbps", 1e3],
    ["Mbps", 1e6],
    ["Gbps", 1e9],
    ["Tbps", 1e12],
];
const PPS_SCALE = [
    ["pps", 1],
    ["Kpps", 1e3],
    ["Mpps", 1e6],
    ["Gpps", 1e9],
];
const factor = (scale, unit) => scale.find(([u]) => u === unit)?.[1] ?? 1;
export const toBps = (value, unit) => value * factor(RATE_SCALE, unit);
export const toPps = (value, unit) => value * factor(PPS_SCALE, unit);
/**
 * A base value as a form entry in the largest unit it reaches, with at most
 * four decimals: 14,880,952.38 pps becomes "14.881" Mpps. Used when the
 * calculator switches direction, so the other side starts from the result.
 */
function asField(base, units, scale) {
    let unit = units[0];
    for (const u of units)
        if (base >= factor(scale, u))
            unit = u;
    const v = base / factor(scale, unit);
    return { value: String(Number(v >= 1 ? v.toFixed(4) : v.toPrecision(4))), unit };
}
export const bpsAsField = (bps) => asField(bps, RATE_UNITS, RATE_SCALE);
export const ppsAsField = (pps) => asField(pps, PPS_UNITS, PPS_SCALE);
/** Bytes one frame occupies: the frame itself, plus preamble, SFD and gap when counted on the wire. */
export const bytesPerFrame = (frame, wire) => frame + (wire ? WIRE_OVERHEAD : 0);
export const ppsFromBps = (bps, frame, wire) => bps / (bytesPerFrame(frame, wire) * 8);
export const bpsFromPps = (pps, frame, wire) => pps * bytesPerFrame(frame, wire) * 8;
/** The largest IP packet an untagged frame of this size carries. */
export const ipPacketIn = (frame) => frame - FRAMING;
/** The frame an IP packet travels in: header and FCS added, then padded to the 64-byte minimum. */
export const frameFor = (ipPacket) => Math.max(ipPacket + FRAMING, ETHERNET.minFrame);
/** Frame sizes worth one click, each derived from header sizes rather than measured. */
export const FRAME_PRESETS = [
    {
        frame: 64,
        label: "Minimum frame",
        detail: "The smallest Ethernet frame. A TCP SYN or ACK without options is a 40-byte IPv4 packet and is padded up to 64 bytes, as is any packet of 46 bytes or less.",
    },
    {
        frame: 78,
        label: "TCP SYN with options",
        detail: "A 60-byte IPv4 SYN carrying the usual MSS, SACK, timestamp and window-scale options. It is above the 46-byte minimum payload, so nothing is padded: 60 + 18 = 78 bytes.",
    },
    {
        frame: 558,
        label: "512-byte DNS reply",
        detail: "A DNS message at the classic 512-byte UDP limit of RFC 1035, plus 8 bytes of UDP, 20 of IPv4 and 18 of Ethernet header and FCS.",
    },
    {
        frame: 1518,
        label: "Full 1,500 MTU",
        detail: "A 1,500-byte IP packet, the standard Ethernet MTU, with its 14-byte header and 4-byte FCS: the largest untagged standard frame.",
    },
    {
        frame: 9018,
        label: "9,000 jumbo",
        detail: "A 9,000-byte IP packet on a network configured for jumbo frames, plus 18 bytes of header and FCS.",
    },
];
/** A non-negative decimal as typed: "10", "14.88", ".5" or "1,000,000" (commas only in groups of three). */
export function parseDecimal(raw) {
    const s = raw.trim();
    if (/^(?:\d+(?:\.\d+)?|\.\d+)$/.test(s))
        return Number(s);
    if (/^\d{1,3}(?:,\d{3})+(?:\.\d+)?$/.test(s))
        return Number(s.replace(/,/g, ""));
    return null;
}
export const BANDWIDTH_DEFAULT = { mode: "rate", value: "10", rateUnit: "Gbps", ppsUnit: "Mpps", frame: "64", wire: true };
export const MAX_BPS = 1e15;
export const MAX_PPS = 1e12;
export function parseBandwidthInput(f) {
    const raw = f.value.trim();
    if (!raw) {
        return {
            ok: false,
            field: "value",
            error: f.mode === "rate" ? "Enter a bit rate, for example 10 with Gbps selected." : "Enter a packet rate, for example 1.5 with Mpps selected.",
        };
    }
    const v = parseDecimal(raw);
    if (v === null) {
        return /^\d+,\d{1,2}$/.test(raw)
            ? { ok: false, field: "value", error: "Use a dot for decimals, for example 14.88." }
            : { ok: false, field: "value", error: "Enter a number, for example 10 or 14.88." };
    }
    if (v <= 0)
        return { ok: false, field: "value", error: "Enter a rate above zero." };
    const base = f.mode === "rate" ? toBps(v, f.rateUnit) : toPps(v, f.ppsUnit);
    if (f.mode === "rate" && base > MAX_BPS)
        return { ok: false, field: "value", error: "The calculator goes up to 1,000 Tbps." };
    if (f.mode === "pps" && base > MAX_PPS)
        return { ok: false, field: "value", error: "The calculator goes up to 1,000,000 Mpps." };
    const fr = f.frame.trim();
    const frame = fr ? parseDecimal(fr) : null;
    if (frame === null)
        return { ok: false, field: "frame", error: "Enter the frame size in bytes, for example 64 or 1518." };
    if (frame < ETHERNET.minFrame) {
        return {
            ok: false,
            field: "frame",
            error: "Ethernet frames are at least 64 bytes: shorter packets are padded, so a 40-byte packet still costs 64. Enter 64 to 9,216.",
        };
    }
    if (frame > ETHERNET.maxJumbo)
        return { ok: false, field: "frame", error: "Enter at most 9,216 bytes, the largest jumbo frame most switches accept." };
    return f.mode === "rate"
        ? { ok: true, mode: "rate", bps: base, pps: null, frame, wire: f.wire }
        : { ok: true, mode: "pps", bps: null, pps: base, frame, wire: f.wire };
}
const NF = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
const SIG = new Intl.NumberFormat("en-US", { maximumSignificantDigits: 3 });
/** Grouped thousands, at most two decimals. */
export const formatNumber = (n) => NF.format(n);
/** A value in the largest unit it reaches: 14,880,952 pps is "14.88 Mpps". */
function scaled(n, scale) {
    let [unit, f] = scale[0];
    for (const [u, x] of scale)
        if (n >= x)
            [unit, f] = [u, x];
    const v = n / f;
    return `${v < 1 && v > 0 ? SIG.format(v) : NF.format(v)} ${unit}`;
}
export const formatBps = (bps) => scaled(bps, RATE_SCALE);
export const formatPps = (pps) => scaled(pps, PPS_SCALE);
/** A duration in the unit that keeps it readable: 67.2 ns, 1.23 µs, 4.5 ms. */
export function formatDuration(seconds) {
    if (seconds >= 1)
        return `${NF.format(seconds)} s`;
    if (seconds >= 1e-3)
        return `${NF.format(seconds * 1e3)} ms`;
    if (seconds >= 1e-6)
        return `${NF.format(seconds * 1e6)} µs`;
    return `${NF.format(seconds * 1e9)} ns`;
}
export function calculateBandwidth(input) {
    const { mode, frame, wire } = input;
    const countedBytes = bytesPerFrame(frame, wire);
    const countedBits = countedBytes * 8;
    const pps = mode === "rate" ? ppsFromBps(input.bps ?? 0, frame, wire) : (input.pps ?? 0);
    const bps = mode === "rate" ? (input.bps ?? 0) : bpsFromPps(pps, frame, wire);
    const n = (x) => formatNumber(x);
    const steps = [
        wire
            ? `Bytes per frame on the wire = ${n(frame)} + ${WIRE_OVERHEAD} = ${n(countedBytes)}`
            : `Bytes per frame = ${n(frame)} (preamble, SFD and gap not counted)`,
        `Bits per frame = ${n(countedBytes)} × 8 = ${n(countedBits)}`,
        mode === "rate"
            ? `Packets per second = ${n(bps)} ÷ ${n(countedBits)} = ${n(pps)} ≈ ${formatPps(pps)}`
            : `Bit rate = ${n(pps)} × ${n(countedBits)} = ${n(bps)} bps ≈ ${formatBps(bps)}`,
    ];
    return {
        mode,
        frame,
        wire,
        countedBytes,
        countedBits,
        pps,
        bps,
        wireBps: bpsFromPps(pps, frame, true),
        frameBps: bpsFromPps(pps, frame, false),
        ipBps: pps * ipPacketIn(frame) * 8,
        ipPacket: ipPacketIn(frame),
        interval: 1 / pps,
        overheadShare: WIRE_OVERHEAD / (frame + WIRE_OVERHEAD),
        steps,
    };
}
/** The same rate at each preset size: what the result table under the calculator lists. */
export function presetRows(input) {
    return FRAME_PRESETS.map((p) => {
        const r = calculateBandwidth({ ...input, frame: p.frame });
        return { frame: p.frame, label: p.label, pps: r.pps, bps: r.bps };
    });
}
export const LINK_SPEEDS = [
    ["1 Gbps", 1e9],
    ["10 Gbps", 1e10],
    ["25 Gbps", 25e9],
    ["40 Gbps", 4e10],
    ["100 Gbps", 1e11],
    ["400 Gbps", 4e11],
];
export const LINE_RATE_FRAMES = [64, 128, 512, 1518, 9018];
/** Maximum frames per second at full line rate, rounded down to whole frames as RFC 2544 does. */
export function lineRateTable() {
    return LINK_SPEEDS.map(([speed, bps]) => ({ speed, bps, pps: LINE_RATE_FRAMES.map((f) => Math.floor(ppsFromBps(bps, f, true))) }));
}
/* ---------------- shareable state (URL fragment) ---------------- */
/** The form as a URL fragment: it stays in the browser and never reaches a server log. */
export function bandwidthToHash(f) {
    return {
        from: f.mode,
        v: f.value.trim(),
        unit: f.mode === "rate" ? f.rateUnit : f.ppsUnit,
        frame: f.frame.trim(),
        wire: f.wire ? "1" : "0",
    };
}
/** A fragment from a shared link back to form fields; null unless it holds a complete, valid state. */
export function bandwidthFromHash(hash) {
    if (!hash || !hash.includes("="))
        return null;
    const p = new URLSearchParams(hash);
    const mode = p.get("from");
    const unit = p.get("unit") ?? "";
    if (mode !== "rate" && mode !== "pps")
        return null;
    const fields = { ...BANDWIDTH_DEFAULT, mode, value: p.get("v") ?? "", frame: p.get("frame") ?? "", wire: p.get("wire") !== "0" };
    if (mode === "rate") {
        if (!RATE_UNITS.includes(unit))
            return null;
        fields.rateUnit = unit;
    }
    else {
        if (!PPS_UNITS.includes(unit))
            return null;
        fields.ppsUnit = unit;
    }
    return parseBandwidthInput(fields).ok ? fields : null;
}
/* ---------------- 95th percentile ---------------- */
export const MAX_SAMPLES = 200_000;
/**
 * One sample per line. Spaces, tabs and semicolons also separate values, so
 * a row pasted from a spreadsheet works; commas only group thousands.
 */
export function parseSamples(text) {
    const values = [];
    const invalid = [];
    let invalidCount = 0;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        for (const tok of lines[i].split(/[\s;]+/)) {
            if (!tok)
                continue;
            const v = parseDecimal(tok);
            if (v === null) {
                invalidCount++;
                if (invalid.length < 3)
                    invalid.push({ line: i + 1, text: tok.length > 24 ? `${tok.slice(0, 24)}…` : tok });
            }
            else
                values.push(v);
        }
    }
    return { values, invalid, invalidCount };
}
/**
 * The 95th percentile as burstable billing computes it: sort the samples,
 * discard the highest 5 % (rounded down), take the highest that remains.
 * Integer arithmetic for the cut, so 8,640 samples drop exactly 432.
 */
export function percentile95(values) {
    const n = values.length;
    if (n === 0)
        return null;
    const sorted = Float64Array.from(values).sort();
    const discarded = Math.floor((n * 5) / 100);
    const rank = n - discarded;
    let sum = 0;
    for (const v of sorted)
        sum += v;
    return { count: n, discarded, rank, p95: sorted[rank - 1], peak: sorted[n - 1], mean: sum / n };
}
/** A small month-like example: mostly steady, a few bursts that the 95th percentile ignores. */
export const SAMPLE_EXAMPLE = [
    "182", "176", "191", "205", "198", "187", "240", "232", "219", "201",
    "195", "188", "176", "214", "226", "209", "197", "228", "1240", "203",
    "199", "211", "218", "207", "193", "186", "179", "224", "236", "212",
    "205", "198", "190", "952", "201", "188", "194", "210", "221", "215",
].join("\n");
