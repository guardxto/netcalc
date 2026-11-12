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
export declare const ETHERNET: {
    /** preamble (7) and start frame delimiter (1) */
    readonly preamble: 8;
    /** minimum inter-frame gap: 96 bit times */
    readonly gap: 12;
    /** destination MAC, source MAC, EtherType */
    readonly header: 14;
    readonly fcs: 4;
    readonly minFrame: 64;
    /** a 1,500-byte payload with header and FCS, no VLAN tag */
    readonly maxFrame: 1518;
    /** the largest jumbo frame most switches accept; jumbo frames are outside IEEE 802.3 */
    readonly maxJumbo: 9216;
};
/** What a frame costs on the line beyond its own bytes: preamble, SFD and gap. */
export declare const WIRE_OVERHEAD: number;
/** What an untagged frame adds around an IP packet: header and FCS. */
export declare const FRAMING: number;
export declare const RATE_UNITS: readonly ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
export type RateUnit = (typeof RATE_UNITS)[number];
export declare const PPS_UNITS: readonly ["pps", "Kpps", "Mpps"];
export type PpsUnit = (typeof PPS_UNITS)[number];
export declare const toBps: (value: number, unit: RateUnit) => number;
export declare const toPps: (value: number, unit: PpsUnit) => number;
export declare const bpsAsField: (bps: number) => {
    value: string;
    unit: "bps" | "Kbps" | "Mbps" | "Gbps" | "Tbps";
};
export declare const ppsAsField: (pps: number) => {
    value: string;
    unit: "pps" | "Kpps" | "Mpps";
};
/** Bytes one frame occupies: the frame itself, plus preamble, SFD and gap when counted on the wire. */
export declare const bytesPerFrame: (frame: number, wire: boolean) => number;
export declare const ppsFromBps: (bps: number, frame: number, wire: boolean) => number;
export declare const bpsFromPps: (pps: number, frame: number, wire: boolean) => number;
/** The largest IP packet an untagged frame of this size carries. */
export declare const ipPacketIn: (frame: number) => number;
/** The frame an IP packet travels in: header and FCS added, then padded to the 64-byte minimum. */
export declare const frameFor: (ipPacket: number) => number;
export type FramePreset = {
    frame: number;
    label: string;
    detail: string;
};
/** Frame sizes worth one click, each derived from header sizes rather than measured. */
export declare const FRAME_PRESETS: FramePreset[];
/** A non-negative decimal as typed: "10", "14.88", ".5" or "1,000,000" (commas only in groups of three). */
export declare function parseDecimal(raw: string): number | null;
export type BandwidthMode = "rate" | "pps";
/** The form as typed: strings for the two number fields, so half-typed values survive. */
export type BandwidthFields = {
    mode: BandwidthMode;
    value: string;
    rateUnit: RateUnit;
    ppsUnit: PpsUnit;
    frame: string;
    wire: boolean;
};
export declare const BANDWIDTH_DEFAULT: BandwidthFields;
export declare const MAX_BPS = 1000000000000000;
export declare const MAX_PPS = 1000000000000;
export type BandwidthInput = {
    ok: true;
    mode: BandwidthMode;
    bps: number | null;
    pps: number | null;
    frame: number;
    wire: boolean;
} | {
    ok: false;
    field: "value" | "frame";
    error: string;
};
export declare function parseBandwidthInput(f: BandwidthFields): BandwidthInput;
/** Grouped thousands, at most two decimals. */
export declare const formatNumber: (n: number) => string;
export declare const formatBps: (bps: number) => string;
export declare const formatPps: (pps: number) => string;
/** A duration in the unit that keeps it readable: 67.2 ns, 1.23 µs, 4.5 ms. */
export declare function formatDuration(seconds: number): string;
export type BandwidthResult = {
    mode: BandwidthMode;
    frame: number;
    wire: boolean;
    /** bytes counted per frame: frame + 20 on the wire, or the frame alone */
    countedBytes: number;
    countedBits: number;
    pps: number;
    /** the bit rate as counted (the input in "rate" mode) */
    bps: number;
    /** bit rate including preamble, SFD and gap */
    wireBps: number;
    /** bit rate of the frames alone, header to FCS */
    frameBps: number;
    /** bit rate of the IP packets inside (frame minus 18 bytes) */
    ipBps: number;
    ipPacket: number;
    /** time between the starts of two frames */
    interval: number;
    /** share of the line taken by preamble, SFD and gap */
    overheadShare: number;
    /** the formula with the numbers filled in, one step per line */
    steps: string[];
};
export declare function calculateBandwidth(input: Extract<BandwidthInput, {
    ok: true;
}>): BandwidthResult;
/** The same rate at each preset size: what the result table under the calculator lists. */
export declare function presetRows(input: Extract<BandwidthInput, {
    ok: true;
}>): {
    frame: number;
    label: string;
    pps: number;
    bps: number;
}[];
export declare const LINK_SPEEDS: [string, number][];
export declare const LINE_RATE_FRAMES: number[];
/** Maximum frames per second at full line rate, rounded down to whole frames as RFC 2544 does. */
export declare function lineRateTable(): {
    speed: string;
    bps: number;
    pps: number[];
}[];
/** The form as a URL fragment: it stays in the browser and never reaches a server log. */
export declare function bandwidthToHash(f: BandwidthFields): Record<string, string>;
/** A fragment from a shared link back to form fields; null unless it holds a complete, valid state. */
export declare function bandwidthFromHash(hash: string | null): BandwidthFields | null;
export declare const MAX_SAMPLES = 200000;
export type SampleParse = {
    values: number[];
    /** the first few tokens that are not numbers, with their line */
    invalid: {
        line: number;
        text: string;
    }[];
    invalidCount: number;
};
/**
 * One sample per line. Spaces, tabs and semicolons also separate values, so
 * a row pasted from a spreadsheet works; commas only group thousands.
 */
export declare function parseSamples(text: string): SampleParse;
export type Percentile95 = {
    count: number;
    /** the top 5 %, rounded down */
    discarded: number;
    /** 1-based position of the 95th percentile in the ascending order */
    rank: number;
    p95: number;
    peak: number;
    mean: number;
};
/**
 * The 95th percentile as burstable billing computes it: sort the samples,
 * discard the highest 5 % (rounded down), take the highest that remains.
 * Integer arithmetic for the cut, so 8,640 samples drop exactly 432.
 */
export declare function percentile95(values: readonly number[]): Percentile95 | null;
/** A small month-like example: mostly steady, a few bursts that the 95th percentile ignores. */
export declare const SAMPLE_EXAMPLE: string;
