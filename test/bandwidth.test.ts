import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BANDWIDTH_DEFAULT,
  bandwidthFromHash,
  bandwidthToHash,
  bpsAsField,
  bpsFromPps,
  calculateBandwidth,
  FRAME_PRESETS,
  formatBps,
  formatDuration,
  formatPps,
  frameFor,
  ipPacketIn,
  lineRateTable,
  parseBandwidthInput,
  parseDecimal,
  parseSamples,
  percentile95,
  ppsAsField,
  ppsFromBps,
  presetRows,
  SAMPLE_EXAMPLE,
  toBps,
  toPps,
  WIRE_OVERHEAD,
  type BandwidthFields,
} from "../src/bandwidth.js";

const ok = (f: Partial<BandwidthFields>) => {
  const r = parseBandwidthInput({ ...BANDWIDTH_DEFAULT, ...f });
  if (!r.ok) throw new Error(r.error);
  return r;
};

describe("bit rate <-> packet rate", () => {
  it("gives 14.88 Mpps for 10 Gbps of 64-byte frames on the wire", () => {
    assert.equal(WIRE_OVERHEAD, 20);
    const pps = ppsFromBps(10e9, 64, true);
    assert.equal(Math.floor(pps), 14_880_952);
    assert.equal(formatPps(pps), "14.88 Mpps");
  });

  it("matches the Ethernet maximum frame rates of RFC 2544 appendix B (10 Mb/s)", () => {
    const rfc: [number, number][] = [
      [64, 14880],
      [128, 8445],
      [256, 4528],
      [512, 2349],
      [1024, 1197],
      [1280, 961],
      [1518, 812],
    ];
    for (const [frame, pps] of rfc) assert.equal(Math.floor(ppsFromBps(10e6, frame, true)), pps, `${frame} bytes`);
  });

  it("counts only the frame when wire overhead is off", () => {
    assert.equal(ppsFromBps(512e3, 64, false), 1000);
    assert.equal(bpsFromPps(1000, 64, false), 512e3);
    assert.equal(bpsFromPps(1e6, 64, true), 672e6);
  });

  it("round-trips", () => {
    for (const frame of [64, 78, 558, 1518, 9018]) {
      for (const wire of [true, false]) {
        const bps = 37e9;
        assert.ok(Math.abs(bpsFromPps(ppsFromBps(bps, frame, wire), frame, wire) - bps) < 1e-3);
      }
    }
  });

  it("converts units with decimal prefixes", () => {
    assert.equal(toBps(10, "Gbps"), 1e10);
    assert.equal(toBps(1, "Tbps"), 1e12);
    assert.equal(toBps(250, "Kbps"), 250_000);
    assert.equal(toPps(3, "Kpps"), 3000);
    assert.equal(toPps(2, "Mpps"), 2e6);
  });

  it("relates frames and IP packets", () => {
    assert.equal(ipPacketIn(1518), 1500);
    assert.equal(ipPacketIn(64), 46);
    assert.equal(frameFor(40), 64); // bare SYN, padded
    assert.equal(frameFor(46), 64);
    assert.equal(frameFor(47), 65);
    assert.equal(frameFor(60), 78); // SYN with options, not padded
    assert.equal(frameFor(512 + 8 + 20), 558); // 512-byte DNS message over UDP/IPv4
    assert.equal(frameFor(9000), 9018);
  });

  it("derives every preset from header sizes", () => {
    assert.deepEqual(
      FRAME_PRESETS.map((p) => p.frame),
      [64, 78, 558, 1518, 9018],
    );
  });
});

describe("calculateBandwidth", () => {
  it("explains 10 Gbps at 64 bytes", () => {
    const r = calculateBandwidth(ok({}));
    assert.equal(r.countedBytes, 84);
    assert.equal(r.countedBits, 672);
    assert.equal(Math.floor(r.pps), 14_880_952);
    assert.equal(r.wireBps, 1e10);
    assert.equal(Math.round(r.frameBps), Math.round((1e10 * 64) / 84));
    assert.equal(r.ipPacket, 46);
    assert.equal(formatDuration(r.interval), "67.2 ns");
    assert.ok(Math.abs(r.overheadShare - 20 / 84) < 1e-12);
    assert.deepEqual(r.steps, [
      "Bytes per frame on the wire = 64 + 20 = 84",
      "Bits per frame = 84 × 8 = 672",
      "Packets per second = 10,000,000,000 ÷ 672 = 14,880,952.38 ≈ 14.88 Mpps",
    ]);
  });

  it("goes from packet rate to bit rate", () => {
    const r = calculateBandwidth(ok({ mode: "pps", value: "1", ppsUnit: "Mpps", frame: "1518" }));
    assert.equal(r.pps, 1e6);
    assert.equal(r.bps, 1538 * 8 * 1e6);
    assert.equal(formatBps(r.bps), "12.3 Gbps");
    assert.equal(r.steps[2], "Bit rate = 1,000,000 × 12,304 = 12,304,000,000 bps ≈ 12.3 Gbps");
    const frameOnly = calculateBandwidth(ok({ mode: "pps", value: "1", ppsUnit: "Mpps", frame: "1518", wire: false }));
    assert.equal(frameOnly.bps, 1518 * 8 * 1e6);
    assert.match(frameOnly.steps[0], /not counted/);
  });

  it("lists the rate at every preset size", () => {
    const rows = presetRows(ok({}));
    assert.equal(rows.length, FRAME_PRESETS.length);
    assert.equal(Math.floor(rows[0].pps), 14_880_952);
    assert.equal(Math.floor(rows[3].pps), 812_743);
  });

  it("builds the line-rate table", () => {
    const t = lineRateTable();
    const ten = t.find((r) => r.speed === "10 Gbps");
    assert.deepEqual(ten?.pps, [14_880_952, 8_445_945, 2_349_624, 812_743, 138_304]);
    assert.equal(t.find((r) => r.speed === "100 Gbps")?.pps[0], 148_809_523);
    assert.equal(t.find((r) => r.speed === "1 Gbps")?.pps[0], 1_488_095);
  });
});

describe("switching direction", () => {
  it("starts the other side from the result in a sensible unit", () => {
    assert.deepEqual(ppsAsField(14_880_952.38), { value: "14.881", unit: "Mpps" });
    assert.deepEqual(ppsAsField(812), { value: "812", unit: "pps" });
    assert.deepEqual(ppsAsField(2.5e9), { value: "2500", unit: "Mpps" });
    assert.deepEqual(bpsAsField(12_304_000_000), { value: "12.304", unit: "Gbps" });
    assert.deepEqual(bpsAsField(0.5), { value: "0.5", unit: "bps" });
    const back = parseBandwidthInput({ ...BANDWIDTH_DEFAULT, mode: "pps", value: "14.881", ppsUnit: "Mpps" });
    assert.ok(back.ok && Math.abs(calculateBandwidth(back).bps - 1e10) < 1e5);
  });
});

describe("formatting", () => {
  it("scales to the largest unit reached", () => {
    assert.equal(formatPps(999), "999 pps");
    assert.equal(formatPps(1500), "1.5 Kpps");
    assert.equal(formatPps(1.488e9), "1.49 Gpps");
    assert.equal(formatPps(0.0123), "0.0123 pps");
    assert.equal(formatBps(672e6), "672 Mbps");
    assert.equal(formatBps(4e14), "400 Tbps");
    assert.equal(formatDuration(1.2304e-5), "12.3 µs");
    assert.equal(formatDuration(0.0045), "4.5 ms");
  });
});

describe("input", () => {
  it("parses decimals strictly", () => {
    assert.equal(parseDecimal("10"), 10);
    assert.equal(parseDecimal(" 14.88 "), 14.88);
    assert.equal(parseDecimal(".5"), 0.5);
    assert.equal(parseDecimal("1,000,000"), 1e6);
    assert.equal(parseDecimal("1,000.5"), 1000.5);
    assert.equal(parseDecimal("14,88"), null);
    assert.equal(parseDecimal("1,00"), null);
    assert.equal(parseDecimal("-5"), null);
    assert.equal(parseDecimal("1e9"), null);
    assert.equal(parseDecimal("10 Gbps"), null);
    assert.equal(parseDecimal(""), null);
  });

  it("rejects what cannot be computed, naming the field", () => {
    const bad = (f: Partial<BandwidthFields>) => {
      const r = parseBandwidthInput({ ...BANDWIDTH_DEFAULT, ...f });
      assert.equal(r.ok, false);
      return r.ok ? null : r;
    };
    assert.equal(bad({ value: "" })?.field, "value");
    assert.equal(bad({ value: "0" })?.error, "Enter a rate above zero.");
    assert.match(bad({ value: "14,88" })?.error ?? "", /dot for decimals/);
    assert.match(bad({ value: "2000", rateUnit: "Tbps" })?.error ?? "", /1,000 Tbps/);
    assert.equal(bad({ frame: "40" })?.field, "frame");
    assert.match(bad({ frame: "40" })?.error ?? "", /padded/);
    assert.match(bad({ frame: "9217" })?.error ?? "", /9,216/);
    assert.equal(bad({ frame: "abc" })?.field, "frame");
    assert.equal(parseBandwidthInput({ ...BANDWIDTH_DEFAULT, frame: "361.83" }).ok, true);
    assert.equal(parseBandwidthInput({ ...BANDWIDTH_DEFAULT, frame: "9216" }).ok, true);
  });
});

describe("URL fragment", () => {
  it("round-trips the form", () => {
    const f: BandwidthFields = { mode: "pps", value: "2.5", rateUnit: "Gbps", ppsUnit: "Mpps", frame: "78", wire: false };
    const hash = new URLSearchParams(bandwidthToHash(f)).toString();
    assert.equal(hash, "from=pps&v=2.5&unit=Mpps&frame=78&wire=0");
    assert.deepEqual(bandwidthFromHash(hash), f);
  });

  it("ignores in-page anchors and broken state", () => {
    assert.equal(bandwidthFromHash(null), null);
    assert.equal(bandwidthFromHash("guide"), null);
    assert.equal(bandwidthFromHash("from=rate&v=10&unit=Mpps&frame=64&wire=1"), null);
    assert.equal(bandwidthFromHash("from=rate&v=10&unit=Gbps&frame=10&wire=1"), null);
    assert.equal(bandwidthFromHash("from=x&v=10&unit=Gbps&frame=64"), null);
    assert.equal(bandwidthFromHash("from=rate&v=10&unit=Gbps&frame=64")?.wire, true);
  });
});

describe("95th percentile", () => {
  it("discards the top 5 % of a month of 5-minute samples", () => {
    // 8,640 samples: 1..8640. The top 432 go, the 8,208th value remains.
    const values = Array.from({ length: 8640 }, (_, i) => 8640 - i);
    const r = percentile95(values);
    assert.equal(r?.count, 8640);
    assert.equal(r?.discarded, 432);
    assert.equal(r?.rank, 8208);
    assert.equal(r?.p95, 8208);
    assert.equal(r?.peak, 8640);
    assert.equal(r?.mean, 4320.5);
  });

  it("keeps the peak when 5 % rounds down to nothing", () => {
    const r = percentile95([5, 1, 3]);
    assert.equal(r?.discarded, 0);
    assert.equal(r?.p95, 5);
    assert.equal(percentile95([]), null);
  });

  it("ignores short bursts in the example", () => {
    const { values, invalidCount } = parseSamples(SAMPLE_EXAMPLE);
    assert.equal(invalidCount, 0);
    assert.equal(values.length, 40);
    const r = percentile95(values);
    assert.equal(r?.discarded, 2);
    assert.equal(r?.p95, 240);
    assert.equal(r?.peak, 1240);
  });

  it("sorts numerically, not as text", () => {
    assert.equal(percentile95([9, 10, 100, 20, ...Array(16).fill(1)])?.p95, 20);
  });

  it("parses pasted samples and reports what is not a number", () => {
    const p = parseSamples("120\n 95.5 \n\n1,250\t80;70\nabc\n12,5\n-3");
    assert.deepEqual(p.values, [120, 95.5, 1250, 80, 70]);
    assert.equal(p.invalidCount, 3);
    assert.deepEqual(p.invalid, [
      { line: 5, text: "abc" },
      { line: 6, text: "12,5" },
      { line: 7, text: "-3" },
    ]);
    assert.deepEqual(parseSamples("1\r\n2\r\n").values, [1, 2]);
  });
});
