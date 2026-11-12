import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { run } from "../src/cli.js";

describe("netcalc subnet", () => {
  it("reads address/prefix", () => {
    const out = run(["subnet", "192.168.1.10/24"]);
    assert.match(out, /Network\s+192\.168\.1\.0\/24/);
    assert.match(out, /Usable hosts\s+254/);
    assert.match(out, /Broadcast\s+192\.168\.1\.255/);
  });
  it("reads address and netmask as two arguments", () => {
    const r = JSON.parse(run(["subnet", "10.0.0.7", "255.255.252.0", "--json"]));
    assert.equal(r.cidr, "10.0.0.0/22");
    assert.equal(r.usableHosts, 1022);
  });
  it("prints the CIDR table", () => {
    const rows = JSON.parse(run(["subnet", "--table", "--json"]));
    assert.equal(rows.length, 25);
    assert.deepEqual(rows[16], { prefix: 24, netmask: "255.255.255.0", wildcard: "0.0.0.255", total: 256, usable: 254 });
  });
  it("explains bad input", () => {
    assert.throws(() => run(["subnet", "300.1.1.1/24"]), /0-255/);
    assert.throws(() => run(["subnet", "10.0.0.1"]), /prefix/);
  });
});

describe("netcalc pps and bps", () => {
  it("turns 10G of 64-byte frames into line rate", () => {
    const r = JSON.parse(run(["pps", "10G", "--json"]));
    assert.equal(Math.round(r.pps), 14_880_952);
    assert.match(run(["pps", "10Gbps"]), /14\.88 Mpps/);
  });
  it("goes back from packets to bits", () => {
    const r = JSON.parse(run(["bps", "1M", "--frame", "1518", "--json"]));
    assert.equal(r.bps, 1e6 * (1518 + 20) * 8);
  });
  it("counts frames only with --no-wire", () => {
    const r = JSON.parse(run(["pps", "1G", "--frame", "1000", "--no-wire", "--json"]));
    assert.equal(r.pps, 125_000);
  });
  it("rejects the wrong unit and bad frames", () => {
    assert.throws(() => run(["pps", "10Mpps"]), /bit rate/);
    assert.throws(() => run(["bps", "10Gbps"]), /packet rate/);
    assert.throws(() => run(["pps", "10G", "--frame", "40"]), /at least 64/);
  });
});

describe("netcalc mtu", () => {
  it("computes GRE over IPv4 on 1500", () => {
    const r = JSON.parse(run(["mtu", "gre", "--json"]));
    assert.equal(r.innerMtu, 1476);
    assert.equal(r.mss4, 1436);
    assert.equal(r.mss6, 1416);
  });
  it("stacks layers from the link inwards", () => {
    const r = JSON.parse(run(["mtu", "pppoe", "wireguard6", "--json"]));
    assert.equal(r.innerMtu, 1500 - 8 - 80);
  });
  it("prints snippets for the given interfaces", () => {
    const out = run(["mtu", "wireguard4", "--iface", "wg9", "--snippets"]);
    assert.match(out, /ip link set dev wg9 mtu 1440/);
    assert.match(out, /--set-mss 1400/);
  });
  it("explains unknown layers and mismatched names", () => {
    assert.throws(() => run(["mtu", "gre5"]), /Unknown layer/);
    assert.throws(() => run(["mtu", "pppoe6"]), /no outer IP header/);
    assert.throws(() => run(["mtu", "gre", "ipip", "--iface", "a"]), /2 name/);
  });
});

describe("netcalc", () => {
  it("shows help and refuses unknown commands", () => {
    assert.match(run([]), /Usage/);
    assert.throws(() => run(["route"]), /Unknown command/);
  });
});
