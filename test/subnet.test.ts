import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  calculateSubnet,
  cidrTable,
  maskToPrefix,
  parsePrefixOrMask,
  parseSubnetInput,
  prefixToMask,
  toBinary,
  usableHosts,
  wildcardOf,
  wildcardToPrefix,
} from "../src/subnet.js";

describe("subnet math", () => {
  it("computes a /24", () => {
    const r = calculateSubnet("192.168.1.10", 24);
    assert.equal(r.network, "192.168.1.0");
    assert.equal(r.broadcast, "192.168.1.255");
    assert.equal(r.firstHost, "192.168.1.1");
    assert.equal(r.lastHost, "192.168.1.254");
    assert.equal(r.usableHosts, 254);
    assert.equal(r.totalAddresses, 256);
    assert.equal(r.netmask, "255.255.255.0");
    assert.equal(r.wildcard, "0.0.0.255");
    assert.equal(r.cidr, "192.168.1.0/24");
    assert.equal(r.ipClass, "C");
    assert.equal(r.type.kind, "private");
    assert.equal(r.reverseZone, "1.168.192.in-addr.arpa");
    assert.equal(r.integer, 3232235786);
    assert.equal(r.hex, "0xC0A8010A");
    assert.equal(r.note, null);
  });

  it("computes a /29", () => {
    const r = calculateSubnet("203.0.113.77", 29);
    assert.equal(r.network, "203.0.113.72");
    assert.equal(r.broadcast, "203.0.113.79");
    assert.equal(r.firstHost, "203.0.113.73");
    assert.equal(r.lastHost, "203.0.113.78");
    assert.equal(r.usableHosts, 6);
    assert.equal(r.netmask, "255.255.255.248");
    assert.equal(r.wildcard, "0.0.0.7");
    assert.equal(r.type.kind, "documentation");
  });

  it("treats /31 as a point-to-point link (RFC 3021)", () => {
    const r = calculateSubnet("10.0.0.5", 31);
    assert.equal(r.network, "10.0.0.4");
    assert.equal(r.broadcast, null);
    assert.equal(r.firstHost, "10.0.0.4");
    assert.equal(r.lastHost, "10.0.0.5");
    assert.equal(r.usableHosts, 2);
    assert.equal(r.totalAddresses, 2);
    assert.match(r.note ?? "", /RFC 3021/);
  });

  it("treats /32 as a single host", () => {
    const r = calculateSubnet("8.8.8.8", 32);
    assert.equal(r.network, "8.8.8.8");
    assert.equal(r.broadcast, null);
    assert.equal(r.firstHost, "8.8.8.8");
    assert.equal(r.lastHost, "8.8.8.8");
    assert.equal(r.usableHosts, 1);
    assert.equal(r.type.kind, "public");
    assert.equal(r.reverseZone, "8.8.8.8.in-addr.arpa");
  });

  it("handles /0 and /8 without 32-bit overflow", () => {
    const zero = calculateSubnet("1.2.3.4", 0);
    assert.equal(zero.network, "0.0.0.0");
    assert.equal(zero.broadcast, "255.255.255.255");
    assert.equal(zero.totalAddresses, 4294967296);
    assert.equal(zero.usableHosts, 4294967294);
    assert.equal(zero.netmask, "0.0.0.0");
    assert.equal(zero.wildcard, "255.255.255.255");
    assert.equal(zero.reverseZone, "in-addr.arpa");
    const eight = calculateSubnet("10.200.3.4", 8);
    assert.equal(eight.network, "10.0.0.0");
    assert.equal(eight.broadcast, "10.255.255.255");
    assert.equal(eight.usableHosts, 16777214);
    assert.equal(eight.ipClass, "A");
  });

  it("works at the top of the address space", () => {
    const r = calculateSubnet("255.255.255.254", 31);
    assert.equal(r.network, "255.255.255.254");
    assert.equal(r.lastHost, "255.255.255.255");
    const c = calculateSubnet("223.255.255.1", 20);
    assert.equal(c.network, "223.255.240.0");
    assert.equal(c.broadcast, "223.255.255.255");
    assert.equal(c.reverseZone, "255.223.in-addr.arpa");
  });

  it("formats binary per octet", () => {
    assert.equal(toBinary(0xc0a8010a), "11000000.10101000.00000001.00001010");
    assert.equal(calculateSubnet("192.168.1.10", 26).binary.netmask, "11111111.11111111.11111111.11000000");
  });

  it("names address classes and types", () => {
    assert.equal(calculateSubnet("172.16.0.1", 12).type.kind, "private");
    assert.equal(calculateSubnet("100.64.1.1", 10).type.kind, "cgnat");
    assert.equal(calculateSubnet("127.0.0.1", 8).type.kind, "loopback");
    assert.equal(calculateSubnet("169.254.10.1", 16).type.kind, "link-local");
    const mc = calculateSubnet("239.1.2.3", 8);
    assert.equal(mc.type.kind, "multicast");
    assert.equal(mc.ipClass, "D");
    assert.equal(calculateSubnet("198.51.100.1", 24).type.kind, "documentation");
    assert.equal(calculateSubnet("192.0.2.1", 24).type.kind, "documentation");
    assert.equal(calculateSubnet("250.1.1.1", 4).ipClass, "E");
    assert.equal(calculateSubnet("150.1.1.1", 16).ipClass, "B");
  });

  it("rejects bad input", () => {
    assert.throws(() => calculateSubnet("256.1.1.1", 24), RangeError);
    assert.throws(() => calculateSubnet("1.2.3", 24), RangeError);
    assert.throws(() => calculateSubnet("1.2.3.4", 33), RangeError);
    assert.throws(() => calculateSubnet("1.2.3.4", -1), RangeError);
    assert.throws(() => calculateSubnet("01.2.3.4", 24), RangeError);
  });
});

describe("netmask <-> prefix", () => {
  it("converts both ways for every prefix", () => {
    for (let p = 0; p <= 32; p++) {
      assert.equal(maskToPrefix(prefixToMask(p)), p);
      assert.equal(wildcardToPrefix(wildcardOf(p)), p);
    }
    assert.equal(prefixToMask(29), "255.255.255.248");
    assert.equal(prefixToMask(22), "255.255.252.0");
  });

  it("rejects non-contiguous masks", () => {
    assert.equal(maskToPrefix("255.0.255.0"), null);
    assert.equal(maskToPrefix("255.255.255.1"), null);
    assert.equal(maskToPrefix("not a mask"), null);
  });

  it("parses the prefix field", () => {
    assert.equal(parsePrefixOrMask("24"), 24);
    assert.equal(parsePrefixOrMask("/29"), 29);
    assert.equal(parsePrefixOrMask("255.255.255.0"), 24);
    assert.equal(parsePrefixOrMask("0.0.0.255"), 24);
    assert.equal(parsePrefixOrMask("33"), null);
    assert.equal(parsePrefixOrMask("abc"), null);
    assert.equal(parsePrefixOrMask("255.0.255.0"), null);
  });

  it("reads CIDR or mask typed into the address field", () => {
    assert.deepEqual(parseSubnetInput("10.0.0.7/8", ""), { ok: true, address: "10.0.0.7", prefix: 8 });
    assert.deepEqual(parseSubnetInput("10.0.0.7 255.255.0.0", "24"), { ok: true, address: "10.0.0.7", prefix: 16 });
    assert.deepEqual(parseSubnetInput(" 10.0.0.7 ", "/30"), { ok: true, address: "10.0.0.7", prefix: 30 });
    const bad = parseSubnetInput("10.0.0.300", "24");
    assert.equal(bad.ok, false);
    assert.equal(!bad.ok && bad.field, "address");
    const noPrefix = parseSubnetInput("10.0.0.1", "");
    assert.equal(!noPrefix.ok && noPrefix.field, "prefix");
    const v6 = parseSubnetInput("2001:db8::1", "64");
    assert.match(!v6.ok ? v6.error : "", /IPv4/);
  });
});

describe("CIDR table", () => {
  it("lists /8 to /32", () => {
    const rows = cidrTable();
    assert.equal(rows.length, 25);
    assert.equal(rows[0].prefix, 8);
    assert.equal(rows[24].prefix, 32);
    const r24 = rows.find((r) => r.prefix === 24);
    assert.deepEqual(r24, { prefix: 24, netmask: "255.255.255.0", wildcard: "0.0.0.255", total: 256, usable: 254 });
    assert.equal(rows.find((r) => r.prefix === 31)?.usable, 2);
    assert.equal(usableHosts(30), 2);
  });
});
