import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildSnippets,
  calculateMtu,
  defaultIfNames,
  isValidIfName,
  layerBytes,
  LAYER_KINDS,
  MTU_DEFAULT,
  mtuFromHash,
  mtuToHash,
  parseUnderlay,
  type Layer,
} from "../src/mtu.js";

const L = (kind: Layer["kind"], ip: 4 | 6 = 4): Layer => ({ kind, ip });

describe("layer overhead", () => {
  it("uses the header sizes from the RFCs and the WireGuard protocol", () => {
    assert.equal(layerBytes(L("pppoe")), 8);
    assert.equal(layerBytes(L("pppoe", 6)), 8); // no outer IP header
    assert.equal(layerBytes(L("gre")), 24);
    assert.equal(layerBytes(L("gre", 6)), 44);
    assert.equal(layerBytes(L("gre-key")), 28);
    assert.equal(layerBytes(L("gre-key", 6)), 48);
    assert.equal(layerBytes(L("ipip")), 20);
    assert.equal(layerBytes(L("ipip", 6)), 40);
    assert.equal(layerBytes(L("wireguard")), 60);
    assert.equal(layerBytes(L("wireguard", 6)), 80);
    assert.equal(layerBytes(L("vxlan")), 50);
    assert.equal(layerBytes(L("vxlan", 6)), 70);
    assert.equal(layerBytes(L("esp")), 57);
    assert.equal(layerBytes(L("esp", 6)), 77);
    assert.equal(layerBytes(L("esp-natt")), 65);
  });
});

describe("calculateMtu", () => {
  it("gives the familiar GRE numbers on a 1,500-byte path", () => {
    const r = calculateMtu(1500, [L("gre")]);
    assert.equal(r.innerMtu, 1476);
    assert.equal(r.mss4, 1436);
    assert.equal(r.mss6, 1416);
    assert.equal(r.overhead, 24);
    assert.equal(r.estimate, false);
    assert.equal(calculateMtu(1500, [L("gre-key")]).innerMtu, 1472);
    assert.equal(calculateMtu(1500, [L("ipip")]).mss4, 1440);
    assert.equal(calculateMtu(1500, [L("gre", 6)]).innerMtu, 1456);
  });

  it("gives WireGuard's 1,420 over IPv6 and 1,440 over IPv4", () => {
    assert.equal(calculateMtu(1500, [L("wireguard", 6)]).innerMtu, 1420);
    assert.equal(calculateMtu(1500, [L("wireguard")]).innerMtu, 1440);
    assert.ok(calculateMtu(1500, [L("wireguard")]).notes.some((n) => /1,420/.test(n.text)));
  });

  it("gives VXLAN's 1,450 and PPPoE's 1,492", () => {
    assert.equal(calculateMtu(1500, [L("vxlan")]).innerMtu, 1450);
    assert.equal(calculateMtu(9000, [L("vxlan")]).innerMtu, 8950);
    const p = calculateMtu(1500, [L("pppoe")]);
    assert.equal(p.innerMtu, 1492);
    assert.equal(p.mss4, 1452);
    assert.equal(calculateMtu(1492, []).mss4, 1452);
  });

  it("stacks layers from the underlay inwards", () => {
    const r = calculateMtu(1500, [L("pppoe"), L("wireguard"), L("gre")]);
    assert.deepEqual(
      r.rows.map((x) => [x.kind, x.bytes, x.mtu]),
      [
        ["pppoe", 8, 1492],
        ["wireguard", 60, 1432],
        ["gre", 24, 1408],
      ],
    );
    assert.equal(r.overhead, 92);
    assert.equal(r.innerMtu, 1408);
    assert.equal(r.rows[0].ip, null);
    assert.equal(r.rows[1].ip, 4);
  });

  it("marks IPsec as an estimate", () => {
    const r = calculateMtu(1500, [L("esp")]);
    assert.equal(r.innerMtu, 1443);
    assert.equal(r.estimate, true);
    assert.ok(r.notes.some((n) => n.title === "IPsec ESP is an estimate"));
  });

  it("warns below the IPv6 minimum and when nothing fits", () => {
    const small = calculateMtu(1300, [L("esp-natt")]);
    assert.equal(small.innerMtu, 1235);
    assert.equal(small.ipv6, false);
    assert.equal(small.mss6, null);
    assert.equal(small.mss4, 1195);
    assert.ok(small.notes.some((n) => n.title === "Too small for IPv6"));
    const none = calculateMtu(100, [L("wireguard", 6)]);
    assert.equal(none.fits, false);
    assert.equal(none.mss4, null);
    assert.ok(none.notes.some((n) => n.title === "The layers do not fit"));
  });

  it("warns about PPPoE counted twice or placed above an IP tunnel", () => {
    assert.ok(calculateMtu(1492, [L("pppoe")]).notes.some((n) => n.title === "PPPoE counted twice"));
    assert.ok(calculateMtu(1500, [L("gre"), L("pppoe")]).notes.some((n) => n.title === "PPPoE runs on Ethernet"));
    assert.ok(!calculateMtu(1500, [L("vxlan"), L("pppoe")]).notes.some((n) => n.title === "PPPoE runs on Ethernet"));
    assert.ok(calculateMtu(1500, [L("gre", 6)]).notes.some((n) => /encaplimit none/.test(n.text)));
    assert.ok(!calculateMtu(1500, [L("gre")]).notes.some((n) => /encaplimit/.test(n.text)));
  });
});

describe("input", () => {
  it("reads the underlay MTU", () => {
    assert.deepEqual(parseUnderlay("1500"), { ok: true, mtu: 1500 });
    assert.deepEqual(parseUnderlay(" 9,000 "), { ok: true, mtu: 9000 });
    assert.equal(parseUnderlay("").ok, false);
    assert.equal(parseUnderlay("1500.5").ok, false);
    assert.equal(parseUnderlay("67").ok, false);
    assert.equal(parseUnderlay("65536").ok, false);
    assert.equal(parseUnderlay("65535").ok, true);
  });

  it("accepts only interface names safe in every snippet", () => {
    assert.ok(isValidIfName("gre1"));
    assert.ok(isValidIfName("br-vx.10"));
    assert.ok(isValidIfName("abcdefghijklmno")); // 15
    assert.ok(!isValidIfName("abcdefghijklmnop")); // 16
    assert.ok(!isValidIfName(""));
    assert.ok(!isValidIfName("gre 1"));
    assert.ok(!isValidIfName('gre1"; drop'));
    assert.ok(!isValidIfName("-gre"));
    assert.ok(!isValidIfName("eth0/1"));
  });

  it("names interfaces without collisions", () => {
    assert.deepEqual(defaultIfNames([L("pppoe"), L("wireguard"), L("gre"), L("gre-key")], 1500), ["ppp0", "wg0", "gre1", "gre2"]);
    assert.deepEqual(defaultIfNames([L("gre", 6), L("ipip", 6), L("vxlan")], 1500), ["ip6gre1", "ip6tnl1", "vxlan100"]);
    assert.deepEqual(defaultIfNames([], 1492), ["ppp0"]);
    assert.deepEqual(defaultIfNames([], 1500), ["eth0"]);
  });
});

describe("snippets", () => {
  it("sets each interface MTU and clamps on the innermost one", () => {
    const layers = [L("wireguard", 6), L("gre")];
    const r = calculateMtu(1500, layers);
    const s = buildSnippets(r, defaultIfNames(layers, 1500));
    const get = (id: string) => s.find((x) => x.id === id)?.code ?? "";
    assert.deepEqual(get("linux").split("\n").slice(1), ["ip link set dev wg0 mtu 1420", "ip link set dev gre1 mtu 1396"]);
    const ipt = get("iptables");
    assert.match(ipt, /^iptables -t mangle -A FORWARD -o gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1356$/m);
    assert.match(ipt, /^iptables -t mangle -A FORWARD -i gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1356$/m);
    assert.match(ipt, /^ip6tables -t mangle -A FORWARD -o gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1336$/m);
    assert.match(ipt, /--clamp-mss-to-pmtu$/m);
    const nft = get("nftables");
    assert.match(nft, /^\t\toifname "gre1" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1356$/m);
    assert.match(nft, /^\t\tiifname "gre1" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1336$/m);
    assert.match(nft, /set rt mtu$/m);
    assert.ok(nft.startsWith("table inet mss_clamp {"));
    const mk = get("mikrotik");
    assert.match(mk, /^add chain=forward out-interface=gre1 protocol=tcp tcp-flags=syn tcp-mss=1357-65535 action=change-mss new-mss=1356 passthrough=yes$/m);
    assert.match(mk, /^\/ipv6 firewall mangle$/m);
  });

  it("leaves IPv6 out when the tunnel is below 1,280", () => {
    const r = calculateMtu(1300, [L("esp-natt")]);
    const s = buildSnippets(r, ["ipsec0"]);
    const ipt = s.find((x) => x.id === "iptables")?.code ?? "";
    assert.doesNotMatch(ipt, /^ip6tables/m);
    assert.match(ipt, /at least 1280/);
    assert.doesNotMatch(s.find((x) => x.id === "nftables")?.code ?? "", /ipv6/);
    assert.doesNotMatch(s.find((x) => x.id === "mikrotik")?.code ?? "", /ipv6/);
  });

  it("offers only the interface MTU when nothing fits", () => {
    const r = calculateMtu(100, [L("wireguard", 6)]);
    assert.deepEqual(
      buildSnippets(r, ["wg0"]).map((x) => x.id),
      ["linux"],
    );
  });
});

describe("URL fragment", () => {
  it("round-trips the form", () => {
    const f = { underlay: "1500", layers: [L("pppoe"), L("wireguard", 6), L("gre-key"), L("esp-natt", 6)], iface: "tun-a" };
    const hash = new URLSearchParams(mtuToHash(f)).toString();
    assert.equal(hash, "mtu=1500&stack=pppoe.wireguard6.gre-key4.esp-natt6&if=tun-a");
    assert.deepEqual(mtuFromHash(hash), f);
    assert.deepEqual(mtuFromHash(new URLSearchParams(mtuToHash(MTU_DEFAULT)).toString()), MTU_DEFAULT);
    assert.deepEqual(mtuFromHash("mtu=1492&stack="), { underlay: "1492", layers: [], iface: null });
  });

  it("ignores in-page anchors and broken state", () => {
    assert.equal(mtuFromHash("guide"), null);
    assert.equal(mtuFromHash("mtu=abc&stack=gre4"), null);
    assert.equal(mtuFromHash("mtu=1500&stack=gre"), null); // outer IP version missing
    assert.equal(mtuFromHash("mtu=1500&stack=pppoe4"), null); // PPPoE has none
    assert.equal(mtuFromHash("mtu=1500&stack=constructor4"), null);
    assert.equal(mtuFromHash("mtu=1500&stack=gre4&if=bad%20name"), null);
    assert.equal(mtuFromHash(`mtu=1500&stack=${Array(7).fill("gre4").join(".")}`), null);
  });

  it("knows every kind it offers", () => {
    for (const k of LAYER_KINDS) assert.ok(layerBytes(L(k)) > 0);
  });
});
