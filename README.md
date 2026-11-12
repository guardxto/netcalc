# netcalc

Subnet, bandwidth-to-PPS and tunnel MTU/MSS calculators for the command line, and the same maths as a TypeScript library. No runtime dependencies.

This is the code behind the free calculators at [guardx.to/tools](https://guardx.to/tools). If you would rather click than type, use the [subnet calculator](https://guardx.to/tools/subnet-calculator), the [bandwidth to PPS calculator](https://guardx.to/tools/bandwidth-pps-calculator) or the [tunnel MTU & MSS calculator](https://guardx.to/tools/mtu-mss-calculator) in the browser.

## Install

Node.js 18.3 or newer. Run it once without installing:

```sh
npx github:guardxto/netcalc subnet 192.168.1.10/24
```

or install the `netcalc` command:

```sh
npm install -g github:guardxto/netcalc
```

## Subnets

An address with a prefix, a netmask or a wildcard mask:

```text
$ netcalc subnet 192.168.1.10/24
  Network       192.168.1.0/24
  Netmask       255.255.255.0  (wildcard 0.0.0.255)
  First host    192.168.1.1
  Last host     192.168.1.254
  Broadcast     192.168.1.255
  Addresses     256
  Usable hosts  254
  Address type  Private network (RFC 1918)
  Class         C
  Reverse zone  1.168.192.in-addr.arpa
  As integer    3232235786  (0xC0A8010A)
```

`netcalc subnet 10.0.0.7 255.255.252.0` works the same way. `/31` and `/32` are counted as RFC 3021 point-to-point and host routes, and the address type comes from the IANA special-purpose registry. `netcalc subnet --table` prints netmasks, wildcards and host counts for /8 to /32.

## Bandwidth and packets per second

A bit rate to packets per second, or back with `bps`. By default the 20 bytes of preamble, start-of-frame delimiter and inter-frame gap that every Ethernet frame costs on the wire are counted. Leave them out with `--no-wire`.

```text
$ netcalc pps 10G
  Packet rate     14.88 Mpps  (14,880,952.38 pps)
  Bit rate        10 Gbps  (on the wire)
  Frame           64 bytes, 46-byte IP packet inside
  On the wire     10 Gbps
  Frames only     7.62 Gbps
  IP packets      5.48 Gbps
  Frame interval  67.2 ns

  Bytes per frame on the wire = 64 + 20 = 84
  Bits per frame = 84 × 8 = 672
  Packets per second = 10,000,000,000 ÷ 672 = 14,880,952.38 ≈ 14.88 Mpps
```

```text
$ netcalc bps 1.5M --frame 1518
  Packet rate     1.5 Mpps  (1,500,000 pps)
  Bit rate        18.46 Gbps  (on the wire)
  Frame           1,518 bytes, 1,500-byte IP packet inside
```

Rates take `k`, `M`, `G` and `T` suffixes, with or without `bps` or `pps`. Frame sizes go from 64 to 9,216 bytes.

## Tunnel MTU and MSS

List the layers from the physical link inwards. Add `4` or `6` for the outer IP version of a layer (`4` if you leave it out):

```text
$ netcalc mtu pppoe wireguard6
  Underlay MTU   1500
  PPPoE                    -  8 bytes  ->  MTU 1492  (ppp0)
  WireGuard over IPv6      - 80 bytes  ->  MTU 1412  (wg0)

  Tunnel MTU     1412
  TCP MSS IPv4   1372
  TCP MSS IPv6   1352

  i WireGuard's own default
    wg-quick and the Linux driver default to 1,420 on a 1,500-byte path: the IPv6 figure, so one MTU works whichever address family the peer uses. Over IPv4 only, 1,440 is safe.
```

`--underlay` sets the MTU of the link (default 1500). `--snippets` adds ready-to-paste configuration, and `--iface` names the interfaces, one per layer:

```text
$ netcalc mtu gre4 --iface gre1 --snippets
...
# MSS clamping with nftables
table inet mss_clamp {
	chain forward {
		type filter hook forward priority mangle; policy accept;
		oifname "gre1" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1436
		iifname "gre1" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1436
		...
```

The snippets cover iproute2, iptables, nftables and MikroTik RouterOS.

| Layer | Name | Bytes (over IPv4 / IPv6) | Source |
| :-- | :-- | :-- | :-- |
| `pppoe` | PPPoE | 8 | RFC 2516 |
| `gre` | GRE | 24 / 44 | RFC 2784 |
| `gre-key` | GRE with key | 28 / 48 | RFC 2784, RFC 2890 |
| `ipip` | IP-in-IP | 20 / 40 | RFC 2003, RFC 2473 |
| `wireguard` | WireGuard | 60 / 80 | WireGuard protocol |
| `vxlan` | VXLAN, incl. inner Ethernet header | 50 / 70 | RFC 7348 |
| `esp` | IPsec ESP, tunnel mode, AES-GCM (estimate) | 57 / 77 | RFC 4303, RFC 4106 |
| `esp-natt` | IPsec ESP with NAT traversal (estimate) | 65 / 85 | RFC 4303, RFC 4106, RFC 3948 |

## JSON

Every command takes `--json` and prints the full result object, for scripts and monitoring:

```sh
netcalc pps 10G --json | jq .pps
```

## As a library

```ts
import { calculateSubnet, calculateBandwidth, calculateMtu } from "netcalc";

calculateSubnet("10.0.0.7", 22).usableHosts; // 1022

calculateBandwidth({ ok: true, mode: "rate", bps: 10e9, pps: null, frame: 64, wire: true }).pps; // 14880952.38...

calculateMtu(1500, [{ kind: "wireguard", ip: 6 }]).mss4; // 1380
```

All functions are pure and synchronous, and the same code runs in the browser. Types are included.

## Development

```sh
npm install
npm test
```

`npm test` builds with TypeScript and runs the tests with Node's built-in test runner. The compiled `dist/` folder is committed so that `npx github:guardxto/netcalc` works without a build step. Run `npm run build` before you commit.

Found a wrong number or a missing layer? [Open an issue](https://github.com/guardxto/netcalc/issues). Security reports go to contact@guardx.to, see [SECURITY.md](https://github.com/guardxto/guardxto/blob/main/SECURITY.md).

## License

[MIT](LICENSE)

---

Maintained by [GuardX](https://guardx.to): WAF, DDoS protection and CDN for websites and APIs, operated in the EU.
