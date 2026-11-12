import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { formatIPv6, parseIp, parseIPv6 } from "../src/ip.js";

describe("IPv6 text", () => {
  it("formats per RFC 5952", () => {
    assert.equal(formatIPv6(parseIPv6("2001:0db8:0000:0000:0001:0000:0000:0001")!), "2001:db8::1:0:0:1");
    assert.equal(formatIPv6(parseIPv6("0:0:0:0:0:0:0:1")!), "::1");
    assert.equal(formatIPv6(parseIPv6("2001:db8:0:1:1:1:1:1")!), "2001:db8:0:1:1:1:1:1");
    assert.equal(formatIPv6(parseIPv6("::ffff:c000:280")!), "::ffff:192.0.2.128");
  });
});
