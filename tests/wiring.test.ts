import { describe, it, expect } from "vitest";
import { buildToolset } from "../src/mcp/toolset.js";

/**
 * The wiring contract: the registered tool set must match the documented 31
 * exactly. If a tool is added/removed/renamed, update this list AND the docs
 * (README, docs/index.html) in the same commit — this test fails on drift.
 */
const EXPECTED: Array<[name: string, kind: "read" | "probe" | "gated"]> = [
  // net.* (9)
  ["net.health", "read"],
  ["net.ping", "probe"],
  ["net.trace", "probe"],
  ["net.httpcheck", "probe"],
  ["net.portcheck", "probe"],
  ["net.portscan", "probe"],
  ["net.ssl", "probe"],
  ["net.publicip", "probe"],
  ["net.deepscan", "probe"],
  // dns.* (5)
  ["dns.lookup", "probe"],
  ["dns.reverse", "probe"],
  ["dns.resolvers", "read"],
  ["dns.propagation", "probe"],
  ["dns.hijackcheck", "probe"],
  // lan.* (9)
  ["lan.interfaces", "read"],
  ["lan.gateway", "read"],
  ["lan.arp", "read"],
  ["lan.sweep", "probe"],
  ["lan.devices", "read"],
  ["lan.hostname", "probe"],
  ["lan.snapshot", "read"],
  ["lan.newdevices", "read"],
  ["lan.wol", "gated"],
  // wifi.* (3)
  ["wifi.status", "read"],
  ["wifi.networks", "read"],
  ["wifi.health", "read"],
  // sec.* (5)
  ["sec.connections", "read"],
  ["sec.listening", "read"],
  ["sec.firewall", "read"],
  ["sec.exposure", "read"],
  ["sec.speedtest", "probe"],
];

describe("wiring contract", () => {
  it("registers exactly the documented 31 tools", () => {
    const tools = buildToolset().map((t) => t.name).sort();
    const expected = EXPECTED.map(([n]) => n).sort();
    expect(tools.length).toBe(31);
    expect(tools).toEqual(expected);
  });

  it("every tool has a name and a description", () => {
    for (const t of buildToolset()) {
      expect(t.name).toMatch(/^[a-z]+\.[a-z]+$/);
      expect(t.description.length).toBeGreaterThan(10);
    }
  });

  it("exactly one gated (mutating) tool: lan.wol", () => {
    const gated = EXPECTED.filter(([, k]) => k === "gated").map(([n]) => n);
    expect(gated).toEqual(["lan.wol"]);
  });

  it("class counts: 15 read · 15 probe · 1 gated", () => {
    const counts = EXPECTED.reduce<Record<string, number>>((acc, [, k]) => {
      acc[k] = (acc[k] ?? 0) + 1;
      return acc;
    }, {});
    expect(counts["read"]).toBe(15);
    expect(counts["probe"]).toBe(15);
    expect(counts["gated"]).toBe(1);
  });
});