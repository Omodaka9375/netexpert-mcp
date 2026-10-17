import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { parseWindowsArp, parseLinuxNeigh, parsePing, parseTraceroute } from "../src/parse/parsers.js";
import { RateLimiter, isRfc1918 } from "../src/safety/caps.js";

const fx = (p: string): string =>
  fs.readFileSync(path.join(import.meta.dirname, "fixtures", p), "utf8");

describe("parseWindowsArp", () => {
  it("parses win32 arp -a fixture", () => {
    const { neighbors, warnings } = parseWindowsArp(fx("win32/arp-a.txt"));
    expect(neighbors.length).toBe(4);
    expect(neighbors[0]?.ip).toBe("192.168.1.1");
    expect(neighbors[0]?.mac).toBe("aa:bb:cc:11:22:33");
    expect(neighbors[0]?.type).toBe("dynamic");
    expect(warnings.length).toBe(0);
  });
  it("is tolerant of truncated output", () => {
    const { neighbors, warnings } = parseWindowsArp("Interface: 10.0.0.2\n  10.0.0.1   incomplete");
    expect(neighbors.length).toBe(0);
    expect(warnings.length).toBe(1);
  });
});

describe("parseLinuxNeigh", () => {
  it("parses ip -j neigh fixture", () => {
    const { neighbors, warnings } = parseLinuxNeigh(fx("linux/ip-j-neigh.json"));
    expect(neighbors.length).toBe(2);
    expect(neighbors[1]?.type).toBe("stale");
    expect(warnings.length).toBe(1); // INCOMPLETE entry without lladdr
  });
  it("rejects garbage JSON", () => {
    const { neighbors, warnings } = parseLinuxNeigh("not json");
    expect(neighbors.length).toBe(0);
    expect(warnings.length).toBe(1);
  });
});

describe("parsePing", () => {
  it("parses windows ping", () => {
    const { stats } = parsePing(fx("win32/ping-n.txt"));
    expect(stats?.transmitted).toBe(4);
    expect(stats?.received).toBe(4);
    expect(stats?.lossPct).toBe(0);
    expect(stats?.minMs).toBe(1);
    expect(stats?.maxMs).toBe(3);
    expect(stats?.avgMs).toBe(2);
  });
  it("parses linux ping", () => {
    const { stats } = parsePing(fx("linux/ping-c.txt"));
    expect(stats?.transmitted).toBe(4);
    expect(stats?.lossPct).toBe(0);
    expect(stats?.minMs).toBeCloseTo(0.388);
    expect(stats?.mdevMs).toBeCloseTo(0.049);
  });
  it("returns null stats on unparseable output", () => {
    const { stats, warnings } = parsePing("total garbage\nno numbers here");
    expect(stats).toBeNull();
    expect(warnings.length).toBe(1);
  });
});

describe("parseTraceroute", () => {
  it("parses windows tracert", () => {
    const { hops } = parseTraceroute("  1    <1 ms   <1 ms   <1 ms  192.168.1.1\n  2    5 ms     6 ms     5 ms  8.8.8.8");
    expect(hops.length).toBe(2);
    expect(hops[0]?.ip).toBe("192.168.1.1");
    expect(hops[1]?.ttl).toBe(2);
  });
});

describe("RateLimiter", () => {
  it("rate-limits per key", () => {
    const rl = new RateLimiter({ sweep: 30, portscan: 10, speedtest: 60, httpCheck: 2 });
    expect(rl.check("portscan", 1000)).toBeUndefined();
    const retry = rl.check("portscan", 2000); // 1s < 10s min gap
    expect(retry).toBeGreaterThan(0);
    expect(rl.check("portscan", 12000)).toBeUndefined();
    expect(rl.check("sweep", 1000)).toBeUndefined(); // independent bucket
  });
});

describe("isRfc1918", () => {
  it("classifies RFC1918 correctly", () => {
    expect(isRfc1918("10.1.2.3")).toBe(true);
    expect(isRfc1918("172.16.0.1")).toBe(true);
    expect(isRfc1918("172.31.255.255")).toBe(true);
    expect(isRfc1918("192.168.0.1")).toBe(true);
    expect(isRfc1918("172.32.0.1")).toBe(false);
    expect(isRfc1918("8.8.8.8")).toBe(false);
    expect(isRfc1918("not-an-ip")).toBe(false);
  });
});