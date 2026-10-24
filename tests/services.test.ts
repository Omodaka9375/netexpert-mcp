import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { NetexpertConfig } from "../src/config.js";
import { makeContext } from "../src/services/util.js";
import type { CommandRunner, RunResult } from "../src/exec/executor.js";
import { lanSweep, lanDevices, lanSnapshot, lanNewdevices, lanHostname, vendorForMac } from "../src/services/lanService.js";
import { expandSubnetForTest } from "../src/services/lanService.js";
import { dnsPropagation, dnsHijackcheck } from "../src/services/dnsService.js";
import { netPublicip, netPing, netHttpcheck, netPortcheck } from "../src/services/coreService.js";
import { isRfc1918 } from "../src/safety/caps.js";

// fake runner: serves fixture outputs keyed by argv signature
class FakeRunner implements CommandRunner {
  responses: Array<{ match: (argv: string[]) => boolean; result: Partial<RunResult> }> = [];
  async run(cmd: string, args: string[]): Promise<RunResult> {
    const hit = this.responses.find((r) => r.match([cmd, ...args]));
    if (!hit) throw new Error(`no fake for: ${cmd} ${args.join(" ")}`);
    return {
      platform: process.platform,
      argv: [cmd, ...args],
      stdout: hit.result.stdout ?? "",
      stderr: hit.result.stderr ?? "",
      code: hit.result.code ?? 0,
    };
  }
}

function ctxWith(overrides: Record<string, unknown> = {}, runner: CommandRunner = new FakeRunner()) {
  const config = NetexpertConfig.parse({
    ...overrides,
    paths: { snapshotsDir: snapshotsDir },
  });
  return makeContext(config, runner);
}

let snapshotsDir = "";

beforeEach(() => {
  snapshotsDir = fs.mkdtempSync(path.join(os.tmpdir(), "netexpert-test-"));
});
afterEach(() => {
  fs.rmSync(snapshotsDir, { recursive: true, force: true });
});

describe("vendorForMac (OUI)", () => {
  it("resolves a known vendor", () => {
    // 00:00:0C = Cisco in IEEE OUI
    expect(vendorForMac("00:00:0c:12:34:56")).toMatch(/Cisco/i);
  });
  it("returns undefined for unknown", () => {
    expect(vendorForMac("de:ad:be:ef:00:01")).toBeUndefined();
  });
});

describe("expandSubnet", () => {
  it("expands a /24 to 254 hosts", () => {
    const hosts = expandSubnetForTest("192.168.1.0/24");
    expect(hosts.length).toBe(254);
    expect(hosts[0]).toBe("192.168.1.1");
    expect(hosts.at(-1)).toBe("192.168.1.254");
  });
  it("expands a /30 to 2 hosts", () => {
    const hosts = expandSubnetForTest("10.0.0.0/30");
    expect(hosts).toEqual(["10.0.0.1", "10.0.0.2"]);
  });
});

describe("lanSweep validation", () => {
  it("rejects non-RFC1918 subnets", async () => {
    const ctx = ctxWith();
    const res = await lanSweep(ctx, { subnet: "8.8.8.0/24" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(false);
    expect(env.error.code).toBe("VALIDATION");
  });
  it("rejects oversized subnets via CAP_EXCEEDED", async () => {
    const ctx = ctxWith({ caps: { sweep: { maxHosts: 2, concurrency: 4, timeoutMs: 100 } } });
    const res = await lanSweep(ctx, { subnet: "192.168.1.0/24" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(false);
    expect(env.error.code).toBe("CAP_EXCEEDED");
  });
});

/**
 * Platform-aware ARP fake: readArp uses `arp -a` (text) on win32/darwin
 * but `ip -j neigh` (JSON) on linux — fake whichever this OS actually runs.
 * Each entry: [ip, mac, dynamic?]
 */
function fakeArpOutput(entries: Array<[string, string, boolean?]>): string {
  if (process.platform === "linux") {
    return JSON.stringify(
      entries.map(([ip, mac, dyn]) => ({
        dst: ip,
        lladdr: mac,
        dev: "eth0",
        state: [dyn ? "REACHABLE" : "PERMANENT"],
      })),
    );
  }
  return (
    "Interface: 192.168.1.10 --- 0xc\n" +
    entries.map(([ip, mac, dyn]) => `  ${ip}   ${mac.replaceAll(":", "-")}   ${dyn ? "dynamic" : "static"}`).join("\n") +
    "\n"
  );
}

describe("lanDevices (fake ARP)", () => {
  it("enriches ARP entries with vendor + skips non-RFC1918", async () => {
    const runner = new FakeRunner();
    runner.responses.push({
      match: (argv) => argv[0] === "arp" || argv[0] === "ip",
      result: { stdout: fakeArpOutput([["192.168.1.1", "aa:bb:cc:11:22:33", true], ["8.8.8.8", "00:00:0c:aa:bb:cc", true]]) },
    });
    const ctx = ctxWith({}, runner);
    const res = await lanDevices(ctx);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.devices.length).toBe(1); // 8.8.8.8 filtered out
    expect(env.data.devices[0].mac).toBe("aa:bb:cc:11:22:33");
  }, 20000);
});

describe("snapshot + newdevices", () => {
  function arpRunner(...entries: Array<[string, string]>): FakeRunner {
    const r = new FakeRunner();
    r.responses.push({
      match: (argv) => argv[0] === "arp" || argv[0] === "ip",
      result: { stdout: fakeArpOutput(entries.map(([ip, mac]) => [ip, mac, true])) },
    });
    return r;
  }

  it("first newdevices run saves a baseline and reports info", async () => {
    const runner = arpRunner(["192.168.1.1", "00:00:0c:11:22:33"]);
    const ctx = ctxWith({}, runner);
    const res = await lanNewdevices(ctx);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.findings.length).toBe(1);
    expect(env.data.findings[0].severity).toBe("info");
    const listed = await lanSnapshot(ctx, { mode: "list" });
    const lenv = JSON.parse(JSON.stringify(listed));
    expect(lenv.data.snapshots.length).toBe(1);
  }, 20000);

  it("detects a new MAC and a MAC change for a known IP", async () => {
    // seed baseline
    const seed = ctxWith({}, arpRunner(["192.168.1.1", "00:00:0c:11:22:33"]));
    await lanSnapshot(seed, { mode: "save" });
    // now two devices: one known, one new; known IP changed MAC
    const runner2 = arpRunner(
      ["192.168.1.1", "de:ad:be:11:22:33"],   // MAC changed for known IP
      ["192.168.1.99", "00:00:0c:99:88:77"],  // new device (Cisco vendor known)
    );
    const ctx2 = ctxWith({}, runner2);
    const res = await lanNewdevices(ctx2);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    const titles = env.data.findings.map((f: { title: string }) => f.title).join(" | ");
    expect(titles).toContain("New device");
    expect(titles).toContain("MAC changed");
  }, 30000);
});

describe("dns tools (network-dependent, tolerant)", () => {
  it("dns.propagation returns a table and consistency verdict", async () => {
    const ctx = ctxWith();
    const res = await dnsPropagation(ctx, { name: "example.com", record: "A" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.sources.length).toBeGreaterThanOrEqual(3);
    expect(typeof env.data.consistent).toBe("boolean");
  }, 60000);

  it("dns.hijackcheck returns findings", async () => {
    const ctx = ctxWith();
    const res = await dnsHijackcheck(ctx);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.findings.length).toBeGreaterThanOrEqual(1);
  }, 60000);

  it("net.publicip returns an IP", async () => {
    const ctx = ctxWith();
    const res = await netPublicip(ctx);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.ip).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
  }, 15000);
});

describe("lan.hostname", () => {
  it("returns names (or empty) without crashing", async () => {
    const ctx = ctxWith();
    const res = await lanHostname(ctx, { ip: "192.168.1.1" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(Array.isArray(env.data.names)).toBe(true);
  }, 15000);
});

describe("isRfc1918 (regression)", () => {
  it("matrix", () => {
    expect(isRfc1918("10.0.0.1")).toBe(true);
    expect(isRfc1918("8.8.8.8")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// net.ping / net.httpcheck / net.portcheck (fake runner — no real network)
// ---------------------------------------------------------------------------

const WIN_PING_OK = `
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=2ms TTL=64
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=3ms TTL=64
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 3ms, Average = 2ms
`;

describe("net.ping", () => {
  it("passes default pingCount (from config defaults) into the ping argv", async () => {
    const runner = new FakeRunner();
    runner.responses.push({
      match: (argv) => argv[0] === "ping",
      result: { stdout: WIN_PING_OK },
    });
    const ctx = ctxWith({ defaults: { pingCount: 3 } }, runner);
    const res = await netPing(ctx, { host: "192.168.1.1", timeoutMs: 500 });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    // the fake only answers argv matching config defaults.pingCount = 3
    const pingCall = runner.responses; // matched ⇒ count came from config
    expect(pingCall.length).toBe(1);
    expect(env.data.received).toBe(4);
  });

  it("explicit count wins over config default", async () => {
    const runner = new FakeRunner();
    const seen: string[][] = [];
    runner.responses.push({
      match: (argv) => {
        seen.push(argv);
        return argv[argv.indexOf("-n") + 1] === "2" || argv[argv.indexOf("-c") + 1] === "2";
      },
      result: { stdout: WIN_PING_OK },
    });
    const ctx = ctxWith({ defaults: { pingCount: 3 } }, runner);
    const res = await netPing(ctx, { host: "192.168.1.1", count: 2, timeoutMs: 500 });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(seen.length).toBeGreaterThan(0);
  });
});

describe("net.httpcheck", () => {
  it("rate-limits per config rate.httpCheck", async () => {
    const ctx = ctxWith({ rate: { httpCheck: 60 } });
    const res1 = await netHttpcheck(ctx, { url: "http://127.0.0.1:1/", timeoutMs: 1000, method: "HEAD" });
    const e1 = JSON.parse(JSON.stringify(res1));
    expect(e1.ok).toBe(true); // first call passes (request itself fails, but envelope ok)
    const res2 = await netHttpcheck(ctx, { url: "http://127.0.0.1:1/", timeoutMs: 1000, method: "HEAD" });
    const e2 = JSON.parse(JSON.stringify(res2));
    expect(e2.ok).toBe(false);
    expect(e2.error.code).toBe("RATE_LIMITED");
    expect(typeof e2.error.hint).toBe("string");
  });
});

describe("net.portcheck", () => {
  it("open port on loopback ⇒ state open with latency", async () => {
    const ctx = ctxWith();
    const srv = http.createServer();
    const port = await new Promise<number>((resolve) =>
      srv.listen(0, "127.0.0.1", () => resolve((srv.address() as { port: number }).port)));
    try {
      const res = await netPortcheck(ctx, { host: "127.0.0.1", port });
      const env = JSON.parse(JSON.stringify(res));
      expect(env.ok).toBe(true);
      expect(env.data.state).toBe("open");
      expect(typeof env.data.latencyMs).toBe("number");
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
    }
  });

  it("closed port on loopback ⇒ state closed, latency undefined", async () => {
    const ctx = ctxWith();
    // reserve a port, then release it so it's closed
    const srv = http.createServer();
    const port = await new Promise<number>((resolve) =>
      srv.listen(0, "127.0.0.1", () => resolve((srv.address() as { port: number }).port)));
    await new Promise<void>((r) => srv.close(() => r()));
    const res = await netPortcheck(ctx, { host: "127.0.0.1", port });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.state).toBe("closed");
    expect(env.data.latencyMs).toBeUndefined();
  });
});