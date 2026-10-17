import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NetexpertConfig } from "../src/config.js";
import { makeContext } from "../src/services/util.js";
import type { CommandRunner, RunResult } from "../src/exec/executor.js";
import { lanSweep, lanDevices, lanSnapshot, lanNewdevices, lanHostname, vendorForMac } from "../src/services/lanService.js";
import { expandSubnetForTest } from "../src/services/lanService.js";
import { dnsPropagation, dnsHijackcheck } from "../src/services/dnsService.js";
import { netPublicip } from "../src/services/coreService.js";
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

describe("lanDevices (fake ARP)", () => {
  it("enriches ARP entries with vendor + skips non-RFC1918", async () => {
    const runner = new FakeRunner();
    runner.responses.push({
      match: (argv) => argv[0] === "arp",
      result: { stdout: "Interface: 192.168.1.10 --- 0xc\n  192.168.1.1   aa-bb-cc-11-22-33 dynamic\n  8.8.8.8       00-00-0c-aa-bb-cc dynamic\n" },
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
  function arpRunner(...lines: string[]): FakeRunner {
    const r = new FakeRunner();
    r.responses.push({
      match: (argv) => argv[0] === "arp",
      result: { stdout: "Interface: 192.168.1.10 --- 0xc\n" + lines.join("\n") + "\n" },
    });
    return r;
  }

  it("first newdevices run saves a baseline and reports info", async () => {
    const runner = arpRunner("  192.168.1.1   00-00-0c-11-22-33 dynamic");
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
    const seed = ctxWith({}, arpRunner("  192.168.1.1   00-00-0c-11-22-33 dynamic"));
    await lanSnapshot(seed, { mode: "save" });
    // now two devices: one known, one new; known IP changed MAC
    const runner2 = arpRunner(
      "  192.168.1.1   de-ad-be-11-22-33 dynamic",   // MAC changed for known IP
      "  192.168.1.99  00-00-0c-99-88-77 dynamic",   // new device (Cisco vendor known)
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
  }, 30000);

  it("dns.hijackcheck returns findings", async () => {
    const ctx = ctxWith();
    const res = await dnsHijackcheck(ctx);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.findings.length).toBeGreaterThanOrEqual(1);
  }, 30000);

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