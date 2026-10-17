import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NetexpertConfig } from "../src/config.js";
import { makeContext } from "../src/services/util.js";
import type { CommandRunner, RunResult } from "../src/exec/executor.js";
import { parseNmapGreppable, netDeepscan, detectNmap, resetNmapDetection } from "../src/services/nmapService.js";

const fx = (p: string): string =>
  fs.readFileSync(path.join(import.meta.dirname, "fixtures", p), "utf8");

class FakeRunner implements CommandRunner {
  responses: Array<{ match: (argv: string[]) => boolean; result: Partial<RunResult> }> = [];
  calls: string[][] = [];
  async run(cmd: string, args: string[]): Promise<RunResult> {
    const argv = [cmd, ...args];
    this.calls.push(argv);
    const hit = this.responses.find((r) => r.match(argv));
    if (!hit) throw new Error(`no fake for: ${argv.join(" ")}`);
    return {
      platform: process.platform,
      argv,
      stdout: hit.result.stdout ?? "",
      stderr: hit.result.stderr ?? "",
      code: hit.result.code ?? 0,
    };
  }
}

let snapshotsDir = "";

beforeEach(() => {
  snapshotsDir = fs.mkdtempSync(path.join(os.tmpdir(), "netexpert-m5-"));
  resetNmapDetection();
});
afterEach(() => {
  fs.rmSync(snapshotsDir, { recursive: true, force: true });
  resetNmapDetection();
});

function ctxWith(nmapEnabled: boolean, runner?: FakeRunner) {
  const r = runner ?? new FakeRunner();
  const config = NetexpertConfig.parse({
    paths: { snapshotsDir },
    ...(nmapEnabled ? { nmap: { enabled: true } } : {}),
  });
  return { ctx: makeContext(config, r), runner: r };
}

describe("parseNmapGreppable", () => {
  it("parses a real -oG fixture", () => {
    const { hosts, warnings } = parseNmapGreppable(fx("nmap/nmap-og.txt"));
    expect(hosts.length).toBe(1);
    const h = hosts[0];
    expect(h.ip).toBe("192.168.1.1");
    expect(h.hostname).toBe("router.lan");
    const open = h.ports.filter((p) => p.state === "open").map((p) => p.port);
    expect(open).toEqual([22, 53, 80]);
    const ssh = h.ports.find((p) => p.port === 22);
    expect(ssh?.banner).toContain("OpenSSH");
    const https = h.ports.find((p) => p.port === 443);
    expect(https?.state).toBe("filtered");
    expect(warnings.length).toBe(0); // comment lines ignored
  });

  it("is tolerant of garbage lines", () => {
    const { hosts, warnings } = parseNmapGreppable("Host: 10.0.0.1 (gw)\tStatus: Up\nrandom garbage line\n");
    expect(hosts.length).toBe(1);
    expect(warnings.length).toBe(1);
  });
});

describe("net.deepscan gates", () => {
  it("gate 1: rejects when nmap.enabled is false (default)", async () => {
    const { ctx } = ctxWith(false);
    const res = await netDeepscan(ctx, { host: "192.168.1.1" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(false);
    expect(env.error.code).toBe("VALIDATION");
    expect(env.error.hint).toContain("nmap");
  });  it("gate 2: BACKEND_MISSING when nmap binary is absent", async () => {
    const { ctx, runner } = ctxWith(true);
    runner.responses.push({
      match: (argv) => argv.includes("--version"),
      result: { code: 127, stdout: "", stderr: "not found" }, // spawn may also throw; both paths must work
    });
    const res = await netDeepscan(ctx, { host: "192.168.1.1" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(false);
    expect(env.error.code).toBe("BACKEND_MISSING");
    expect(env.error.hint).toContain("install");
  });
  it("gate 4: rejects non-RFC1918 IP targets", async () => {
    const { ctx, runner } = ctxWith(true);
    runner.responses.push({
      match: (argv) => argv.includes("--version"),
      result: { stdout: "Nmap version 7.95" },
    });
    const res = await netDeepscan(ctx, { host: "8.8.8.8" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(false);
    expect(env.error.code).toBe("VALIDATION");
    expect(env.error.hint).toContain("net.portscan");
  });

  it("full flow: detects nmap, scans, parses ports (fake binary)", async () => {
    const { ctx, runner } = ctxWith(true);
    runner.responses.push({
      match: (argv) => argv.includes("--version"),
      result: { stdout: "Nmap version 7.95 ( https://nmap.org )" },
    });
    runner.responses.push({
      match: (argv) => argv.includes("-oG"),
      result: { stdout: fx("nmap/nmap-og.txt") },
    });
    const res = await netDeepscan(ctx, { host: "192.168.1.1", ports: "22,53,80,443" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.backend).toContain("binary:nmap"); // "nmap" or "nmap (install-dir)" depending on host
    expect(env.data.hosts[0].ports.length).toBe(7);
    // argv hygiene: -p with our port spec, arg-array (no shell)
    const scanCall = runner.calls.find((c) => c.includes("-oG"));
    expect(scanCall).toBeDefined();
    expect(scanCall?.[scanCall.indexOf("-p") + 1]).toBe("22,53,80,443");
  });

  it("hostname targets are allowed (LAN names resolve to RFC1918 normally)", async () => {
    const { ctx, runner } = ctxWith(true);
    runner.responses.push({
      match: (argv) => argv.includes("--version"),
      result: { stdout: "Nmap version 7.95" },
    });
    runner.responses.push({
      match: (argv) => argv.includes("-oG"),
      result: { stdout: "Host: 192.168.1.1 (router)\tPorts: 80/open/tcp//http///\tStatus: Up" },
    });
    const res = await netDeepscan(ctx, { host: "router.lan" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
  });
});

describe("detectNmap caching", () => {
  it("caches the probe across calls", async () => {
    const { ctx, runner } = ctxWith(true);
    runner.responses.push({
      match: (argv) => argv.includes("--version"),
      result: { stdout: "Nmap version 7.95" },
    });
    expect(await detectNmap(ctx)).toBe(true);
    expect(await detectNmap(ctx)).toBe(true);
    expect(runner.calls.filter((c) => c.includes("--version")).length).toBe(1); // second call hit cache
  });
});