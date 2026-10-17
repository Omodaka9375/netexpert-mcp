import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NetexpertConfig } from "../src/config.js";
import { makeContext } from "../src/services/util.js";
import type { CommandRunner, RunResult } from "../src/exec/executor.js";
import { parseNetshWlanInterfaces, parseIwLink, rssiToQuality } from "../src/services/wifiService.js";
import { secFirewall, secExposure } from "../src/services/secService.js";

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

let snapshotsDir = "";

beforeEach(() => {
  snapshotsDir = fs.mkdtempSync(path.join(os.tmpdir(), "netexpert-m3-"));
});
afterEach(() => {
  fs.rmSync(snapshotsDir, { recursive: true, force: true });
});

function ctxWith(runner: CommandRunner = new FakeRunner()) {
  const config = NetexpertConfig.parse({ paths: { snapshotsDir } });
  return makeContext(config, runner);
}

describe("parseNetshWlanInterfaces", () => {
  const NETSH = `There are 2 interfaces on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Homelab-5G
    BSSID                  : aa:bb:cc:11:22:33
    Radio type             : 802.11ax
    Authentication         : WPA3-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Channel                : 44
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 866.7
    Signal                 : 72%`;

  it("parses link fields", () => {
    const link = parseNetshWlanInterfaces(NETSH);
    expect(link).not.toBeNull();
    expect(link?.ssid).toBe("Homelab-5G");
    expect(link?.bssid).toBe("aa:bb:cc:11:22:33");
    expect(link?.channel).toBe(44);
    expect(link?.band).toBe("5");
    expect(link?.phyRateMbps).toBe(866.7);
    expect(link?.rssiDbm).toBeDefined();
    expect(link?.quality).toBeGreaterThan(0);
  });

  it("returns null when disconnected", () => {
    const link = parseNetshWlanInterfaces("There is 1 interface on the system:\n\n    Name : Wi-Fi\n    State : disconnected");
    expect(link).toBeNull();
  });
});

describe("parseIwLink", () => {
  it("parses SSID and RSSI", () => {
    const link = parseIwLink("Connected to aa:bb:cc:11:22:33 (on wlan0)\n\tSSID: Homelab\n\tfreq: 2437\n\tsignal: -61.00 dBm\n\ttx bitrate: 72.2 MBit/s");
    expect(link?.ssid).toBe("Homelab");
    expect(link?.rssiDbm).toBe(-61);
  });
});

describe("rssiToQuality", () => {
  it("maps bands sanely", () => {
    expect(rssiToQuality(-40)).toBe(100);
    expect(rssiToQuality(-90)).toBe(0);
    expect(rssiToQuality(-65)).toBe(50);
  });
});

describe("secFirewall (win32 fake)", () => {
  it("parses profile JSON", async () => {
    const runner = new FakeRunner();
    runner.responses.push({
      match: (argv) => argv[0] === "powershell.exe",
      result: { stdout: JSON.stringify([{ Name: "Domain", Enabled: true }, { Name: "Private", Enabled: true }, { Name: "Public", Enabled: false }]) },
    });
    const ctx = ctxWith(runner);
    const res = await secFirewall(ctx);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.enabled).toBe(false); // Public profile off ⇒ not all enabled
    expect(env.data.profiles.length).toBe(3);
  });
});

describe("secExposure", () => {
  it("flags risky exposed ports and firewall off (faked firewall)", async () => {
    const runner = new FakeRunner();
    runner.responses.push({
      match: (argv) => argv[0] === "powershell.exe",
      result: { stdout: JSON.stringify([{ Name: "Public", Enabled: false }]) },
    });
    const ctx = ctxWith(runner);
    const res = await secExposure(ctx);
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    const highTitles = env.data.findings.filter((f: { severity: string }) => f.severity === "high").map((f: { title: string }) => f.title);
    expect(highTitles.some((t: string) => t.includes("firewall"))).toBe(true);
    // On a real dev machine, some risky port may or may not be exposed — the high finding set should be non-empty either way from the firewall
    expect(env.data.findings.length).toBeGreaterThan(0);
  }, 30000);
});