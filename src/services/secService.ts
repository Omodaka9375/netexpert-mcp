import si from "systeminformation";
import { z } from "zod";
import type { ServiceContext, Envelope } from "./util.js";
import { okEnvelope, failEnvelope } from "./util.js";
import type { Finding } from "./lanService.js";

export interface Socket {
  proto: "tcp" | "udp";
  local: string;
  remote?: string;
  state?: string;
  pid?: number;
  process?: string;
  risk?: string;
}

// ---------------------------------------------------------------------------
// sec.connections / sec.listening (L2 systeminformation → L3 fallback)
// ---------------------------------------------------------------------------

export async function secConnections(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  try {
    const conns = await si.networkConnections();
    const sockets: Socket[] = conns
      .filter((c) => c.protocol === "tcp" || c.protocol === "udp")
      .map((c) => ({
        proto: c.protocol as "tcp" | "udp",
        local: `${c.localAddress ?? "*"}:${c.localPort || "?"}`,
        remote: c.peerAddress && c.peerAddress !== "-" && c.peerAddress !== "Address" && c.peerPort && c.peerPort !== "0" ? `${c.peerAddress}:${c.peerPort}` : undefined,
        state: c.state || undefined,
        pid: c.pid && c.pid !== 0 ? c.pid : undefined,
        process: c.process || undefined,
      }));
    return okEnvelope(ctx, "sec.connections", { sockets }, { backend: "systeminformation.networkConnections", durationMs: Date.now() - start });
  } catch (e) {
    return failEnvelope(ctx, "sec.connections", { code: "EXEC_FAILED", message: `connection enumeration failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

const LISTEN_RE = /^(0\.0\.0\.0|\*|::|\[::\])/;

export async function secListening(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  try {
    const conns = await si.networkConnections();
    const listeners = conns
      .filter((c) => c.state === "LISTEN" || (c.state === "" && c.protocol === "udp"))
      .map((c) => {
        const exposed = LISTEN_RE.test(c.localAddress ?? "*");
        const port = Number.parseInt(c.localPort || "0", 10);
        return {
          proto: c.protocol as "tcp" | "udp",
          port,
          localAddress: c.localAddress ?? "*",
          exposed, // true = non-loopback (0.0.0.0/::/*)
          pid: c.pid && c.pid !== 0 ? c.pid : undefined,
          process: c.process || undefined,
          risk: undefined as string | undefined,
        };
      })
      .filter((l) => l.port > 0);
    const exposedCount = listeners.filter((l) => l.exposed).length;
    return okEnvelope(ctx, "sec.listening", { listeners, exposedCount }, {
      backend: "systeminformation.networkConnections",
      durationMs: Date.now() - start,
      warnings: exposedCount > 0 ? [`${exposedCount} listeners bound on all interfaces (0.0.0.0/::)`] : undefined,
    });
  } catch (e) {
    return failEnvelope(ctx, "sec.listening", { code: "EXEC_FAILED", message: `listening enumeration failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

// ---------------------------------------------------------------------------
// sec.firewall (L3, per-platform)
// ---------------------------------------------------------------------------

export interface FirewallProfile {
  platform: NodeJS.Platform;
  enabled: boolean | null;
  profiles?: Array<{ name: string; enabled: boolean }>;
  detail?: string;
}

export async function secFirewall(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const platform = process.platform;
  try {
    if (platform === "win32") {
      const res = await ctx.runner.run(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"],
        { timeoutMs: 15000 },
      );
      let profiles: Array<{ Name?: string; Enabled?: boolean }> = [];
      try {
        const parsed = JSON.parse(res.stdout);
        profiles = Array.isArray(parsed) ? parsed : [parsed];
      } catch { /* fall through to null */ }
      const norm = profiles
        .filter((p) => typeof p.Name === "string")
        .map((p) => ({ name: String(p.Name), enabled: p.Enabled === true }));
      return okEnvelope(ctx, "sec.firewall", {
        platform, enabled: norm.length > 0 && norm.every((p) => p.enabled),
        profiles: norm,
      }, { backend: "cmd:powershell Get-NetFirewallProfile", durationMs: Date.now() - start });
    }
    if (platform === "linux") {
      // ufw, then nftables presence
      try {
        const res = await ctx.runner.run("ufw", ["status"], { timeoutMs: 10000 });
        const enabled = /status:\s*active/i.test(res.stdout);
        return okEnvelope(ctx, "sec.firewall", { platform, enabled, detail: res.stdout.trim() }, { backend: "cmd:ufw status", durationMs: Date.now() - start });
      } catch {
        const res = await ctx.runner.run("nft", ["list", "ruleset"], { timeoutMs: 10000 }).catch(() => null);
        return okEnvelope(ctx, "sec.firewall", {
          platform, enabled: null,
          detail: res ? "nftables ruleset present (state unknown without policy analysis)" : "no ufw/nft backend found",
        }, { backend: "cmd:nft list ruleset", durationMs: Date.now() - start, warnings: ["firewall state not determinable — install ufw or check nftables manually"] });
      }
    }
    // darwin
    const res = await ctx.runner.run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], { timeoutMs: 10000 });
    const enabled = /enabled/i.test(res.stdout) && !/disabled/i.test(res.stdout);
    return okEnvelope(ctx, "sec.firewall", { platform, enabled, detail: res.stdout.trim() }, { backend: "cmd:socketfilterfw --getglobalstate", durationMs: Date.now() - start });
  } catch (e) {
    return failEnvelope(ctx, "sec.firewall", {
      code: "BACKEND_MISSING",
      message: `firewall state query failed: ${e instanceof Error ? e.message : "unknown"}`,
      hint: platform === "linux" ? "sudo apt install ufw" : undefined,
    });
  }
}

// ---------------------------------------------------------------------------
// sec.exposure — composite report (headline tool)
// ---------------------------------------------------------------------------

const RISKY_PORTS: Record<number, string> = {
  23: "Telnet — cleartext remote shell",
  135: "MSRPC endpoint mapper — LAN-reachable RPC",
  139: "NetBIOS session — legacy SMB",
  445: "SMB — wormable (WannaCry class) if exposed beyond LAN",
  3389: "RDP — brute-force magnet if exposed",
  5357: "WSDAPI — UPnP device host",
  5900: "VNC — often weakly authenticated",
};

export async function secExposure(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const findings: Finding[] = [];

  const [listenEnv, fwEnv] = await Promise.all([secListening(ctx), secFirewall(ctx)]);
  if (!listenEnv.ok || !listenEnv.data) {
    return failEnvelope(ctx, "sec.exposure", { code: "EXEC_FAILED", message: "cannot enumerate listeners", hint: "run sec.listening for details" });
  }
  const listeners = (listenEnv.data as { listeners: Array<{ proto: string; port: number; exposed: boolean; process?: string; pid?: number }> }).listeners;
  const exposed = listeners.filter((l) => l.exposed);

  const fwEnabled = fwEnv.ok && fwEnv.data ? (fwEnv.data as FirewallProfile).enabled : null;

  if (fwEnabled === false) {
    findings.push({
      severity: "high",
      title: "Host firewall is OFF",
      evidence: (fwEnv.data as FirewallProfile).detail ?? "firewall profiles report disabled",
      nextStep: "enable the firewall now (Windows Security → Firewall; `sudo ufw enable` on linux), then re-run sec.exposure",
    });
  }

  const risky = exposed.filter((l) => l.port in RISKY_PORTS);
  for (const l of risky) {
    findings.push({
      severity: l.port === 445 || l.port === 3389 || l.port === 23 ? "high" : "med",
      title: `Risky port ${l.port} exposed on all interfaces`,
      evidence: `${RISKY_PORTS[l.port] ?? "risky service"} — process ${l.process ?? "?"} (pid ${l.pid ?? "?"}) listening on 0.0.0.0:${l.port}${fwEnabled === false ? " AND firewall is off" : ""}`,
      nextStep: l.port === 3389 || l.port === 23
        ? "bind to loopback or restrict via firewall rule; if remote access is required, tunnel over VPN/SSH"
        : "verify the service must be LAN-wide; otherwise bind to 127.0.0.1 or add a firewall allow-rule",
    });
  }

  const otherExposed = exposed.filter((l) => !(l.port in RISKY_PORTS));
  if (otherExposed.length > 0) {
    findings.push({
      severity: "info",
      title: `${otherExposed.length} other non-loopback listeners`,
      evidence: otherExposed.map((l) => `${l.process ?? "?"}:${l.port}`).join(", "),
      nextStep: "cross-check unexpected entries with sec.connections; known-good services (NAS, dev servers) can be ignored",
    });
  }

  if (findings.length === 0) {
    findings.push({ severity: "info", title: "No exposure findings", evidence: `no non-loopback risky listeners; firewall=${fwEnabled === null ? "unknown" : fwEnabled ? "on" : "off"}`, nextStep: "none — posture looks clean" });
  }

  return okEnvelope(ctx, "sec.exposure", {
    firewallEnabled: fwEnabled,
    exposedCount: exposed.length,
    riskyCount: risky.length,
    findings,
  }, { backend: "computed (systeminformation + firewall state)", durationMs: Date.now() - start });
}


// ---------------------------------------------------------------------------
// M4: sec.speedtest — bounded ranged download (Cloudflare default, configurable)
// ---------------------------------------------------------------------------

import type { NetexpertConfigT } from "../config.js";

const SPEEDTEST_URL = "https://speed.cloudflare.com/__down?bytes=";

export async function secSpeedtest(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const retry = ctx.caps.rate.check("speedtest");
  if (retry !== undefined) {
    return failEnvelope(ctx, "sec.speedtest", { code: "RATE_LIMITED", message: "speedtest rate limit hit (1/min)", hint: `retry in ${retry}ms` });
  }
  const caps: NetexpertConfigT["caps"]["speedtest"] = ctx.config.caps.speedtest;
  let received = 0;
  let elapsedMs = 0;
  let aborted = false;
  try {
    const bytes = caps.downloadBytes;
    const res = await fetch(`${SPEEDTEST_URL}${bytes}`, {
      headers: { "user-agent": ctx.config.ua },
      signal: AbortSignal.timeout(caps.timeoutMs),
    });
    if (!res.ok) {
      return failEnvelope(ctx, "sec.speedtest", { code: "EXEC_FAILED", message: `speed endpoint returned ${res.status}`, hint: "check internet connectivity" });
    }
    const t0 = Date.now();
    const reader = res.body?.getReader();
    if (reader) {
      try {
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) break;
          received += chunk.value?.byteLength ?? 0;
          elapsedMs = Date.now() - t0; // update on every chunk so aborts still yield elapsed
        }
      } catch {
        aborted = true;
        elapsedMs = Date.now() - t0;
      }
    }
    if (elapsedMs === 0) elapsedMs = Date.now() - t0;
  } catch {
    // fetch-level failure (headers/connect): if we streamed nothing, fail below
    aborted = true;
  }
  if (received > 0 && elapsedMs > 0) {
    const mbps = (received * 8) / (elapsedMs / 1000) / 1_000_000;
    return okEnvelope(ctx, "sec.speedtest", {
      downloadMbps: Math.round(mbps * 100) / 100,
      bytes: received,
      elapsedMs,
      endpoint: "speed.cloudflare.com",
      complete: !aborted,
    }, { backend: "http:speed.cloudflare.com", durationMs: Date.now() - start, warnings: aborted ? [`transfer aborted at ${caps.timeoutMs}ms cap after ${received} bytes — throughput is a lower bound; lower caps.speedtest.downloadBytes or raise timeoutMs for slow links`] : undefined });
  }
  return failEnvelope(ctx, "sec.speedtest", { code: "TIMEOUT", message: `no data received within ${caps.timeoutMs}ms`, hint: "check internet connectivity or raise caps.speedtest.timeoutMs" });
}