import { z } from "zod";
import fs from "node:fs";
import path from "node:path";
import type { ServiceContext, Envelope } from "./util.js";
import { okEnvelope, failEnvelope } from "./util.js";
import { isRfc1918 } from "../safety/caps.js";
import type { PortHit } from "../services/coreService.js";

// ---------------------------------------------------------------------------
// M5: optional nmap adapter. Capability-detected, never a hard dep, opt-in
// via config `nmap.enabled` (SPEC §8: "deep scan only when explicitly enabled").
// ---------------------------------------------------------------------------

/**
 * Windows PATH staleness: a freshly installed nmap updates the registry PATH,
 * but processes started before the install (including this server's parent)
 * never see it. Probe the default install locations as a fallback.
 */
const NMAP_FALLBACK_PATHS =
  process.platform === "win32"
    ? [
        path.join(process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)", "Nmap", "nmap.exe"),
        path.join(process.env["ProgramFiles"] ?? "C:\\Program Files", "Nmap", "nmap.exe"),
      ]
    : [];

function resolveNmapBinary(): string {
  for (const p of NMAP_FALLBACK_PATHS) {
    try {
      if (fs.existsSync(p)) return p;
    } catch { /* not readable — try next */ }
  }
  return "nmap"; // PATH resolution
}

/** Cached capability probe: version check via the resolved binary. */
let nmapAvailable: { available: boolean; binary: string } | null = null;

export async function detectNmap(ctx: ServiceContext): Promise<boolean> {
  if (nmapAvailable !== null) return nmapAvailable.available;
  const binary = resolveNmapBinary();
  try {
    const res = await ctx.runner.run(binary, ["--version"], { timeoutMs: 8000 });
    const ok = res.code === 0 && /nmap version/i.test(res.stdout);
    nmapAvailable = { available: ok, binary };
  } catch {
    nmapAvailable = { available: false, binary };
  }
  return nmapAvailable.available;
}

/** The resolved binary path (for net.health backend reporting). */
export function nmapBinary(): string | undefined {
  return nmapAvailable?.binary !== "nmap" ? nmapAvailable?.binary : undefined;
}

/** Reset cache (tests). */
export function resetNmapDetection(): void {
  nmapAvailable = null;
}

export const DeepscanInput = z.object({
  host: z.string().min(1).max(253).regex(/^[a-zA-Z0-9._-]+$/, "invalid hostname"),
  ports: z.string().regex(/^(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?)*$/, "port spec like '22,80,443' or '1-1024'").optional(),
  topPorts: z.number().int().min(1).max(1000).optional(),
});

/**
 * Parse nmap grepable output (-oG -):
 *   Host: 192.168.1.1 (router.local)  Status: Up
 *   Host: 192.168.1.1 (router.local)  Ports: 22/open/tcp//ssh//OpenSSH/, 80/open/tcp//http///
 */
export function parseNmapGreppable(out: string): { hosts: Array<{ ip: string; hostname?: string; ports: PortHit[] }>; warnings: string[] } {
  const hosts: Array<{ ip: string; hostname?: string; ports: PortHit[] }> = [];
  const warnings: string[] = [];
  let current: { ip: string; hostname?: string; ports: PortHit[] } | null = null;
  for (const line of out.split(/\r?\n/)) {
    const hostMatch = line.match(/^Host:\s+(\S+)(?:\s+\(([^)]*)\))?\s+(?:Status:|Ports:)\s*(.*)$/);
    if (!hostMatch?.[1]) {
      if (line.trim() !== "" && !line.startsWith("#")) warnings.push(`unparsed line: ${line.trim().slice(0, 80)}`);
      continue;
    }
    if (!current || current.ip !== hostMatch[1]) {
      current = { ip: hostMatch[1], hostname: hostMatch[2] || undefined, ports: [] };
      hosts.push(current);
    }
    if (hostMatch[2] && !current.hostname) current.hostname = hostMatch[2];
    const portsPart = hostMatch[3] ?? "";
    for (const tok of portsPart.split(", ")) {
      // <port>/<state>/<proto>|<owner>|<service>|<version> (fields separated by /)
      const m = tok.match(/^(\d{1,5})\/(open|closed|filtered)\/(\w+)\/([^/]*)\/([^/]*)\/(.*)$/);
      if (!m) continue;
      current.ports.push({
        port: Number.parseInt(m[1] ?? "0", 10),
        state: m[2] as "open" | "closed" | "filtered",
        banner: [m[5], m[6]].filter((s) => s && s.trim() !== "").join(" ") || undefined,
      });
    }
  }
  return { hosts, warnings };
}

export async function netDeepscan(ctx: ServiceContext, input: z.infer<typeof DeepscanInput>): Promise<Envelope<object>> {
  const start = Date.now();
  // gate 1: config opt-in
  if (!ctx.config.nmap.enabled) {
    return failEnvelope(ctx, "net.deepscan", {
      code: "VALIDATION",
      message: "nmap deep scan is disabled in config",
      hint: 'set "nmap": { "enabled": true } in ~/.netexpert-mcp/config.json — deep scans are opt-in by design',
    });
  }
  // gate 2: rate limit (same bucket as portscan — bounded probes, SPEC §6)
  const retry = ctx.caps.rate.check("portscan");
  if (retry !== undefined) {
    return failEnvelope(ctx, "net.deepscan", { code: "RATE_LIMITED", message: "deepscan shares the portscan rate limit", hint: `retry in ${retry}ms` });
  }
  // gate 3: binary present
  if (!(await detectNmap(ctx))) {
    return failEnvelope(ctx, "net.deepscan", {
      code: "BACKEND_MISSING",
      message: "nmap binary not found on PATH",
      hint: process.platform === "win32" ? "winget install Insecure.Nmap (then restart the terminal so PATH refreshes)" : "sudo apt install nmap",
    });
  }
  // gate 4: LAN targets only (deep scans are a LAN concern; public hosts use net.portscan)
  const hostIsIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(input.host);
  if (hostIsIp && !isRfc1918(input.host)) {
    return failEnvelope(ctx, "net.deepscan", {
      code: "VALIDATION",
      message: "deepscan targets must be RFC1918 hosts",
      hint: "for public targets use net.portscan (bounded connect scan)",
    });
  }
  // build argv: arg-array only, never a shell string (SPEC §3.5)
  const binary = nmapAvailable?.binary ?? "nmap";
  const argv = ["-Pn", "-sT", "-T4", "--max-retries", "2", "-oG", "-"];
  if (input.ports) argv.push("-p", input.ports);
  else if (input.topPorts) argv.push("--top-ports", String(input.topPorts));
  else argv.push("--top-ports", "100");
  argv.push(input.host);
  try {
    const res = await ctx.runner.run(binary, argv, { timeoutMs: 120000 });
    if (res.code !== 0 && res.stdout.trim() === "") {
      return failEnvelope(ctx, "net.deepscan", { code: "EXEC_FAILED", message: `nmap exited ${res.code}: ${res.stderr.trim().slice(0, 200)}`, hint: "check nmap permissions (some scans need admin)" });
    }
    const parsed = parseNmapGreppable(res.stdout);
    return okEnvelope(ctx, "net.deepscan", {
      command: [binary, ...argv].join(" "),
      hosts: parsed.hosts,
    }, { backend: `binary:${binary === "nmap" ? "nmap" : "nmap (install-dir)"}`, durationMs: Date.now() - start, warnings: parsed.warnings });
  } catch (e) {
    return failEnvelope(ctx, "net.deepscan", { code: "EXEC_FAILED", message: `nmap execution failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

export const nmapToolSchemas = { DeepscanInput };