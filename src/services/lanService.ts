import fs from "node:fs";
import path from "node:path";
import dns from "node:dns";
import dgram from "node:dgram";

/** Bounded reverse-DNS: never hangs, returns undefined on timeout/failure. */
async function reverseBounded(ip: string, timeoutMs = 2000): Promise<string | undefined> {
  const resolver = new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 });
  try {
    const names = await resolver.reverse(ip);
    return names[0];
  } catch {
    return undefined;
  }
}
import si from "systeminformation";
import defaultGateway from "default-gateway";
import { z } from "zod";
import type { ServiceContext, Envelope } from "./util.js";
import { okEnvelope, failEnvelope } from "./util.js";
import { commandMapFor, backendTag } from "../exec/platform.js";
import { parseWindowsArp, parseLinuxNeigh, type Neighbor } from "../parse/parsers.js";
import { isRfc1918 } from "../safety/caps.js";
import oui from "../data/oui.json" with { type: "json" };

const OUI = oui as Record<string, string>;

export function vendorForMac(mac: string): string | undefined {
  const hex = mac.replaceAll(":", "").replaceAll("-", "").toUpperCase();
  return OUI[hex.slice(0, 6)];
}

// ---------------------------------------------------------------------------
// M1: interfaces / gateway / arp
// ---------------------------------------------------------------------------

export async function lanInterfaces(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const raw = await si.networkInterfaces();
  const nics = raw.map((n) => ({
    name: n.iface,
    mac: n.mac,
    ipv4: n.ip4 ? [n.ip4] : [],
    ipv6: n.ip6 ? [n.ip6] : [],
    type: n.type,
    virtual: n.virtual,
    default: false, // default detection via lan.gateway
  }));
  return okEnvelope(ctx, "lan.interfaces", { interfaces: nics }, { backend: "systeminformation", durationMs: Date.now() - start });
}

export async function lanGateway(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  try {
    const gw = await (defaultGateway as unknown as { v4: () => Promise<{ gateway: string; interface?: string }> }).v4();
    let subnet: string | undefined;
    try {
      const raw = await si.networkInterfaces();
      const match = raw.find((n) => n.iface === gw.interface && n.ip4);
      if (match?.ip4) {
        subnet = `${match.ip4.split(".").slice(0, 3).join(".")}.0/24`;
      }
    } catch { /* best-effort */ }
    return okEnvelope(ctx, "lan.gateway", { gateway: gw.gateway, interface: gw.interface, subnet }, { backend: "default-gateway+systeminformation", durationMs: Date.now() - start });
  } catch (e) {
    return failEnvelope(ctx, "lan.gateway", { code: "EXEC_FAILED", message: `default gateway detection failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

/** Shared: read the raw ARP cache (no filtering). */
async function readArp(ctx: ServiceContext): Promise<{ neighbors: Neighbor[]; backend: string }> {
  const platform = process.platform;
  const map = commandMapFor(platform);
  const spec = map.arp();
  const res = await ctx.runner.run(spec.argv[0] ?? "arp", spec.argv.slice(1), { timeoutMs: 10000 });
  const parsed = platform === "linux" ? parseLinuxNeigh(res.stdout) : parseWindowsArp(res.stdout);
  return { neighbors: parsed.neighbors, backend: backendTag(spec) };
}

export async function lanArp(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  try {
    const { neighbors: raw, backend } = await readArp(ctx);
    const neighbors = raw.filter((n) => n.type !== "failed" && n.type !== "incomplete");
    const warnings: string[] = [];
    if (neighbors.length < raw.length) {
      warnings.push(`${raw.length - neighbors.length} stale/incomplete entries excluded`);
    }
    return okEnvelope(ctx, "lan.arp", { neighbors }, { backend, durationMs: Date.now() - start, warnings });
  } catch (e) {
    return failEnvelope(ctx, "lan.arp", { code: "EXEC_FAILED", message: `ARP table read failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

// ---------------------------------------------------------------------------
// M2: sweep
// ---------------------------------------------------------------------------

export const SubnetInput = z.object({
  subnet: z
    .string()
    .regex(/^\d{1,3}(\.\d{1,3}){3}\/(24|25|26|27|28|29|30)$/, "must be an RFC1918 CIDR between /24 and /30")
    .optional(),
});

function expandSubnet(cidr: string): string[] {
  const [base, prefixStr] = cidr.split("/");
  const prefix = Number.parseInt(prefixStr ?? "24", 10);
  const baseParts = (base ?? "0.0.0.0").split(".").map((p) => Number.parseInt(p, 10));
  const baseNum = ((baseParts[0] ?? 0) << 24) | ((baseParts[1] ?? 0) << 16) | ((baseParts[2] ?? 0) << 8) | (baseParts[3] ?? 0);
  const hostBits = 32 - prefix;
  const size = 2 ** hostBits;
  const network = baseNum & (size === 2 ** 32 ? 0 : (~0 << hostBits) >>> 0);
  const hosts: string[] = [];
  for (let i = 1; i < size - 1; i++) {
    const n = (network + i) >>> 0;
    hosts.push(`${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`);
  }
  return hosts;
}

async function pingAlive(ctx: ServiceContext, host: string): Promise<boolean> {
  const map = commandMapFor(process.platform);
  const spec = map.ping({ count: 1, timeoutMs: ctx.config.caps.sweep.timeoutMs, host });
  try {
    const res = await ctx.runner.run(spec.argv[0] ?? "ping", spec.argv.slice(1), { timeoutMs: ctx.config.caps.sweep.timeoutMs + 1500 });
    // Host considered alive if any reply line or linux "1 received"
    return /ttl=|TTL=|1 received|1 packets? received/i.test(res.stdout);
  } catch {
    return false;
  }
}

export async function lanSweep(ctx: ServiceContext, input: z.infer<typeof SubnetInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const retry = ctx.caps.rate.check("sweep");
  if (retry !== undefined) {
    return failEnvelope(ctx, "lan.sweep", { code: "RATE_LIMITED", message: "sweep rate limit hit", hint: `retry in ${retry}ms` });
  }
  try {
    // Resolve target subnet: explicit, or local /24 derived from default iface
    let cidr = input.subnet;
    if (!cidr) {
      const gws = await (defaultGateway as unknown as { v4: () => Promise<{ gateway: string; interface?: string }> }).v4();
      const ifaces = await si.networkInterfaces();
      const me = ifaces.find((n) => n.iface === gws.interface && n.ip4);
      if (!me?.ip4) {
        throw new Error("cannot derive local subnet — pass subnet explicitly");
      }
      cidr = `${me.ip4.split(".").slice(0, 3).join(".")}.0/24`;
    }
    const [netBase] = cidr.split("/");
    if (!netBase || !isRfc1918(netBase.replace(/\.0$/, ".1"))) {
      return failEnvelope(ctx, "lan.sweep", { code: "VALIDATION", message: "sweep targets must be RFC1918 subnets", hint: "use e.g. 192.168.1.0/24" });
    }
    const hosts = expandSubnet(cidr);
    if (hosts.length > ctx.config.caps.sweep.maxHosts) {
      return failEnvelope(ctx, "lan.sweep", { code: "CAP_EXCEEDED", message: `subnet has ${hosts.length} hosts, cap is ${ctx.config.caps.sweep.maxHosts}`, hint: "narrow the CIDR (e.g. /26) or raise caps.sweep.maxHosts in config" });
    }
    const queue = [...hosts];
    const alive: string[] = [];
    const workers = Array.from({ length: Math.min(ctx.config.caps.sweep.concurrency, queue.length) }, async () => {
      for (;;) {
        const h = queue.shift();
        if (h === undefined) return;
        if (await pingAlive(ctx, h)) alive.push(h);
      }
    });
    await Promise.all(workers);
    alive.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    return okEnvelope(ctx, "lan.sweep", { subnet: cidr, probed: hosts.length, aliveCount: alive.length, alive }, { backend: "cmd:ping", durationMs: Date.now() - start });
  } catch (e) {
    return failEnvelope(ctx, "lan.sweep", { code: "EXEC_FAILED", message: `sweep failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

// ---------------------------------------------------------------------------
// M2: devices (inventory), hostname
// ---------------------------------------------------------------------------

export async function lanDevices(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  try {
    const { neighbors: arpNeighbors, backend } = await readArp(ctx);
    const live = arpNeighbors.filter((n) => isRfc1918(n.ip) && n.mac);
    const devices = await Promise.all(
      live.map(async (n) => {
        const vendor = n.mac !== undefined ? vendorForMac(n.mac) : undefined;
        const hostname = await reverseBounded(n.ip);
        return { ...n, vendor, hostname, firstSeen: undefined, lastSeen: new Date().toISOString() };
      }),
    );
    devices.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
    const unknownVendor = devices.filter((d) => !d.vendor).length;
    return okEnvelope(ctx, "lan.devices", { devices }, {
      backend,
      durationMs: Date.now() - start,
      warnings: unknownVendor > 0 ? [`${unknownVendor} devices have unknown vendor (no OUI match)`] : undefined,
    });
  } catch (e) {
    return failEnvelope(ctx, "lan.devices", { code: "EXEC_FAILED", message: `device inventory failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

const HostnameInput = z.object({ ip: z.string().ip() });

export async function lanHostname(ctx: ServiceContext, input: z.infer<typeof HostnameInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const names = new Set<string>();
  const backends: string[] = [];
  // PTR
  try {
    const ptr = await reverseBounded(input.ip, 4000);
    if (ptr) names.add(ptr);
    backends.push("PTR");
  } catch { /* no PTR */ }
  // NetBIOS (win32 only)
  if (process.platform === "win32") {
    try {
      const res = await ctx.runner.run("nbtstat", ["-A", input.ip], { timeoutMs: 5000 });
      for (const m of res.stdout.matchAll(/^\s*<20>\s+UNIQUE\s+([^\s]+)\s+/gim)) {
        if (m[1]) names.add(m[1]);
      }
      backends.push("nbtstat");
    } catch { /* nbtstat missing or host silent */ }
  }
  return okEnvelope(ctx, "lan.hostname", { ip: input.ip, names: [...names], backends }, { backend: backends.join("+") || "PTR", durationMs: Date.now() - start });
}

// ---------------------------------------------------------------------------
// M2: snapshots + new-device detection
// ---------------------------------------------------------------------------

interface SnapshotEntry {
  ip: string;
  mac?: string;
  vendor?: string;
  hostname?: string;
  seenAt: string;
}

function snapshotsDir(ctx: ServiceContext): string {
  return ctx.config.paths.snapshotsDir;
}

function snapshotFiles(ctx: ServiceContext): string[] {
  const dir = snapshotsDir(ctx);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => /^lan-devices-\d{4}-\d{2}-\d{2}T[\d:.]+Z\.json$/.test(f))
    .sort();
}

export const SnapshotInput = z.object({ mode: z.enum(["save", "list"]).default("list") });

export async function lanSnapshot(ctx: ServiceContext, input: z.infer<typeof SnapshotInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const dir = snapshotsDir(ctx);
  if (input.mode === "list") {
    const files = snapshotFiles(ctx);
    return okEnvelope(ctx, "lan.snapshot", { mode: "list", dir, snapshots: files }, { backend: "filestore", durationMs: Date.now() - start });
  }
  // save
  const devEnv = await lanDevices(ctx);
  if (!devEnv.ok || !devEnv.data) {
    return failEnvelope(ctx, "lan.snapshot", { code: "EXEC_FAILED", message: "cannot snapshot: device inventory failed" });
  }
  const devices = (devEnv.data as { devices: Array<Record<string, unknown>> }).devices ?? [];
  const entries: SnapshotEntry[] = devices.map((d) => ({
    ip: String(d["ip"] ?? ""),
    mac: d["mac"] !== undefined ? String(d["mac"]) : undefined,
    vendor: d["vendor"] !== undefined ? String(d["vendor"]) : undefined,
    hostname: d["hostname"] !== undefined ? String(d["hostname"]) : undefined,
    seenAt: String(d["lastSeen"] ?? new Date().toISOString()),
  }));
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replaceAll(":", ".");
  const file = path.join(dir, `lan-devices-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify({ savedAt: new Date().toISOString(), devices: entries }, null, 2));
  return okEnvelope(ctx, "lan.snapshot", { mode: "save", file, deviceCount: entries.length }, { backend: "filestore", durationMs: Date.now() - start });
}

export type Finding = { severity: "info" | "low" | "med" | "high"; title: string; evidence: string; nextStep: string };

function loadLatestSnapshot(ctx: ServiceContext): { savedAt: string; devices: SnapshotEntry[] } | null {
  const files = snapshotFiles(ctx);
  const last = files.at(-1);
  if (!last) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(snapshotsDir(ctx), last), "utf8"));
    if (typeof raw === "object" && raw !== null && Array.isArray((raw as { devices?: unknown }).devices)) {
      return raw as { savedAt: string; devices: SnapshotEntry[] };
    }
    return null;
  } catch {
    return null;
  }
}

export async function lanNewdevices(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const findings: Finding[] = [];
  const devEnv = await lanDevices(ctx);
  if (!devEnv.ok || !devEnv.data) {
    return failEnvelope(ctx, "lan.newdevices", { code: "EXEC_FAILED", message: "cannot diff: device inventory failed" });
  }
  const live = (devEnv.data as { devices: Array<Record<string, unknown>> }).devices ?? [];
  const liveByMac = new Map<string, Record<string, unknown>>();
  const liveByIp = new Map<string, Record<string, unknown>>();
  for (const d of live) {
    if (typeof d["mac"] === "string") liveByMac.set(d["mac"], d);
    if (typeof d["ip"] === "string") liveByIp.set(d["ip"], d);
  }
  const baseline = loadLatestSnapshot(ctx);
  if (!baseline) {
    // First run: save baseline automatically (SPEC)
    const save = await lanSnapshot(ctx, { mode: "save" });
    findings.push({ severity: "info", title: "No baseline snapshot existed — first baseline saved", evidence: `saved ${save.ok ? String((save.data as Record<string, unknown>)?.["deviceCount"] ?? "?") : "?"} devices`, nextStep: "run lan.newdevices again after your network sees normal traffic to diff against the baseline" });
    return okEnvelope(ctx, "lan.newdevices", { findings }, { backend: "arp+filestore", durationMs: Date.now() - start });
  }
  const knownMacs = new Set(baseline.devices.map((d) => d.mac).filter((m): m is string => m !== undefined));
  const knownByIp = new Map(baseline.devices.filter((d) => d.ip).map((d) => [d.ip as string, d]));

  for (const d of live) {
    const ip = String(d["ip"] ?? "");
    const mac = d["mac"] !== undefined ? String(d["mac"]) : undefined;
    const vendor = d["vendor"] !== undefined ? String(d["vendor"]) : undefined;
    if (mac && !knownMacs.has(mac)) {
      findings.push({
        severity: vendor ? "low" : "high",
        title: `New device on LAN: ${ip}${vendor ? ` (${vendor})` : " (unknown vendor)"}`,
        evidence: `MAC ${mac} not in baseline snapshot ${path.basename(snapshotFiles(ctx).at(-1) ?? "?")} (saved ${baseline.savedAt})`,
        nextStep: "run lan.hostname on the IP; if unrecognized, check the router client list or block the MAC",
      });
    }
    const prior = ip ? knownByIp.get(ip) : undefined;
    if (prior?.mac && mac && prior.mac !== mac) {
      findings.push({
        severity: "med",
        title: `MAC changed for known IP ${ip}`,
        evidence: `was ${prior.mac}${prior.vendor ? ` (${prior.vendor})` : ""}, now ${mac}${vendor ? ` (${vendor})` : ""}`,
        nextStep: "verify whether DHCP re-assigned this IP or a device was swapped; ARP flapping can indicate duplicate IPs",
      });
    }
  }
  return okEnvelope(ctx, "lan.newdevices", { baselineSavedAt: baseline.savedAt, liveDevices: live.length, findings }, { backend: "arp+filestore", durationMs: Date.now() - start });
}

// ---------------------------------------------------------------------------
// M4: lan.wol — magic packet via UDP broadcast (dry-run + confirmToken)
// ---------------------------------------------------------------------------

export const WolInput = z.object({
  mac: z.string().regex(/^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/, "must be a MAC address"),
  port: z.number().int().min(1).max(65535).default(9),
  confirmToken: z.string().optional(),
});

function magicPacket(mac: string): Buffer {
  const clean = mac.replaceAll(":", "").replaceAll("-", "");
  const buf = Buffer.alloc(6 + 16 * 6);
  for (let i = 0; i < 6; i++) buf[i] = 0xff;
  const bytes = Buffer.from(clean, "hex");
  for (let i = 0; i < 16; i++) bytes.copy(buf, 6 + i * 6);
  return buf;
}

export async function lanWol(ctx: ServiceContext, input: z.infer<typeof WolInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const params = { mac: input.mac.toLowerCase(), port: input.port };
  // dry-run: no token ⇒ plan
  if (!input.confirmToken) {
    const { planned, confirmToken } = ctx.confirm.plan(
      "lan.wol",
      `Send Wake-on-LAN magic packet to ${params.mac} via UDP broadcast :${params.port}`,
      params,
    );
    return {
      ok: true,
      tool: "lan.wol",
      platform: process.platform,
      data: { planned, confirmToken, note: "dry-run — re-call with confirmToken to execute" },
    };
  }
  const confirmed = ctx.confirm.confirm("lan.wol", params, input.confirmToken);
  if (!confirmed.ok) {
    return failEnvelope(ctx, "lan.wol", { code: "CONFIRMATION_REQUIRED", message: confirmed.reason, hint: "call lan.wol once without confirmToken to get a fresh plan" });
  }
  // execute: one UDP broadcast via node:dgram (SPEC: no shell, no raw sockets)
  try {
    const pkt = magicPacket(params.mac);
    await new Promise<void>((resolve, reject) => {
      const sock = dgram.createSocket("udp4");
      sock.on("error", (e) => { sock.close(); reject(e); });
      sock.bind(() => {
        sock.setBroadcast(true);
        sock.send(pkt, params.port, "255.255.255.255", (err) => {
          sock.close();
          if (err) reject(err);
          else resolve();
        });
      });
    });
    return okEnvelope(ctx, "lan.wol", { sent: true, mac: params.mac, port: params.port, bytes: 102 }, { backend: "node:dgram udp broadcast", durationMs: Date.now() - start });
  } catch (e) {
    return failEnvelope(ctx, "lan.wol", { code: "EXEC_FAILED", message: `magic packet send failed: ${e instanceof Error ? e.message : "unknown"}`, hint: "verify the target device has WoL enabled in BIOS/UEFI" });
  }
}

export const lanToolSchemas = { SubnetInput, HostnameInput, SnapshotInput, WolInput };


/** test-only export of subnet math */
export function expandSubnetForTest(cidr: string): string[] {
  return expandSubnet(cidr);
}