import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import { z } from "zod";
import type { ServiceContext, Envelope } from "./util.js";
import { okEnvelope, failEnvelope, ToolError } from "./util.js";
import { commandMapFor, backendTag } from "../exec/platform.js";
import { parsePing, parseTraceroute } from "../parse/parsers.js";
import { detectNmap, nmapBinary } from "./nmapService.js";

export const VERSION = "0.1.0";

export async function netHealth(ctx: ServiceContext): Promise<Envelope<object>> {
  const map = commandMapFor(process.platform);
  const nmapPresent = await detectNmap(ctx);
  const backends: Record<string, { backend: string; available: boolean; enabled?: boolean; hint?: string }> = {
    arp: { backend: backendTag(map.arp()), available: true },
    routes: { backend: backendTag(map.routes()), available: true },
    ping: { backend: "cmd:ping (tcp-connect fallback)", available: true },
    trace: { backend: backendTag(map.trace({ maxHops: 20, timeoutMs: 1000, host: "placeholder" })), available: true },
    nmap: {
      backend: nmapPresent ? `binary:${nmapBinary() ?? "nmap (PATH)"}` : "binary",
      available: nmapPresent,
      enabled: ctx.config.nmap.enabled,
      hint: nmapPresent
        ? undefined
        : process.platform === "win32"
          ? "winget install Insecure.Nmap — then set nmap.enabled=true in config to unlock net.deepscan"
          : "sudo apt install nmap — then set nmap.enabled=true in config to unlock net.deepscan",
    },
  };
  return okEnvelope(ctx, "net.health", {
    version: VERSION,
    platform: process.platform,
    uptimeSec: Math.round(process.uptime()),
    config: { caps: ctx.config.caps, rate: ctx.config.rate },
    backends,
  }, { backend: "internal" });
}

const hostSchema = z.string().min(1).max(253).regex(/^[a-zA-Z0-9._-]+$/, "hostname has invalid characters");

const PingInput = z.object({ host: hostSchema, count: z.number().int().min(1).max(20).default(4), timeoutMs: z.number().int().min(100).max(10000).default(2000) });

export async function netPing(ctx: ServiceContext, input: z.infer<typeof PingInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const map = commandMapFor(process.platform);
  try {
    const spec = map.ping({ count: input.count, timeoutMs: input.timeoutMs, host: input.host });
    const res = await ctx.runner.run(spec.argv[0] ?? "ping", spec.argv.slice(1), { timeoutMs: input.timeoutMs * input.count + 5000 });
    const parsed = parsePing(res.stdout + "\n" + res.stderr);
    if (!parsed.stats) {
      throw new ToolError("EXEC_FAILED", `ping ${input.host} produced no parseable output`);
    }
    return okEnvelope(ctx, "net.ping", parsed.stats, { backend: backendTag(spec), durationMs: Date.now() - start, warnings: parsed.warnings });
  } catch (e) {
    // Fall back to TCP connect (honest backend label)
    const tcpStats = await tcpPing(input.host, input.count);
    if (tcpStats) {
      return okEnvelope(ctx, "net.ping", tcpStats, { backend: "tcp-connect", durationMs: Date.now() - start, warnings: [`icmp ping failed (${e instanceof Error ? e.message : "unknown"}); used TCP connect fallback`] });
    }
    return failEnvelope(ctx, "net.ping", { code: "EXEC_FAILED", message: `ping ${input.host} failed`, hint: `verify ${input.host} is reachable or a ping binary exists` });
  }
}

async function tcpPing(host: string, count: number): Promise<object | null> {
  const times: number[] = [];
  for (let i = 0; i < count; i++) {
    const t = await tcpConnectMs(host, 80);
    if (t !== undefined) times.push(t);
  }
  if (times.length === 0) return null;
  return {
    host, count, transmitted: count, received: times.length,
    lossPct: Math.round(((count - times.length) / count) * 1000) / 10,
    minMs: Math.min(...times), avgMs: times.reduce((a, b) => a + b, 0) / times.length, maxMs: Math.max(...times), times,
  };
}

export function tcpConnectMs(host: string, port: number, timeoutMs = 2000): Promise<number | undefined> {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => { sock.destroy(); resolve(Date.now() - start); });
    sock.once("timeout", () => { sock.destroy(); resolve(undefined); });
    sock.once("error", () => resolve(undefined));
    sock.connect(port, host);
  });
}

const TraceInput = z.object({ host: hostSchema, maxHops: z.number().int().min(1).max(30).default(20), timeoutMs: z.number().int().min(100).max(5000).default(1000) });

export async function netTrace(ctx: ServiceContext, input: z.infer<typeof TraceInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const map = commandMapFor(process.platform);
  try {
    const spec = map.trace({ maxHops: input.maxHops, timeoutMs: input.timeoutMs, host: input.host });
    const res = await ctx.runner.run(spec.argv[0] ?? "traceroute", spec.argv.slice(1), { timeoutMs: 30000 });
    const parsed = parseTraceroute(res.stdout);
    return okEnvelope(ctx, "net.trace", { hops: parsed.hops }, { backend: backendTag(spec), durationMs: Date.now() - start, warnings: parsed.warnings });
  } catch {
    return failEnvelope(ctx, "net.trace", { code: "BACKEND_MISSING", message: "traceroute binary not available", hint: process.platform === "win32" ? "tracert ships with Windows — check PATH" : "sudo apt install traceroute" });
  }
}

const HttpCheckInput = z.object({ url: z.string().url(), method: z.enum(["GET", "HEAD"]).default("GET"), timeoutMs: z.number().int().min(1000).max(30000).default(10000) });

export async function netHttpcheck(ctx: ServiceContext, input: z.infer<typeof HttpCheckInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const timings = { dnsMs: 0, connectMs: 0, ttfbMs: 0, totalMs: 0 };
  let status = 0;
  let headers: Record<string, string> = {};
  let bytes = 0;
  const t0 = Date.now();
  await new Promise<void>((resolve) => {
    const req = http.request(input.url, { method: input.method, timeout: input.timeoutMs, headers: { "user-agent": ctx.config.ua } }, (res) => {
      status = res.statusCode ?? 0;
      headers = Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : String(v ?? "")]));
      timings.ttfbMs = Date.now() - t0;
      res.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes >= ctx.config.caps.http.maxBytes) req.destroy();
      });
      res.on("end", () => resolve());
      res.on("error", () => resolve());
    });
    req.on("socket", (sock: net.Socket) => {
      sock.on("lookup", () => { timings.dnsMs = Date.now() - t0; timings.connectMs = timings.dnsMs; });
      sock.on("connect", () => { timings.connectMs = Date.now() - t0; });
    });
    req.on("timeout", () => { req.destroy(); resolve(); });
    req.on("error", () => resolve());
    req.end();
  });
  timings.totalMs = Date.now() - t0;
  return okEnvelope(ctx, "net.httpcheck", { status, timings, bytes, headers }, { backend: "node:http", durationMs: Date.now() - start });
}

const PortcheckInput = z.object({ host: hostSchema, port: z.number().int().min(1).max(65535) });

export async function netPortcheck(ctx: ServiceContext, input: z.infer<typeof PortcheckInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const latency = await tcpConnectMs(input.host, input.port, ctx.config.caps.portscan.timeoutMs);
  const state = latency === undefined ? "closed" : "open";
  return okEnvelope(ctx, "net.portcheck", { port: input.port, host: input.host, state, latencyMs: latency }, { backend: "tcp-connect", durationMs: Date.now() - start });
}

export const COMMON_PORTS = [22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5353, 5432, 8080, 8443, 9090, 9100];

/** Normalized port-scan hit (SPEC §5). */
export interface PortHit {
  port: number;
  state: "open" | "closed" | "filtered";
  latencyMs?: number;
  banner?: string;
}

const PortscanInput = z.object({
  host: hostSchema,
  ports: z.array(z.number().int().min(1).max(65535)).max(256).optional(),
});

export async function netPortscan(ctx: ServiceContext, input: z.infer<typeof PortscanInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const retry = ctx.caps.rate.check("portscan");
  if (retry !== undefined) {
    return failEnvelope(ctx, "net.portscan", { code: "RATE_LIMITED", message: "portscan rate limit hit", hint: `retry in ${retry}ms` });
  }
  const ports = (input.ports ?? COMMON_PORTS).slice(0, ctx.config.caps.portscan.maxPorts);
  const concurrency = ctx.config.caps.portscan.concurrency;
  const hits: object[] = [];
  const queue = [...ports];
  async function worker(): Promise<void> {
    for (;;) {
      const p = queue.shift();
      if (p === undefined) return;
      const latency = await tcpConnectMs(input.host, p, ctx.config.caps.portscan.timeoutMs);
      hits.push({ port: p, state: latency === undefined ? "closed" : "open", latencyMs: latency });
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  hits.sort((a, b) => (a as { port: number }).port - (b as { port: number }).port);
  return okEnvelope(ctx, "net.portscan", { host: input.host, portsScanned: ports.length, hits }, { backend: "tcp-connect", durationMs: Date.now() - start });
}

const SslInput = z.object({ host: hostSchema, port: z.number().int().min(1).max(65535).default(443), timeoutMs: z.number().int().default(10000) });

export async function netSsl(ctx: ServiceContext, input: z.infer<typeof SslInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const certData = await new Promise<object | null>((resolve) => {
    const sock = tls.connect(
      { host: input.host, port: input.port, servername: input.host, timeout: input.timeoutMs, rejectUnauthorized: false },
      () => {
        const cert = sock.getPeerCertificate(true);
        const chainCount = sock.getPeerCertificate !== undefined ? 1 : 0;
        const info = cert && typeof cert === "object" && "subject" in cert
          ? {
              subject: (cert as { subject?: unknown }).subject ?? null,
              issuer: (cert as { issuer?: unknown }).issuer ?? null,
              subjectaltname: (cert as { subjectaltname?: string }).subjectaltname ?? null,
              validFrom: (cert as { valid_from?: string }).valid_from ?? null,
              validTo: (cert as { valid_to?: string }).valid_to ?? null,
              fingerprint: (cert as { fingerprint?: string }).fingerprint ?? null,
              chainLength: chainCount,
            }
          : null;
        sock.destroy();
        resolve(info);
      },
    );
    sock.on("error", () => resolve(null));
    sock.on("timeout", () => { sock.destroy(); resolve(null); });
  });
  if (!certData) {
    return failEnvelope(ctx, "net.ssl", { code: "EXEC_FAILED", message: `TLS connect to ${input.host}:${input.port} failed`, hint: "check host/port and network path" });
  }
  const validToStr = (certData as { validTo?: string | null }).validTo;
  const daysLeft = validToStr ? Math.round((new Date(validToStr).getTime() - Date.now()) / 86400000) : undefined;
  const grade = daysLeft === undefined ? "unknown" : daysLeft < 0 ? "expired" : daysLeft < 3 ? "low" : daysLeft < 14 ? "med" : "high";
  return okEnvelope(ctx, "net.ssl", { ...certData, daysLeft, grade }, { backend: "node:tls", durationMs: Date.now() - start });
}

// ---------------------------------------------------------------------------
// M4 (pulled into M2 batch): public IP — explicit user-requested external call
// ---------------------------------------------------------------------------

const PUBLIC_IP_ENDPOINTS = [
  "https://api.ipify.org?format=json",
  "https://ipinfo.io/json",
];

export async function netPublicip(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  let ip: string | undefined;
  let org: string | undefined;
  let hostname: string | undefined;
  for (const url of PUBLIC_IP_ENDPOINTS) {
    try {
      const res = await fetch(url, { headers: { "user-agent": ctx.config.ua }, signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const json = (await res.json()) as Record<string, string>;
      if (typeof json["ip"] === "string" && !ip) ip = json["ip"];
      if (typeof json["org"] === "string" && !org) org = json["org"];
      if (typeof json["hostname"] === "string" && !hostname) hostname = json["hostname"];
      if (ip) break;
    } catch { /* try next endpoint */ }
  }
  if (!ip) {
    return failEnvelope(ctx, "net.publicip", { code: "EXEC_FAILED", message: "public IP lookup failed at all endpoints", hint: "check internet connectivity" });
  }
  return okEnvelope(ctx, "net.publicip", { ip, org, hostname }, { backend: "http:ipify/ipinfo", durationMs: Date.now() - start });
}

export const coreToolSchemas = { PingInput, TraceInput, HttpCheckInput, PortcheckInput, PortscanInput, SslInput };