import dns from "node:dns";
import { z } from "zod";
import type { ServiceContext, Envelope } from "./util.js";
import { okEnvelope, failEnvelope } from "./util.js";

const nameSchema = z.string().min(1).max(253).regex(/^[a-zA-Z0-9._-]+$/, "invalid name");
const ipSchema = z.string().ip();

const LookupInput = z.object({
  name: nameSchema,
  record: z.enum(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR"]).default("A"),
  nameserver: ipSchema.optional(),
});

export async function dnsLookup(ctx: ServiceContext, input: z.infer<typeof LookupInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const resolver = new dns.promises.Resolver({ timeout: 5000, tries: 2 });
  if (input.nameserver) resolver.setServers([input.nameserver]);
  try {
    switch (input.record) {
      case "A": {
        const r = await resolver.resolve4(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "A", value: v })) }, { backend: input.nameserver ? `node:dns@${input.nameserver}` : "node:dns", durationMs: Date.now() - start });
      }
      case "AAAA": {
        const r = await resolver.resolve6(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "AAAA", value: v })) }, { backend: input.nameserver ? `node:dns@${input.nameserver}` : "node:dns", durationMs: Date.now() - start });
      }
      case "CNAME": {
        const r = await resolver.resolveCname(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "CNAME", value: v })) }, { backend: "node:dns", durationMs: Date.now() - start });
      }
      case "MX": {
        const r = await resolver.resolveMx(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "MX", value: `${v.exchange} (pri ${v.priority})` })) }, { backend: "node:dns", durationMs: Date.now() - start });
      }
      case "TXT": {
        const r = await resolver.resolveTxt(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "TXT", value: v.join("") })) }, { backend: "node:dns", durationMs: Date.now() - start });
      }
      case "NS": {
        const r = await resolver.resolveNs(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "NS", value: v })) }, { backend: "node:dns", durationMs: Date.now() - start });
      }
      case "SRV": {
        const r = await resolver.resolveSrv(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "SRV", value: `${v.name}:${v.port} (pri ${v.priority}, weight ${v.weight})` })) }, { backend: "node:dns", durationMs: Date.now() - start });
      }
      case "PTR": {
        const r = await resolver.reverse(input.name);
        return okEnvelope(ctx, "dns.lookup", { name: input.name, record: input.record, answers: r.map((v) => ({ name: input.name, type: "PTR", value: v })) }, { backend: "node:dns", durationMs: Date.now() - start });
      }
    }
  } catch (e) {
    return failEnvelope(ctx, "dns.lookup", { code: "EXEC_FAILED", message: `DNS ${input.record} lookup for ${input.name} failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

const ReverseInput = z.object({ ip: ipSchema });

export async function dnsReverse(ctx: ServiceContext, input: z.infer<typeof ReverseInput>): Promise<Envelope<object>> {
  const start = Date.now();
  try {
    const names = await dns.promises.reverse(input.ip);
    return okEnvelope(ctx, "dns.reverse", { ip: input.ip, names }, { backend: "node:dns", durationMs: Date.now() - start });
  } catch {
    return okEnvelope(ctx, "dns.reverse", { ip: input.ip, names: [] }, { backend: "node:dns", durationMs: Date.now() - start, warnings: ["no PTR record"] });
  }
}

/** R-class: which resolvers the OS actually uses. */
export async function dnsResolvers(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const platform = process.platform;
  try {
    if (platform === "win32") {
      const res = await ctx.runner.run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-DnsClientServerAddress | ConvertTo-Json -Compress"], { timeoutMs: 10000 });
      let parsed: unknown;
      try { parsed = JSON.parse(res.stdout); } catch { parsed = null; }
      const servers = new Set<string>();
      if (Array.isArray(parsed)) {
        for (const e of parsed) {
          const rec = e as Record<string, unknown>;
          if (Array.isArray(rec["ServerAddresses"])) {
            for (const s of rec["ServerAddresses"] as string[]) servers.add(s);
          }
        }
      }
      return okEnvelope(ctx, "dns.resolvers", { resolvers: [...servers] }, { backend: "cmd:powershell Get-DnsClientServerAddress", durationMs: Date.now() - start });
    }
    if (platform === "darwin") {
      const res = await ctx.runner.run("scutil", ["--dns"], { timeoutMs: 10000 });
      const servers = new Set<string>();
      for (const m of res.stdout.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)) {
        if (m[1]) servers.add(m[1]);
      }
      return okEnvelope(ctx, "dns.resolvers", { resolvers: [...servers] }, { backend: "cmd:scutil --dns", durationMs: Date.now() - start });
    }
    // linux: resolv.conf
    const res = await ctx.runner.run("sh", ["-c", "cat /etc/resolv.conf"], { timeoutMs: 5000 }).catch(() => null);
    if (!res) {
      return failEnvelope(ctx, "dns.resolvers", { code: "BACKEND_MISSING", message: "cannot read /etc/resolv.conf", hint: "check resolv.conf exists" });
    }
    const servers = new Set<string>();
    for (const line of res.stdout.split("\n")) {
      const m = line.trim().match(/^nameserver\s+(\S+)/);
      if (m?.[1]) servers.add(m[1]);
    }
    return okEnvelope(ctx, "dns.resolvers", { resolvers: [...servers] }, { backend: "file:/etc/resolv.conf", durationMs: Date.now() - start });
  } catch {
    return failEnvelope(ctx, "dns.resolvers", { code: "EXEC_FAILED", message: "could not enumerate OS resolvers", hint: platform === "linux" ? "check /etc/resolv.conf" : undefined });
  }
}

export const dnsToolSchemas = { LookupInput, ReverseInput };

/** Bounded system-resolver lookup: never hangs past timeoutMs. */
async function resolve4Bounded(name: string, timeoutMs = 4000): Promise<string[]> {
  const resolver = new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 });
  return resolver.resolve4(name);
}

// ---------------------------------------------------------------------------
// M2: propagation + hijack check (DoH via trusted resolver)
// ---------------------------------------------------------------------------

import type { Finding } from "./lanService.js";

const PropagationInput = z.object({
  name: nameSchema,
  record: z.enum(["A", "AAAA", "TXT", "NS"]).default("A"),
});

const TYPE_NUM: Record<string, number> = { A: 1, AAAA: 28, TXT: 16, NS: 2 };

async function dohQuery(ctx: ServiceContext, name: string, type: string, serverUrl?: string): Promise<string[]> {
  const url = `${serverUrl ?? ctx.config.resolvers.dohUrl}?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`DoH ${res.status}`);
  const json = (await res.json()) as { Answer?: Array<{ name: string; type: number; TTL?: number; data: string }> };
  return (json.Answer ?? []).filter((a) => a.type === (TYPE_NUM[type] ?? 1)).map((a) => a.data);
}

export async function dnsPropagation(ctx: ServiceContext, input: z.infer<typeof PropagationInput>): Promise<Envelope<object>> {
  const start = Date.now();
  const rows: Array<{ source: string; answers: string[] }> = [];
  // system resolver
  try {
    const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 1 });
    const sys = input.record === "A"
      ? await resolver.resolve4(input.name)
      : input.record === "AAAA"
        ? await resolver.resolve6(input.name)
        : input.record === "NS"
          ? await resolver.resolveNs(input.name)
          : (await resolver.resolveTxt(input.name)).map((t) => t.join(""));
    rows.push({ source: "system", answers: sys });
  } catch (e) {
    rows.push({ source: "system", answers: [], ...(e instanceof Error ? { error: e.message } : {}) } as { source: string; answers: string[] });
  }
  // trusted resolvers + DoH
  for (const ip of ctx.config.resolvers.trusted) {
    try {
      const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 1 });
      resolver.setServers([ip]);
      const ans = input.record === "A"
        ? await resolver.resolve4(input.name)
        : input.record === "AAAA"
          ? await resolver.resolve6(input.name)
          : input.record === "NS"
            ? await resolver.resolveNs(input.name)
            : (await resolver.resolveTxt(input.name)).map((t) => t.join(""));
      rows.push({ source: `udp:${ip}`, answers: ans });
    } catch {
      rows.push({ source: `udp:${ip}`, answers: [] });
    }
  }
  try {
    rows.push({ source: "doh", answers: await dohQuery(ctx, input.name, input.record) });
  } catch {
    rows.push({ source: "doh", answers: [] });
  }
  // diff: set-of-answers per source
  const sets = rows.map((r) => ({ source: r.source, set: new Set(r.answers), answers: r.answers }));
  const allAgree = sets.length > 1 && sets.every((s) => sameSet(s.set, sets[0]?.set ?? new Set()));
  return okEnvelope(ctx, "dns.propagation", { name: input.name, record: input.record, sources: rows, consistent: allAgree }, { backend: "node:dns+DoH", durationMs: Date.now() - start, warnings: allAgree ? undefined : ["sources disagree — answers may be propagating or one resolver is stale/hijacked"] });
}

function sameSet(a: Set<string>, b: Set<string>): boolean {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

const HIJACK_DOMAINS = ["example.com", "google.com", "cloudflare.com"];

export async function dnsHijackcheck(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const findings: Finding[] = [];
  const table: Array<{ domain: string; system: string[]; doh: string[]; match: boolean }> = [];
  // One domain = one bounded (4s) system lookup + one (8s-capped) DoH query.
  // Run the probe domains in parallel so the tool finishes in ~one probe
  // duration instead of three sequential ones (keeps it well under test/tool
  // timeouts on slow or stalling resolvers).
  await Promise.all(HIJACK_DOMAINS.map(async (domain) => {
    let sys: string[] = [];
    let sysErr: string | undefined;
    try {
      sys = await resolve4Bounded(domain, 4000);
    } catch (e) {
      sysErr = e instanceof Error ? e.message : "lookup failed";
    }
    let dohAns: string[] = [];
    try {
      dohAns = await dohQuery(ctx, domain, "A");
    } catch { /* DoH unreachable */ }
    const match = sysErr === undefined && dohAns.length > 0 && sys.length > 0 && sys.every((ip) => dohAns.includes(ip));
    table.push({ domain, system: sysErr ? [`ERROR: ${sysErr}`] : sys, doh: dohAns, match });
    if (sysErr?.includes("ENOTFOUND") || sysErr?.includes("NOTFOUND")) {
      findings.push({ severity: "high", title: `System resolver returns NXDOMAIN for ${domain}`, evidence: `system: ${sysErr}; DoH: ${dohAns.join(", ") || "unreachable"}`, nextStep: "run dns.resolvers — your DNS server may be down or hijacked; point the host at a trusted resolver" });
    } else if (!match && dohAns.length > 0 && sys.length > 0) {
      findings.push({ severity: "high", title: `DNS answer mismatch for ${domain}`, evidence: `system: ${sys.join(", ")} vs trusted DoH: ${dohAns.join(", ")}`, nextStep: "run dns.resolvers to see which server the OS uses; compare with dns.propagation for corroboration" });
    }
  }));
  // restore probe-domain order regardless of completion order
  table.sort((a, b) => HIJACK_DOMAINS.indexOf(a.domain) - HIJACK_DOMAINS.indexOf(b.domain));
  if (findings.length === 0) {
    findings.push({ severity: "info", title: "No DNS hijack indicators", evidence: table.map((r) => `${r.domain}: system=DoH`).join("; "), nextStep: "none — system resolver agrees with trusted DoH on all probe domains" });
  }
  return okEnvelope(ctx, "dns.hijackcheck", { table, findings }, { backend: "node:dns+DoH", durationMs: Date.now() - start });
}

export const dnsM2Schemas = { PropagationInput };