import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";

/** No credentials ever. If a key looks like a secret, reject it. */
function noSecretKeys<T extends Record<string, unknown>>(obj: T): T {
  for (const [k, v] of Object.entries(obj)) {
    if (/password|token|secret|credential/i.test(k)) {
      throw new Error(`config key "${k}" looks like a secret — netexpert-mcp refuses secrets`);
    }
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      noSecretKeys(v as Record<string, unknown>);
    }
  }
  return obj;
}

export const NetexpertConfig = z
  .object({
    defaults: z
      .object({
        subnet: z.string().default("auto"),
        pingCount: z.number().int().min(1).max(20).default(4),
        traceMaxHops: z.number().int().min(1).max(30).default(20),
      })
      .default({}),
    resolvers: z
      .object({
        trusted: z.array(z.string().ip()).default(["1.1.1.1", "8.8.8.8"]),
        dohUrl: z.string().url().default("https://cloudflare-dns.com/dns-query"),
      })
      .default({}),
    caps: z
      .object({
        portscan: z
          .object({
            maxPorts: z.number().int().min(1).max(256).default(32),
            concurrency: z.number().int().min(1).max(32).default(16),
            timeoutMs: z.number().int().min(100).max(2000).default(2000),
          })
          .default({}),
        sweep: z
          .object({
            maxHosts: z.number().int().min(1).max(1024).default(256),
            concurrency: z.number().int().min(1).max(64).default(64),
            timeoutMs: z.number().int().min(100).max(1000).default(1000),
          })
          .default({}),
        http: z
          .object({
            timeoutMs: z.number().int().min(1000).max(30000).default(10000),
            maxBytes: z.number().int().min(1024).default(2097152),
          })
          .default({}),
        speedtest: z
          .object({
            downloadBytes: z.number().int().default(26214400),
            timeoutMs: z.number().int().default(30000),
          })
          .default({}),
      })
      .default({}),
    rate: z
      .object({
        sweep: z.number().int().min(0).default(30),
        portscan: z.number().int().min(0).default(10),
        speedtest: z.number().int().min(0).default(60),
        httpCheck: z.number().int().min(0).default(2),
      })
      .default({}),
    paths: z
      .object({
        snapshotsDir: z.string().default(path.join(os.homedir(), ".netexpert-mcp", "snapshots")),
      })
      .default({}),
    nmap: z
      .object({
        enabled: z.boolean().default(false), // deep scans only when explicitly enabled (SPEC §8 M5)
      })
      .default({}),
    ua: z.string().default("netexpert-mcp/0.1 (local diagnostics)"),
    httpPort: z.number().int().min(0).max(65535).default(0),
    logLevel: z.enum(["debug", "info", "warn", "error"]).default("info"),
  })
  .transform(noSecretKeys);

export type NetexpertConfigT = z.infer<typeof NetexpertConfig>;

const CONFIG_PATH =
  process.env["NETEXPERT_MCP_CONFIG"] ??
  path.join(os.homedir(), ".netexpert-mcp", "config.json");

export function loadConfig(): NetexpertConfigT {
  let raw: unknown = {};
  if (fs.existsSync(CONFIG_PATH)) {
    raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  }
  const fileValidated = NetexpertConfig.safeParse(raw);
  if (fileValidated.success) {
    // env overrides (only httpPort + logLevel are env-overridable here)
    const merged = { ...fileValidated.data } as { httpPort?: unknown };
    const envPort = process.env["NETEXPERT_HTTP_PORT"];
    if (envPort !== undefined && envPort !== "") {
      const p = Number.parseInt(envPort, 10);
      if (Number.isInteger(p) && p >= 0 && p <= 65535) {
        merged["httpPort"] = p;
      }
    }
    return NetexpertConfig.parse(merged);
  }
  throw new Error(
    `netexpert-mcp config invalid at ${CONFIG_PATH}: ${fileValidated.error.message}`,
  );
}