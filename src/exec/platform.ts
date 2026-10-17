export interface PingArgs { count: number; timeoutMs: number; host: string }
export interface TraceArgs { maxHops: number; timeoutMs: number; host: string }

export interface CommandSpec {
  argv: string[];
}

export interface CommandMap {
  arp(): CommandSpec;
  routes(): CommandSpec;
  ping(args: PingArgs): CommandSpec;
  trace(args: TraceArgs): CommandSpec;
}

export function backendTag(spec: CommandSpec): string {
  return `cmd:${spec.argv[0] ?? "?"} ${spec.argv.slice(1).join(" ").trimEnd()}`;
}

// ---------------------------------------------------------------------------
// win32 command map. powershell.exe (not pwsh) per SPEC §4.3.
// ---------------------------------------------------------------------------

const ps = (script: string): string[] => [
  "-NoProfile",
  "-NonInteractive",
  "-Command",
  script,
];

export const win32: CommandMap = {
  arp: () => ({ argv: ["arp", "-a"] }),
  routes: () => ({
    argv: [
      "powershell.exe",
      ...ps("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 | ConvertTo-Json -Compress)"),
    ],
  }),
  ping: (a) => ({
    argv: ["ping", "-n", String(a.count), "-w", String(a.timeoutMs), a.host],
  }),
  trace: (a) => ({
    argv: ["tracert", "-d", "-h", String(a.maxHops), "-w", String(a.timeoutMs), a.host],
  }),
};

// ---------------------------------------------------------------------------
// linux
// ---------------------------------------------------------------------------

export const linux: CommandMap = {
  arp: () => ({ argv: ["ip", "-j", "neigh"] }),
  routes: () => ({ argv: ["ip", "-j", "route"] }),
  ping: (a) => ({
    argv: ["ping", "-c", String(a.count), "-W", String(Math.max(1, Math.round(a.timeoutMs / 1000))), a.host],
  }),
  trace: (a) => ({
    argv: ["traceroute", "-n", "-q", "1", "-w", "2", "-m", String(a.maxHops), a.host],
  }),
};

// ---------------------------------------------------------------------------
// darwin
// ---------------------------------------------------------------------------

export const darwin: CommandMap = {
  arp: () => ({ argv: ["arp", "-a"] }),
  routes: () => ({ argv: ["netstat", "-rn", "-f", "inet"] }),
  ping: (a) => ({
    argv: ["ping", "-c", String(a.count), "-t", String(Math.max(1, Math.round(a.timeoutMs / 1000))), a.host],
  }),
  trace: (a) => ({
    argv: ["traceroute", "-n", "-m", String(a.maxHops), a.host],
  }),
};

export function commandMapFor(platform: NodeJS.Platform): CommandMap {
  switch (platform) {
    case "win32": return win32;
    case "linux": return linux;
    case "darwin": return darwin;
    default: throw new Error(`unsupported platform ${platform}`);
  }
}