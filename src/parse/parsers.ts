/** Parse `arp -a` BSD-style output (win32 + darwin). */
export interface Neighbor {
  ip: string;
  mac?: string;
  interface?: string;
  type?: string;
}

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const MAC_RE = /^[0-9a-f]{2}[-:]([0-9a-f]{2}[-:]){4}[0-9a-f]{2}$/i;

export function parseWindowsArp(out: string): { neighbors: Neighbor[]; warnings: string[] } {
  const neighbors: Neighbor[] = [];
  const warnings: string[] = [];
  let currentIface: string | undefined;
  for (const rawLine of out.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    const ifaceMatch = line.match(/^Interface:\s*(\S+)/i);
    if (ifaceMatch?.[1]) {
      currentIface = ifaceMatch[1];
      continue;
    }
    // "<ip> <type> <mac> <iface>" windows; "<ip> -> (mac) [type] on iface" darwin
    const parts = line.split(/\s+/);
    const ip = parts[0] ?? "";
    if (!IP_RE.test(ip)) continue;
    const macPart = parts.find((p) => MAC_RE.test(p));
    if (!macPart) {
      warnings.push(`arp entry for ${ip} has no parseable MAC, skipped`);
      continue;
    }
    neighbors.push({
      ip,
      mac: macPart.toLowerCase().replaceAll("-", ":"),
      interface: currentIface,
      type: parts.includes("dynamic") ? "dynamic" : parts.includes("static") ? "static" : undefined,
    });
  }
  return { neighbors, warnings };
}

/** Parse `ip -j neigh` JSON output (linux). */
export function parseLinuxNeigh(out: string): { neighbors: Neighbor[]; warnings: string[] } {
  const neighbors: Neighbor[] = [];
  const warnings: string[] = [];
  let arr: unknown;
  try {
    arr = JSON.parse(out);
  } catch {
    return { neighbors, warnings: ["ip -j neigh output is not valid JSON"] };
  }
  if (!Array.isArray(arr)) return { neighbors, warnings: ["ip -j neigh: unexpected shape"] };
  for (const e of arr) {
    if (typeof e !== "object" || e === null) continue;
    const rec = e as Record<string, unknown>;
    const ip = typeof rec["dst"] === "string" ? rec["dst"] : undefined;
    const mac = typeof rec["lladdr"] === "string" ? rec["lladdr"] : undefined;
    const state0 = Array.isArray(rec["state"]) ? rec["state"][0] : rec["state"];
    const state = typeof state0 === "string" ? state0.toLowerCase() : undefined;
    if (!ip) continue;
    if (!mac) {
      warnings.push(`neigh ${ip} without lladdr, skipped`);
      continue;
    }
    neighbors.push({ ip, mac: mac.toLowerCase(), type: state, interface: typeof rec["dev"] === "string" ? rec["dev"] : undefined });
  }
  return { neighbors, warnings };
}

export type PingStats = {
  host: string;
  count: number;
  transmitted: number;
  received: number;
  lossPct: number;
  minMs?: number;
  avgMs?: number;
  maxMs?: number;
  mdevMs?: number;
  times: number[];
};

/** Generic ping parser: handles windows, linux(iputils), darwin(inetutils) outputs. */
export function parsePing(out: string): { stats: PingStats | null; warnings: string[] } {
  const warnings: string[] = [];
  const times: number[] = [];
  let host: string | undefined;
  let transmitted: number | undefined;
  let received: number | undefined;
  let lossPct: number | undefined;
  let rtt: { min?: number; avg?: number; max?: number; mdev?: number } = {};

  for (const rawLine of out.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    const timeMatch = line.match(/[=<]?\s*(\d+(?:\.\d+)?)\s*(?:ms|毫秒)/i);
    if (timeMatch?.[1]) {
      const t = Number.parseFloat(timeMatch[1]);
      if (Number.isFinite(t)) times.push(t);
    }
    // windows: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
    const winStats = line.match(/Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*\d+\s*\((\d+)%/i);
    if (winStats) {
      transmitted = Number.parseInt(winStats[1] ?? "0", 10);
      received = Number.parseInt(winStats[2] ?? "0", 10);
      lossPct = Number.parseFloat(winStats[3] ?? "0");
    }
    // linux/darwin: "4 packets transmitted, 4 received, 0% packet loss"
    const unixStats = line.match(/(\d+)\s+packets?\s+transmitted.*?(\d+)\s+received[^\d]*(\d+(?:\.\d+)?)%/i);
    if (unixStats) {
      transmitted = Number.parseInt(unixStats[1] ?? "0", 10);
      received = Number.parseInt(unixStats[2] ?? "0", 10);
      lossPct = Number.parseFloat(unixStats[3] ?? "0");
    }
    // rtt summary lines
    const linuxRtt = line.match(/rtt min\/avg\/max(?:\/mdev)?\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)(?:\/([\d.]+))?/i);
    if (linuxRtt) {
      rtt = {
        min: Number.parseFloat(linuxRtt[1] ?? ""),
        avg: Number.parseFloat(linuxRtt[2] ?? ""),
        max: Number.parseFloat(linuxRtt[3] ?? ""),
        mdev: linuxRtt[4] !== undefined ? Number.parseFloat(linuxRtt[4]) : undefined,
      };
    }
    const winRtt = line.match(/Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms/i);
    if (winRtt) {
      rtt = {
        min: Number.parseInt(winRtt[1] ?? "0", 10),
        avg: Number.parseInt(winRtt[3] ?? "0", 10),
        max: Number.parseInt(winRtt[2] ?? "0", 10),
      };
    }
    // darwin: "round-trip min/avg/max/stddev = x/y/z/w ms"
    const darwinRtt = line.match(/round-trip\s+min\/avg\/max(?:\/stddev)?\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)(?:\/([\d.]+))?/i);
    if (darwinRtt) {
      rtt = {
        min: Number.parseFloat(darwinRtt[1] ?? ""),
        avg: Number.parseFloat(darwinRtt[2] ?? ""),
        max: Number.parseFloat(darwinRtt[3] ?? ""),
        mdev: darwinRtt[4] !== undefined ? Number.parseFloat(darwinRtt[4]) : undefined,
      };
    }
    const hostMatch = line.match(/Pinging\s+(\S+)\s+with/i) ?? line.match(/PING\s+(\S+)/i);
    if (hostMatch?.[1]) host = hostMatch[1];
  }

  if (times.length === 0 && received === undefined) {
    return { stats: null, warnings: ["ping produced no parseable replies"] };
  }
  const tx = transmitted ?? times.length;
  const rx = received ?? times.length;
  const min = rtt.min ?? (times.length ? Math.min(...times) : undefined);
  const avg = rtt.avg ?? (times.length ? times.reduce((a, b) => a + b, 0) / times.length : undefined);
  const max = rtt.max ?? (times.length ? Math.max(...times) : undefined);
  const loss = lossPct ?? (tx > 0 ? ((tx - rx) / tx) * 100 : 100);
  return {
    stats: { host: host ?? "", count: times.length, transmitted: tx, received: rx, lossPct: Math.round(loss * 10) / 10, minMs: min, avgMs: avg, maxMs: max, mdevMs: rtt.mdev, times },
    warnings,
  };
}

export type Hop = { ttl: number; ip?: string; latencyMs?: number; hostname?: string };

/** Traceroute/tracert parser (both formats). */
export function parseTraceroute(out: string): { hops: Hop[]; warnings: string[] } {
  const hops: Hop[] = [];
  const warnings: string[] = [];
  for (const rawLine of out.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    const hopMatch = line.match(/^(\d{1,2})\s+/);
    if (!hopMatch?.[1]) continue;
    const ttl = Number.parseInt(hopMatch[1], 10);
    // windows: "1  <10 ms  <10 ms  <10 ms  192.168.1.1"
    // linux:   "1  192.168.1.1 (192.168.1.1)  0.512 ms"
    const ipMatch = line.match(/(\d{1,3}(?:\.\d{1,3}){3})/) ?? line.match(/\(([^)]+)\)/);
    const timeMatch = line.match(/(\d+(?:\.\d+)?)\s*ms/i);
    hops.push({
      ttl,
      ip: ipMatch?.[1],
      latencyMs: timeMatch?.[1] !== undefined ? Number.parseFloat(timeMatch[1]) : undefined,
    });
  }
  if (hops.length === 0) warnings.push("no parseable hops");
  return { hops, warnings };
}
