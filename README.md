# netexpert-mcp

> *"What's on my network, is my link healthy, is this machine safe, and why is X slow?"*
> — answered by an AI, on your LAN, in one conversation.

**netexpert** is a cross-platform local-network diagnostics & security-posture MCP server for AI clients (Kai, Claude Desktop, anything that speaks MCP). It's the *local host + LAN* half of a home-lab toolkit — the NAS half already exists as the `ugnas` MCP server, and the two compose: netexpert never duplicates ugnas tools.

---

## Why it exists

Existing network MCP servers are either deprecated Python packages, wrappers that demand Nmap, or router-config tools for enterprises. None of them answer the home-lab questions:

| Question | netexpert answer |
|---|---|
| *What devices are on my network — anything new?* | `lan.devices` builds an inventory (ARP ∪ sweep, OUI vendor, PTR hostname); `lan.newdevices` diffs it against snapshots and emits findings |
| *Is my WiFi actually good?* | `wifi.health` interprets RSSI bands, channel overlap, and band mismatch — with concrete next steps, not raw numbers |
| *Is this machine exposed?* | `sec.exposure` cross-references listening ports with firewall state and a risky-port knowledge base |
| *Is my DNS lying to me?* | `dns.hijackcheck` compares your system resolver against trusted DoH for known-good domains |
| *Why is X unreachable?* | Layered triage — link → ARP → routing/DNS → port → app (`docs/persona.md`) |

## Design guarantees

- **One envelope.** Every tool returns the same JSON shape (`ok`, `backend`, `data`, `warnings` / closed-set `error.code` + actionable `hint`) — no raw `netsh` or `ip` output ever reaches the model.
- **Platform-normalized.** Same field names on Windows, Linux, and macOS; platform dispatch lives below the service layer.
- **Bounded everything.** Port caps, host caps, byte caps, timeouts, and token-bucket rate limits are enforced in code — never left to the model's judgment.
- **No shell, ever.** All subprocesses spawn via arg arrays (`execFile`-style); all inputs are zod-validated before touching the OS. No raw sockets, no Npcap, no Python.
- **Read-only by default.** The one mutating tool (`lan.wol`) uses a dry-run plan + single-use, 10-min-TTL `confirmToken` — parameters frozen at plan time.
- **Capability honesty.** Tools report *which backend produced the data* (`backend: "tcp-connect"`, not a fake "ping"); `net.health` self-describes what works on this host, with install hints for what doesn't.
- **No telemetry.** No phone-home — except the three tools that are *about* the internet (`net.publicip`, `sec.speedtest`, DoH in `dns.hijackcheck`), which you invoked explicitly.

## Tool catalog (31)

### `net.*` — connectivity
| Tool | What it does |
|---|---|
| `net.health` | Version, platform, capability matrix (which backends exist on this host, with install hints) |
| `net.ping` | ICMP loss/latency stats; honest TCP-connect fallback when ping is unavailable |
| `net.trace` | Traceroute hops, normalized across `tracert`/`traceroute`/`tracepath` |
| `net.httpcheck` | GET/HEAD with timing split: dns / connect / ttfb / total |
| `net.portcheck` | Single TCP connect — open/closed + latency |
| `net.portscan` | Bounded connect scan (≤256 ports, default top-20 common) |
| `net.ssl` | TLS cert: subject, SANs, issuer, chain, days-left, expiry grade |
| `net.publicip` | Your public IPv4 + ASN/org (ipify → ipinfo fallback) |
| `net.deepscan` | Optional nmap adapter — **opt-in only**: requires the binary *and* `nmap.enabled` in config; RFC1918 targets only |

### `dns.*` — name resolution
| Tool | What it does |
|---|---|
| `dns.lookup` | A/AAAA/CNAME/MX/TXT/NS/SRV/PTR with optional nameserver override |
| `dns.reverse` | PTR names for an IP |
| `dns.resolvers` | Which DNS servers the OS *actually* uses (per-platform) |
| `dns.propagation` | Same record at system + trusted resolvers + DoH — diff table |
| `dns.hijackcheck` | The killer check: known-good domains via system vs trusted DoH; mismatch or NXDOMAIN ⇒ `Finding{sev:high}` |

### `lan.*` — devices & inventory
| Tool | What it does |
|---|---|
| `lan.interfaces` | NICs: name, MAC, addresses, type, virtual flag |
| `lan.gateway` | Default gateway + interface + local subnet CIDR |
| `lan.arp` | Parsed neighbor cache, stale entries filtered |
| `lan.sweep` | Ping-probe an RFC1918 subnet (≤1024 hosts, rate-limited 1/30s) → live set |
| `lan.devices` | Inventory: ARP ∩ RFC1918, enriched with vendor (40k-entry IEEE OUI db) + PTR hostname |
| `lan.hostname` | All known names for an IP: PTR + NetBIOS (win) |
| `lan.snapshot` | Save device inventory to dated snapshots; or list them |
| `lan.newdevices` | Diff live vs baseline ⇒ findings (new MAC, MAC-changed-for-IP); first run auto-saves a baseline |
| `lan.wol` | Wake-on-LAN magic packet — dry-run plan → `confirmToken` → one UDP broadcast |

### `wifi.*` — link health
| Tool | What it does |
|---|---|
| `wifi.status` | Current link: SSID, BSSID, band, channel, RSSI, PHY rate, quality 0–100 |
| `wifi.networks` | Nearby AP survey with band inference |
| `wifi.health` | Interpretation: RSSI bands (≥−50 … <−78 unusable), 2.4 GHz channel overlap, band mismatch, low PHY rate — each a `Finding` with the next tool call |

### `sec.*` — host posture
| Tool | What it does |
|---|---|
| `sec.connections` | Active sockets with owning PID |
| `sec.listening` | Listeners per process; flags `0.0.0.0`/`::` exposures |
| `sec.firewall` | Get-NetFirewallProfile / ufw→nft / socketfilterfw |
| `sec.exposure` | Headline report: exposed listeners × firewall state × risky-port table (445, 3389, 23, 135–139, 5357, 5900) ⇒ `Finding[]` |
| `sec.speedtest` | Bounded Cloudflare download; reports a lower bound instead of failing on slow links |

---

## Getting started

```bash
git clone <repo> && cd netexpert-mcp
pnpm install
pnpm build
pnpm smoke        # build → stdio → tools/list → net.health
```

**Daily commands**

```bash
pnpm typecheck    # verify (Kai runs this after every edit)
pnpm test         # 46 tests: fixture-driven parsers, gates, safety — zero real network in units
pnpm build        # emit dist/
```

**MCP client config**

```jsonc
{ "mcpServers": { "netexpert": { "command": "node", "args": ["<abs-path>/dist/server.js"] } } }
```

Optional stateless HTTP transport:

```bash
NETEXPERT_HTTP_PORT=3100 node dist/server.js
# POST http://127.0.0.1:3100/mcp   (JSON-RPC: tools/list, tools/call)
# GET  http://127.0.0.1:3100/health
```

## Configuration

`~/.netexpert-mcp/config.json` — sane defaults, so **zero-config first run**:

```jsonc
{
  "defaults":  { "pingCount": 4, "traceMaxHops": 20 },
  "resolvers": { "trusted": ["1.1.1.1", "8.8.8.8"],
                 "dohUrl": "https://cloudflare-dns.com/dns-query" },
  "caps":      { "portscan": { "maxPorts": 256 }, "sweep": { "maxHosts": 1024 }, "http": {}, "speedtest": {} },
  "rate":      { "sweep": 30, "portscan": 10, "speedtest": 60, "httpCheck": 2 },
  "nmap":      { "enabled": false }   // deep scans are opt-in by design
}
```

Invariants: caps are **ceilings** — tool inputs may go lower, never higher. Env overrides via `NETEXPERT_*` (`NETEXPERT_HTTP_PORT`, `NETEXPERT_MCP_CONFIG`). **No credentials ever** — any config key containing `password`/`token`/`secret`/`credential` is rejected at load.

The OUI vendor database (`src/data/oui.json`, 40k IEEE MA-L entries) is committed — never fetched at runtime. Regenerate with `node scripts/gen-oui.mjs`.

## Monitoring without a daemon

netexpert stays request/response; recurring checks are your MCP client's job. Kai `watch_create` recipes:

```text
New-device tripwire   lan.newdevices    every 15 min   fire on Finding[] beyond the info baseline
Gateway reachability  net.ping <gw>    every 60 s      fire on lossPct > 0
DNS integrity         dns.hijackcheck   hourly          fire on sev=high
WiFi degradation      wifi.health       every 10 min    fire on severity ≥ med
```

## AI usage — `docs/persona.md`

The server provides hands; the persona provides judgment. The rule pack in `docs/persona.md` gives your AI client:

1. a **triage ladder** (link → ARP → IP/DNS → port → app — always state which layer exonerated/implicated),
2. **baselines** for "suspicious" (new MAC with no vendor match, RFC1918 host on 445/3389 that isn't the NAS, resolver ≠ DoH, ARP flapping),
3. the **Finding format** — every answer ends with the concrete next tool call, never a data dump,
4. **composition rules with ugnas** for the NAS half.

## Project layout

```text
src/
  exec/        LocalExecutor (execFile, arg arrays) + per-platform CommandMaps (win32/linux/darwin)
  parse/       pure parsers (arp, ping, traceroute, netsh, iw, nmap -oG) — fixture-tested
  services/    coreService dnsService lanService wifiService secService nmapService
  safety/      caps.ts (bounds + token-bucket rate limiter) · confirm.ts (dry-run/confirmToken)
  data/        oui.json (40k IEEE OUI entries, committed)
  mcp/         toolset.ts (31 tools, zod inputs) · createServer.ts
scripts/       gen-oui.mjs · smoke.mjs · http-smoke.mjs
docs/          persona.md
tests/         fixtures/ + parsers · services · wifiSec · m4 · nmap (46 tests)
```

## Supply-chain stance

Runtime deps are 4 well-known packages (`@modelcontextprotocol/sdk`, `zod`, `systeminformation`, `default-gateway`) + the Node stdlib. Prior art was studied, not installed. Optional binaries (nmap, traceroute) are capability-detected, never required, and their absence produces an install hint — not a crash.

## Status

Spec-complete: M1–M5. Verified: `pnpm typecheck` clean, 46/46 tests, stdio + HTTP smoke on real hardware — where the very first `sec.exposure` run correctly flagged the dev machine's disabled firewall and exposed SMB port.

License: MIT — see `LICENSE`. Published as [`netexpert-mcp` on npm](https://www.npmjs.com/package/netexpert-mcp).
