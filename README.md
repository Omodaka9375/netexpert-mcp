# netexpert-mcp

> *"What's on my network, is my link healthy, is this machine safe, and why is X slow?"*
> — answered by an AI, on your LAN, in one conversation.

**netexpert** is a cross-platform local-network diagnostics & security-posture MCP server for AI clients (Claude Desktop, Claude Code, or any client that speaks MCP). Windows, Linux, macOS — one normalized JSON envelope, 31 tools, zero config on first run, read-only by default.

It's the *local host + LAN* half of a home-lab toolkit — the NAS half already exists as [`ugnas-mcp`](https://github.com/Omodaka9375/ugnas-mcp), and the two compose.

Also listed in the [MCP registry](https://registry.modelcontextprotocol.io) as `io.github.Omodaka9375/netexpert-mcp`.

---

## Install

The package is on npm — no clone, no build:

```bash
# run once, on demand (no install)
npx -y netexpert-mcp

# or install globally
npm install -g netexpert-mcp
netexpert-mcp
```

**Wire it into your MCP client** (stdio):

```jsonc
{
  "mcpServers": {
    "netexpert": {
      "command": "npx",
      "args": ["-y", "netexpert-mcp"]
    }
  }
}
```

That's it — first run needs no config file, no environment variables, nothing. Ask your client *"what devices are on my network?"* and it has the tools to answer.

**Optional HTTP transport** (stateless, same JSON-RPC surface):

```bash
NETEXPERT_HTTP_PORT=3100 netexpert-mcp
# POST http://127.0.0.1:3100/mcp     (tools/list, tools/call)
# GET  http://127.0.0.1:3100/health  (liveness)
```

---

## Try it in 30 seconds

Once wired into your client, try:

1. **"Am I exposed?"** → the client calls `sec.exposure` — listening ports × firewall state × a risky-port knowledge base, reported as `Finding`s.
2. **"What's on my network?"** → `lan.devices` — ARP inventory enriched with IEEE-OUI vendor names and PTR hostnames.
3. **"Is my DNS lying to me?"** → `dns.hijackcheck` — known-good domains via your system resolver vs trusted DoH; mismatch ⇒ `Finding{severity:high}`.
4. **"Is my WiFi any good?"** → `wifi.health` — RSSI quality bands, channel overlap, band mismatch — interpreted, with next steps.

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

## Configuration (all optional)

`~/.netexpert-mcp/config.json` — sane defaults, so **zero-config first run**:

```jsonc
{
  "defaults":  { "pingCount": 4, "traceMaxHops": 20 },
  "resolvers": { "trusted": ["1.1.1.1", "8.8.8.8"],
                 "dohUrl": "https://cloudflare-dns.com/dns-query" },
  "caps":      { "portscan": { "maxPorts": 256 }, "sweep": { "maxHosts": 1024 } },
  "rate":      { "sweep": 30, "portscan": 10, "speedtest": 60, "httpCheck": 2 },
  "nmap":      { "enabled": false }   // deep scans are opt-in by design
}
```

Invariants:

- caps are **ceilings** — tool inputs may go lower, never higher
- env overrides via `NETEXPERT_*`: `NETEXPERT_MCP_CONFIG` (config path), `NETEXPERT_HTTP_PORT`, `NETEXPERT_WIFI_IF` (linux wlan iface)
- **no credentials ever** — any config key containing `password`/`token`/`secret`/`credential` is rejected at load

**Optional extras:**

- **nmap deep scans** — install nmap (`winget install Insecure.Nmap` / `sudo apt install nmap`), then set `"nmap": { "enabled": true }` in config. Absence just produces an install hint, never a crash.
- **OUI vendor db** — ships inside the package; never fetched at runtime.

## Monitoring without a daemon

netexpert stays request/response; recurring checks are your MCP client's job:

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
3. the **Finding format** — every answer ends with the concrete next tool call, never a data dump.

---

## Development

```bash
git clone https://github.com/Omodaka9375/netexpert-mcp.git
cd netexpert-mcp
pnpm install

pnpm typecheck     # strict TS (Kai/Claude Code runs this after edits)
pnpm test          # 50 fixture-driven tests (fake runner, zero real network in units)
pnpm build         # → dist/
pnpm smoke         # build → stdio → tools/list → net.health
pnpm smoke:http     # HTTP transport check
node scripts/gen-oui.mjs   # regenerate the OUI db (rarely needed)
```

Project layout:

```text
src/
  exec/        LocalExecutor (execFile, arg arrays) + per-platform CommandMaps (win32/linux/darwin)
  parse/       pure parsers (arp, ping, traceroute, netsh, iw, nmap -oG) — fixture-tested
  services/    coreService dnsService lanService wifiService secService nmapService
  safety/      caps.ts (bounds + token-bucket rate limiter) · confirm.ts (dry-run/confirmToken)
  data/        oui.json (40k IEEE OUI entries, committed)
  mcp/         toolset.ts (31 tools, zod inputs) · createServer.ts
scripts/       gen-oui.mjs · smoke.mjs · http-smoke.mjs
docs/          persona.md · index.html (the docs page)
tests/         fixtures/ + 50 tests across 6 files
```

CI (GitHub Actions): 4-way matrix (ubuntu/windows × node 20/22) runs the full chain on every push and PR — including a wiring contract test that fails if the registered tool set ever drifts from this README.

## Status

Spec-complete: M1–M5. Verified live on Windows against a real home LAN — where the very first `sec.exposure` run correctly flagged the dev machine's disabled firewall and exposed SMB port.

**License:** MIT — see [`LICENSE`](LICENSE).
**npm:** [`netexpert-mcp`](https://www.npmjs.com/package/netexpert-mcp) · **MCP registry:** `io.github.Omodaka9375/netexpert-mcp`
**Source & issues:** [GitHub](https://github.com/Omodaka9375/netexpert-mcp)