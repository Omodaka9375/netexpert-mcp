import { z } from "zod";
import type { ServiceContext } from "../services/util.js";
import { makeContext } from "../services/util.js";
import { loadConfig } from "../config.js";
import * as core from "../services/coreService.js";
import * as dnsS from "../services/dnsService.js";
import * as lan from "../services/lanService.js";
import * as wifi from "../services/wifiService.js";
import * as sec from "../services/secService.js";
import * as nmapS from "../services/nmapService.js";

export interface ToolDef {
  name: string;
  description: string;
  schema?: z.ZodType;
  handler: (ctx: ServiceContext, input: unknown) => Promise<unknown>;
}

function tool(name: string, description: string, schema: z.ZodType | undefined, handler: ToolDef["handler"]): ToolDef {
  return { name, description, schema, handler };
}

function withSchema<S extends z.ZodType>(name: string, description: string, schema: S, handler: (ctx: ServiceContext, input: z.infer<S>) => Promise<unknown>): ToolDef {
  return tool(name, description, schema, (ctx, raw) => {
    const parsed = schema.safeParse(raw ?? {});
    if (!parsed.success) {
      return Promise.resolve({
        ok: false,
        tool: name,
        platform: process.platform,
        error: { code: "VALIDATION", message: parsed.error.message },
      });
    }
    return handler(ctx, parsed.data);
  });
}

export function buildToolset(): ToolDef[] {
  return [
    // net.*
    tool("net.health", "Server version, platform, capability matrix, config caps.", undefined, core.netHealth),
    withSchema("net.ping", "ICMP ping (min/avg/max/mdev), TCP-connect fallback reported honestly.", core.coreToolSchemas.PingInput, core.netPing),
    withSchema("net.trace", "Traceroute hop list (ttl, ip, latency).", core.coreToolSchemas.TraceInput, core.netTrace),
    withSchema("net.httpcheck", "GET/HEAD with timing split (dns/connect/ttfb/total), status, headers, size. LAN-safe.", core.coreToolSchemas.HttpCheckInput, core.netHttpcheck),
    withSchema("net.portcheck", "Single TCP connect: open/closed + latency.", core.coreToolSchemas.PortcheckInput, core.netPortcheck),
    withSchema("net.portscan", "Bounded TCP connect scan, default top common ports, cap 256.", core.coreToolSchemas.PortscanInput, core.netPortscan),
    withSchema("net.ssl", "TLS cert inspection: subject, SANs, issuer, expiry, daysLeft, grade.", core.coreToolSchemas.SslInput, core.netSsl),
    withSchema("net.deepscan", "Optional nmap deep scan (LAN RFC1918 targets). Requires nmap on PATH AND nmap.enabled=true in config. Opt-in by design.", nmapS.nmapToolSchemas.DeepscanInput, nmapS.netDeepscan),
    // dns.*
    withSchema("dns.lookup", "A/AAAA/CNAME/MX/TXT/NS/SRV/PTR lookup, optional nameserver override.", dnsS.dnsToolSchemas.LookupInput, dnsS.dnsLookup),
    tool("dns.reverse", "PTR names for an IP.", undefined, (ctx, raw) => dnsS.dnsReverse(ctx, dnsS.dnsToolSchemas.ReverseInput.parse(raw ?? {}))),
    tool("dns.resolvers", "Which DNS resolvers the OS actually uses.", undefined, dnsS.dnsResolvers),
    withSchema("dns.propagation", "Same record queried at trusted resolvers + DoH; diff table.", dnsS.dnsM2Schemas.PropagationInput, dnsS.dnsPropagation),
    tool("dns.hijackcheck", "Killer check: known-good domains via system resolver vs trusted DoH; mismatch ⇒ Finding.", undefined, dnsS.dnsHijackcheck),
    // net M4
    tool("net.publicip", "Public IPv4 (+ASN/org). Explicitly user-requested external call.", undefined, core.netPublicip),
    // lan.*
    tool("lan.interfaces", "Network interfaces (Nic[]): name, mac, ipv4[], ipv6[], type.", undefined, lan.lanInterfaces),
    tool("lan.gateway", "Default gateway + interface + local subnet CIDR.", undefined, lan.lanGateway),
    tool("lan.arp", "ARP/neighbor cache, parsed, stale entries filtered.", undefined, lan.lanArp),
    withSchema("lan.sweep", "Ping-probe an RFC1918 subnet (cap 1024 hosts) → live set.", lan.lanToolSchemas.SubnetInput, lan.lanSweep),
    tool("lan.devices", "Inventory: ARP ∪ RFC1918 filter, enriched with vendor (OUI) + hostname (PTR).", undefined, lan.lanDevices),
    withSchema("lan.hostname", "All known names for an IP: PTR, NetBIOS (win).", lan.lanToolSchemas.HostnameInput, lan.lanHostname),
    withSchema("lan.snapshot", "Save current lan.devices to a dated snapshot; or list snapshots.", lan.lanToolSchemas.SnapshotInput, lan.lanSnapshot),
    tool("lan.newdevices", "Diff live devices vs latest snapshot ⇒ Finding[] (new MAC, MAC change). First run saves baseline.", undefined, lan.lanNewdevices),
    // wifi.*
    tool("wifi.status", "Current WiFi link: SSID, BSSID, band, channel, RSSI, PHY rate, quality.", undefined, wifi.wifiStatus),
    tool("wifi.networks", "Nearby AP survey: SSID, BSSID, band, channel, security.", undefined, wifi.wifiNetworks),
    tool("wifi.health", "WiFi interpretation: RSSI bands, channel overlap, band mismatch ⇒ Finding[].", undefined, wifi.wifiHealth),
    // sec.*
    tool("sec.connections", "Active sockets with owning PID/process.", undefined, sec.secConnections),
    tool("sec.listening", "Listening ports per process; flags non-loopback exposures.", undefined, sec.secListening),
    tool("sec.firewall", "Firewall profile state per platform (win profiles / ufw / socketfilterfw).", undefined, sec.secFirewall),
    tool("sec.exposure", "Composite security report: exposed listeners × firewall state × risky ports ⇒ Finding[].", undefined, sec.secExposure),
    tool("sec.speedtest", "Bounded download speed test (Cloudflare default, configurable). Rate-limited 1/min.", undefined, sec.secSpeedtest),
    withSchema("lan.wol", "Wake-on-LAN magic packet (UDP broadcast). Mutating: dry-run returns confirmToken; re-call with token to execute.", lan.lanToolSchemas.WolInput, lan.lanWol),
  ];
}

export function defaultContext(): ServiceContext {
  return makeContext(loadConfig());
}