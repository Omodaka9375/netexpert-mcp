import si from "systeminformation";
import { z } from "zod";
import type { ServiceContext, Envelope } from "./util.js";
import { okEnvelope, failEnvelope } from "./util.js";
import type { Finding } from "./lanService.js";

export interface WifiLink {
  ssid?: string;
  bssid?: string;
  band: "2.4" | "5" | "6" | "?";
  channel?: number;
  rssiDbm?: number;
  phyRateMbps?: number;
  quality: number; // 0-100
  security?: string;
  notes: string[];
}

export interface WifiAp {
  ssid?: string;
  bssid?: string;
  band: "2.4" | "5" | "6" | "?";
  channel?: number;
  rssiDbm?: number;
  security?: string;
}

function bandFor(channel: number | undefined, freqStr?: string): "2.4" | "5" | "6" | "?" {
  if (channel === undefined) return "?";
  if (freqStr?.startsWith("6")) return "6";
  if (channel >= 1 && channel <= 14) return "2.4";
  if (channel >= 32 && channel <= 233) return "5";
  return "?";
}

/** RSSI → quality 0-100 (log-ish scale; −40≈100, −90≈0). */
export function rssiToQuality(dbm: number): number {
  const clamped = Math.max(-90, Math.min(-40, dbm));
  return Math.round(((clamped + 90) / 50) * 100);
}

/** Interpret RSSI into a finding per SPEC band table. */
function rssiFinding(dbm: number): Finding | null {
  if (dbm >= -50) return null;
  if (dbm >= -60) {
    return { severity: "info", title: `Signal ${dbm} dBm — good`, evidence: "RSSI between −50 and −60 dBm", nextStep: "none needed; comfortable margin" };
  }
  if (dbm >= -70) {
    return { severity: "low", title: `Weak signal: ${dbm} dBm`, evidence: "RSSI between −60 and −70 dBm — expect throughput loss on 2.4 GHz", nextStep: "run wifi.networks to check for a closer/stronger AP or 5 GHz SSID" };
  }
  if (dbm >= -78) {
    return { severity: "med", title: `Poor signal: ${dbm} dBm`, evidence: "RSSI between −70 and −78 dBm — drops and retransmits likely", nextStep: "relocate the client or AP; verify with wifi.health after moving" };
  }
  return { severity: "high", title: `Unusable signal: ${dbm} dBm`, evidence: "RSSI below −78 dBm", nextStep: "move within sight of the AP or add a mesh node; check antenna orientation" };
}

// ---------------------------------------------------------------------------
// netsh wlan show interfaces parser (win32)
// ---------------------------------------------------------------------------

export function parseNetshWlanInterfaces(out: string): WifiLink | null {
  let ssid: string | undefined;
  let bssid: string | undefined;
  let channel: number | undefined;
  let rssi: number | undefined;
  let phyRate: number | undefined;
  let band: "2.4" | "5" | "6" | "?" = "?";
  let security: string | undefined;
  let bandRadio: string | undefined;
  for (const rawLine of out.split(/\r?\n/)) {
    const line = rawLine.trim();
    const kv = line.match(/^([^:]+)\s*:\s*(.*)$/);
    if (!kv?.[1]) continue;
    const key = kv[1].trim().toLowerCase();
    const val = (kv[2] ?? "").trim();
    if (key.startsWith("ssid") && key !== "bssid" && !key.includes("bis") && !val.startsWith("<")) ssid = val || undefined;
    if (key === "bssid") bssid = val.toLowerCase() || undefined;
    if (key === "channel") {
      const ch = Number.parseInt(val.split(/\s*:\s*/)[0] ?? val, 10);
      if (Number.isFinite(ch)) channel = ch;
    }
    if (key === "signal") {
      const pct = Number.parseFloat(val);
      if (Number.isFinite(pct)) rssi = Math.round((pct / 100) * 50 - 90);
    }
    if (key.startsWith("receive rate") || key.startsWith("transmit rate")) {
      const m = Number.parseFloat(val);
      if (Number.isFinite(m)) phyRate = Math.max(phyRate ?? 0, m);
    }
    if (key === "radio type" || key === "band") bandRadio = val;
    if (key === "authentication") security = val || undefined;
  }
  // Band: prefer radio type, fall back to channel
  if (bandRadio) {
    if (/802\.11a|5|6/.test(bandRadio) && !/2\.4/.test(bandRadio)) band = bandRadio.includes("6") ? "6" : "5";
    if (/802\.11b|802\.11g|2\.4/.test(bandRadio)) band = "2.4";
  } else {
    band = bandFor(channel);
  }
  if (ssid === undefined && bssid === undefined) return null;
  return {
    ssid, bssid, band, channel, rssiDbm: rssi, phyRateMbps: phyRate,
    quality: rssi !== undefined ? rssiToQuality(rssi) : 0,
    security, notes: [],
  };
}

// ---------------------------------------------------------------------------
// iw dev <if> link parser (linux) — RSSI only, channel absent (needs iw dev scan)
// ---------------------------------------------------------------------------

export function parseIwLink(out: string): WifiLink | null {
  let ssid: string | undefined;
  let rssi: number | undefined;
  for (const rawLine of out.split(/\r?\n/)) {
    const line = rawLine.trim();
    const ssidM = line.match(/^SSID:\s*(.+)$/);
    if (ssidM?.[1]) ssid = ssidM[1].trim();
    const sigM = line.match(/signal:\s*(-?\d+(?:\.\d+)?)\s*dBm/i);
    if (sigM?.[1]) rssi = Number.parseFloat(sigM[1]);
  }
  if (ssid === undefined && rssi === undefined) return null;
  return {
    ssid, band: "?",
    rssiDbm: rssi,
    quality: rssi !== undefined ? rssiToQuality(rssi) : 0,
    notes: rssi !== undefined ? [] : ["RSSI not reported by iw link"],
  };
}

// ---------------------------------------------------------------------------
// wifi.status / wifi.networks / wifi.health
// ---------------------------------------------------------------------------

export async function wifiStatus(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const platform = process.platform;
  try {
    if (platform === "win32") {
      const res = await ctx.runner.run("netsh", ["wlan", "show", "interfaces"], { timeoutMs: 10000 });
      const link = parseNetshWlanInterfaces(res.stdout);
      if (!link) {
        return failEnvelope(ctx, "wifi.status", { code: "EXEC_FAILED", message: "no connected WiFi interface found (netsh reported none)", hint: "you may be on Ethernet — check lan.interfaces" });
      }
      return okEnvelope(ctx, "wifi.status", { link }, { backend: "cmd:netsh wlan show interfaces", durationMs: Date.now() - start });
    }
    if (platform === "linux") {
      // try iw via a default wlan interface discovered from systeminformation
      const ifaces = await si.wifiNetworks().catch(() => [] as si.Systeminformation.WifiNetworkData[]);
      const iface = process.env["NETEXPERT_WIFI_IF"] ?? "wlan0";
      void ifaces;
      const res = await ctx.runner.run("iw", ["dev", iface, "link"], { timeoutMs: 10000 });
      const link = parseIwLink(res.stdout);
      if (!link) {
        return failEnvelope(ctx, "wifi.status", { code: "EXEC_FAILED", message: `iw dev ${iface} link returned nothing parseable`, hint: "iw not present or no WiFi — try nmcli or check the interface name (NETEXPERT_WIFI_IF)" });
      }
      return okEnvelope(ctx, "wifi.status", { link, scannedNetworksCount: ifaces.length }, { backend: `cmd:iw dev ${iface} link`, durationMs: Date.now() - start });
    }
    // darwin: systeminformation (airport deprecated per SPEC)
    const networks = await si.wifiNetworks();
    void networks;
    const link = await si.wifiConnections().then((conns) => conns[0] ?? null).catch(() => null);
    if (!link) {
      return failEnvelope(ctx, "wifi.status", { code: "EXEC_FAILED", message: "no WiFi connection found via systeminformation", hint: "try running while connected to WiFi, or check System Settings" });
    }
    return okEnvelope(ctx, "wifi.status", { link }, { backend: "systeminformation.wifiConnections", durationMs: Date.now() - start });
  } catch (e) {
    return failEnvelope(ctx, "wifi.status", {
      code: process.platform === "win32" ? "EXEC_FAILED" : "BACKEND_MISSING",
      message: `WiFi link query failed: ${e instanceof Error ? e.message : "unknown"}`,
      hint: process.platform === "linux" ? "sudo apt install iw (or use a machine with WiFi)" : "verify the machine has a WiFi adapter",
    });
  }
}

export async function wifiNetworks(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  try {
    const nets = await si.wifiNetworks();
    const aps: WifiAp[] = nets.map((n) => {
      const channel = Number.parseInt(String(n.channel ?? ""), 10);
      return {
        ssid: n.ssid || undefined,
        bssid: n.bssid || undefined,
        band: bandFor(Number.isFinite(channel) ? channel : undefined, String(n.frequency ?? "")),
        channel: Number.isFinite(channel) ? channel : undefined,
        security: Array.isArray(n.security) ? n.security.join(", ") : String(n.security) || undefined,
      };
    });
    return okEnvelope(ctx, "wifi.networks", { aps }, { backend: "systeminformation.wifiNetworks", durationMs: Date.now() - start });
  } catch (e) {
    return failEnvelope(ctx, "wifi.networks", { code: "EXEC_FAILED", message: `WiFi survey failed: ${e instanceof Error ? e.message : "unknown"}`, hint: "verify the WiFi adapter is enabled" });
  }
}

export async function wifiHealth(ctx: ServiceContext): Promise<Envelope<object>> {
  const start = Date.now();
  const findings: Finding[] = [];
  const statusEnv = await wifiStatus(ctx);
  if (!statusEnv.ok || !statusEnv.data) {
    return failEnvelope(ctx, "wifi.health", { code: "EXEC_FAILED", message: "cannot assess WiFi health — no link", hint: "run wifi.status for details" });
  }
  const link = (statusEnv.data as { link: WifiLink }).link;
  if (link.rssiDbm !== undefined) {
    const f = rssiFinding(link.rssiDbm);
    if (f) findings.push(f);
  } else {
    findings.push({ severity: "info", title: "Signal strength not reported", evidence: "backend did not expose RSSI", nextStep: "interpret throughput issues via net.ping to the gateway instead" });
  }

  // Channel-overlap + band-mismatch analysis needs the survey
  const surveyEnv = await wifiNetworks(ctx);
  let aps: WifiAp[] = [];
  let mySsid: string | undefined;
  let myChannel: number | undefined;
  let coChannelAps = 0;
  let fiveGhzAvailable = false;
  if (surveyEnv.ok && surveyEnv.data) {
    aps = (surveyEnv.data as { aps: WifiAp[] }).aps;
    mySsid = link.ssid;
    myChannel = link.channel;
    for (const ap of aps) {
      if (ap.band === "5" || ap.band === "6") fiveGhzAvailable = true;
      if (myChannel !== undefined && ap.channel === myChannel && (mySsid === undefined || ap.ssid !== mySsid)) coChannelAps++;
      void mySsid;
    }
  }
  if (link.band === "2.4" && coChannelAps > 0) {
    findings.push({
      severity: coChannelAps > 2 ? "med" : "low",
      title: `2.4 GHz channel overlap: ${coChannelAps} other AP${coChannelAps > 1 ? "s" : ""} on channel ${myChannel}`,
      evidence: `client is on 2.4 GHz channel ${myChannel}; co-channel APs cause airtime contention`,
      nextStep: "move the AP to channels 1/6/11 with least overlap, or lock the client to 5 GHz",
    });
  }
  if (link.band === "2.4" && fiveGhzAvailable) {
    findings.push({
      severity: "low",
      title: "Band mismatch: client on 2.4 GHz while 5/6 GHz SSIDs exist",
      evidence: "5 GHz has more channels and less interference for the same SSID",
      nextStep: "lock the client to the 5 GHz SSID or enable band steering on the router",
    });
  }
  if (link.phyRateMbps !== undefined && link.phyRateMbps < 100 && link.rssiDbm !== undefined && link.rssiDbm < -60) {
    findings.push({
      severity: "low",
      title: `Low PHY rate: ${link.phyRateMbps} Mbps`,
      evidence: `negotiated rate ${link.phyRateMbps} Mbps with RSSI ${link.rssiDbm} dBm`,
      nextStep: "improve signal or verify the adapter supports 802.11ac/ax on this band",
    });
  }
  if (findings.length === 0) {
    findings.push({ severity: "info", title: "WiFi link healthy", evidence: `band ${link.band}, quality ${link.quality}%`, nextStep: "none — no thresholds exceeded" });
  }
  return okEnvelope(ctx, "wifi.health", { link, surveyedAps: aps.length, findings }, { backend: "computed (netsh/iw + systeminformation)", durationMs: Date.now() - start });
}

export const wifiToolSchemas = {};