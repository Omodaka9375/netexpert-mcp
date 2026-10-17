#!/usr/bin/env node
// Build-time only: fetch the IEEE OUI registry (via Wireshark's mirrored `manuf`
// since standards-ieee.org may be DNS-blocked on some machines) → src/data/oui.json
// (map of 6-hex uppercase prefixes → vendor names).
// Never fetched at runtime. Regenerate on demand: `node scripts/gen-oui.mjs`
import fs from "node:fs";
import path from "node:path";

const SOURCES = [
  "https://www.wireshark.org/download/automated/data/manuf", // Wireshark mirror of IEEE OUI (MA-L)
  "https://standards-ieee.org/wp-content/uploads/develop/oui/oui.csv", // canonical IEEE CSV
];
const OUT = path.join(import.meta.dirname, "..", "src", "data", "oui.json");

/** Wireshark manuf format (tshark -G manuf): `<MAC>\t<short name>\t<full vendor name>`.
 *  MA-L = 24-bit = 3 colon-separated byte pairs; we keep only those. */
async function fromManuf() {
  const res = await fetch(SOURCES[0]);
  if (!res.ok) throw new Error(`manuf fetch failed: ${res.status}`);
  const text = await res.text();
  const oui = {};
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("#") || line.trim() === "") continue;
    const cells = line.split("\t");
    if (cells.length < 2) continue;
    const prefix = (cells[0] ?? "").trim();
    // 24-bit MA-L prefixes only: exactly 3 hex byte pairs
    if (!/^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$/.test(prefix)) continue;
    const hex = prefix.replaceAll(":", "");
    const name = (cells[cells.length - 1] ?? "").trim();
    if (name) oui[hex] = name;
  }
  return oui;
}

/** IEEE CSV: columns Registry, Assignment, Organization Name. */
async function fromIeeeCsv() {
  const res = await fetch(SOURCES[1]);
  if (!res.ok) throw new Error(`IEEE CSV fetch failed: ${res.status}`);
  const csv = await res.text();
  const lines = csv.split(/\r?\n/);
  const header = lines.shift() ?? "";
  const cols = header.split(",").map((h) => h.trim().replace(/"/g, ""));
  const registryCol = cols.indexOf("Registry");
  const assignmentCol = cols.indexOf("Assignment");
  const orgCol = cols.indexOf("Organization Name");
  if (registryCol < 0 || assignmentCol < 0 || orgCol < 0) {
    throw new Error("unexpected CSV header: " + header);
  }
  const oui = {};
  for (const line of lines) {
    if (!line) continue;
    const cells = line.split(",");
    const registry = (cells[registryCol] ?? "").replace(/"/g, "").trim();
    if (registry !== "MA-L") continue;
    const hex = (cells[assignmentCol] ?? "").replace(/"/g, "").trim().toUpperCase();
    if (!/^[0-9A-F]{6}$/.test(hex)) continue;
    const name = (cells[orgCol] ?? "").replace(/"/g, "").trim();
    if (name) oui[hex] = name;
  }
  return oui;
}

async function main() {
  let oui;
  try {
    oui = await fromManuf();
  } catch {
    oui = await fromIeeeCsv();
  }
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(oui));
  console.log(`wrote ${OUT}: ${Object.keys(oui).length} OUI entries`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});