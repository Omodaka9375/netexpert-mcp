#!/usr/bin/env node
// Smoke: build → spawn stdio → tools/list → net.health
import { spawn } from "node:child_process";

const proc = spawn(process.execPath, ["dist/server.js"], { stdio: ["pipe", "pipe", "inherit"] });
let buf = "";
const results = [];

function send(id, method, params) {
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
}

proc.stdout.on("data", (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id === 1) {
      results.push(`tools/list ok=${msg.result?.tools?.length ?? 0}`);
      send(2, "tools/call", { name: "net.health", arguments: {} });
    } else if (msg.id === 2) {
      const text = msg.result?.content?.[0]?.text ?? "";
      const parsed = JSON.parse(text);
      results.push(`net.health ok=${parsed.ok} platform=${parsed.data?.platform} version=${parsed.data?.version}`);
      console.log(results.join("\n"));
      proc.kill();
      process.exit(0);
    }
  }
});

proc.on("spawn", () => {
  send(1, "tools/list", {});
});

setTimeout(() => {
  console.error("SMOKE TIMEOUT");
  proc.kill();
  process.exit(1);
}, 20000);