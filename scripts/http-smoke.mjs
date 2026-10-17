#!/usr/bin/env node
// HTTP transport smoke: /health, tools/list, net.health over streamable HTTP
import { spawn } from "node:child_process";

const PORT = "3177";
const proc = spawn(process.execPath, ["dist/server.js"], {
  stdio: ["ignore", "pipe", "pipe"],
  env: { ...process.env, NETEXPERT_HTTP_PORT: PORT },
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

try {
  await sleep(1500);
  const h = await fetch(`http://127.0.0.1:${PORT}/health`);
  console.log("health", h.status, await h.text());

  const r = await fetch(`http://127.0.0.1:${PORT}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  const j = await r.json();
  console.log("tools/list via http:", j.result.tools.length, "tools");

  const c = await fetch(`http://127.0.0.1:${PORT}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "net.health", arguments: {} } }),
  });
  const cj = await c.json();
  console.log("net.health via http:", JSON.parse(cj.result.content[0].text).ok);
  process.exit(0);
} finally {
  proc.kill();
}