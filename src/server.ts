import http from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./mcp/createServer.js";
import { loadConfig } from "./config.js";
import { VERSION } from "./services/coreService.js";

async function main(): Promise<void> {
  const config = loadConfig();

  if (config.httpPort > 0) {
    // Optional stateless streamable HTTP at /mcp + /health (fresh server per request)
    const httpServer = http.createServer(async (req, res) => {
      const url = req.url ?? "/";
      if (url === "/health") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, server: "netexpert-mcp", version: VERSION }));
        return;
      }
      if (url === "/mcp" && req.method === "POST") {
        // streamable HTTP: single JSON-RPC message per request body
        let body = "";
        for await (const chunk of req) body += chunk as string;
        let message: unknown;
        try {
          message = JSON.parse(body);
        } catch {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }));
          return;
        }
        // minimal dispatch: handle initialize + tools/list without persistent session
        // (full stateful transport requires the SDK's HTTP transport; for stateless
        // probing we respond to initialize directly)
        const msg = message as { id?: number | string; method?: string; jsonrpc?: string };
        if (msg.method === "initialize") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "netexpert-mcp", version: VERSION } } }));
          return;
        }
        if (msg.method === "tools/list") {
          const { buildToolset } = await import("./mcp/toolset.js");
          const tools = buildToolset().map((t) => ({ name: t.name, description: t.description }));
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools } }));
          return;
        }
        if (msg.method === "tools/call") {
          // stateless tool calls over HTTP: spawn a fresh server per request (SPEC §4.1)
          // reuse the stdio path in-process
          const { buildToolset, defaultContext } = await import("./mcp/toolset.js");
          const params = (msg as { params?: { name?: string; arguments?: unknown } }).params ?? {};
          const tool = buildToolset().find((t) => t.name === params.name);
          if (!tool) {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: JSON.stringify({ ok: false, error: { code: "VALIDATION", message: `unknown tool ${params.name ?? ""}` } }) }] } }));
            return;
          }
          const result = await tool.handler(defaultContext(), params.arguments ?? {});
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] } }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? null, error: { code: -32601, message: `method ${msg.method ?? "?"} not supported over stateless HTTP` } }));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found — POST to /mcp, GET /health" }));
    });
    httpServer.listen(config.httpPort);
    console.error(`netexpert-mcp streamable HTTP on http://127.0.0.1:${config.httpPort}/mcp (stateless)`);
    return;
  }

  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

void main();