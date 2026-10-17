import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShape } from "zod";
import { z } from "zod";
import { buildToolset, defaultContext } from "./toolset.js";

/** Convert a zod object schema into the raw shape MCP tool() expects. */
function toRawShape(schema: unknown): ZodRawShape {
  if (schema instanceof z.ZodObject) {
    return schema.shape as ZodRawShape;
  }
  return {};
}

export function createServer(): McpServer {
  const server = new McpServer({ name: "netexpert-mcp", version: "0.1.0" });
  const ctx = defaultContext();
  for (const t of buildToolset()) {
    server.tool(
      t.name,
      t.description,
      toRawShape(t.schema),
      async (raw: unknown) => {
        const result = await t.handler(ctx, raw);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      },
    );
  }
  return server;
}