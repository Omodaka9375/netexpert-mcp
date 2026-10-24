import { describe, it, expect } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import type { SpawnSyncOptionsWithBufferEncoding } from "node:child_process";
import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/** npm via its real node entry — never a .cmd shim (Node >=18 refuses
 *  spawnSync(cmd-file) with shell:false on Windows: EINVAL), never a shell
 *  string (quoting mangles cwd paths with spaces). */
function npmCli(): string {
  const nodeDir = path.dirname(process.execPath);
  const candidates = [
    path.join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    path.join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"), // posix layout
  ];
  for (const c of candidates) {
    try {
      if (readdirSync(path.dirname(c)).includes(path.basename(c))) return c;
    } catch { /* keep looking */ }
  }
  throw new Error("cannot locate npm-cli.js next to " + process.execPath);
}
const NPM_CLI = npmCli();

/**
 * The shim regression test.
 *
 * 0.1.3/0.1.4 shipped a bin target with no shebang; npm 11's cmd-shim then
 * generated a DIRECT call to dist/server.js, which on Windows went through
 * the .js file association (WScript/notepad) instead of node — "opens
 * server.js in notepad", "Connection closed" in every MCP client.
 *
 * This test exercises the REAL artifact end-to-end, the way a user gets it:
 *   npm pack → npm install <tarball> → spawn the generated .bin shim →
 *   stdio MCP handshake (initialize + tools/list).
 *
 * It therefore fails on: missing shebang, broken shim generation, missing
 * dist files, broken bin entry — anything that makes the installed command
 * not speak MCP. Nothing in the unit suite catches this class of bug;
 * only the real artifact can.
 *
 * Runs in CI on ubuntu and windows (node 20/22).
 */

const ROOT = path.resolve(import.meta.dirname, "..");

/** Bounded exec: arg arrays only, capture stdout, fail hard on non-zero exit. */
function run(args: string[], opts: { cwd?: string; timeoutMs?: number } = {}): string {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const r = spawnSync(process.execPath, [NPM_CLI, ...args], {
    cwd: opts.cwd,
    timeout: timeoutMs,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    shell: false,
    windowsHide: true,
  });
  if (r.error || r.status !== 0) {
    throw new Error(`npm ${args.join(" ")} failed: ${r.error?.message ?? r.status}\n${(r.stderr ?? "").slice(0, 600)}`);
  }
  return r.stdout ?? "";
}

/** Full stdio MCP handshake against a spawned server binary. */
function mcpHandshake(cmd: string, args: string[], timeoutMs = 30_000): Promise<{ version?: string; tools?: unknown[] }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, { shell: false, stdio: ["pipe", "pipe", "inherit"] });
    let buf = "";
    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`handshake timeout after ${timeoutMs}ms (server never completed initialize/tools-list)`));
    }, timeoutMs);
    const fail = (m: string) => { clearTimeout(timer); proc.kill(); reject(new Error(m)); };

    proc.on("error", (e) => fail(`spawn failed: ${(e as NodeJS.ErrnoException).code ?? e.message}`));
    proc.stdout.on("data", (d: Buffer) => {
      buf += d.toString();
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(line) as Record<string, unknown>;
        } catch {
          // non-JSON on stdout = the bin is NOT speaking MCP (e.g. notepad
          // would never produce this, but a CLI printing help would)
          return fail(`stdout is not JSON-RPC: ${line.slice(0, 120)}`);
        }
        if (msg["id"] === 1) {
          const r = msg["result"] as { serverInfo?: { name?: string; version?: string } } | undefined;
          if (!r?.serverInfo) return fail("initialize reply missing serverInfo");
          proc.stdin?.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");
        } else if (msg["id"] === 2) {
          const r = msg["result"] as { tools?: unknown[] } | undefined;
          clearTimeout(timer);
          proc.kill();
          resolve({ version: undefined, tools: r?.tools });
          return;
        }
      }
    });
    proc.on("close", (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited before handshake completed (code=${code}) — the bin is broken`));
    });
    proc.stdin?.write(JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "pack-bin-test", version: "0" } },
    }) + "\n");
  });
}

describe("pack → install → real bin shim (the 0.1.4 notepad regression)", () => {
  it("the installed netexpert-mcp command speaks MCP over stdio", { timeout: 180_000 }, async () => {
    // 1. build dist/ first — CI runs the suite before `npm run build`, and
    //    npm pack --ignore-scripts skips prepublishOnly, so nothing else will
    run(["run", "build"], { cwd: ROOT, timeoutMs: 120_000 });

    // 2. pack the CURRENT tree (skip hooks: prepublishOnly re-runs the whole gate)
    run(["pack", "--ignore-scripts"], { cwd: ROOT, timeoutMs: 120_000 });

    // 2. find the tarball (name comes from package.json; glob by prefix)
    const entries = readdirSync(ROOT).filter((f) => /^netexpert-mcp-.*\.tgz$/.test(f));
    expect(entries.length).toBeGreaterThan(0);
    const tarball = path.join(ROOT, entries[0] ?? "");

    // 3. install into a temp dir (no hoisting surprises, like a real project)
    const tmp = mkdtempSync(path.join(os.tmpdir(), "netexpert-packbin-"));
    try {
      run(["install", "--no-audit", "--no-fund", "--loglevel=error", tarball], { cwd: tmp, timeoutMs: 120_000 });

      // 4. resolve the REAL generated shim from node_modules/.bin
      const binDir = path.join(tmp, "node_modules", ".bin");
      const binName = process.platform === "win32" ? "netexpert-mcp.cmd" : "netexpert-mcp";
      const shim = path.join(binDir, binName);
      expect(() => readdirSync(binDir)).not.toThrow();
      const bins = readdirSync(binDir);
      expect(bins).toContain(binName);

      // 5. spawn it and complete a full MCP handshake
      const spawnArgs: [string, string[]] =
        process.platform === "win32" ? ["cmd.exe", ["/c", shim]] : [shim, []];
      const result = await mcpHandshake(...spawnArgs);

      expect(Array.isArray(result.tools)).toBe(true);
      expect((result.tools as unknown[]).length).toBe(31);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});