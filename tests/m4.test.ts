import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NetexpertConfig } from "../src/config.js";
import { makeContext } from "../src/services/util.js";
import { ConfirmationTokenService } from "../src/safety/confirm.js";
import { lanWol } from "../src/services/lanService.js";

let snapshotsDir = "";

beforeEach(() => {
  snapshotsDir = fs.mkdtempSync(path.join(os.tmpdir(), "netexpert-m4-"));
});
afterEach(() => {
  fs.rmSync(snapshotsDir, { recursive: true, force: true });
});

function ctx() {
  const config = NetexpertConfig.parse({
    paths: { snapshotsDir },
    caps: { speedtest: { downloadBytes: 100000, timeoutMs: 20000 } },
  });
  return makeContext(config);
}

describe("ConfirmationTokenService", () => {
  it("dry-run plans, then confirms exactly the same action", () => {
    const svc = new ConfirmationTokenService();
    const { confirmToken } = svc.plan("lan.wol", "test", { mac: "aa:bb:cc:dd:ee:ff", port: 9 });
    const res = svc.confirm("lan.wol", { mac: "aa:bb:cc:dd:ee:ff", port: 9 }, confirmToken);
    expect(res.ok).toBe(true);
  });

  it("rejects parameter drift between plan and confirm", () => {
    const svc = new ConfirmationTokenService();
    const { confirmToken } = svc.plan("lan.wol", "test", { mac: "aa:bb:cc:dd:ee:ff", port: 9 });
    const res = svc.confirm("lan.wol", { mac: "11:22:33:44:55:66", port: 9 }, confirmToken);
    expect(res.ok).toBe(false);
  });

  it("is single-use", () => {
    const svc = new ConfirmationTokenService();
    const { confirmToken } = svc.plan("lan.wol", "test", { mac: "aa:bb:cc:dd:ee:ff", port: 9 });
    expect(svc.confirm("lan.wol", { mac: "aa:bb:cc:dd:ee:ff", port: 9 }, confirmToken).ok).toBe(true);
    const second = svc.confirm("lan.wol", { mac: "aa:bb:cc:dd:ee:ff", port: 9 }, confirmToken);
    expect(second.ok).toBe(false);
  });

  it("rejects unknown tokens", () => {
    const svc = new ConfirmationTokenService();
    expect(svc.confirm("lan.wol", { mac: "aa:bb:cc:dd:ee:ff", port: 9 }, "bogus").ok).toBe(false);
  });
});

describe("lan.wol (executes over real UDP loopback-safe broadcast)", () => {
  it("dry-run returns a plan + token, no packet sent", async () => {
    const res = await lanWol(ctx(), { mac: "AA:BB:CC:DD:EE:FF", port: 9 });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.planned.tool).toBe("lan.wol");
    expect(typeof env.data.confirmToken).toBe("string");
    expect(env.data.note).toContain("dry-run");
  });

  it("wrong token ⇒ CONFIRMATION_REQUIRED", async () => {
    const res = await lanWol(ctx(), { mac: "AA:BB:CC:DD:EE:FF", port: 9, confirmToken: "bogus" });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(false);
    expect(env.error.code).toBe("CONFIRMATION_REQUIRED");
  });

  it("valid token sends the magic packet", async () => {
    const c = ctx();
    const dry = await lanWol(c, { mac: "AA:BB:CC:DD:EE:FF", port: 9 });
    const token = (JSON.parse(JSON.stringify(dry)).data as { confirmToken: string }).confirmToken;
    const res = await lanWol(c, { mac: "AA:BB:CC:DD:EE:FF", port: 9, confirmToken: token });
    const env = JSON.parse(JSON.stringify(res));
    expect(env.ok).toBe(true);
    expect(env.data.sent).toBe(true);
    expect(env.data.bytes).toBe(102); // 6×0xFF + 16×6 MAC bytes
  });

  it("token reuse is rejected", async () => {
    const c = ctx();
    const dry = await lanWol(c, { mac: "AA:BB:CC:DD:EE:FF", port: 9 });
    const token = (JSON.parse(JSON.stringify(dry)).data as { confirmToken: string }).confirmToken;
    await lanWol(c, { mac: "AA:BB:CC:DD:EE:FF", port: 9, confirmToken: token });
    const again = await lanWol(c, { mac: "AA:BB:CC:DD:EE:FF", port: 9, confirmToken: token });
    const env = JSON.parse(JSON.stringify(again));
    expect(env.ok).toBe(false);
    expect(env.error.code).toBe("CONFIRMATION_REQUIRED");
  });
});