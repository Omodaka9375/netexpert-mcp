import crypto from "node:crypto";

/** A planned mutating action, commands frozen at plan time (ugnas pattern). */
export interface PlannedAction {
  tool: string;
  summary: string;
  params: Record<string, unknown>;
  /** ISO time when the plan expires */
  expiresAt: string;
}

const TTL_MS = 10 * 60 * 1000; // 10-min TTL per SPEC §6

interface StoredPlan {
  action: PlannedAction;
  /** canonical string the token is bound to */
  boundTo: string;
  token: string;
}

/** Single-use, action-bound, 10-min-TTL confirmation tokens. */
export class ConfirmationTokenService {
  private plans = new Map<string, StoredPlan>();

  /** Create a plan → returns the dry-run payload and a token the client echoes back. */
  plan(tool: string, summary: string, params: Record<string, unknown>): { planned: PlannedAction; confirmToken: string } {
    const token = crypto.randomUUID();
    const action: PlannedAction = {
      tool,
      summary,
      params,
      expiresAt: new Date(Date.now() + TTL_MS).toISOString(),
    };
    const boundTo = JSON.stringify({ tool, params });
    this.plans.set(token, { action, boundTo, token });
    return { planned: action, confirmToken: token };
  }

  /** Validate a token against the exact action being confirmed. Single-use. */
  confirm(tool: string, params: Record<string, unknown>, token: string): { ok: true; action: PlannedAction } | { ok: false; reason: string } {
    const stored = this.plans.get(token);
    this.plans.delete(token); // single use, always
    if (!stored) {
      return { ok: false, reason: "unknown or already-used confirmation token" };
    }
    if (stored.action.tool !== tool) {
      return { ok: false, reason: "token was issued for a different action" };
    }
    if (JSON.stringify({ tool, params }) !== stored.boundTo) {
      return { ok: false, reason: "action parameters differ from the planned ones — re-plan and re-confirm" };
    }
    if (Date.now() > new Date(stored.action.expiresAt).getTime()) {
      return { ok: false, reason: "confirmation token expired (10-min TTL) — re-plan" };
    }
    return { ok: true, action: stored.action };
  }
}