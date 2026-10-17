import type { NetexpertConfigT } from "../config.js";
import type { RunResult, CommandRunner } from "../exec/executor.js";
import { LocalExecutor } from "../exec/executor.js";
import { RateLimiter } from "../safety/caps.js";
import { ConfirmationTokenService } from "../safety/confirm.js";

export type { NetexpertConfigT, RunResult, CommandRunner, RateLimiter, ConfirmationTokenService };

/** One envelope for every tool (SPEC §5). */
export interface Envelope<T> {
  ok: boolean;
  tool: string;
  platform: NodeJS.Platform;
  backend?: string;
  durationMs?: number;
  data?: T;
  warnings?: string[];
  error?: { code: string; message: string; hint?: string };
}

export class ToolError extends Error {
  constructor(
    public code: string,
    message: string,
    public hint?: string,
  ) {
    super(message);
  }
}

export interface ServiceContext {
  runner: CommandRunner;
  config: NetexpertConfigT;
  caps: { rate: RateLimiter };
  confirm: ConfirmationTokenService;
}

export function makeContext(config: NetexpertConfigT, runner: CommandRunner = new LocalExecutor()): ServiceContext {
  return { runner, config, caps: { rate: new RateLimiter(config.rate) }, confirm: new ConfirmationTokenService() };
}

export function okEnvelope<T>(
  ctx: ServiceContext,
  tool: string,
  data: T,
  opts: { backend?: string; warnings?: string[]; durationMs?: number } = {},
): Envelope<T> {
  return {
    ok: true,
    tool,
    platform: process.platform,
    backend: opts.backend,
    durationMs: opts.durationMs,
    data,
    warnings: opts.warnings?.length ? opts.warnings : undefined,
  };
}

export function failEnvelope(
  ctx: ServiceContext,
  tool: string,
  e: { code: string; message: string; hint?: string },
): Envelope<never> {
  return {
    ok: false,
    tool,
    platform: process.platform,
    error: e,
  };
}