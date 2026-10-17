import type { NetexpertConfigT } from "../config.js";

/** Token-bucket-ish rate limiter: min seconds between calls per key. */
export class RateLimiter {
  private last = new Map<string, number>();

  constructor(private rateCfg: NetexpertConfigT["rate"]) {}

  /** Returns retryAfterMs if rate-limited, else undefined (and marks the call). */
  check(key: string, now = Date.now()): number | undefined {
    const minSec = this.rateCfg[key as keyof NetexpertConfigT["rate"]] ?? 0;
    if (minSec <= 0) {
      this.last.set(key, now);
      return undefined;
    }
    const prev = this.last.get(key);
    if (prev !== undefined) {
      const elapsed = (now - prev) / 1000;
      if (elapsed < minSec) {
        return Math.ceil((minSec - elapsed) * 1000);
      }
    }
    this.last.set(key, now);
    return undefined;
  }
}

export function isRfc1918(ip: string): boolean {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return false;
  }
  const [a, b] = [parts[0] ?? 0, parts[1] ?? 0];
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

export function cidrHostCount(cidrPrefix: number): number {
  return 2 ** (32 - cidrPrefix);
}

/** Hard bounds check for sweep subnets. */
export function sweepWithinBounds(cidrPrefix: number, maxHosts: number): boolean {
  return cidrHostCount(cidrPrefix) <= maxHosts * 4;
}