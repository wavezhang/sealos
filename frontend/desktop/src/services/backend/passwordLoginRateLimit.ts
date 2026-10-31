import type { NextApiRequest } from 'next';
import { getClientIp } from './requestIp';

/**
 * In-memory password login throttling.
 *
 * Scope: one Desktop process. Deployments with multiple replicas must put this
 * state in Redis (or another shared store), otherwise an attacker can multiply
 * the allowed attempts by the replica count.
 */
const WINDOW_MS = 60_000;
const MAX_FAILURES_PER_WINDOW = 5;
const BASE_LOCK_MS = 15 * 60_000;
const MAX_LOCK_MS = 24 * 60 * 60_000;
const MAX_ENTRIES = 10_000;

type PasswordLoginBucket = {
  failures: number;
  windowStartedAt: number;
  lockedUntil: number;
  lockLevel: number;
};

const buckets = new Map<string, PasswordLoginBucket>();

const prune = (now: number) => {
  if (buckets.size <= MAX_ENTRIES) return;
  for (const [key, bucket] of buckets) {
    if (bucket.lockedUntil <= now) buckets.delete(key);
    if (buckets.size <= MAX_ENTRIES) return;
  }
  // Every remaining bucket is locked: drop the oldest entries so a flood of
  // unique keys cannot grow the map without bound.
  for (const key of buckets.keys()) {
    buckets.delete(key);
    if (buckets.size <= MAX_ENTRIES) return;
  }
};

export const getPasswordLoginRateLimitKey = (req: NextApiRequest, username: string) => {
  const ip = getClientIp(req) || 'unknown-ip';
  return `${ip}|${username.trim().toLowerCase()}`;
};

export type PasswordLoginRateLimitResult =
  | { allowed: true }
  | { allowed: false; retryAfter: number };

export function checkPasswordLoginAllowed(key: string): PasswordLoginRateLimitResult {
  const now = Date.now();
  prune(now);
  const bucket = buckets.get(key);
  if (!bucket) return { allowed: true };
  if (bucket.lockedUntil > now) {
    return { allowed: false, retryAfter: Math.ceil((bucket.lockedUntil - now) / 1000) };
  }
  return { allowed: true };
}

export function recordPasswordLoginFailure(key: string): void {
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || now - bucket.windowStartedAt > WINDOW_MS) {
    buckets.set(key, {
      failures: 1,
      windowStartedAt: now,
      lockedUntil: 0,
      // Keep the escalation level so repeated lockouts back off exponentially.
      lockLevel: bucket?.lockLevel ?? 0
    });
    return;
  }

  bucket.failures += 1;
  if (bucket.failures >= MAX_FAILURES_PER_WINDOW) {
    bucket.lockLevel += 1;
    const lockMs = Math.min(BASE_LOCK_MS * 2 ** (bucket.lockLevel - 1), MAX_LOCK_MS);
    bucket.lockedUntil = now + lockMs;
    bucket.failures = 0;
    bucket.windowStartedAt = now;
  }
}

export function resetPasswordLoginFailures(key: string): void {
  buckets.delete(key);
}

// Exposed for tests; returns a snapshot without mutating state.
export const getPasswordLoginBucketCount = () => buckets.size;
