import { createHash } from 'node:crypto';
import { HttpError } from './http.ts';

const MAX_BUCKETS = 10000;
type Bucket = { tokens: number; at: number; capacity: number; perMinute: number };
const refilled = (b: Bucket, now: number): number => Math.min(b.capacity, b.tokens + Math.max(0, now - b.at) * b.perMinute / 60_000);

const fullAt = (b: Bucket): number => b.at + Math.max(0, b.capacity - b.tokens) * 60_000 / b.perMinute;

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  /** No bucket is full before this instant: until then a new key is refused without scanning the map. Taking from a
   *  bucket only delays its refill and no bucket is added while the map is full, so the bound stays true. */
  private noRoomUntil = 0;
  take(key: string, now: number, capacity = 120, perMinute = capacity, cost = 1): void {
    const old = this.buckets.get(key);
    // A full map makes room only by dropping a bucket that has refilled: dropping a drained one would hand its sender a
    // fresh bucket, so a sender holding many addresses could reset its own limits. No room: the new key waits.
    if (!old && this.buckets.size >= MAX_BUCKETS && !this.evictRefilled(now)) {
      throw new HttpError(429, 'rate_limited', 'Too many requests', [Math.max(1, Math.ceil((this.noRoomUntil - now) / 1000))]);
    }
    const tokens = old ? refilled({ ...old, capacity, perMinute }, now) : capacity;
    if (tokens < cost) throw new HttpError(429, 'rate_limited', 'Too many requests', [Math.ceil((cost - tokens) * 60 / perMinute)]);
    this.buckets.delete(key);
    this.buckets.set(key, { tokens: tokens - cost, at: now, capacity, perMinute });
  }

  /** Drops the least recently used bucket that is full again (it holds no state); false when none is. */
  private evictRefilled(now: number): boolean {
    if (now < this.noRoomUntil) return false;
    let earliest = Infinity;
    for (const [key, bucket] of this.buckets) {
      if (refilled(bucket, now) >= bucket.capacity) { this.buckets.delete(key); return true; }
      earliest = Math.min(earliest, fullAt(bucket));
    }
    this.noRoomUntil = earliest;
    return false;
  }
}

export interface RateLimitLease { granted: number; available: number }
export type LeaseRateLimit = (key: string, capacity: number, perMinute: number, amount: number) => Promise<RateLimitLease>;
type LeaseBucket = { tokens: number; retryAt: number; pending?: Promise<RateLimitLease> };

/** Cluster mode: tokens come only from the shared bucket. Leasing can idle capacity on a node, never overspend it. */
export class LeasedRateLimiter {
  private readonly buckets = new Map<string, LeaseBucket>();
  private readonly lease: LeaseRateLimit;
  constructor(lease: LeaseRateLimit) { this.lease = lease; }

  private keep(key: string, bucket: LeaseBucket): void {
    this.buckets.delete(key); this.buckets.set(key, bucket);
    while (this.buckets.size > 10000) this.buckets.delete(this.buckets.keys().next().value!);
  }

  async take(key: string, _now: number, capacity = 120, perMinute = capacity, cost = 1): Promise<void> {
    if (cost > capacity) throw new HttpError(429, 'rate_limited', 'Too many requests', [Math.ceil((cost - capacity) * 60 / perMinute)]);
    const bucket = this.buckets.get(key) ?? { tokens: 0, retryAt: 0 };
    this.keep(key, bucket);
    while (bucket.pending) {
      try { await bucket.pending; }
      catch (err) {
        if (err instanceof HttpError) throw err;
        throw new HttpError(503, 'unavailable', 'Rate limit store unavailable');
      }
    }
    if (bucket.tokens < cost) {
      const now = Date.now();
      if (now < bucket.retryAt) throw new HttpError(429, 'rate_limited', 'Too many requests', [Math.ceil((bucket.retryAt - now) / 1000)]);
      // One statement leases at most 1000 tokens, or a tenth of a smaller bucket (a large single request still fits).
      const amount = Math.min(capacity, Math.max(cost, Math.min(1000, Math.ceil(capacity / 10))));
      const pending = this.lease(createHash('sha256').update(key).digest('hex'), capacity, perMinute, amount);
      bucket.pending = pending;
      try {
        const leased = await pending;
        bucket.tokens += leased.granted;
        if (bucket.tokens < cost) {
          const seconds = Math.max(1, Math.ceil((cost - bucket.tokens - leased.available) * 60 / perMinute));
          bucket.retryAt = Date.now() + seconds * 1000;
        } else bucket.retryAt = 0;
      } catch (err) {
        if (err instanceof HttpError) throw err;
        throw new HttpError(503, 'unavailable', 'Rate limit store unavailable');
      } finally {
        bucket.pending = undefined;
        this.keep(key, bucket);
      }
      if (bucket.tokens < cost) throw new HttpError(429, 'rate_limited', 'Too many requests', [Math.max(1, Math.ceil((bucket.retryAt - Date.now()) / 1000))]);
    }
    bucket.tokens -= cost;
    bucket.retryAt = 0;
    this.keep(key, bucket);
  }
}

export const DEFAULT_RATE_LIMIT = 120;
export const DEFAULT_PEP_RATE_LIMIT = 60_000;
/** The largest batch (/access/v1/evaluations) costs 1000: a smaller decision-plane budget could never serve it. */
export const MIN_PEP_RATE_LIMIT = 1000;

/** Rate limits from the environment: positive integers per minute; the decision-plane one at least MIN_PEP_RATE_LIMIT. */
export function rateLimitsFromEnv(env: Record<string, string | undefined>): { rateLimit?: number; pepRateLimit?: number; blpSessionCreationRateLimit?: number } {
  const read = (name: string, v: string | undefined, min: number): number | undefined => {
    if (v === undefined || v === '') return undefined;
    const n = Number(v);
    if (!Number.isInteger(n) || n < min) throw new Error(`${name} must be an integer of at least ${min} (requests per minute)`);
    return n;
  };
  const rateLimit = read('RATE_LIMIT_PER_MINUTE', env.RATE_LIMIT_PER_MINUTE, 1);
  const pepRateLimit = read('PEP_RATE_LIMIT_PER_MINUTE', env.PEP_RATE_LIMIT_PER_MINUTE, MIN_PEP_RATE_LIMIT);
  const blpSessionCreationRateLimit = read('BLP_SESSION_CREATION_PER_MINUTE', env.BLP_SESSION_CREATION_PER_MINUTE, 1);
  return { ...(rateLimit !== undefined ? { rateLimit } : {}), ...(pepRateLimit !== undefined ? { pepRateLimit } : {}),
    ...(blpSessionCreationRateLimit !== undefined ? { blpSessionCreationRateLimit } : {}) };
}
