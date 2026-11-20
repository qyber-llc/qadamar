import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';

/** OpenTelemetry traces over OTLP/HTTP JSON without an SDK: one SERVER span per request, INTERNAL child spans for
 *  decisions and commits, W3C traceparent in. Attributes are route family, status, effect and rule ids only. */
export interface TracingConfig {
  /** OTEL_EXPORTER_OTLP_ENDPOINT: the collector base URL; spans go to <endpoint>/v1/traces. */
  endpoint: string;
  serviceName?: string;
  maxQueue?: number; maxBatch?: number; intervalMs?: number; timeoutMs?: number; backoffBaseMs?: number; backoffMaxMs?: number;
}
type Value = string | number | readonly string[];
interface Span { traceId: string; spanId: string; parentSpanId?: string; name: string; kind: 1 | 2; start: number; end: number; attributes: Record<string, Value>; error: boolean }
interface Active { tracer: Tracer; traceId: string; spanId: string; parentSpanId?: string; start: number; children: number; dropped: number }

const current = new AsyncLocalStorage<Active>();
/** A search can decide thousands of candidates: past this, child spans are counted on the request span, not sent. */
export const MAX_CHILD_SPANS = 100;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
// collector answers worth retrying (OTLP/HTTP spec); any other refusal drops the batch
const RETRYABLE = new Set([429, 502, 503, 504]);
/** Real wall time in ms: traces never follow a pinned business clock. */
export const traceClock = (): number => performance.timeOrigin + performance.now();
const hex = (bytes: number): string => randomBytes(bytes).toString('hex');

export function parseTraceparent(header: unknown): { traceId: string; parentSpanId: string; sampled: boolean } | undefined {
  if (typeof header !== 'string') return undefined;
  const m = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?$/.exec(header.trim());
  if (!m || m[1] === 'ff' || (m[1] === '00' && m[5] !== undefined) || /^0+$/.test(m[2]!) || /^0+$/.test(m[3]!)) return undefined;
  return { traceId: m[2]!, parentSpanId: m[3]!, sampled: (Number.parseInt(m[4]!, 16) & 1) === 1 };
}
export function tracesUrl(endpoint: string): string {
  let url: URL;
  try { url = new URL(endpoint); } catch { throw new Error('Invalid OTEL_EXPORTER_OTLP_ENDPOINT'); }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.search || url.hash) {
    throw new Error('OTEL_EXPORTER_OTLP_ENDPOINT must be an http(s) URL without credentials, query or fragment');
  }
  const base = url.toString();
  return base.endsWith('/') ? `${base}v1/traces` : `${base}/v1/traces`;
}
export function tracingFromEnv(env: NodeJS.ProcessEnv): TracingConfig | undefined {
  if (!env.OTEL_EXPORTER_OTLP_ENDPOINT) return undefined;
  return { endpoint: env.OTEL_EXPORTER_OTLP_ENDPOINT, ...(env.OTEL_SERVICE_NAME ? { serviceName: env.OTEL_SERVICE_NAME } : {}) };
}

/** Records an INTERNAL span under the current request span; a no-op outside a traced request. */
export function childSpan(name: string, start: number, attributes: Record<string, Value> = {}, error = false): void {
  const parent = current.getStore();
  if (!parent) return;
  if (parent.children >= MAX_CHILD_SPANS) { parent.dropped++; return; }
  parent.children++;
  parent.tracer.record({ traceId: parent.traceId, spanId: hex(8), parentSpanId: parent.spanId, name, kind: 1, start, end: traceClock(), attributes, error });
}
/** Ends the current request span; called once, when the response is written. */
export function endRequestSpan(method: string, family: string, status: number, client?: string): void {
  const span = current.getStore();
  if (!span) return;
  const verb = METHODS.has(method) ? method : '_OTHER';
  span.tracer.record({ traceId: span.traceId, spanId: span.spanId, ...(span.parentSpanId ? { parentSpanId: span.parentSpanId } : {}),
    name: `${verb} ${family}`, kind: 2, start: span.start, end: traceClock(), error: status >= 500,
    attributes: { 'http.request.method': verb, 'http.response.status_code': status, 'gate.route_family': family,
      ...(client ? { 'client.address': client } : {}), ...(span.dropped ? { 'gate.dropped_child_spans': span.dropped } : {}) } });
}

function positive(value: number | undefined, fallback: number, name: string): number {
  const v = value ?? fallback;
  if (!Number.isSafeInteger(v) || v < 1) throw new Error(`Invalid tracing ${name}`);
  return v;
}
const attributes = (values: Record<string, Value>): unknown[] => Object.entries(values).map(([key, v]) => ({ key,
  value: typeof v === 'string' ? { stringValue: v } : typeof v === 'number' ? { intValue: String(v) } : { arrayValue: { values: v.map((s) => ({ stringValue: s })) } } }));
const nanos = (ms: number): string => (BigInt(Math.round(ms * 1000)) * 1000n).toString();

export class Tracer {
  readonly url: string;
  private readonly serviceName: string;
  private readonly limits: { maxQueue: number; maxBatch: number; timeoutMs: number; backoffBaseMs: number; backoffMaxMs: number };
  private queue: Span[] = [];
  private failures = 0;
  private retryAt = 0;
  private sending?: Promise<void>;
  private readonly timer: NodeJS.Timeout;
  /** Spans not exported: queue full, or refused by the collector with a non-retryable status. */
  dropped = 0;

  constructor(config: TracingConfig) {
    this.url = tracesUrl(config.endpoint);
    this.serviceName = config.serviceName || 'gate-pdp';
    this.limits = { maxQueue: positive(config.maxQueue, 2048, 'queue size'), maxBatch: positive(config.maxBatch, 512, 'batch size'),
      timeoutMs: positive(config.timeoutMs, 10_000, 'timeout'), backoffBaseMs: positive(config.backoffBaseMs, 1_000, 'backoff'),
      backoffMaxMs: positive(config.backoffMaxMs, 60_000, 'maximum backoff') };
    this.timer = setInterval(() => void this.flush(), positive(config.intervalMs, 5_000, 'interval'));
    this.timer.unref();
  }
  get queued(): number { return this.queue.length; }

  /** Runs one request inside its SERVER span; an incoming unsampled traceparent records nothing (parent-based sampling). */
  trace<T>(traceparent: unknown, run: () => Promise<T>): Promise<T> {
    const parent = parseTraceparent(traceparent);
    if (parent && !parent.sampled) return run();
    return current.run({ tracer: this, traceId: parent?.traceId ?? hex(16), spanId: hex(8), ...(parent ? { parentSpanId: parent.parentSpanId } : {}),
      start: traceClock(), children: 0, dropped: 0 }, run);
  }
  record(span: Span): void {
    if (this.queue.length >= this.limits.maxQueue) { this.dropped++; return; }
    this.queue.push(span);
    if (this.queue.length === this.limits.maxBatch) setImmediate(() => void this.flush());
  }
  /** Exports what is queued unless a backoff is running. Never rejects. */
  flush(): Promise<void> {
    this.sending ??= this.drain().finally(() => { this.sending = undefined; });
    return this.sending;
  }
  /** Stops the timer and makes one last attempt, backoff or not. */
  async close(): Promise<void> {
    clearInterval(this.timer);
    await this.sending;
    this.retryAt = 0;
    await this.flush();
  }

  private async drain(): Promise<void> {
    while (this.queue.length && traceClock() >= this.retryAt) {
      const batch = this.queue.splice(0, this.limits.maxBatch);
      const outcome = await this.post(batch);
      if (outcome === 'retry') {
        if (++this.failures === 1) console.error('Trace export failed; retrying with backoff');
        this.retryAt = traceClock() + Math.min(this.limits.backoffMaxMs, this.limits.backoffBaseMs * 2 ** (this.failures - 1));
        const kept = batch.slice(0, this.limits.maxQueue - this.queue.length);
        this.dropped += batch.length - kept.length;
        this.queue = [...kept, ...this.queue];
        return;
      }
      this.failures = 0;
      if (outcome === 'drop') this.dropped += batch.length;
    }
  }
  private async post(batch: readonly Span[]): Promise<'ok' | 'retry' | 'drop'> {
    const body = JSON.stringify({ resourceSpans: [{ resource: { attributes: attributes({ 'service.name': this.serviceName }) },
      scopeSpans: [{ scope: { name: 'gate-pdp-http' }, spans: batch.map((s) => ({ traceId: s.traceId, spanId: s.spanId,
        ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}), name: s.name, kind: s.kind, startTimeUnixNano: nanos(s.start),
        endTimeUnixNano: nanos(s.end), attributes: attributes(s.attributes), status: { code: s.error ? 2 : 0 } })) }] }] });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.limits.timeoutMs);
    try {
      const response = await fetch(this.url, { method: 'POST', body, redirect: 'error', signal: controller.signal, headers: { 'content-type': 'application/json' } });
      await response.body?.cancel().catch(() => undefined);
      return response.ok ? 'ok' : RETRYABLE.has(response.status) ? 'retry' : 'drop';
    } catch { return 'retry'; }
    finally { clearTimeout(timer); }
  }
}
