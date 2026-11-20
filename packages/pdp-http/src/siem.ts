import { createHmac } from 'node:crypto';
import { LEGACY_NODE, type AuditLog, type AuditRecord } from './audit.ts';
import { allowed, type User } from './auth.ts';
import { HttpError } from './http.ts';
import type { Backing } from './store.ts';
import { pseudonymise } from './admin/privacy.ts';

export const AUDIT_EXPORT_MAX_LIMIT = 1000;
export const AUDIT_NDJSON_CONTENT_TYPE = 'application/x-ndjson; charset=utf-8';
export const SIEM_SIGNATURE_HEADER = 'x-siem-signature';
export const SIEM_TIMESTAMP_HEADER = 'x-siem-timestamp';

export interface AuditPullResult {
  body: string;
  contentType: typeof AUDIT_NDJSON_CONTENT_TYPE;
  /** The inclusive `from` value for the following pull: a seq while there is only chain "0", else "node:seq,...". */
  next: number | string;
}
/** Last exported seq per chain. A number is chain "0" (every cursor before chains were per node). */
export type AuditPosition = ReadonlyMap<string, number>;
const NODE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

function validBatchArguments(cursor: AuditPosition, limit: number): void {
  if (![...cursor].every(([node, seq]) => NODE.test(node) && Number.isSafeInteger(seq) && seq >= 0) || !Number.isInteger(limit) || limit < 1 || limit > AUDIT_EXPORT_MAX_LIMIT) {
    throw new RangeError('Invalid audit cursor or limit');
  }
}
const position = (cursor: number | AuditPosition): AuditPosition => typeof cursor === 'number' ? new Map([[LEGACY_NODE, cursor]]) : cursor;
/** The position after `rows`, starting from `cursor`. */
export function advance(cursor: AuditPosition, rows: readonly AuditRecord[]): Map<string, number> {
  const next = new Map(cursor);
  for (const row of rows) { const node = row.node ?? LEGACY_NODE; next.set(node, Math.max(next.get(node) ?? 0, row.seq)); }
  return next;
}

/** `until`: the last seq to read of each chain (inclusive); a chain it does not name is not read. Absent: no bound. */
export async function readAuditBatch(audit: AuditLog, cursor: number | AuditPosition, limit = 100, until?: AuditPosition): Promise<AuditRecord[]> {
  const after = position(cursor);
  validBatchArguments(after, limit);
  if (until) validBatchArguments(until, limit);
  if (audit.exportBatch) return audit.exportBatch(after, limit, until);
  const from = after.get(LEGACY_NODE) ?? 0;
  const below = (row: AuditRecord): boolean => row.seq > from && (!until || row.seq <= (until.get(row.node ?? LEGACY_NODE) ?? 0));
  if (audit.list) {
    const page = await audit.list({ cursor: from, limit });
    return page.items.filter(below).slice(0, limit);
  }
  return audit.records().filter(below).slice(0, limit);
}

function badRequest(): never {
  throw new HttpError(400, 'bad_request');
}

function parameter(url: URL, name: 'limit', fallback: number, minimum: number, maximum: number): number {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) badRequest();
  if (values.length === 0) return fallback;
  const raw = values[0]!;
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) badRequest();
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) badRequest();
  return value;
}
const seqText = /^[1-9][0-9]{0,15}$/;
/** `from` (shifted by -1: the position after which to read) or `until` (as given): a seq (chain "0", as before chains
 *  were per node) or "node:seq,node:seq", each inclusive. Absent: `from` is 1, `until` undefined. */
function positionParameter(url: URL, name: 'from' | 'until'): Map<string, number> | undefined {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) badRequest();
  if (values.length === 0 && name === 'until') return undefined;
  const raw = values[0] ?? '1';
  const shift = name === 'from' ? 1 : 0;
  const out = new Map<string, number>();
  if (seqText.test(raw)) out.set(LEGACY_NODE, Number(raw) - shift);
  else {
    for (const part of raw.split(',')) {
      const at = part.lastIndexOf(':');
      const node = part.slice(0, at), seq = part.slice(at + 1);
      if (at < 1 || !NODE.test(node) || !seqText.test(seq) || out.has(node)) badRequest();
      out.set(node, Number(seq) - shift);
    }
  }
  if (![...out.values()].every((seq) => Number.isSafeInteger(seq + shift))) badRequest();
  return out;
}
/** The inclusive `from` for the rows after `after`: a plain seq while only chain "0" is named. */
export function fromText(after: AuditPosition): number | string {
  // a chain still at its start needs no entry: absent means from 1
  const entries = [...after].filter(([, seq]) => seq > 0).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  if (entries.every(([node]) => node === LEGACY_NODE)) return (after.get(LEGACY_NODE) ?? 0) + 1;
  return entries.map(([node, seq]) => `${node}:${seq + 1}`).join(',');
}

/** `pseudonymKey`: `pseudonymise=1` replaces person ids by keyed pseudonyms (admin/privacy.ts). */
export async function pullAudit(audit: AuditLog, user: User, url: URL, pseudonymKey?: Buffer): Promise<AuditPullResult> {
  allowed(user, ['security_officer', 'auditor']);
  for (const key of new Set(url.searchParams.keys())) if (!['from', 'until', 'limit', 'pseudonymise'].includes(key)) badRequest();
  const after = positionParameter(url, 'from')!;
  // an auditor stops at the signed manifest's heads: rows after them are not covered by its signature
  const until = positionParameter(url, 'until');
  const limit = parameter(url, 'limit', 100, 1, AUDIT_EXPORT_MAX_LIMIT);
  const flag = url.searchParams.getAll('pseudonymise');
  if (flag.length > 1 || (flag.length === 1 && (flag[0] !== '1' || !pseudonymKey))) badRequest();
  const read = await readAuditBatch(audit, after, limit, until);
  const rows = flag.length === 1 ? read.map((row) => pseudonymise(row, pseudonymKey!)) : read;
  return {
    body: rows.length ? rows.map((row) => JSON.stringify(row)).join('\n') + '\n' : '',
    contentType: AUDIT_NDJSON_CONTENT_TYPE,
    next: fromText(advance(after, read)),
  };
}

export interface SiemConfig {
  url: string;
  secret: string;
  batchSize?: number;
  requestTimeoutMs?: number;
  maxAttempts?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
}

export interface SiemHooks {
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  allowLoopbackHttp?: boolean;
  /** Makes the saved cursor durable (PostgreSQL); file cursors are written at once. */
  commit?: () => Promise<void>;
}
/** `seq`: chain "0"; `chains`: the others' last delivered seq (absent while there is only chain "0"). */
export type SiemCursor = Backing<{ seq: number; chains?: Record<string, number> }>;

/** SIEM_WEBHOOK_URL and SIEM_HMAC_SECRET enable the push export; both or neither. */
export function siemFromEnv(env: NodeJS.ProcessEnv): (SiemConfig & { intervalSeconds: number }) | undefined {
  if (!env.SIEM_WEBHOOK_URL && !env.SIEM_HMAC_SECRET) return undefined;
  if (!env.SIEM_WEBHOOK_URL || !env.SIEM_HMAC_SECRET) throw new Error('SIEM_WEBHOOK_URL and SIEM_HMAC_SECRET must be set together');
  if (env.SIEM_HMAC_SECRET.length < 32) throw new Error('SIEM_HMAC_SECRET must contain at least 32 characters');
  // each variable is read by name, so scripts/docs/env-table.ts finds it
  const number = (value: string | undefined, fallback: number): number => value === undefined ? fallback : Number(value);
  return { url: env.SIEM_WEBHOOK_URL, secret: env.SIEM_HMAC_SECRET, batchSize: number(env.SIEM_BATCH_SIZE, 100),
    intervalSeconds: integer(number(env.SIEM_INTERVAL_SECONDS, 30), 'interval', 1, 86_400) };
}

function integer(value: number, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`Invalid SIEM ${name}`);
  return value;
}

function endpoint(raw: string, allowLoopbackHttp: boolean): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('Invalid SIEM webhook URL'); }
  if (url.username || url.password || (url.protocol !== 'https:' && !(allowLoopbackHttp && url.protocol === 'http:' && isLoopback(url)))) {
    throw new Error('SIEM webhook must use https');
  }
  // receivers often take tokens as query parameters; secrets belong in SIEM_HMAC_SECRET, never in the URL
  if (url.search) throw new Error('SIEM webhook URL must not contain a query string');
  return url.toString();
}

function isLoopback(url: URL): boolean {
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
}

function loadCursor(cursor: SiemCursor): Map<string, number> {
  const value: unknown = cursor.load();
  if (value === undefined) return new Map([[LEGACY_NODE, 0]]);
  const { seq, chains } = value && typeof value === 'object' ? value as { seq?: unknown; chains?: unknown } : { seq: undefined, chains: undefined };
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0) throw new Error('Invalid SIEM cursor');
  const result = new Map([[LEGACY_NODE, seq]]);
  if (chains !== undefined) {
    if (!chains || typeof chains !== 'object' || Array.isArray(chains)) throw new Error('Invalid SIEM cursor');
    for (const [node, n] of Object.entries(chains)) {
      if (!NODE.test(node) || node === LEGACY_NODE || typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) throw new Error('Invalid SIEM cursor');
      result.set(node, n);
    }
  }
  return result;
}
function storedCursor(position: AuditPosition): { seq: number; chains?: Record<string, number> } {
  const chains = [...position].filter(([node]) => node !== LEGACY_NODE);
  return { seq: position.get(LEGACY_NODE) ?? 0, ...(chains.length ? { chains: Object.fromEntries(chains) } : {}) };
}

export class SiemExporter {
  private readonly audit: AuditLog;
  private readonly config: Required<Omit<SiemConfig, 'url' | 'secret'>>;
  private readonly url: string;
  private readonly secret: string;
  private readonly store: SiemCursor;
  private readonly commit: () => Promise<void>;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private delivered: Map<string, number>;
  private active?: Promise<void>;

  constructor(audit: AuditLog, cursor: SiemCursor, config: SiemConfig, hooks: SiemHooks = {}) {
    if (!config.secret) throw new Error('SIEM secret is required');
    this.audit = audit;
    this.url = endpoint(config.url, hooks.allowLoopbackHttp ?? false);
    this.secret = config.secret;
    this.config = {
      batchSize: integer(config.batchSize ?? 100, 'batch size', 1, AUDIT_EXPORT_MAX_LIMIT),
      requestTimeoutMs: integer(config.requestTimeoutMs ?? 10_000, 'request timeout', 1, 2_147_483_647),
      maxAttempts: integer(config.maxAttempts ?? 5, 'maximum attempts', 1, 100),
      backoffBaseMs: integer(config.backoffBaseMs ?? 1_000, 'backoff base', 0, 2_147_483_647),
      backoffMaxMs: integer(config.backoffMaxMs ?? 30_000, 'maximum backoff', 0, 2_147_483_647),
    };
    if (this.config.backoffMaxMs < this.config.backoffBaseMs) throw new Error('Invalid SIEM maximum backoff');
    this.store = cursor;
    this.delivered = loadCursor(cursor);
    this.commit = hooks.commit ?? (async (): Promise<void> => undefined);
    this.fetcher = hooks.fetch ?? globalThis.fetch;
    this.now = hooks.now ?? Date.now;
    this.sleep = hooks.sleep ?? ((milliseconds) => new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, milliseconds);
      timer.unref();
    }));
  }

  /** Last delivered seq of chain "0". */
  get cursor(): number { return this.delivered.get(LEGACY_NODE) ?? 0; }
  /** Last delivered seq of every chain. */
  get cursors(): AuditPosition { return this.delivered; }
  /** Rereads the cursor document (a follower that takes the lead resumes where the old leader stopped). */
  reload(): void { this.delivered = loadCursor(this.store); }

  flush(): Promise<void> {
    this.active ??= this.drain().finally(() => { this.active = undefined; });
    return this.active;
  }

  private async drain(): Promise<void> {
    while (true) {
      const rows = await readAuditBatch(this.audit, this.delivered, this.config.batchSize);
      if (!rows.length) return;
      const body = rows.map((row) => JSON.stringify(row)).join('\n') + '\n';
      await this.deliver(advance(this.delivered, rows), body);
      if (rows.length < this.config.batchSize) return;
    }
  }

  private async deliver(next: Map<string, number>, body: string): Promise<void> {
    for (let attempt = 0; attempt < this.config.maxAttempts; attempt++) {
      if (await this.post(body)) {
        this.store.save(storedCursor(next));
        await this.commit();
        this.delivered = next;
        return;
      }
      if (attempt + 1 >= this.config.maxAttempts) throw new Error('SIEM webhook delivery failed');
      await this.sleep(Math.min(this.config.backoffMaxMs, this.config.backoffBaseMs * 2 ** attempt));
    }
  }

  /** True when the receiver acknowledged the batch with a 2xx; transport errors and refusals are retried alike. */
  private async post(body: string): Promise<boolean> {
    const timestamp = String(Math.floor(this.now() / 1000));
    const signature = createHmac('sha256', this.secret).update(`${timestamp}.${body}`, 'utf8').digest('hex');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      const response = await this.fetcher(this.url, {
        method: 'POST', body, redirect: 'error', signal: controller.signal,
        headers: { 'content-type': AUDIT_NDJSON_CONTENT_TYPE, [SIEM_TIMESTAMP_HEADER]: timestamp, [SIEM_SIGNATURE_HEADER]: `sha256=${signature}` },
      });
      await response.body?.cancel().catch(() => undefined);
      return response.ok;
    } catch { return false; }
    finally { clearTimeout(timer); }
  }
}
