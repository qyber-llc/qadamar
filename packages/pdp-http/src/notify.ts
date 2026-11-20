// Break-glass notices: a signed JSON POST to BREAK_GLASS_WEBHOOK when an emergency access opens, is revoked or expires.
import { createHmac, randomUUID } from 'node:crypto';

export const NOTICE_SIGNATURE_HEADER = 'x-gate-signature';
export const NOTICE_TIMESTAMP_HEADER = 'x-gate-timestamp';

/** Ids and times only: never the reason, a name or any other free text. */
export interface BreakGlassNotice {
  event: 'opened' | 'revoked' | 'expired'; emergencyId: string; subjectId: string; resourceId: string; actorId: string; at: string;
}
export interface WebhookConfig { url: string; secret: string; maxAttempts?: number; backoffBaseMs?: number; backoffMaxMs?: number; requestTimeoutMs?: number }
export interface WebhookHooks {
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  /** Tests only: a loopback http receiver. */
  allowLoopbackHttp?: boolean;
}
export type NoticeOutcome = { outcome: 'sent'; attempts: number } | { outcome: 'failed'; attempts: number; error: string };

/** BREAK_GLASS_WEBHOOK and BREAK_GLASS_WEBHOOK_SECRET turn notices on; both or neither. */
export function breakGlassFromEnv(env: NodeJS.ProcessEnv): WebhookConfig | undefined {
  if (!env.BREAK_GLASS_WEBHOOK && !env.BREAK_GLASS_WEBHOOK_SECRET) return undefined;
  if (!env.BREAK_GLASS_WEBHOOK || !env.BREAK_GLASS_WEBHOOK_SECRET) throw new Error('BREAK_GLASS_WEBHOOK and BREAK_GLASS_WEBHOOK_SECRET must be set together');
  return { url: env.BREAK_GLASS_WEBHOOK, secret: env.BREAK_GLASS_WEBHOOK_SECRET };
}

function endpoint(raw: string, allowLoopbackHttp: boolean): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('Invalid BREAK_GLASS_WEBHOOK'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || (url.protocol !== 'https:' && !(allowLoopbackHttp && url.protocol === 'http:' && loopback))) {
    throw new Error('BREAK_GLASS_WEBHOOK must use https');
  }
  if (url.search) throw new Error('BREAK_GLASS_WEBHOOK must not contain a query string');
  return url.toString();
}

export class BreakGlassNotifier {
  private readonly url: string;
  private readonly secret: string;
  private readonly maxAttempts: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly timeoutMs: number;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly report: (notice: BreakGlassNotice, result: NoticeOutcome) => void | Promise<void>;
  private readonly inFlight = new Set<Promise<void>>();

  constructor(config: WebhookConfig, report: BreakGlassNotifier['report'], hooks: WebhookHooks = {}) {
    if (config.secret.length < 32) throw new Error('BREAK_GLASS_WEBHOOK_SECRET must contain at least 32 characters');
    this.url = endpoint(config.url, hooks.allowLoopbackHttp ?? false);
    this.secret = config.secret;
    this.maxAttempts = config.maxAttempts ?? 5;
    this.backoffBaseMs = config.backoffBaseMs ?? 1_000;
    this.backoffMaxMs = config.backoffMaxMs ?? 30_000;
    this.timeoutMs = config.requestTimeoutMs ?? 10_000;
    if (![this.maxAttempts, this.backoffBaseMs, this.backoffMaxMs, this.timeoutMs].every((n) => Number.isSafeInteger(n) && n >= 0) || this.maxAttempts < 1) {
      throw new Error('Invalid break-glass webhook retry settings');
    }
    this.report = report;
    this.fetcher = hooks.fetch ?? globalThis.fetch;
    this.now = hooks.now ?? Date.now;
    this.sleep = hooks.sleep ?? ((milliseconds) => new Promise<void>((resolve) => { setTimeout(resolve, milliseconds).unref(); }));
  }

  /** Fire and forget: the caller is never delayed and never sees a delivery error (it is reported, then audited). */
  send(notice: BreakGlassNotice): void {
    const delivery = this.deliver(notice).finally(() => { this.inFlight.delete(delivery); });
    this.inFlight.add(delivery);
  }

  /** Resolves when every notice sent so far is delivered or given up (tests, shutdown). */
  async settled(): Promise<void> { while (this.inFlight.size) await Promise.all([...this.inFlight]); }

  private async deliver(notice: BreakGlassNotice): Promise<void> {
    // one id for every attempt: the receiver deduplicates retries by it
    const body = JSON.stringify({ type: 'break_glass', id: randomUUID(), ...notice });
    let error = 'not sent';
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      error = await this.post(body);
      if (!error) { await this.safeReport(notice, { outcome: 'sent', attempts: attempt }); return; }
      if (attempt < this.maxAttempts) await this.sleep(Math.min(this.backoffMaxMs, this.backoffBaseMs * 2 ** (attempt - 1)));
    }
    await this.safeReport(notice, { outcome: 'failed', attempts: this.maxAttempts, error });
  }

  private async safeReport(notice: BreakGlassNotice, result: NoticeOutcome): Promise<void> {
    try { await this.report(notice, result); }
    catch (err) { console.error(`Break-glass notice outcome not recorded: ${err instanceof Error ? err.message : 'unknown error'}`); }
  }

  /** '' on a 2xx; otherwise a short reason without the URL (redirects are refused, not followed). */
  private async post(body: string): Promise<string> {
    const timestamp = String(Math.floor(this.now() / 1000));
    const signature = createHmac('sha256', this.secret).update(`${timestamp}.${body}`, 'utf8').digest('hex');
    try {
      const response = await this.fetcher(this.url, {
        method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs),
        headers: { 'content-type': 'application/json', [NOTICE_TIMESTAMP_HEADER]: timestamp, [NOTICE_SIGNATURE_HEADER]: `sha256=${signature}` },
      });
      await response.body?.cancel().catch(() => undefined);
      return response.ok ? '' : `HTTP ${response.status}`;
    } catch (err) { return err instanceof Error && err.name === 'TimeoutError' ? 'timeout' : 'transport error'; }
  }
}
