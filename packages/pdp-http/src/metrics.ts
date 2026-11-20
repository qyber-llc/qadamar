import { timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Runtime } from './runtime.ts';
import { HttpError, json } from './http.ts';

const BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30] as const;
type Histogram = { counts: number[]; sum: number; count: number };
const histogram = (): Histogram => ({ counts: BUCKETS.map(() => 0), sum: 0, count: 0 });
function observe(h: Histogram, seconds: number): void {
  const value = Math.max(0, seconds);
  for (const [i, bound] of BUCKETS.entries()) if (value <= bound) h.counts[i] = (h.counts[i] ?? 0) + 1;
  h.sum += value;
  h.count++;
}

export class Metrics {
  private readonly requests = new Map<string, Histogram>();
  private readonly commits = histogram();
  private readonly decisions = { allow: 0, deny: 0 };
  private readonly notices = { sent: 0, failed: 0 };
  /** PEP resource registration (resources.ts): calls by operation, resources by what became of them. */
  private readonly registrations = { register: 0, retire: 0, sync: 0, refused: 0 };
  private readonly registered = { created: 0, updated: 0, unchanged: 0, retired: 0, proposed: 0 };
  replicaRefusals = 0;

  observeDecision(effect: 'allow' | 'deny' | undefined): void {
    if (effect) this.decisions[effect]++;
  }
  observeCommit(seconds: number): void { observe(this.commits, seconds); }
  observeNotice(outcome: 'sent' | 'failed'): void { this.notices[outcome]++; }
  /** A resource registration audit row: `resource_<operation>` with its counts, or a refusal on the registration route. */
  observeRegistration(action: string, details: Record<string, unknown> | undefined): void {
    const operation = action === 'refused' ? 'refused' : action.slice('resource_'.length);
    if (!Object.hasOwn(this.registrations, operation)) return;
    this.registrations[operation as keyof Metrics['registrations']]++;
    const counts = details?.counts;
    if (counts === null || typeof counts !== 'object') return;
    for (const [status, n] of Object.entries(counts)) if (Object.hasOwn(this.registered, status) && Number.isSafeInteger(n)) this.registered[status as keyof Metrics['registered']] += n as number;
  }
  observeRequest(route: string, seconds: number): void {
    let h = this.requests.get(route);
    if (!h) { h = histogram(); this.requests.set(route, h); }
    observe(h, seconds);
  }
  render(rt: Runtime): string {
    const lines = [
      '# HELP gate_decisions_total Authorization decisions appended to the audit log.',
      '# TYPE gate_decisions_total counter',
      `gate_decisions_total{effect="allow"} ${this.decisions.allow}`,
      `gate_decisions_total{effect="deny"} ${this.decisions.deny}`,
    ];
    histogramLines(lines, 'gate_http_request_duration_seconds', 'HTTP request latency by route family.', this.requests);
    // the head, not verify(): a scrape must not reread the whole file log
    lines.push('# HELP gate_audit_length Records in the audit chain (head sequence).',
      '# TYPE gate_audit_length gauge', `gate_audit_length ${rt.audit.tip().seq}`);
    const anchor = rt.audit.anchors.at(-1);
    const age = anchor ? Math.max(0, (Date.now() - Date.parse(anchor.genTime)) / 1000) : -1;
    lines.push('# HELP gate_audit_last_anchor_age_seconds Age of the latest audit anchor, or -1 when none exists.',
      '# TYPE gate_audit_last_anchor_age_seconds gauge', `gate_audit_last_anchor_age_seconds ${Number.isFinite(age) ? age : -1}`);
    if (rt.audit.fullChainVerified !== undefined) {
      lines.push('# HELP gate_audit_full_chain_verified 1 once every audit chain was verified from its genesis since start (0 while the background verification after a checkpointed start runs, or after an integrity failure).',
        '# TYPE gate_audit_full_chain_verified gauge', `gate_audit_full_chain_verified ${rt.audit.fullChainVerified ? 1 : 0}`);
    }
    histogramLines(lines, 'gate_commit_duration_seconds', 'State and audit commit latency.', new Map([['', this.commits]]));
    lines.push('# HELP gate_active_node Whether this process is the active Qadamar node (standbys do not open a port).',
      '# TYPE gate_active_node gauge', 'gate_active_node 1',
      '# HELP gate_break_glass_notices_total Break-glass webhook notices delivered or given up after the last retry.',
      '# TYPE gate_break_glass_notices_total counter',
      `gate_break_glass_notices_total{outcome="sent"} ${this.notices.sent}`,
      `gate_break_glass_notices_total{outcome="failed"} ${this.notices.failed}`,
      '# HELP gate_resource_registrations_total PEP resource registration calls by operation (refused: answered with an error).',
      '# TYPE gate_resource_registrations_total counter',
      ...Object.entries(this.registrations).map(([operation, n]) => `gate_resource_registrations_total{operation="${operation}"} ${n}`),
      '# HELP gate_registered_resources_total Resources named by PEP registration calls, by outcome (proposed: queued for two-person review).',
      '# TYPE gate_registered_resources_total counter',
      ...Object.entries(this.registered).map(([outcome, n]) => `gate_registered_resources_total{outcome="${outcome}"} ${n}`),
      '# HELP gate_replica_audit_refused_total Replica audit refusal rows this node wrote (gap, fork, tampering, behind; at most one a minute per replica and reason).',
      '# TYPE gate_replica_audit_refused_total counter', `gate_replica_audit_refused_total ${this.replicaRefusals}`,
      ...rt.node?.metrics?.() ?? []);
    return `${lines.join('\n')}\n`;
  }
}

function histogramLines(lines: string[], name: string, help: string, values: ReadonlyMap<string, Histogram>): void {
  lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} histogram`);
  for (const [route, h] of values) {
    const label = route ? `{route="${route}"}` : '';
    const labels = (le: string): string => route ? `{route="${route}",le="${le}"}` : `{le="${le}"}`;
    for (const [i, bound] of BUCKETS.entries()) lines.push(`${name}_bucket${labels(String(bound))} ${h.counts[i] ?? 0}`);
    lines.push(`${name}_bucket${labels('+Inf')} ${h.count}`, `${name}_sum${label} ${h.sum}`, `${name}_count${label} ${h.count}`);
  }
}

const registries = new WeakMap<Runtime, Metrics>();
export function metrics(rt: Runtime): Metrics {
  const existing = registries.get(rt);
  if (existing) return existing;
  const registry = new Metrics();
  registries.set(rt, registry);
  const append = rt.audit.append.bind(rt.audit);
  rt.audit.append = (event) => {
    append(event);
    if (event.type === 'decision') registry.observeDecision(event.effect);
    else if (event.type === 'security' && event.action === 'replica_audit_refused') registry.replicaRefusals++;
    else if (event.type === 'change' && (event.action.startsWith('resource_') || (event.action === 'refused' && String(event.details?.route ?? '').startsWith('/x/v1/resources')))) {
      registry.observeRegistration(event.action, event.details);
    }
  };
  const commit = rt.commit?.bind(rt);
  if (commit) rt.commit = async () => {
    const started = performance.now();
    try { await commit(); }
    finally { registry.observeCommit((performance.now() - started) / 1000); }
  };
  return registry;
}

export function routeFamily(path: string): string {
  if (path === '/healthz') return 'health';
  if (path === '/readyz') return 'readiness';
  if (path === '/metrics') return 'metrics';
  if (path === '/.well-known/authzen-configuration') return 'discovery';
  if (path === '/access/v1/evaluation') return 'evaluation';
  if (path === '/access/v1/evaluations') return 'evaluations';
  if (path.startsWith('/access/v1/search/')) return 'search';
  if (path === '/x/v1/explain') return 'explain';
  if (path === '/x/v1/filter') return 'filter';
  if (path === '/x/v1/tokens/consume' || path === '/x/v1/tokens/outcome') return 'tokens';
  if (path === '/x/v1/resources' || path.startsWith('/x/v1/resources/')) return 'resources';
  if (path === '/xacml/v3/authorize') return 'xacml';
  if (path === '/admin/v1/session') return 'session';
  if (path.startsWith('/admin/v1/oidc/')) return 'oidc';
  if (path.startsWith('/admin/v1/saml/')) return 'saml';
  if (path.startsWith('/admin/v1/')) return 'admin';
  return 'static';
}

/** `tokenRequired`: the node listens on a non-loopback address, so /metrics is never served without METRICS_TOKEN. */
export function metricsText(rt: Runtime, req: IncomingMessage, res: ServerResponse, tokenRequired = false): void {
  const expected = process.env.METRICS_TOKEN;
  if (!expected && tokenRequired) throw new HttpError(403, 'forbidden', 'Set METRICS_TOKEN: /metrics is not served unauthenticated on a non-loopback address');
  if (expected) {
    const header = req.headers.authorization;
    const supplied = typeof header === 'string' && /^Bearer [^\s]+$/.test(header) ? header.slice(7) : '';
    const a = Buffer.from(supplied); const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      throw new HttpError(401, 'unauthenticated');
    }
  }
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.end(metrics(rt).render(rt));
}

/** The probe is public: one commit, recheck and full verify per window, whatever the request rate. */
export const READINESS_CACHE_MS = 5_000;
const readinessChecks = new WeakMap<Runtime, { at: number; ready: Promise<boolean> }>();
async function checkReady(rt: Runtime): Promise<boolean> {
  try {
    await rt.commit?.();
    if (rt.audit.recheck && !await rt.audit.recheck()) throw new Error('Audit integrity failure');
    if (!rt.audit.verify().verified) throw new Error('Audit integrity failure');
    return true;
  } catch (err) {
    console.error(`Readiness check failed: ${err instanceof Error ? err.message : 'unknown error'}`);
    return false;
  }
}
/** `elapsed` is real time in ms (not the business clock, which may be pinned). */
export async function readiness(rt: Runtime, res: ServerResponse, elapsed = performance.now()): Promise<void> {
  let cached = readinessChecks.get(rt);
  if (!cached || elapsed - cached.at >= READINESS_CACHE_MS || elapsed < cached.at) {
    cached = { at: elapsed, ready: checkReady(rt) };
    readinessChecks.set(rt, cached);
  }
  // the cached probe covers the audit; freshness is read now, it changes between probes
  if (await cached.ready && (!rt.node || rt.node.fresh())) json(res, { status: 'ready', active: true,
    audit: { verified: true, ...(rt.audit.fullChainVerified === undefined ? {} : { fullChain: rt.audit.fullChainVerified }) }, ...(rt.node ? { role: rt.node.leader() ? 'leader' : rt.node.role ?? 'follower', node: rt.node.id } : {}) });
  else json(res, { status: 'unavailable' }, 503);
}
