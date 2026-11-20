import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { HttpError } from '../http.ts';
import { AUDIT_TYPES, LEGACY_NODE, type AuditList, type AuditPage, type AuditRecord } from '../audit.ts';
import { presentAuditRow } from '../audit-subjects.ts';

const presented = (rt: Runtime, row: AuditRecord): AuditRecord => presentAuditRow(row, (id) => rt.audit.displayIdentity?.(id));
const page = (rt: Runtime, value: AuditPage): AuditPage => ({ ...value, items: value.items.map((row) => presented(rt, row)) });

export function audit(rt: Runtime, user: User, url: URL): unknown {
  allowed(user, ['security_officer', 'auditor']);
  if (url.pathname.endsWith('/verify')) {
    if (rt.audit.recheck) return rt.audit.recheck().then(() => rt.audit.verify());
    return rt.audit.verify();
  }
  if (url.pathname.endsWith('/anchors')) return { tsa: rt.anchoring?.url ?? null, lastError: rt.anchoring?.lastError ?? null, items: rt.audit.anchors };
  const q = url.searchParams; const limit = Number(q.get('limit') ?? 50);
  // "seq" (chain "0", as before chains were per node) or "node:seq", as the previous page's `next` gave it
  const raw = q.get('cursor') || '0';
  const chained = /^([A-Za-z0-9][A-Za-z0-9_.-]{0,63}):(\d{1,16})$/.exec(raw);
  const cursor = Number(chained ? chained[2] : /^\d{1,16}$/.test(raw) ? raw : NaN);
  const node = chained?.[1];
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000 || !Number.isSafeInteger(cursor) || cursor < 0) throw new HttpError(400, 'bad_request');
  if ((q.has('effect') && !['allow', 'deny'].includes(q.get('effect')!)) || (q.has('type') && !(AUDIT_TYPES as readonly string[]).includes(q.get('type')!))) throw new HttpError(400, 'bad_request');
  const query: AuditList = { cursor, limit, ...(node === undefined ? {} : { node }),
    ...(q.get('effect') ? { effect: q.get('effect') as AuditList['effect'] } : {}),
    ...(q.get('rule') ? { rule: q.get('rule')! } : {}),
    ...(q.get('subject') ? { subject: rt.audit.subjectPseudonym?.(q.get('subject')!) ?? q.get('subject')! } : {}),
    ...(q.get('resource') ? { resource: q.get('resource')! } : {}),
    ...(q.get('type') ? { type: q.get('type') as AuditList['type'] } : {}) };
  if (rt.audit.list) return rt.audit.list(query).then((value) => page(rt, value));
  const rows = rt.audit.records().filter((r) => (node ?? LEGACY_NODE) === (r.node ?? LEGACY_NODE) && r.seq > cursor && (!query.effect || r.effect === query.effect) &&
    (!query.rule || r.rules?.includes(query.rule)) && (!query.subject || r.subject === query.subject) &&
    (!query.resource || r.resource === query.resource) && (!query.type || r.type === query.type));
  const items = rows.slice(0, limit);
  return { items: items.map((row) => presented(rt, row)), next: rows.length > limit ? String(items.at(-1)?.seq) : null };
}
