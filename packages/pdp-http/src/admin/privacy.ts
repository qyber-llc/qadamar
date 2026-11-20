// Personal data in the audit and the model: pseudonymised exports and the subject access report (docs/compliance).
import { createHmac, randomBytes } from 'node:crypto';
import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { HttpError } from '../http.ts';
import { LEGACY_NODE, type AuditList, type AuditRecord } from '../audit.ts';
import { PERSON_DETAILS, presentAuditRow, technicalActor } from '../audit-subjects.ts';
import { decideChange, propose } from './changes.ts';
import { dueGrants } from './reviews.ts';
import { forgetApprover } from './inbox.ts';

/** HKDF info for the pseudonym key derived from SIGNING_KEY_SEAL (tokens.ts derivedKey): never the seal key itself. */
export const PSEUDONYM_KEY_LABEL = 'qadamar/audit-pseudonym/hmac-sha256/v1';
// shortcut: without SIGNING_KEY_SEAL pseudonyms are stable for this process only; set the seal for stable ones
const PROCESS_KEY = randomBytes(32);
export const MAX_REPORT_ROWS = 1000;

export const pseudonymKey = (rt: Runtime): Buffer => rt.pseudonymKey ?? PROCESS_KEY;
export const pseudonym = (key: Buffer, id: string): string => /^ps\.[0-9a-f]{32}$/.test(id) ? id : `ps.${createHmac('sha256', key).update(id, 'utf8').digest('hex').slice(0, 32)}`;

/** The row with subject, actor and person ids in its details replaced by keyed pseudonyms. Equal ids keep equal
 *  pseudonyms under one key, so maker/checker separation stays checkable. The row no longer hashes to `hash`:
 *  `pseudonymised: true` says so, and the chain is verified on the server (GET /admin/v1/audit/verify). */
export function pseudonymise(row: AuditRecord, key: Buffer): AuditRecord & { pseudonymised: true } {
  const p = (id: unknown): unknown => typeof id === 'string' ? pseudonym(key, id) : Array.isArray(id) ? id.map(p) : id;
  const service = technicalActor(row.actor);
  const details = row.details && Object.fromEntries(Object.entries(row.details).map(([k, v]) => [k, (PERSON_DETAILS as readonly string[]).includes(k) ? p(v) : v]));
  return { ...row, actor: service ? row.actor : pseudonym(key, row.actor), ...(row.subject === undefined ? {} : { subject: pseudonym(key, row.subject) }),
    ...(details ? { details } : {}), pseudonymised: true };
}

const byTime = (a: AuditRecord, b: AuditRecord): number =>
  a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : (a.node ?? LEGACY_NODE) < (b.node ?? LEGACY_NODE) ? -1 : (a.node ?? LEGACY_NODE) > (b.node ?? LEGACY_NODE) ? 1 : a.seq - b.seq;
/** A list page's `next`: "seq" on chain "0", "node:seq" on a node's chain (postgres-chains.ts auditCursor). */
export function listCursor(next: string): Pick<AuditList, 'cursor' | 'node'> {
  const at = next.lastIndexOf(':');
  return at < 0 ? { cursor: Number(next) } : { node: next.slice(0, at), cursor: Number(next.slice(at + 1)) };
}

/** Audit rows matching `filter`, oldest first, at most the last `max`; `complete` is false when older ones were left out. */
export async function auditRows(rt: Runtime, filter: Pick<AuditList, 'type' | 'subject' | 'rule' | 'actor'>, max = MAX_REPORT_ROWS): Promise<{ items: AuditRecord[]; complete: boolean }> {
  const stored = (id: string): string => rt.audit.subjectPseudonym?.(id) ?? id;
  const resolved = { ...filter, ...(filter.subject ? { subject: stored(filter.subject) } : {}), ...(filter.actor ? { actor: stored(filter.actor) } : {}) };
  let items: AuditRecord[] = [];
  let total = 0;
  if (rt.audit.list) {
    // shortcut: pages through the filtered rows to keep the newest; add a descending query if these logs grow large
    // pages come chain by chain in a cluster (cursor "node:seq"): the window keeps the newest by time across chains
    let after: Pick<AuditList, 'cursor' | 'node'> = { cursor: 0 };
    for (;;) {
      const page = await rt.audit.list({ ...resolved, ...after, limit: MAX_REPORT_ROWS });
      total += page.items.length; items = [...items, ...page.items].sort(byTime).slice(-max);
      if (page.next === null) break;
      after = listCursor(page.next);
    }
  } else {
    const rows = rt.audit.records().filter((r) => (!resolved.type || r.type === resolved.type) && (!resolved.subject || r.subject === resolved.subject) &&
      (!resolved.actor || r.actor === resolved.actor) && (!resolved.rule || r.rules?.includes(resolved.rule) === true));
    total = rows.length; items = rows.slice(-max);
  }
  return { items: items.map((row) => presentAuditRow(row, (id) => rt.audit.displayIdentity?.(id))), complete: total <= max };
}

function subjectId(rawId: string): string {
  let id: string;
  try { id = decodeURIComponent(rawId); } catch { throw new HttpError(400, 'bad_request'); }
  if (!id || id.length > 256) throw new HttpError(400, 'bad_request');
  return id;
}

/** Everything the control plane holds about one subject id (right of access). The report itself is audited. */
export async function subjectReport(rt: Runtime, user: User, rawId: string): Promise<Record<string, unknown>> {
  allowed(user, ['security_officer']);
  const id = subjectId(rawId);
  const state = rt.store.state;
  const quoted = JSON.stringify(id);
  // rows about the person and rows by the person (as actor): two bounded reads, merged, the newest MAX_REPORT_ROWS kept
  const about = await auditRows(rt, { subject: id }); const by = await auditRows(rt, { actor: id });
  const merged = [...new Map([...about.items, ...by.items].map((r) => [`${r.node ?? LEGACY_NODE}:${r.seq}`, r])).values()].sort(byTime);
  const audit = { items: merged.slice(-MAX_REPORT_ROWS), complete: about.complete && by.complete && merged.length <= MAX_REPORT_ROWS };
  const report = {
    subjectId: id, generatedAt: rt.now(),
    subjects: state.subjects.filter((s) => s.id === id),
    // as the subject of a grant, and as the person who granted it
    tuples: state.tuples.filter((t) => t.subject.id === id || t.grantedBy === id),
    emergencies: rt.store.emergencies.filter((e) => e.subjectId === id || e.openedBy === id || e.reviewedBy === id),
    certifications: (state.certifications ?? []).filter((c) => c.certifiedBy === id || c.approvedBy === id),
    publications: rt.store.history.filter((p) => p.publishedBy === id || p.approvedBy === id)
      .map((p) => ({ version: p.version, publishedAt: p.publishedAt, publishedBy: p.publishedBy, approvedBy: p.approvedBy, reason: p.reason })),
    // a change names the subject as a JSON string value somewhere in its payload, or as its maker or checker
    changes: rt.store.changes.filter((c) => c.makerId === id || c.checkerId === id || JSON.stringify(c.payload).includes(quoted))
      .map((c) => ({ id: c.id, kind: c.kind, status: c.status, makerId: c.makerId, checkerId: c.checkerId ?? null, createdAt: c.createdAt, decidedAt: c.decidedAt ?? null })),
    audit: { rows: audit.items, complete: audit.complete,
      retention: 'New rows carry per-subject keyed pseudonyms. Erasure removes their separate mapping; sealed retention may remove old rows (docs/compliance/iso27701.md).' },
  };
  rt.audit.append({ type: 'security', actor: user.id, action: 'subject_access_report', subject: id, details: { auditRows: audit.items.length } });
  return report;
}

function assertErasable(rt: Runtime, id: string, officers: readonly string[]): void {
  if (!rt.audit.eraseSubject) throw new HttpError(503, 'unavailable', 'Audit subject mapping is not configured');
  if (officers.includes(id)) throw new HttpError(403, 'self_erasure', 'A security officer cannot erase their own subject mapping');
  if (!rt.audit.subjectPseudonym?.(id)) throw new HttpError(404, 'not_found', 'No live pseudonym mapping for this subject');
  if (rt.store.emergencies.some((e) => e.subjectId === id && e.status === 'active' && !e.reviewedBy)) {
    throw new HttpError(409, 'open_break_glass', 'Close and review the subject\'s break-glass access before erasure');
  }
  if (dueGrants(rt, (tuple) => tuple.subject.id === id).length) throw new HttpError(409, 'pending_reviews', 'Complete the subject\'s pending access reviews before erasure');
}

/** The first security officer proposes; a different one must approve before the mapping is deleted. */
export async function eraseSubject(rt: Runtime, user: User, rawId: string): Promise<Record<string, unknown>> {
  allowed(user, ['security_officer']);
  const id = subjectId(rawId);
  assertErasable(rt, id, [user.id]);
  return { ...propose(rt, user, { kind: 'erase_subject', payload: { id }, reason: 'Subject erasure request requiring independent security review' }) };
}

export async function approveErasure(rt: Runtime, user: User, changeId: string, approve: boolean, b: Record<string, unknown>): Promise<Record<string, unknown>> {
  allowed(user, ['security_officer']);
  const change = rt.store.changes.find((item) => item.id === changeId);
  if (!change || change.kind !== 'erase_subject') throw new HttpError(404, 'not_found');
  if (!approve) return { ...decideChange(rt, user, changeId, false, b) };
  const id = String(change.payload.id);
  // the maker too: a proposal made through POST /changes did not pass eraseSubject's checks
  assertErasable(rt, id, [user.id, change.makerId]);
  const pending = rt.store.changes;
  decideChange(rt, user, changeId, true, b);
  let result;
  try { result = await rt.audit.eraseSubject!(id, user.id, { changeId, approvedBy: user.id }); } catch (err) {
    // the erasure did not complete: the proposal is not left 'applied', so it can be approved again
    rt.store.changes = pending; rt.store.save(); throw err;
  }
  // the applied proposal must not keep the raw id that the erasure just made unlinkable
  forgetApprover(rt, id, result.pseudonym);
  const scrubbed = { ...rt.store.changes.find((item) => item.id === changeId)!, payload: { pseudonym: result.pseudonym } };
  rt.store.changes = rt.store.changes.map((item) => item.id === changeId ? scrubbed : item); rt.store.save();
  await rt.commit?.();
  return { ...scrubbed, erasure: result };
}
