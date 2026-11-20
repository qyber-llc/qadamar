import type { Runtime } from '../runtime.ts';
import { inScope, resourceScope } from '../runtime.ts';
import type { User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { propose } from './changes.ts';
import type { Change, StoredTuple } from '../store.ts';
import { HttpError, string } from '../http.ts';
import { windowOf } from '../../../core/src/index.ts';

export function reviews(rt: Runtime, user: User): { items: unknown[]; roleAssignments?: unknown[] } {
  allowed(user, ['security_officer', 'resource_owner']);
  const items = dueGrants(rt, (t) => inScope(rt, user, t.object));
  // role assignments belong to subjects, not to an owner's resources: a security officer sees them
  return user.roles.includes('security_officer') ? { items, roleAssignments: dueRoleAssignments(rt) } : { items };
}
/** Time-bound role assignments (CBAC grant duration) not yet expired and ending within 30 days, with their windows.
 *  Read-only: an assignment is changed through update_subject. */
export function dueRoleAssignments(rt: Runtime): Array<Record<string, unknown>> {
  const at = Date.parse(rt.now());
  return rt.store.state.subjects.flatMap((s) => (s.roleAssignments ?? []).flatMap((a) => {
    const to = a.notAfter === undefined ? NaN : Date.parse(a.notAfter);
    return to > at && to <= at + 30 * 86400000 ? [{ subject: { type: s.type, id: s.id }, role: a.role,
      ...(a.notBefore === undefined ? {} : { notBefore: a.notBefore }), notAfter: a.notAfter, daysLeft: Math.ceil((to - at) / 86400000) }] : [];
  }));
}
/** Grants and allocations due for review: ending within 30 days, or grants older than 90 days. */
export function dueGrants(rt: Runtime, keep: (t: StoredTuple) => boolean = () => true): Array<Record<string, unknown>> {
  const at = Date.parse(rt.now());
  return rt.store.state.tuples.flatMap((t) => {
    const { from, to } = windowOf(t);
    const due = keep(t) && !t.breakGlass && (!to || Date.parse(to) > at) && ['granted', 'allocated'].includes(t.relation) &&
      ((to && Date.parse(to) <= at + 30 * 86400000) || (t.relation === 'granted' && from && Date.parse(from) <= at - 90 * 86400000));
    return due ? [{ tupleId: t.id, subject: t.subject, resource: t.object, relation: t.relation, validTo: to ?? null,
      daysLeft: to ? Math.ceil((Date.parse(to) - at) / 86400000) : null, grantedBy: t.grantedBy, reason: t.reason }] : [];
  });
}
export function review(rt: Runtime, user: User, id: string, b: Record<string, unknown>): Change {
  allowed(user, ['security_officer', 'resource_owner']);
  const t = rt.store.state.tuples.find((t) => { const to = windowOf(t).to; return t.id === id && !t.breakGlass && (!to || Date.parse(to) > Date.parse(rt.now())) && ['granted', 'allocated'].includes(t.relation); });
  if (!t) throw new HttpError(404, 'not_found');
  resourceScope(rt, user, t.object);
  if (b.decision === 'revoke') return propose(rt, user, { kind: 'remove_tuple', payload: { tupleId: id }, reason: b.reason }, true);
  if (b.decision !== 'certify') throw new HttpError(422, 'unprocessable');
  if (t.grantedBy === user.id || t.subject.id === user.id) throw new HttpError(403, 'forbidden', 'Self-certification forbidden');
  const to = string(b.newValidTo);
  const until = windowOf(t).to;
  if (until && Date.parse(to) <= Date.parse(until)) throw new HttpError(422, 'unprocessable', 'Certification must extend the validity');
  return propose(rt, user, { kind: 'add_tuple', payload: { replacesTupleId: t.id, object: t.object, subject: t.subject, relation: t.relation,
    ...(t.subjectRelation ? { subjectRelation: t.subjectRelation } : {}), notBefore: rt.now(), notAfter: to, reason: b.reason }, reason: b.reason }, true);
}
