import { randomUUID } from 'node:crypto';
import { policyVersion } from '../../../core/src/index.ts';
import type { Runtime } from '../runtime.ts';
import { context, decide } from '../runtime.ts';
import type { User } from '../auth.ts';
import { allowed } from '../auth.ts';
import type { Emergency, StoredTuple } from '../store.ts';
import { withRecordDeltas } from '../record-deltas.ts';
import { HttpError, string, reason } from '../http.ts';
import type { BreakGlassNotice } from '../notify.ts';

/** fallbackReview: the emergencies `user` may review or revoke only as the access_admin fallback (reviewerRole). */
export function emergencies(rt: Runtime, user?: User, officers?: readonly string[]): { active: Emergency[]; toReview: Emergency[]; reviewed: Emergency[]; fallbackReview: string[] } {
  const all = rt.store.emergencies;
  return { active: all.filter((e) => ['active', 'reviewed'].includes(e.status) && Date.parse(e.expiresAt) > Date.parse(rt.now())),
    toReview: all.filter((e) => !e.reviewedBy), reviewed: all.filter((e) => !!e.reviewedBy),
    fallbackReview: user ? all.filter((e) => (!e.reviewedBy || e.status !== 'revoked') && reviewerRole(e, user, officers) === 'access_admin').map((e) => e.id) : [] };
}
/** Who may review or revoke `e`, never its opener or its subject: a security officer, or (owner decision, "revue par un
 *  2e role") an access_admin when no security officer other than the opener and the subject exists, so the pair is never
 *  locked. `officers`: the console's security officers; when they cannot be counted, there is no fallback. */
function reviewerRole(e: Emergency, user: User, officers?: readonly string[]): 'security_officer' | 'access_admin' | undefined {
  if (e.openedBy === user.id || e.subjectId === user.id) return undefined;
  if (user.roles.includes('security_officer')) return 'security_officer';
  const others = officers?.filter((id) => id !== e.openedBy && id !== e.subjectId);
  return user.roles.includes('access_admin') && others?.length === 0 ? 'access_admin' : undefined;
}
export function open(rt: Runtime, user: User, b: Record<string, unknown>): Emergency {
  allowed(user, ['access_admin', 'security_officer']);
  const why = reason(b.reason); const hours = b.hours;
  const maxHours = Math.min(4, rt.store.state.bundle.needToKnow.breakGlassMaxHours);
  if (typeof hours !== 'number' || !Number.isFinite(hours) || hours <= 0 || hours > maxHours) throw new HttpError(422, 'unprocessable', `hours must be in (0, ${maxHours}]`);
  const subjects = rt.store.state.subjects.filter((s) => s.id === string(b.subjectId));
  const resources = rt.store.state.resources.filter((r) => r.id === string(b.resourceId));
  if (subjects.length > 1 || resources.length > 1) throw new HttpError(422, 'unprocessable');
  const s = subjects[0], r = resources[0];
  if (!s || !r) throw new HttpError(404, 'not_found');
  if (s.id === user.id) throw new HttpError(403, 'forbidden', 'Self-grant forbidden');
  if (!Object.hasOwn(rt.store.state.bundle.schema.resourceTypes, r.type)) throw new HttpError(422, 'unprocessable');
  if (!Object.hasOwn(rt.store.state.bundle.schema.resourceTypes[r.type]?.relations ?? {}, 'granted')) throw new HttpError(422, 'unprocessable', 'Resource does not support grants');
  const id = randomUUID(); const at = rt.now(); const expiresAt = new Date(Date.parse(at) + hours * 3_600_000).toISOString();
  const tuple: StoredTuple = { id, object: { type: r.type, id: r.id }, subject: { type: s.type, id: s.id }, relation: 'granted',
    notBefore: at, notAfter: expiresAt, breakGlass: true, grantedBy: user.id, reason: why };
  const temporary = withRecordDeltas({ ...rt.store.state, tuples: [...rt.store.state.tuples, tuple] }, [{ kind: 'tuple', op: 'put', type: '', id, value: tuple }]);
  // admission defaults to a trusted network: the network condition is enforced again on every access request
  const d = decide(rt, s, r, 'read', context({ network: b.network ?? 'trusted' }, at), user.id, temporary, false);
  const mandatory = d.rules.filter((rule) => /(?:^|\.)(BLP\.|MAC\.|NET\.|BIBA\.)/.test(rule));
  if (mandatory.length) throw new HttpError(422, 'unprocessable', 'Mandatory restrictions still deny access', mandatory);
  const ineligible = d.rules.filter((rule) => /(?:^|\.)(?:CORE\.INACTIVE|DELEGATION\.INACTIVE|RBAC\.NOT_ELIGIBLE)$/.test(rule));
  if (ineligible.length) throw new HttpError(422, 'unprocessable', 'Emergency grant cannot permit access', ineligible);
  if (!d.decision) throw new HttpError(422, 'unprocessable', 'Emergency grant cannot permit access', [...d.rules]);
  // one emergency per (subject, resource) at a time: re-opening would make the time box no bound and a revoke not stick
  if (rt.store.emergencies.some((e) => e.subjectId === s.id && e.resourceId === r.id && (e.resourceType ?? r.type) === r.type &&
    (!e.reviewedBy || (e.status !== 'revoked' && Date.parse(e.expiresAt) > Date.parse(at))))) {
    throw new HttpError(409, 'break_glass_pending', 'An emergency for this subject and resource is still active or awaits review');
  }
  const event: Emergency = { id, subjectId: s.id, resourceId: r.id, resourceType: r.type, reason: why, openedBy: user.id, openedAt: at, expiresAt, status: 'active', tupleId: id };
  // audit first: a refused append (integrity failure, disk error) leaves no privileged grant behind
  rt.audit.append({ type: 'break_glass', actor: user.id, action: 'open', subject: s.id, resource: r.id, policyVersion: policyVersion(temporary.bundle),
    details: { id, notify: temporary.bundle.needToKnow.breakGlassNotify, expiresAt } });
  rt.store.state = temporary; rt.store.emergencies = [...rt.store.emergencies, event]; rt.store.save();
  rt.notifyBreakGlass?.({ event: 'opened', emergencyId: id, subjectId: s.id, resourceId: r.id, actorId: user.id, at });
  return event;
}
/** Expired emergencies not yet notified: audited as `expire`, marked, then notified. Returns the notices to send. */
export function expireEmergencies(rt: Runtime): BreakGlassNotice[] {
  const at = rt.now();
  const due = rt.store.emergencies.filter((e) => e.status !== 'revoked' && !e.expiryNotified && Date.parse(e.expiresAt) <= Date.parse(at));
  if (!due.length) return [];
  // audited before marked: a failed append leaves the emergency un-notified, so the next sweep audits it again
  for (const e of due) rt.audit.append({ type: 'break_glass', actor: 'system', action: 'expire', subject: e.subjectId, resource: e.resourceId, details: { id: e.id, expiresAt: e.expiresAt } });
  rt.store.emergencies = rt.store.emergencies.map((e) => due.includes(e) ? { ...e, expiryNotified: true } : e); rt.store.save();
  return due.map((e) => ({ event: 'expired', emergencyId: e.id, subjectId: e.subjectId, resourceId: e.resourceId, actorId: 'system', at }));
}
export function reviewEmergency(rt: Runtime, user: User, id: string, action: string, b: Record<string, unknown>, officers?: readonly string[]): Emergency {
  allowed(user, ['security_officer', 'access_admin']);
  const e = rt.store.emergencies.find((e) => e.id === id);
  if (!e) throw new HttpError(404, 'not_found');
  if (e.openedBy === user.id || e.subjectId === user.id) throw new HttpError(403, 'self_approval', 'The opener cannot review or revoke their own emergency');
  const role = reviewerRole(e, user, officers);
  if (!role) throw new HttpError(403, 'forbidden', 'A security officer other than the opener and the subject must review this emergency');
  let updated: Emergency; let nextState = rt.store.state;
  if (action === 'revoke') {
    reason(b.reason);
    if (e.status === 'revoked') throw new HttpError(409, 'conflict');
    nextState = withRecordDeltas({ ...rt.store.state, tuples: rt.store.state.tuples.filter((t) => t.id !== e.tupleId) }, [{ kind: 'tuple', op: 'delete', type: '', id: e.tupleId }]);
    updated = { ...e, status: 'revoked' };
  } else {
    if (e.reviewedBy) throw new HttpError(409, 'conflict');
    if (b.outcome !== 'justified' && b.outcome !== 'escalated') throw new HttpError(422, 'unprocessable');
    updated = { ...e, status: e.status === 'active' ? 'reviewed' : e.status, reviewedBy: user.id, outcome: b.outcome, note: string(b.note) };
  }
  rt.audit.append({ type: 'break_glass', actor: user.id, action, subject: e.subjectId, resource: e.resourceId, policyVersion: policyVersion(rt.store.state.bundle), details: { id, openedBy: e.openedBy, reviewerRole: role, fallback: role === 'access_admin', ...(updated.outcome ? { outcome: updated.outcome } : {}) } });
  rt.store.state = nextState; rt.store.emergencies = rt.store.emergencies.map((x) => x.id === id ? updated : x); rt.store.save();
  if (action === 'revoke') rt.notifyBreakGlass?.({ event: 'revoked', emergencyId: id, subjectId: e.subjectId, resourceId: e.resourceId, actorId: user.id, at: rt.now() });
  return updated;
}
