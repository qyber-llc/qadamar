import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import { inScope, subjectInScope } from '../runtime.ts';
import { policyVersion } from '../../../core/src/index.ts';
import { HttpError } from '../http.ts';

export function model(rt: Runtime, user: User, path: string): unknown {
  const state = rt.store.state; const b = state.bundle;
  if (path === '/schema') return { ...b.schema, mandatory: b.mandatory, needToKnow: b.needToKnow };
  if (path === '/policy') {
    const version = policyVersion(b); const latest = rt.store.history.at(-1);
    const signature = latest?.signature && rt.tokens.verifyDetached(b, latest.signature.jws) ? latest.signature : null;
    return { current: { version, bundle: b, signature }, history: rt.store.history };
  }
  if (path === '/resources') return { items: state.resources.filter((r) => inScope(rt, user, r)).map((r) => ({
    type: r.type, id: r.id, title: r.attrs?.title ?? r.id, status: r.attrs?.status ?? null, level: r.level,
    compartments: r.compartments, integrity: r.integrity, owner: r.owner, contentClasses: r.contentClasses ?? [],
  })) };
  const tuples = state.tuples.filter((t) => inScope(rt, user, t.object));
  if (path === '/tuples') return { items: tuples };
  if (path === '/subjects') return { items: state.subjects.filter((s) => subjectInScope(rt, user, s)).map((s) => ({
    type: s.type, id: s.id, name: s.attrs?.name ?? s.id, unit: s.attrs?.unit ?? null, active: s.active, roles: s.roles, ...(s.roleAssignments?.length ? { roleAssignments: s.roleAssignments } : {}),
    clearance: s.clearance, compartments: s.compartments, integrity: s.integrity, ...(s.attrs?.delegatedBy ? { delegatedBy: s.attrs.delegatedBy } : {}),
  })) };
  throw new HttpError(404, 'not_found');
}
