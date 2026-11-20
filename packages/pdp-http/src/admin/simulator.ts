import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { context, decide, inScope, resourceScope, subjectInScope } from '../runtime.ts';
import { candidate, impact, scopedImpact } from './changes.ts';
import { HttpError, string } from '../http.ts';
import { matrix } from './matrix.ts';

export function simulator(rt: Runtime, user: User, path: string, b: Record<string, unknown>): unknown {
  allowed(user, ['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner']);
  if (path === '/simulate/impact') {
    const c = candidate(rt, user, string(b.kind), b.payload, false, true); return scopedImpact(rt, user, impact(rt, c.state));
  }
  const ctx = context(b, rt.now()); const action = string(b.action);
  const state = rt.store.state;
  if (path === '/simulate/matrix') return matrix(rt, user, action, ctx);
  if (path === '/simulate/what-can') {
    const s = state.subjects.find((x) => x.id === string(b.subjectId));
    if (!s || !subjectInScope(rt, user, s)) throw new HttpError(404, 'not_found');
    return { items: state.resources.filter((r) => inScope(rt, user, r)).map((r) => {
      const d = decide(rt, s, r, action, ctx, user.id, state, false);
      return { resource: { type: r.type, id: r.id, title: r.attrs?.title ?? r.id, level: r.level }, decision: d.decision,
        rules: d.rules, reasons: d.reasons, path: d.trace.find((t) => t.path)?.path, obligations: d.obligations };
    }) };
  }
  const id = string(b.resourceId); resourceScope(rt, user, id);
  const r = state.resources.find((x) => x.id === id);
  if (!r) throw new HttpError(404, 'not_found');
  if (path === '/simulate/who-can') return { items: state.subjects.filter((s) => subjectInScope(rt, user, s)).map((s) => {
    const d = decide(rt, s, r, action, ctx, user.id, state, false);
    return { subject: { type: s.type, id: s.id, name: s.attrs?.name ?? s.id }, decision: d.decision, rules: d.rules, reasons: d.reasons, path: d.trace.find((t) => t.path)?.path };
  }) };
  if (path === '/explain') {
    const s = state.subjects.find((x) => x.id === string(b.subjectId));
    if (!s || !subjectInScope(rt, user, s)) throw new HttpError(404, 'not_found');
    return decide(rt, s, r, action, ctx, user.id, state, false);
  }
  throw new HttpError(404, 'not_found');
}
