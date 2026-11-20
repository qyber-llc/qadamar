import { policyVersion, windowOf } from '../../../core/src/index.ts';
import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import { ownerOnly } from '../auth.ts';
import { inScope } from '../runtime.ts';
import { emergencies } from './break-glass.ts';
import { visibleChange } from './changes.ts';

export function overview(rt: Runtime, user: User): unknown {
  const state = rt.store.state; const emergency = emergencies(rt);
  const scopedId = (id: string) => { const matches = state.resources.filter((r) => r.id === id); return matches.length === 1 && inScope(rt, user, matches[0]!); };
  const at = Date.parse(rt.now()); const verification = rt.audit.verify();
  const response = (scoped?: { length: number; decisions: number }): unknown => ({ policy: { name: state.bundle.name, ...rt.store.history.at(-1), version: policyVersion(state.bundle) },
    needToKnowMode: state.bundle.needToKnow.mode, counts: {
      pendingChanges: rt.store.changes.filter((c) => c.status === 'pending' && visibleChange(rt, user, c)).length,
      activeBreakGlass: emergency.active.filter((e) => scopedId(e.resourceId)).length,
      breakGlassToReview: emergency.toReview.filter((e) => scopedId(e.resourceId)).length,
      expiringGrants30d: state.tuples.filter((t) => {
        const to = windowOf(t).to;
        return inScope(rt, user, t.object) && ['granted', 'allocated'].includes(t.relation) && to !== undefined && Date.parse(to) >= at && Date.parse(to) <= at + 30 * 86400000;
      }).length,
    }, audit: { verified: verification.verified, length: scoped?.length ?? verification.length,
      head: rt.audit.list ? rt.audit.tip().hash : rt.audit.records().at(-1)?.hash ?? '0'.repeat(64) },
    pdp: { status: 'ok', uptimeSeconds: Math.max(0, Math.floor((Date.parse(rt.now()) - rt.started) / 1000)), decisions: scoped?.decisions ?? rt.decisions } });
  if (!ownerOnly(user)) return response();
  if (rt.audit.countScoped) {
    const resources = state.resources.filter((r) => scopedId(r.id)).map((r) => r.id);
    return Promise.all([rt.audit.countScoped(resources), rt.audit.countScoped(resources, 'decision')])
      .then(([length, decisions]) => response({ length, decisions }));
  }
  return response({ length: rt.audit.records().filter((r) => r.resource && scopedId(r.resource)).length,
    decisions: rt.audit.records().filter((r) => r.type === 'decision' && r.resource && scopedId(r.resource)).length });
}
