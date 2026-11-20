// Clark-Wilson administration: run the integrity verification procedures over every constrained item (C1), and list
// the certification records of transformation procedures (C2, E4), and list reservations no PEP settled. Ids and rule
// ids only, never item content.
import { policyVersion, verifyIntegrity } from '../../../core/src/index.ts';
import type { Runtime } from '../runtime.ts';
import { certificationCurrent } from '../runtime.ts';
import type { User } from '../auth.ts';
import { allowed } from '../auth.ts';

interface AdminResult { value: unknown; status: number }

/** Certified actions on constrained types: the transformation procedures that need a certification record. */
function procedures(rt: Runtime): Array<{ resourceType: string; action: string }> {
  return Object.entries(rt.store.state.bundle.schema.resourceTypes).filter(([, t]) => t.constrained)
    .flatMap(([resourceType, t]) => Object.entries(t.actions).filter(([, a]) => a.certified).map(([action]) => ({ resourceType, action })));
}

export function integrity(rt: Runtime, user: User, method: string, path: string): AdminResult | undefined {
  if (method === 'GET' && path === '/integrity/certifications') {
    allowed(user, ['access_admin', 'policy_author', 'approver', 'security_officer', 'auditor']);
    const state = rt.store.state;
    // `current`: the record certified the procedure as the bundle now defines it; a stale one needs recertifying
    const items = (state.certifications ?? []).map((c) => ({ ...c, current: certificationCurrent(state, c) }));
    const has = (p: { resourceType: string; action: string }, current: boolean) => items.some((c) => c.resourceType === p.resourceType && c.action === p.action && (!current || c.current));
    const missing = procedures(rt).filter((p) => !has(p, true));
    return { value: { items, missing, stale: missing.filter((p) => has(p, false)) }, status: 200 };
  }
  if (method === 'GET' && path === '/integrity/reservations') {
    // certified actions whose PEP never reported an outcome: they count for SoD until reconciled (docs/API.md 2.0.3)
    allowed(user, ['access_admin', 'security_officer', 'auditor']);
    const items = rt.store.pendingReservations().map((p) => ({ reservation: p.id, subject: p.subject, resource: p.resource, action: p.action, reservedAt: p.at,
      ...(p.pep ? { pep: p.pep } : {}), ...(p.onBehalfOf ? { onBehalfOf: p.onBehalfOf } : {}) }));
    // completed commands whose post-state the PDP could not apply to its copy of the item, with the reason
    return { value: { items, unappliedPostStates: rt.store.state.unappliedPostStates ?? [] }, status: 200 };
  }
  if (method === 'POST' && path === '/integrity/verify') {
    allowed(user, ['security_officer', 'auditor']);
    const { bundle, resources } = rt.store.state;
    const items = resources.flatMap((r) => verifyIntegrity(bundle, r).map((x) => ({ ivp: x.ivp, resourceType: r.type, resource: r.id, ok: x.ok })));
    const failed = items.filter((x) => !x.ok);
    const version = policyVersion(bundle);
    rt.audit.append({ type: 'security', actor: user.id, action: 'ivp_run', effect: failed.length ? 'deny' : 'allow',
      rules: [...new Set(failed.map((x) => `CW.IVP.${x.ivp}`))], policyVersion: version,
      details: { checked: items.length, failed: failed.map((x) => ({ ivp: x.ivp, resourceType: x.resourceType, resource: x.resource })) } });
    return { value: { verified: failed.length === 0, checked: items.length, policyVersion: version, items }, status: 200 };
  }
  return undefined;
}
