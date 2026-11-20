// Clark-Wilson integrity verification procedures (IVP, rule C1): declared predicates over a constrained data item.
// An IVP holds only when its check is TRUE; a missing or null value is UNKNOWN and fails (fail closed). Pure.
import { evalExpr } from './conditions.ts';
import type { IvpDef, PolicyBundle, Resource } from './types.ts';

export interface IvpResult { readonly ivp: string; readonly ok: boolean; readonly reason: string }

export function ivpsFor(bundle: PolicyBundle, type: string): readonly IvpDef[] {
  return (bundle.clarkWilson.ivps ?? []).filter((i) => i.resourceTypes.includes(type));
}

/** Every IVP declared for the resource's type, run on this state of the resource. A check that throws fails. */
export function verifyIntegrity(bundle: PolicyBundle, resource: Resource): IvpResult[] {
  return ivpsFor(bundle, resource.type).map((i) => {
    let ok = false;
    try { ok = evalExpr(i.check, { subject: null, resource, action: null, context: null }); } catch { ok = false; }
    return { ivp: i.id, ok, reason: i.description };
  });
}
