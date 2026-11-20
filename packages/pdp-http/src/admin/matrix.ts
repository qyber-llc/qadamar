import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import type { Context, Decision, StageName, TraceStep } from '../../../core/src/index.ts';
import { actionDef } from '../../../core/src/index.ts';
import { decide, inScope, subjectInScope } from '../runtime.ts';

/** The access layers in the order the engine applies them (docs/ARCHITECTURE.md §3.2). */
export const LAYERS = ['rights', 'clearance', 'needToKnow', 'conditions', 'content', 'context', 'controls'] as const;
export type Layer = (typeof LAYERS)[number];
type Outcome = 'pass' | 'deny' | 'would_deny' | 'obligation' | 'none';

const STAGE_LAYER: Readonly<Record<StageName, Layer>> = {
  rbac: 'rights', mandatory: 'clearance', need_to_know: 'needToKnow', abac: 'conditions', cbac: 'context',
  inactive: 'controls', delegation: 'controls', clark_wilson: 'controls', sod: 'controls', engine: 'controls',
};
const RANK: Readonly<Record<Outcome, number>> = { none: 0, pass: 1, obligation: 2, would_deny: 3, deny: 4 };

/** An ABAC permit is eligibility, so it belongs to the rights layer, not to the conditions layer. */
const layerOf = (t: TraceStep): Layer => {
  // ABAC on content attributes runs in the abac stage but keeps its own column
  if (t.kind === 'content') return 'content';
  if (t.stage === 'abac' && t.outcome === 'pass') return 'rights';
  // the person an agent acts for must also be cleared: those findings are clearance, an inactive delegator is a control
  if (t.stage === 'delegation' && t.rule !== 'DELEGATION.INACTIVE') return 'clearance';
  return STAGE_LAYER[t.stage];
};

export function layers(d: Decision): Record<Layer, { o: Outcome; rules: string[]; reason?: string }> {
  const out = Object.fromEntries(LAYERS.map((l) => [l, { o: 'none' as Outcome, rules: [] as string[] }])) as Record<Layer, { o: Outcome; rules: string[]; reason?: string }>;
  for (const t of d.trace) {
    const cell = out[layerOf(t)];
    const o: Outcome = t.outcome === 'skip' ? 'none' : t.outcome;
    if (!cell.rules.includes(t.rule)) cell.rules.push(t.rule);
    if (RANK[o] >= RANK[cell.o]) { cell.o = o; cell.reason = t.reason; }
  }
  // mandatory findings are always computed; the engine only writes its pass line when nothing at all was denied
  if (out.clearance.o === 'none' && out.controls.o !== 'deny') out.clearance = { o: 'pass', rules: ['MAC'], reason: 'level, compartments, network and integrity satisfied' };
  return out;
}

/** Every subject × resource the caller may see, for one action: each cell carries the outcome of every layer. */
export function matrix(rt: Runtime, user: User, action: string, ctx: Context): unknown {
  const state = rt.store.state;
  const subjects = state.subjects.filter((s) => subjectInScope(rt, user, s));
  const resources = state.resources.filter((r) => inScope(rt, user, r));
  const actions = [...new Set(Object.values(state.bundle.schema.resourceTypes).flatMap((t) => Object.keys(t.actions)))];
  const cells = subjects.flatMap((s) => resources.map((r) => {
    if (!actionDef(state.bundle, r.type, action)) return { subject: s.id, resource: r.id, applicable: false };
    const d = decide(rt, s, r, action, ctx, user.id, state, false);
    return { subject: s.id, resource: r.id, applicable: true, decision: d.decision, layers: layers(d),
      path: d.trace.find((t) => t.path)?.path, obligations: d.obligations };
  }));
  return {
    action, network: ctx.network, layers: LAYERS, actions,
    subjects: subjects.map((s) => ({ id: s.id, type: s.type, name: s.attrs?.name ?? s.id, roles: s.roles,
      ...(s.roleAssignments?.length ? { roleAssignments: s.roleAssignments } : {}), clearance: s.clearance, compartments: s.compartments })),
    resources: resources.map((r) => ({ id: r.id, type: r.type, title: r.attrs?.title ?? r.id, level: r.level, compartments: r.compartments, contentClasses: r.contentClasses ?? [] })),
    cells,
  };
}
