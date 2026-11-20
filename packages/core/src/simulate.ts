// Impact of a change before it applies: the same (subject, resource, action) grid decided against the current and the
// candidate world, returning who gains and who loses access, and on cells allowed in both worlds which obligations
// (redaction, masking, field allowlist, notification, decision token) are lost or gained (KIMI-02). Metadata only: ids,
// rule ids, field and class names, never content.
import { evaluate } from './evaluate.ts';
import { indexTuples, keyOf, type Graph } from './relations.ts';
import type { Context, Decision, Obligations, PolicyBundle, Ref, Resource, Subject, Tuple } from './types.ts';
import { policyVersion } from './version.ts';

export interface World {
  readonly bundle: PolicyBundle;
  readonly subjects: readonly Subject[];
  readonly resources: readonly Resource[];
  readonly tuples: readonly Tuple[];
}

export interface Change {
  readonly subjectType: string;
  readonly subject: string;
  readonly resourceType: string;
  readonly resource: string;
  readonly action: string;
  /** Rule ids on the denying side (after the change for a loss, before it for a gain). */
  readonly rules: readonly string[];
}

/** What one side has and the other has not. fieldAllowlist: the allowlist on both sides (null: every field) when it changed. */
export interface ObligationDelta {
  readonly redact: readonly string[];
  readonly maskClasses: readonly string[];
  readonly notify: readonly string[];
  readonly fieldAllowlist?: { readonly before: readonly string[] | null; readonly after: readonly string[] | null };
  /** The single-use decision token is no longer (lost) or newly (gained) required, or its lifetime or post-state binding changed that way. */
  readonly decisionToken?: true;
}

/** A cell allowed in both worlds whose obligations changed; rules: the obligation rules present on one side only. */
export interface ObligationChange extends Change {
  readonly obligations: ObligationDelta;
}

export interface ImpactAnalysis {
  /** Unique affected cells before network and maker/history variants multiply the work. */
  readonly affectedCells: number;
  readonly reasons: readonly string[];
}

export interface ImpactContextClass {
  readonly context: Context;
  readonly evaluated: number;
  readonly gained: readonly Change[];
  readonly lost: readonly Change[];
  readonly obligationsLost: readonly ObligationChange[];
  readonly obligationsGained: readonly ObligationChange[];
}

export interface ImpactContextAnalysis {
  /** Representative classes per network; one-signal variants are considered before their cross-product. */
  readonly cap: number;
  readonly evaluatedClasses: number;
  readonly truncated: boolean;
  /** True when the cap or an unsupported expression leaves part of the context space unanalysed. */
  readonly incomplete?: boolean;
  readonly unsupported?: readonly string[];
  /** Classes with a decision or obligation change; maker/history variants are merged within each class. */
  readonly classes: readonly ImpactContextClass[];
}

export interface Impact {
  readonly evaluated: number;
  readonly gained: readonly Change[];
  readonly lost: readonly Change[];
  /** Still allowed, with less protection: a broadening. */
  readonly obligationsLost: readonly ObligationChange[];
  /** Still allowed, with more protection: a narrowing. */
  readonly obligationsGained: readonly ObligationChange[];
  readonly policyVersionBefore: string;
  readonly policyVersionAfter: string;
  /** Absent in impacts stored before affected-set analysis. */
  readonly analysis?: ImpactAnalysis;
  /** Absent in stored previews and when no context signal needs partitioning. */
  readonly contextAnalysis?: ImpactContextAnalysis;
}

export interface ImpactCell {
  readonly subject: Ref;
  readonly resource: Ref;
  readonly action: string;
}

const key = (s: Ref, r: Ref, action: string): string => JSON.stringify([s.type, s.id, r.type, r.id, action]);

type GridCell = { key: string; subject: Subject; resource: Resource; action: string };
function* grid(w: World, actions: readonly string[] | undefined, cells?: readonly ImpactCell[]): Generator<GridCell> {
  if (cells) {
    const subjects = new Map(w.subjects.map((s) => [keyOf(s), s]));
    const resources = new Map(w.resources.map((r) => [keyOf(r), r]));
    for (const cell of cells) {
      if (actions && !actions.includes(cell.action)) continue;
      const subject = subjects.get(keyOf(cell.subject)); const resource = resources.get(keyOf(cell.resource));
      if (!subject || !resource || !Object.hasOwn(w.bundle.schema.resourceTypes[resource.type]?.actions ?? {}, cell.action)) continue;
      yield { key: key(subject, resource, cell.action), subject, resource, action: cell.action };
    }
    return;
  }
  for (const subject of w.subjects) {
    for (const resource of w.resources) {
      const declared = Object.keys(w.bundle.schema.resourceTypes[resource.type]?.actions ?? {});
      for (const action of actions ? declared.filter((x) => actions.includes(x)) : declared) {
        yield { key: key(subject, resource, action), subject, resource, action };
      }
    }
  }
}

/** Cells compared, as reported in Impact.evaluated (the engine evaluates each in both worlds, so up to twice this). */
export function evaluationCount(before: World, after: World, actions: readonly string[] | undefined, limit = Number.MAX_SAFE_INTEGER): number {
  const keys = new Set<string>();
  for (const world of [before, after]) {
    for (const cell of grid(world, actions)) {
      keys.add(cell.key);
      if (keys.size > limit) return keys.size;
    }
  }
  return keys.size;
}

type CellContext = (subject: Subject, resource: Resource, action: string, context: Context, world: World) => Context;
const sameContext: CellContext = (_subject, _resource, _action, context) => context;

const missing = (a: readonly string[], b: readonly string[]): string[] => a.filter((x) => !b.includes(x));
const obligationRules = (d: Decision): string[] => [...new Set(d.trace.filter((t) => t.outcome === 'obligation').map((t) => t.rule))];

/** What `was` imposes and `now` does not (call it both ways for gains). Null when nothing. Both decisions allow. */
export function obligationLoss(was: Pick<Decision, 'obligations' | 'trace'>, now: Pick<Decision, 'obligations' | 'trace'>): { obligations: ObligationDelta; rules: string[] } | null {
  const o: Obligations = was.obligations; const p: Obligations = now.obligations;
  const allowWider = o.fieldAllowlist !== undefined && (p.fieldAllowlist === undefined || missing(p.fieldAllowlist, o.fieldAllowlist).length > 0);
  const t0 = o.decisionToken; const t1 = p.decisionToken;
  const token = t0 !== undefined && (t1 === undefined || t1.ttlSeconds > t0.ttlSeconds || (t0.postState === true && t1.postState !== true));
  const delta: ObligationDelta = { redact: missing(o.redact, p.redact), maskClasses: missing(o.maskClasses, p.maskClasses), notify: missing(o.notify, p.notify),
    ...(allowWider ? { fieldAllowlist: { before: o.fieldAllowlist ?? null, after: p.fieldAllowlist ?? null } } : {}), ...(token ? { decisionToken: true as const } : {}) };
  if (!delta.redact.length && !delta.maskClasses.length && !delta.notify.length && !allowWider && !token) return null;
  return { obligations: delta, rules: missing(obligationRules(was as Decision), obligationRules(now as Decision)) };
}

type Cell = { allowed: boolean; rules: readonly string[]; pv: string; obligations: Obligations; trace: Decision['trace'] };

function decideAll(w: World, context: Context, actions: readonly string[] | undefined, graph = indexTuples(w.tuples), cellContext: CellContext = sameContext, cells?: readonly ImpactCell[]) {
  const out = new Map<string, Cell>();
  for (const cell of grid(w, actions, cells)) {
    const derived = cellContext(cell.subject, cell.resource, cell.action, context, w);
    const d = evaluate(w.bundle, { subject: cell.subject, resource: cell.resource, action: cell.action, context: derived }, graph);
    // the key carries the types: a user and an agent, or a case and a folder, may share an id
    out.set(cell.key, { allowed: d.decision, rules: d.rules, pv: d.policyVersion, obligations: d.obligations, trace: d.trace });
  }
  return out;
}

/** `graphs`: tuple indexes built once by a caller that simulates the same worlds many times. `cells`: an affected set; omit for the full grid. */
export function simulate(before: World, after: World, context: Context, actions?: readonly string[], graphs?: { before: Graph; after: Graph }, cellContext?: CellContext, cells?: readonly ImpactCell[]): Impact {
  const b = decideAll(before, context, actions, graphs?.before, cellContext, cells);
  const a = decideAll(after, context, actions, graphs?.after, cellContext, cells);
  const gained: Change[] = [];
  const lost: Change[] = [];
  const obligationsLost: ObligationChange[] = [];
  const obligationsGained: ObligationChange[] = [];
  for (const key of new Set([...b.keys(), ...a.keys()])) {
    const was = b.get(key);
    const now = a.get(key);
    const [subjectType, subject, resourceType, resource, action] = JSON.parse(key) as string[];
    const base = { subjectType, subject, resourceType, resource, action } as Omit<Change, 'rules'>;
    if (now?.allowed && !was?.allowed) gained.push({ ...base, rules: was?.rules ?? ['ABSENT'] });
    if (was?.allowed && !now?.allowed) lost.push({ ...base, rules: now?.rules ?? ['ABSENT'] });
    if (was?.allowed && now?.allowed) {
      const less = obligationLoss(was, now); const more = obligationLoss(now, was);
      if (less) obligationsLost.push({ ...base, ...less });
      if (more) obligationsGained.push({ ...base, ...more });
    }
  }
  const order = (x: Change, y: Change) => `${x.subject}${x.resource}${x.action}`.localeCompare(`${y.subject}${y.resource}${y.action}`);
  return {
    evaluated: new Set([...b.keys(), ...a.keys()]).size,
    gained: gained.sort(order),
    lost: lost.sort(order),
    obligationsLost: obligationsLost.sort(order),
    obligationsGained: obligationsGained.sort(order),
    policyVersionBefore: policyVersion(before.bundle),
    policyVersionAfter: policyVersion(after.bundle),
  };
}
