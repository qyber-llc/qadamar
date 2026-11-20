// ReBAC: Zanzibar-style relation checks over an in-memory tuple graph, with the rewrites declared in the bundle
// (direct, computed, from-parent, via-reports). Every positive answer carries the path that produced it, for explain.
// A relation only ever supplies a reason to know: the mandatory models are checked elsewhere and are never lifted here.
import type { PolicyBundle, Ref, RelationDef, Tuple } from './types.ts';

export interface Graph {
  readonly byObject: ReadonlyMap<string, readonly Tuple[]>;
  readonly bySubject: ReadonlyMap<string, readonly Tuple[]>;
  readonly objectsByType: ReadonlyMap<string, readonly string[]>;
  readonly usersetRelations: ReadonlyMap<string, readonly string[]>;
  readonly usersetSubjectTypes: ReadonlyMap<string, readonly string[]>;
  readonly parentSubjectTypes: ReadonlyMap<string, readonly string[]>;
}

export interface RelationResult {
  readonly ok: boolean;
  readonly path: readonly string[];
  readonly breakGlass: boolean;
}

export interface TupleIndexChange { readonly op: 'put' | 'delete'; readonly tuple: Tuple }
interface IndexCounts { relations: Map<string, number>; subjects: Map<string, number>; parents: Map<string, number> }
const indexCounts = new WeakMap<Graph, IndexCounts>();

const NO: RelationResult = { ok: false, path: [], breakGlass: false };
const MAX_HOPS = 32;

/** Collision-free key: an id containing ':' or '#' cannot impersonate another (type, id) pair. */
export const keyOf = (r: Ref): string => JSON.stringify([r.type, r.id]);
const label = (r: Ref): string => `${r.type}:${r.id}`;

const indexKey = (...parts: readonly string[]): string => JSON.stringify(parts);

export function indexTuples(tuples: readonly Tuple[]): Graph {
  const byObject = new Map<string, Tuple[]>();
  const bySubject = new Map<string, Tuple[]>();
  const objects = new Map<string, Set<string>>();
  const usersetRelations = new Map<string, Set<string>>();
  const usersetSubjects = new Map<string, Set<string>>();
  const parentSubjects = new Map<string, Set<string>>();
  const counts: IndexCounts = { relations: new Map(), subjects: new Map(), parents: new Map() };
  for (const t of tuples) {
    const o = keyOf(t.object);
    const s = keyOf(t.subject);
    byObject.set(o, [...(byObject.get(o) ?? []), t]);
    bySubject.set(s, [...(bySubject.get(s) ?? []), t]);
    objects.set(t.object.type, (objects.get(t.object.type) ?? new Set()).add(t.object.id));
    countLabels(counts, t, 1);
    const relationKey = indexKey(t.object.type, t.relation);
    if (t.subjectRelation) {
      usersetRelations.set(relationKey, (usersetRelations.get(relationKey) ?? new Set()).add(t.subjectRelation));
      const key = indexKey(t.object.type, t.relation, t.subjectRelation);
      usersetSubjects.set(key, (usersetSubjects.get(key) ?? new Set()).add(t.subject.type));
    }
    parentSubjects.set(relationKey, (parentSubjects.get(relationKey) ?? new Set()).add(t.subject.type));
  }
  const sorted = (index: Map<string, Set<string>>) => new Map([...index].map(([k, v]) => [k, [...v].sort()] as const));
  const graph: Graph = {
    byObject,
    bySubject,
    objectsByType: sorted(objects),
    usersetRelations: sorted(usersetRelations),
    usersetSubjectTypes: sorted(usersetSubjects),
    parentSubjectTypes: sorted(parentSubjects),
  };
  indexCounts.set(graph, counts);
  return graph;
}

function countLabels(counts: IndexCounts, t: Tuple, by: number): void {
  const relation = indexKey(t.object.type, t.relation);
  const add = (map: Map<string, number>, key: string): void => { map.set(key, (map.get(key) ?? 0) + by); };
  if (t.subjectRelation) {
    add(counts.relations, indexKey(relation, t.subjectRelation));
    add(counts.subjects, indexKey(relation, t.subjectRelation, t.subject.type));
  }
  add(counts.parents, indexKey(relation, t.subject.type));
}

function removeLabel(map: ReadonlyMap<string, readonly string[]>, key: string, value: string): void {
  const values = map.get(key) as string[] | undefined;
  if (!values) return;
  const at = values.indexOf(value);
  if (at >= 0) values.splice(at, 1);
  if (!values.length) (map as Map<string, readonly string[]>).delete(key);
}

function addLabel(map: ReadonlyMap<string, readonly string[]>, key: string, value: string): void {
  const values = map.get(key) as string[] | undefined;
  if (values) { if (!values.includes(value)) { values.push(value); values.sort(); } }
  else (map as Map<string, readonly string[]>).set(key, [value]);
}

/** Applies the same additions and removals to an index and its label counts, without walking the unchanged tuples. */
export function patchTupleIndex(graph: Graph, changes: readonly TupleIndexChange[]): void {
  const counts = indexCounts.get(graph);
  if (!counts) throw new Error('Tuple index was not built by indexTuples');
  const byObject = graph.byObject as Map<string, Tuple[]>;
  const bySubject = graph.bySubject as Map<string, Tuple[]>;
  const same = (a: Tuple, b: Tuple): boolean => a === b ||
    (typeof (a as Tuple & { id?: unknown }).id === 'string' && (a as Tuple & { id?: unknown }).id === (b as Tuple & { id?: unknown }).id);
  for (const { op, tuple } of changes) {
    const object = keyOf(tuple.object), subject = keyOf(tuple.subject);
    if (op === 'delete') {
      for (const [map, key] of [[byObject, object], [bySubject, subject]] as const) {
        const rows = map.get(key);
        if (!rows) continue;
        const at = rows.findIndex((row) => same(row, tuple));
        if (at >= 0) rows.splice(at, 1);
        if (!rows.length) map.delete(key);
      }
      const objects = graph.objectsByType.get(tuple.object.type) as string[] | undefined;
      if (!byObject.has(object) && objects) {
        const at = objects.indexOf(tuple.object.id);
        if (at >= 0) objects.splice(at, 1);
        if (!objects.length) (graph.objectsByType as Map<string, readonly string[]>).delete(tuple.object.type);
      }
    } else {
      byObject.set(object, [...(byObject.get(object) ?? []), tuple]);
      bySubject.set(subject, [...(bySubject.get(subject) ?? []), tuple]);
      addLabel(graph.objectsByType, tuple.object.type, tuple.object.id);
    }
    countLabels(counts, tuple, op === 'put' ? 1 : -1);
    const relation = indexKey(tuple.object.type, tuple.relation);
    if (tuple.subjectRelation) {
      const relationKey = indexKey(relation, tuple.subjectRelation);
      const subjectKey = indexKey(relation, tuple.subjectRelation, tuple.subject.type);
      const subjectMapKey = indexKey(tuple.object.type, tuple.relation, tuple.subjectRelation);
      if (op === 'put') {
        addLabel(graph.usersetRelations, relation, tuple.subjectRelation);
        addLabel(graph.usersetSubjectTypes, subjectMapKey, tuple.subject.type);
      } else {
        if (!counts.relations.get(relationKey)) removeLabel(graph.usersetRelations, relation, tuple.subjectRelation);
        if (!counts.subjects.get(subjectKey)) removeLabel(graph.usersetSubjectTypes, subjectMapKey, tuple.subject.type);
      }
    }
    const parentKey = indexKey(relation, tuple.subject.type);
    if (op === 'put') addLabel(graph.parentSubjectTypes, relation, tuple.subject.type);
    else if (!counts.parents.get(parentKey)) removeLabel(graph.parentSubjectTypes, relation, tuple.subject.type);
  }
}

const describe = (t: Tuple): string => {
  const until = windowOf(t).to;
  return `${label(t.object)}#${t.relation}@${label(t.subject)}${t.subjectRelation ? `#${t.subjectRelation}` : ''}` +
    `${t.breakGlass ? ' [break-glass]' : ''}${until ? ` until ${until.slice(0, 10)}` : ''}`;
};

/** A time-bounded grant: notBefore/notAfter, or the legacy tuple names validFrom/validTo for records written earlier. */
export interface GrantBounds { readonly notBefore?: string; readonly notAfter?: string; readonly validFrom?: string; readonly validTo?: string }
/** The grant's window; notBefore/notAfter win over the legacy names. */
export const windowOf = (g: GrantBounds): { from?: string; to?: string } => ({ from: g.notBefore ?? g.validFrom, to: g.notAfter ?? g.validTo });
/** Where `nowMs` falls in the window, both bounds inclusive. An unparseable bound or instant is never live (fail closed). */
export function windowState(g: GrantBounds, nowMs: number): 'live' | 'expired' | 'not_yet' {
  const { from, to } = windowOf(g);
  const start = from === undefined ? -Infinity : Date.parse(from);
  const end = to === undefined ? Infinity : Date.parse(to);
  if (!Number.isFinite(nowMs) || Number.isNaN(start) || Number.isNaN(end)) return 'expired';
  return nowMs < start ? 'not_yet' : nowMs > end ? 'expired' : 'live';
}

/** A tuple counts only inside its validity window, compared as instants; an unparseable bound means not live. */
export function isLive(t: Tuple, nowMs: number, breakGlassMaxHours: number): boolean {
  if (windowState(t, nowMs) !== 'live') return false;
  if (!t.breakGlass) return true;
  const { from, to } = windowOf(t);
  const hours = (Date.parse(to ?? '') - Date.parse(from ?? '')) / 3_600_000;
  return Number.isFinite(hours) && hours > 0 && hours <= breakGlassMaxHours;
}

function definition(bundle: PolicyBundle, type: string, relation: string): RelationDef {
  const rt = Object.hasOwn(bundle.schema.resourceTypes, type) ? bundle.schema.resourceTypes[type] : undefined;
  const fromResource = rt?.relations && Object.hasOwn(rt.relations, relation) ? rt.relations[relation] : undefined;
  const st = bundle.schema.subjectRelations && Object.hasOwn(bundle.schema.subjectRelations, type)
    ? bundle.schema.subjectRelations[type] : undefined;
  const fromSubject = st && Object.hasOwn(st, relation) ? st[relation] : undefined;
  return fromResource ?? fromSubject ?? { union: [{ this: true }] };
}

interface Walk {
  readonly bundle: PolicyBundle;
  readonly graph: Graph;
  readonly nowMs: number;
  readonly seen: Set<string>;
  /** Nodes already proven false in this check: keeps diamond-shaped graphs linear. */
  readonly failed: Set<string>;
}

function live(w: Walk, object: Ref, relation: string): readonly Tuple[] {
  const max = w.bundle.needToKnow.breakGlassMaxHours;
  return (w.graph.byObject.get(keyOf(object)) ?? []).filter((t) => t.relation === relation && isLive(t, w.nowMs, max));
}

function walk(w: Walk, object: Ref, relation: string, subject: Ref, hops: number): RelationResult {
  const visit = `${keyOf(object)}#${relation}@${keyOf(subject)}`;
  if (hops > MAX_HOPS || w.seen.has(visit) || w.failed.has(visit)) return NO;
  w.seen.add(visit);
  try {
    for (const rewrite of definition(w.bundle, object.type, relation).union) {
      const r = step(w, object, relation, subject, hops, rewrite);
      if (r.ok) return r;
    }
    // shortcut: a node cut by a cycle may be memoised as false; this can only deny, never allow
    w.failed.add(visit);
    return NO;
  } finally {
    w.seen.delete(visit);
  }
}

type Rewrite = RelationDef['union'][number];

const join = (t: Tuple, inner: RelationResult): RelationResult =>
  ({ ok: true, path: [describe(t), ...inner.path], breakGlass: !!t.breakGlass || inner.breakGlass });

function step(w: Walk, object: Ref, relation: string, subject: Ref, hops: number, rewrite: Rewrite): RelationResult {
  if ('this' in rewrite) {
    for (const t of live(w, object, relation)) {
      if (!t.subjectRelation && keyOf(t.subject) === keyOf(subject)) return { ok: true, path: [describe(t)], breakGlass: !!t.breakGlass };
      if (t.subjectRelation) {
        const inner = walk(w, t.subject, t.subjectRelation, subject, hops + 1);
        if (inner.ok) return join(t, inner);
      }
    }
    return NO;
  }
  if ('computed' in rewrite) return walk(w, object, rewrite.computed, subject, hops + 1);
  if ('fromParent' in rewrite) {
    for (const t of live(w, object, rewrite.fromParent.relation)) {
      const inner = walk(w, t.subject, rewrite.fromParent.then, subject, hops + 1);
      if (inner.ok) return join(t, inner);
    }
    return NO;
  }
  return viaReports(w, object, subject, hops, rewrite.viaReports);
}

/** The subject manages (transitively, bounded) someone who has `then` on the object. */
function viaReports(w: Walk, object: Ref, subject: Ref, hops: number,
  r: { managerRelation: string; then: string; maxDepth: number }): RelationResult {
  const max = w.bundle.needToKnow.breakGlassMaxHours;
  let frontier: { ref: Ref; chain: readonly Tuple[] }[] = [{ ref: subject, chain: [] }];
  const met = new Set([keyOf(subject)]);
  for (let depth = 0; depth < Math.min(r.maxDepth, 50) && frontier.length > 0; depth++) {
    const next: { ref: Ref; chain: readonly Tuple[] }[] = [];
    for (const f of frontier) {
      const reports = (w.graph.bySubject.get(keyOf(f.ref)) ?? [])
        .filter((t) => t.relation === r.managerRelation && !t.subjectRelation && isLive(t, w.nowMs, max));
      for (const t of reports) {
        if (met.has(keyOf(t.object))) continue; // a cycle in the org chart is never followed
        met.add(keyOf(t.object));
        const chain = [...f.chain, t];
        const inner = walk(w, object, r.then, t.object, hops + 1);
        if (inner.ok) {
          const edges = [...chain].reverse();
          return { ok: true, path: [...inner.path, ...edges.map(describe)], breakGlass: inner.breakGlass || edges.some((e) => !!e.breakGlass) };
        }
        next.push({ ref: t.object, chain });
      }
    }
    frontier = next;
  }
  return NO;
}

export function check(bundle: PolicyBundle, graph: Graph, object: Ref, relation: string, subject: Ref, now: string): RelationResult {
  return walk({ bundle, graph, nowMs: Date.parse(now), seen: new Set(), failed: new Set() }, object, relation, subject, 0);
}

interface ReverseState {
  readonly type: string;
  readonly relation: string;
  readonly subject: Ref;
  readonly objects: Set<string>;
  readonly listeners: ((id: string) => void)[];
}

interface Reverse {
  readonly bundle: PolicyBundle;
  readonly graph: Graph;
  readonly nowMs: number;
  readonly states: Map<string, ReverseState>;
  readonly pending: (() => void)[];
}

function addObject(r: Reverse, state: ReverseState, id: string): void {
  if (state.objects.has(id)) return;
  state.objects.add(id);
  for (const listener of state.listeners) r.pending.push(() => listener(id));
}

function onObject(r: Reverse, source: ReverseState, listener: (id: string) => void): void {
  source.listeners.push(listener);
  for (const id of source.objects) r.pending.push(() => listener(id));
}

const counts = (r: Reverse, t: Tuple): boolean =>
  isLive(t, r.nowMs, r.bundle.needToKnow.breakGlassMaxHours);

function addDirect(r: Reverse, state: ReverseState): void {
  for (const t of r.graph.bySubject.get(keyOf(state.subject)) ?? []) {
    if (t.object.type === state.type && t.relation === state.relation && !t.subjectRelation && counts(r, t)) {
      addObject(r, state, t.object.id);
    }
  }
}

function addUserset(r: Reverse, state: ReverseState, subjectRelation: string): void {
  const types = r.graph.usersetSubjectTypes.get(indexKey(state.type, state.relation, subjectRelation)) ?? [];
  for (const type of types) {
    const source = reverseState(r, type, subjectRelation, state.subject);
    onObject(r, source, (id) => {
      for (const t of r.graph.bySubject.get(keyOf({ type: source.type, id })) ?? []) {
        if (t.object.type === state.type && t.relation === state.relation &&
          t.subjectRelation === subjectRelation && counts(r, t)) addObject(r, state, t.object.id);
      }
    });
  }
}

function addParents(r: Reverse, state: ReverseState, relation: string, then: string): void {
  const types = r.graph.parentSubjectTypes.get(indexKey(state.type, relation)) ?? [];
  for (const type of types) {
    const source = reverseState(r, type, then, state.subject);
    onObject(r, source, (id) => {
      for (const t of r.graph.bySubject.get(keyOf({ type: source.type, id })) ?? []) {
        if (t.object.type === state.type && t.relation === relation && counts(r, t)) addObject(r, state, t.object.id);
      }
    });
  }
}

function addReports(r: Reverse, state: ReverseState,
  rewrite: { managerRelation: string; then: string; maxDepth: number }): void {
  let frontier = [state.subject];
  const met = new Set([keyOf(state.subject)]);
  for (let depth = 0; depth < Math.min(rewrite.maxDepth, 50) && frontier.length > 0; depth++) {
    const next: Ref[] = [];
    for (const ref of frontier) {
      const reports = (r.graph.bySubject.get(keyOf(ref)) ?? [])
        .filter((t) => t.relation === rewrite.managerRelation && !t.subjectRelation && counts(r, t));
      for (const t of reports) {
        if (met.has(keyOf(t.object))) continue;
        met.add(keyOf(t.object));
        onObject(r, reverseState(r, state.type, rewrite.then, t.object), (id) => addObject(r, state, id));
        next.push(t.object);
      }
    }
    frontier = next;
  }
}

function initialise(r: Reverse, state: ReverseState): void {
  const rewrites = definition(r.bundle, state.type, state.relation).union;
  if (rewrites.some((rewrite) => 'this' in rewrite)) addDirect(r, state);
  for (const rewrite of rewrites) {
    if ('this' in rewrite) {
      for (const relation of r.graph.usersetRelations.get(indexKey(state.type, state.relation)) ?? []) {
        addUserset(r, state, relation);
      }
    } else if ('computed' in rewrite) {
      onObject(r, reverseState(r, state.type, rewrite.computed, state.subject), (id) => addObject(r, state, id));
    } else if ('fromParent' in rewrite) {
      addParents(r, state, rewrite.fromParent.relation, rewrite.fromParent.then);
    } else {
      addReports(r, state, rewrite.viaReports);
    }
  }
}

function reverseState(r: Reverse, type: string, relation: string, subject: Ref): ReverseState {
  const key = indexKey(type, relation, subject.type, subject.id);
  const existing = r.states.get(key);
  if (existing) return existing;
  const state: ReverseState = { type, relation, subject, objects: new Set(), listeners: [] };
  r.states.set(key, state);
  r.pending.push(() => initialise(r, state));
  return state;
}

function reverseCandidates(bundle: PolicyBundle, graph: Graph,
  type: string, relation: string, subject: Ref, now: string): ReadonlySet<string> {
  const r: Reverse = { bundle, graph, nowMs: Date.parse(now), states: new Map(), pending: [] };
  const root = reverseState(r, type, relation, subject);
  for (let i = 0; i < r.pending.length; i++) r.pending[i]!();
  return root.objects;
}

/** Every object of a type the subject has `relation` on: the subject's derived "known set" for list filters. */
export function knownObjects(bundle: PolicyBundle, graph: Graph, type: string, relation: string, subject: Ref, now: string): string[] {
  const candidates = reverseCandidates(bundle, graph, type, relation, subject, now);
  // Reverse reachability ignores hop limits and path-local denial caching; point checks keep those semantics exact.
  return [...candidates].filter((id) => check(bundle, graph, { type, id }, relation, subject, now).ok).sort();
}

interface SubjectState {
  readonly object: Ref;
  readonly relation: string;
  readonly subjects: Set<string>;
  readonly listeners: ((key: string) => void)[];
}
interface Forward {
  readonly bundle: PolicyBundle;
  readonly graph: Graph;
  readonly nowMs: number;
  readonly states: Map<string, SubjectState>;
  readonly pending: (() => void)[];
}

function addSubject(r: Forward, state: SubjectState, key: string): void {
  if (state.subjects.has(key)) return;
  state.subjects.add(key);
  for (const listener of state.listeners) r.pending.push(() => listener(key));
}

function onSubject(r: Forward, source: SubjectState, listener: (key: string) => void): void {
  source.listeners.push(listener);
  for (const key of source.subjects) r.pending.push(() => listener(key));
}

function forwardLive(r: Forward, object: Ref, relation: string): readonly Tuple[] {
  return (r.graph.byObject.get(keyOf(object)) ?? []).filter((t) => t.relation === relation &&
    isLive(t, r.nowMs, r.bundle.needToKnow.breakGlassMaxHours));
}

function forwardState(r: Forward, object: Ref, relation: string): SubjectState {
  const key = `${keyOf(object)}#${relation}`;
  const existing = r.states.get(key);
  if (existing) return existing;
  const state: SubjectState = { object, relation, subjects: new Set(), listeners: [] };
  r.states.set(key, state);
  r.pending.push(() => {
    for (const rewrite of definition(r.bundle, object.type, relation).union) {
      if ('this' in rewrite) {
        for (const t of forwardLive(r, object, relation)) {
          if (t.subjectRelation) onSubject(r, forwardState(r, t.subject, t.subjectRelation), (subject) => addSubject(r, state, subject));
          else addSubject(r, state, keyOf(t.subject));
        }
      } else if ('computed' in rewrite) {
        onSubject(r, forwardState(r, object, rewrite.computed), (subject) => addSubject(r, state, subject));
      } else if ('fromParent' in rewrite) {
        for (const t of forwardLive(r, object, rewrite.fromParent.relation)) {
          onSubject(r, forwardState(r, t.subject, rewrite.fromParent.then), (subject) => addSubject(r, state, subject));
        }
      } else {
        const source = forwardState(r, object, rewrite.viaReports.then);
        onSubject(r, source, (reportKey) => {
          const [type, id] = JSON.parse(reportKey) as [string, string];
          let frontier = [{ type, id }];
          const met = new Set(frontier.map(keyOf));
          for (let depth = 0; depth < Math.min(rewrite.viaReports.maxDepth, 50) && frontier.length > 0; depth++) {
            const next: Ref[] = [];
            for (const report of frontier) {
              for (const t of forwardLive(r, report, rewrite.viaReports.managerRelation)) {
                if (t.subjectRelation || met.has(keyOf(t.subject))) continue;
                met.add(keyOf(t.subject));
                addSubject(r, state, keyOf(t.subject));
                next.push(t.subject);
              }
            }
            frontier = next;
          }
        });
      }
    }
  });
  return state;
}

/** A conservative known-subject set for subject search. Like reverse discovery, it ignores point-check hop limits;
 *  every returned candidate is therefore still decided point-wise before it is released. */
export function knownSubjects(bundle: PolicyBundle, graph: Graph, object: Ref, relation: string, now: string): ReadonlySet<string> {
  const r: Forward = { bundle, graph, nowMs: Date.parse(now), states: new Map(), pending: [] };
  const root = forwardState(r, object, relation);
  for (let i = 0; i < r.pending.length; i++) r.pending[i]!();
  return root.subjects;
}
