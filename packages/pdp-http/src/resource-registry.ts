// Resource registration (docs/API.md §2.2): the application that owns the records tells the PDP about them at run time.
// Pure state functions shared by the PEP-plane API (resources.ts) and the two-person change workflow (admin/changes.ts):
// parsing against the bundle schema, the direct-or-review split, and the state after a batch. Lists are replaced, never
// mutated (runtime.ts indexes them per array).
import { randomUUID } from 'node:crypto';
import { canonical, contentRules, INTEGRITY_RANK, ivpsFor, levelInheritanceErrors, verifyIntegrity } from '../../core/src/index.ts';
import type { Expr, Integrity, Json, Level, PolicyBundle, Ref, Resource } from '../../core/src/index.ts';
import type { Performed, RetiredId, RetiredLog, State, StoredTuple, UnappliedPostState } from './store.ts';
import { recordDeltasOf, withRecordDeltas, type RecordDelta } from './record-deltas.ts';
import { findRef, patchDecisionState, resourceChildren, tuplesOn } from './decision-index.ts';
import { HttpError } from './http.ts';

/** Largest batch: resources plus retirements in one sync call (the same bound as /access/v1/evaluations). */
export const MAX_BATCH = 1000;

const KEYS = new Set(['type', 'id', 'level', 'compartments', 'integrity', 'owner', 'parent', 'version', 'contentClasses', 'attrs']);
const ID = /^[^\u0000-\u001f\u007f]{1,256}$/u;
const CONTENT_CLASS = /^[A-Za-z0-9_.:-]{1,64}$/;
const MAX_ATTRS = 8192;
const bad = (message: string): never => { throw new HttpError(400, 'bad_request', message); };
const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
export const resourceKey = (r: Ref): string => JSON.stringify([r.type, r.id]);

function text(value: unknown, where: string): string {
  if (typeof value !== 'string' || !ID.test(value)) bad(`${where} must be 1..256 characters without control characters`);
  return value as string;
}
function list(value: unknown, where: string, valid: (item: string) => boolean): string[] {
  if (!Array.isArray(value) || value.length > 64 || !value.every((x) => typeof x === 'string' && valid(x))) bad(`${where} is not a valid list`);
  const items = value as string[];
  if (new Set(items).size !== items.length) bad(`${where} lists an entry twice`);
  return [...items];
}
/** A resource type the bundle declares (own property only: "constructor" is not a type). */
export const knownType = (bundle: PolicyBundle, type: string): boolean => Object.hasOwn(bundle.schema.resourceTypes, type);

export function parseRef(input: unknown, where: string, bundle: PolicyBundle): Ref {
  if (!plain(input) || Object.keys(input).some((k) => k !== 'type' && k !== 'id')) return bad(`${where} must be { type, id }`);
  const ref = { type: text(input.type, `${where}.type`), id: text(input.id, `${where}.id`) };
  if (!knownType(bundle, ref.type)) bad(`${where}.type is not a resource type of the policy`);
  return ref;
}

/** A resource as the PEP sends it, checked against the bundle schema, in a fixed shape (no undefined values, so that
 *  canonical() compares content). Fails closed: anything unknown or malformed is a 400. */
export function parseResource(bundle: PolicyBundle, input: unknown, where: string): Resource {
  if (!plain(input)) return bad(`${where} must be an object`);
  const unknown = Object.keys(input).find((k) => !KEYS.has(k));
  if (unknown !== undefined) bad(`${where}.${unknown} is not a resource field`);
  const { type, id } = parseRef({ type: input.type, id: input.id }, where, bundle);
  if (!Number.isInteger(input.level) || (input.level as number) < 0 || (input.level as number) > 3) bad(`${where}.level must be an integer 0..3`);
  const compartments = list(input.compartments, `${where}.compartments`, (c) => bundle.schema.compartments.includes(c));
  if (typeof input.integrity !== 'string' || !Object.hasOwn(INTEGRITY_RANK, input.integrity)) bad(`${where}.integrity must be derived, extracted, system or verified`);
  // an unscanned resource is not free of sensitive content (core request.ts): the scan result is required
  const contentClasses = list(input.contentClasses, `${where}.contentClasses`, (c) => CONTENT_CLASS.test(c));
  const owner = input.owner === undefined ? undefined : text(input.owner, `${where}.owner`);
  const parent = input.parent === undefined ? undefined : parseRef(input.parent, `${where}.parent`, bundle);
  if (parent && resourceKey(parent) === resourceKey({ type, id })) bad(`${where}.parent cannot be the resource itself`);
  if (input.version !== undefined && (!Number.isSafeInteger(input.version) || (input.version as number) < 0)) bad(`${where}.version must be a non-negative integer`);
  if (input.attrs !== undefined && (!plain(input.attrs) || canonical(input.attrs).length > MAX_ATTRS)) bad(`${where}.attrs must be an object of at most ${MAX_ATTRS} bytes`);
  return { type, id, level: input.level as Level, compartments, integrity: input.integrity as Integrity,
    ...(owner === undefined ? {} : { owner }), ...(parent ? { parent } : {}),
    ...(input.version === undefined ? {} : { version: input.version as number }), contentClasses,
    ...(input.attrs === undefined ? {} : { attrs: input.attrs as Record<string, Json> }) };
}

/** Everything but the version (and a tombstone's date), in one shape. */
function content(r: Resource): string {
  const { version: _version, retiredAt: _at, ...fields } = r as Resource & { retiredAt?: string };
  return canonical({ ...fields, contentClasses: fields.contentClasses ?? [] });
}
export const sameContent = (a: Resource, b: Resource): boolean => content(a) === content(b);

/** What a proposal was made against: "live:<version>", "retired:<version>" or "new" (never registered). A proposal
 *  on a live resource that was retired since is stale too: approving it must not bring the record back. */
export function storedBasis(state: State, retired: RetiredLog, r: Ref): string {
  const live = state.resources.find((x) => x.type === r.type && x.id === r.id);
  const gone = live ? undefined : retired.get(r.type, r.id);
  return live ? `live:${live.version ?? 0}` : gone ? `retired:${gone.version}` : 'new';
}
const BASIS = /^(?:(?:live|retired):\d{1,16}|new)$/;
export const validBasis = (value: unknown): boolean => typeof value === 'string' && BASIS.test(value);

/** Attribute names under resource.attrs an expression reads; "*" when it reads resource.attrs as a whole. */
function attributesRead(e: Expr | undefined, out: Set<string>, depth = 0): void {
  if (!e || depth > 64) return;
  const path = (p: string): void => {
    if (p === 'resource.attrs') out.add('*');
    else if (p.startsWith('resource.attrs.')) out.add(p.slice('resource.attrs.'.length).split('.')[0]!);
  };
  if (e.op === 'and' || e.op === 'or') for (const a of e.args) attributesRead(a, out, depth + 1);
  else if (e.op === 'not') attributesRead(e.arg, out, depth + 1);
  else if (e.op === 'has') path(e.path);
  else if ('left' in e) for (const side of [e.left, e.right]) if ('path' in side) path(side.path);
}
const governedCache = new WeakMap<PolicyBundle, Map<string, ReadonlySet<string>>>();
/** The attributes of `type` a PEP may not change alone: those any ABAC rule applying to the type reads (a forbid or an
 *  obligation lifted, or a permit met, by a new value), those any CBAC rule reads, and the type's governedAttributes.
 *  Computed once per bundle (a published bundle is a new object). */
export function governedAttributes(bundle: PolicyBundle, type: string): ReadonlySet<string> {
  let byType = governedCache.get(bundle);
  if (!byType) { byType = new Map(); governedCache.set(bundle, byType); }
  let found = byType.get(type);
  if (!found) {
    const out = new Set<string>(knownType(bundle, type) ? bundle.schema.resourceTypes[type]!.governedAttributes ?? [] : []);
    for (const rule of bundle.abac) if (!rule.resourceTypes || rule.resourceTypes.includes(type)) attributesRead(rule.when, out);
    for (const rule of contentRules(bundle)) attributesRead(rule.unless, out);
    found = out; byType.set(type, found);
  }
  return found;
}
const attr = (r: Resource, k: string): string => r.attrs && Object.hasOwn(r.attrs, k) ? canonical(r.attrs[k]) : 'absent';

/** The post-state a token consumption may carry (Clark-Wilson C2/C5), checked before the token is consumed: only for a
 *  constrained type, bounded like registered attrs, keys limited to what the certified procedure declares (its input
 *  validators' fields) or the type's IVPs read. An attribute the policy reads (governedAttributes) may be set only by a
 *  procedure that declares it as input: then the certified procedure, validated field by field, is what changes it;
 *  merely being read by an IVP does not make the procedure its author, so a compromised PEP could otherwise flip a
 *  policy-read attribute alone. */
export function checkPostState(bundle: PolicyBundle, type: string, action: string, attrs: Record<string, unknown>): void {
  if (!knownType(bundle, type) || bundle.schema.resourceTypes[type]!.constrained !== true) bad('attrs (a post-state) is accepted only for a constrained type');
  const keys = Object.keys(attrs);
  if (keys.length > 64 || canonical(attrs).length > MAX_ATTRS) bad(`attrs must hold at most 64 attributes and ${MAX_ATTRS} bytes`);
  const declared = new Set((bundle.clarkWilson.inputValidators ?? []).filter((v) => v.resourceTypes.includes(type) && v.actions.includes(action)).flatMap((v) => Object.keys(v.fields)));
  const read = new Set<string>();
  for (const i of ivpsFor(bundle, type)) attributesRead(i.check, read);
  const governed = governedAttributes(bundle, type);
  for (const k of keys) {
    if (!declared.has(k) && !read.has(k) && !read.has('*')) bad(`attrs.${k} is neither an input of this certified procedure nor read by an IVP of the type`);
    if ((governed.has(k) || governed.has('*')) && !declared.has(k)) throw new HttpError(403, 'forbidden', `attrs.${k} is read by the policy: only a certified procedure that declares it as input may set it`);
  }
}

/** The retired-id record of live resource `r` (resources removed by a retirement are recorded with their version). */
export const retiredId = (r: Resource, at: string): RetiredId => ({ type: r.type, id: r.id, version: r.version ?? 0, at });

/** Why a change to a live resource needs a second person; none: the PEP may make it alone.
 *  Each listed change can widen who sees or relies on the record: a lowered level or a removed compartment is a
 *  declassification (BLP), a removed content class lifts a CBAC deny or mask, an integrity change moves the Biba bounds
 *  either way, the owner is an ABAC subject (owner-read rules) and a console scope (RESOURCE_OWNERS), the parent
 *  carries need-to-know inheritance (the parent relation) and the level floor. */
export function reviewReasons(bundle: PolicyBundle, prev: Resource | undefined, next: Resource): string[] {
  if (!prev) return [];
  const out: string[] = [];
  const governed = governedAttributes(bundle, next.type);
  const keys = [...new Set([...Object.keys(prev.attrs ?? {}), ...Object.keys(next.attrs ?? {})])];
  if (keys.some((k) => (governed.has('*') || governed.has(k)) && attr(prev, k) !== attr(next, k))) out.push('policy attribute changed');
  if (next.level < prev.level) out.push('level lowered');
  if (prev.compartments.some((c) => !next.compartments.includes(c))) out.push('compartment removed');
  if ((prev.contentClasses ?? []).some((c) => !(next.contentClasses ?? []).includes(c))) out.push('content class removed');
  if (next.integrity !== prev.integrity) out.push('integrity changed');
  if ((next.owner ?? null) !== (prev.owner ?? null)) out.push('owner changed');
  if (canonical(next.parent ?? null) !== canonical(prev.parent ?? null)) out.push('parent changed');
  return out;
}

/** Parent relation deltas for `r`, found through the tuple graph rather than the tuple array. */
function resourceDeltas(state: State, upserts: readonly Resource[], retired: readonly Ref[]): RecordDelta[] {
  const deltas: RecordDelta[] = [
    ...retired.map((r): RecordDelta => ({ kind: 'resource', op: 'delete', type: r.type, id: r.id })),
    ...upserts.map((r): RecordDelta => ({ kind: 'resource', op: 'put', type: r.type, id: r.id, value: r })),
  ];
  for (const r of upserts) {
    const relations = state.bundle.schema.resourceTypes[r.type]?.relations ?? {};
    if (!Object.hasOwn(relations, 'parent')) continue;
    const current = tuplesOn(state.tuples, r).filter((t) => t.relation === 'parent' && !t.breakGlass);
    if (r.parent && current.length === 1 && canonical(current[0]!.subject) === canonical(r.parent) && !current[0]!.subjectRelation) continue;
    for (const tuple of current) deltas.push({ kind: 'tuple', op: 'delete', type: '', id: tuple.id, value: tuple });
    if (r.parent) {
      const tuple: StoredTuple = { id: randomUUID(), object: { type: r.type, id: r.id }, relation: 'parent', subject: { type: r.parent.type, id: r.parent.id } };
      deltas.push({ kind: 'tuple', op: 'put', type: '', id: tuple.id, value: tuple });
    }
  }
  return deltas;
}

/** Preview state for impact simulation; committed writes use applyResourcesInPlace instead. */
export function applyResources(state: State, upserts: readonly Resource[], retired: readonly Ref[] = []): State {
  if (upserts.length === 0 && retired.length === 0) return state;
  const byKey = new Map(upserts.map((r) => [resourceKey(r), r]));
  const gone = new Set(retired.map(resourceKey));
  const kept = state.resources.filter((r) => !gone.has(resourceKey(r))).map((r) => byKey.get(resourceKey(r)) ?? r);
  const present = new Set(kept.map(resourceKey));
  const resources = [...kept, ...upserts.filter((r) => !present.has(resourceKey(r)))];
  const deltas = resourceDeltas(state, upserts, retired);
  const removed = new Set(deltas.filter((d) => d.kind === 'tuple' && d.op === 'delete').map((d) => d.id));
  const added = deltas.filter((d) => d.kind === 'tuple' && d.op === 'put').map((d) => d.value as StoredTuple);
  return withRecordDeltas({ ...state, resources, tuples: [...state.tuples.filter((t) => !removed.has(t.id)), ...added] }, deltas);
}

/** Commits only the deltas: arrays, lookup indexes, the tuple graph and PostgreSQL all see the same mutation. */
export function applyResourcesInPlace(state: State, upserts: readonly Resource[], retired: readonly Ref[] = []): State {
  if (upserts.length === 0 && retired.length === 0) return state;
  const deltas = resourceDeltas(state, upserts, retired);
  return withRecordDeltas(patchDecisionState(state, state, deltas), deltas, true);
}

/** Level errors only where this batch can create one. The rule is pairwise (child against parent, levelInheritanceErrors),
 *  so only the changed records and the stored children of changed records can break it: not ancestors, nor siblings. */
export function checkResourceChanges(state: State, upserts: readonly Resource[], retired: readonly Ref[], written = upserts): void {
  const replacements = new Map(upserts.map((r) => [resourceKey(r), r]));
  const gone = new Set(retired.map(resourceKey));
  const live = (ref: Ref): Resource | undefined => gone.has(resourceKey(ref)) ? undefined : replacements.get(resourceKey(ref)) ?? findRef(state.resources, ref.id, ref.type);
  const affected = new Set([...upserts, ...retired].map(resourceKey));
  for (const changed of [...upserts, ...retired]) {
    for (const child of resourceChildren(state.resources, changed)) affected.add(resourceKey(child));
  }
  const levels: string[] = [];
  for (const key of affected) {
    const [type, id] = JSON.parse(key) as [string, string];
    const r = live({ type, id });
    if (!r?.parent) continue;
    const p = live(r.parent);
    if (!p) levels.push(`${r.type}:${r.id} has an unknown parent ${r.parent.type}:${r.parent.id}`);
    else if (p.level > r.level) levels.push(`${r.type}:${r.id} is L${r.level}, below its parent ${p.type}:${p.id} at L${p.level}`);
  }
  if (levels.length) throw new HttpError(422, 'unprocessable', 'A resource cannot have an unknown parent or sit below its parent level', levels.slice(0, 20));
  const failed = written.flatMap((r) => verifyIntegrity(state.bundle, r).filter((x) => !x.ok).map((x) => `${r.type}:${r.id} CW.IVP.${x.ivp}`));
  if (failed.length) throw new HttpError(422, 'unprocessable', 'An integrity verification procedure does not hold on a constrained item', failed.slice(0, 20));
}

/** Preview validation; committed writes use checkResourceChanges against the unmodified state. */
export function checkResources(state: State, written: readonly Resource[]): void {
  const levels = levelInheritanceErrors(state.resources);
  if (levels.length) throw new HttpError(422, 'unprocessable', 'A resource cannot have an unknown parent or sit below its parent level', levels.slice(0, 20));
  const failed = written.flatMap((r) => verifyIntegrity(state.bundle, r).filter((x) => !x.ok).map((x) => `${r.type}:${r.id} CW.IVP.${x.ivp}`));
  if (failed.length) throw new HttpError(422, 'unprocessable', 'An integrity verification procedure does not hold on a constrained item', failed.slice(0, 20));
}

/** At most this many unapplied post-states are kept (the oldest go first); each names its reservation. */
const MAX_UNAPPLIED = 1000;
/** The PDP's copy of a constrained item follows a completed certified command: its post-state attrs are merged in and
 *  the version becomes the one the token was bound to plus one. Only when the item is still at that version: otherwise
 *  (changed or retired since) nothing is applied and the post-state is kept for reconciliation. A post-state applied to
 *  an item settles the earlier unapplied ones of the same item (it now mirrors a later command). */
export function applyPostState(state: State, p: Performed, at: string): { state: State; applied: boolean; reason?: string; version?: number } {
  if (!p.postState || p.id === undefined) return { state, applied: false };
  const bound = p.boundVersion ?? 0;
  const live = findRef(state.resources, p.resource.id, p.resource.type);
  const stored = live ? live.version ?? 0 : null;
  if (!live || stored !== bound) {
    const reason = live ? `the item is at version ${stored}, the command was decided at version ${bound}` : 'the item is no longer registered';
    const entry: UnappliedPostState = { reservation: p.id, resource: { ...p.resource }, action: p.action, boundVersion: bound, storedVersion: stored, reason, at };
    return { state: { ...state, unappliedPostStates: [...(state.unappliedPostStates ?? []), entry].slice(-MAX_UNAPPLIED) }, applied: false, reason };
  }
  const next: Resource = { ...live, attrs: { ...live.attrs, ...p.postState }, version: bound + 1 };
  const others = (state.unappliedPostStates ?? []).filter((u) => u.resource.type !== live.type || u.resource.id !== live.id);
  const applied = applyResourcesInPlace(state, [next]);
  const withMetadata = state.unappliedPostStates ? withRecordDeltas({ ...applied, unappliedPostStates: others }, recordDeltasOf(applied)!, true) : applied;
  return { state: withMetadata, applied: true, version: bound + 1 };
}
