// The PEP-plane resource registration API (docs/API.md §2.2): the application that owns the records registers,
// updates and retires them, one at a time or in bounded batches, with an authenticated PEP credential bound to their
// resource types. What can only narrow access, or creates a record nobody could reach before, is applied at once;
// what could widen it on a known record goes through the two-person change workflow (resource-registry.ts
// reviewReasons). One audit row per call; cluster followers forward these requests to the leader (router.ts).
import { canonical, policyVersion } from '../../core/src/index.ts';
import type { Ref, Resource } from '../../core/src/index.ts';
import type { Runtime } from './runtime.ts';
import { findRef } from './runtime.ts';
import type { PepCaller, User } from './auth.ts';

import { propose } from './admin/changes.ts';
import { HttpError } from './http.ts';
import { applyResources, applyResourcesInPlace, checkResourceChanges, checkResources, knownType, MAX_BATCH, parseRef, parseResource, resourceKey, retiredId, reviewReasons, sameContent, storedBasis } from './resource-registry.ts';
import { MIN_PEP_RATE_LIMIT } from './ratelimit.ts';

export const RESOURCE_PATHS = '/x/v1/resources';
export type RegistrationStatus = 'created' | 'updated' | 'unchanged' | 'retired' | 'proposed';
export const REGISTRATION_STATUSES: readonly RegistrationStatus[] = ['created', 'updated', 'unchanged', 'retired', 'proposed'];
interface Item { type: string; id: string; status: RegistrationStatus; version?: number; changeId?: string }
/** A queued registration (`next`) or retirement (`retire`), with what it was proposed against (storedBasis). */
interface Review { next?: Resource; retire?: Ref; basis: string }
/** At most this many "type:id" in an audit row; the counts cover the rest. */
const AUDITED_IDS = 32;

const bad = (message: string): never => { throw new HttpError(400, 'bad_request', message); };
function only(b: Record<string, unknown>, permitted: readonly string[]): void {
  const extra = Object.keys(b).find((k) => !permitted.includes(k));
  if (extra !== undefined) bad(`${extra} is not a field of this request`);
}
function bound(caller: PepCaller, type: string, where: string): void {
  if (!caller.resourceTypes.includes(type)) throw new HttpError(403, 'forbidden', `${where}: this PEP credential is not bound to resource type ${type}`);
}
/** Not a console role: sign-in never grants it, so no person can propose a registration. */
const registrar = (caller: PepCaller): User => ({ id: caller.actor, name: 'PEP resource registration', roles: ['resource_registrar'] });

/** Fixed rate cost of a registration write: each one checks its changed resources against their parents and children and, with PostgreSQL,
 *  writes only changed rows that followers apply incrementally; budget about ten decisions. */
export const REGISTRATION_WRITE_COST = 10;
/** The decision-plane rate cost of a call: a listing costs one; a write costs REGISTRATION_WRITE_COST plus one per
 *  resource it names, capped at the smallest decision-plane budget so that the largest sync can still be served. */
export function registrationCost(path: string, b: Record<string, unknown>): number {
  if (path === `${RESOURCE_PATHS}/list`) return 1;
  const n = (v: unknown): number => Array.isArray(v) ? v.length : 0;
  const named = path === `${RESOURCE_PATHS}/sync` ? n(b.resources) + n(b.retire) : 1;
  return Math.min(MIN_PEP_RATE_LIMIT, REGISTRATION_WRITE_COST + named);
}
const positive = (name: string, raw: string | undefined, fallback: number): number => {
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name} must be a positive integer`);
  return n;
};
/** RESOURCE_PENDING_PROPOSALS_PER_PEP: pending register_resources changes one PEP credential may have at once. */
export const pendingPerPep = (): number => positive('RESOURCE_PENDING_PROPOSALS_PER_PEP', process.env.RESOURCE_PENDING_PROPOSALS_PER_PEP, 100);

export function resources(rt: Runtime, path: string, b: Record<string, unknown>, caller: PepCaller): { value: unknown; status: number } {
  if (path === `${RESOURCE_PATHS}/list`) return { value: list(rt, b, caller), status: 200 };
  let upserts: unknown[]; let retires: unknown[]; let operation: string;
  if (path === RESOURCE_PATHS || path === `${RESOURCE_PATHS}/retire`) {
    only(b, ['resource']);
    operation = path === RESOURCE_PATHS ? 'register' : 'retire';
    upserts = operation === 'register' ? [b.resource] : []; retires = operation === 'retire' ? [b.resource] : [];
  } else if (path === `${RESOURCE_PATHS}/sync`) {
    only(b, ['resources', 'retire']);
    if ((b.resources !== undefined && !Array.isArray(b.resources)) || (b.retire !== undefined && !Array.isArray(b.retire))) bad('resources and retire must be lists');
    upserts = (b.resources as unknown[] | undefined) ?? []; retires = (b.retire as unknown[] | undefined) ?? [];
    if (upserts.length + retires.length < 1 || upserts.length + retires.length > MAX_BATCH) bad(`A sync names 1..${MAX_BATCH} resources`);
    operation = 'sync';
  } else throw new HttpError(404, 'not_found');
  const items = write(rt, caller, upserts, retires, operation !== 'sync');
  const counts = Object.fromEntries(REGISTRATION_STATUSES.map((s) => [s, items.filter((x) => x.status === s).length])) as Record<RegistrationStatus, number>;
  const changeIds = [...new Set(items.flatMap((x) => x.changeId ? [x.changeId] : []))];
  rt.audit.append({ type: 'change', actor: caller.actor, action: `resource_${operation}`, policyVersion: policyVersion(rt.store.state.bundle),
    details: { credential: caller.credential, counts, resources: items.slice(0, AUDITED_IDS).map((x) => `${x.type}:${x.id}`),
      ...(items.length > AUDITED_IDS ? { omitted: items.length - AUDITED_IDS } : {}), ...(changeIds.length ? { changeIds } : {}) } });
  const status = counts.proposed > 0 ? 202 : operation === 'register' && counts.created > 0 ? 201 : 200;
  return { value: { items, counts }, status };
}

/** Validates the whole batch, then keeps it whole or not at all. */
function write(rt: Runtime, caller: PepCaller, upserts: readonly unknown[], retires: readonly unknown[], single: boolean): Item[] {
  const state = rt.store.state; const bundle = state.bundle;
  const seen = new Set<string>();
  const once = (r: Ref, where: string): void => {
    if (seen.has(resourceKey(r))) bad(`${where} names a resource already in this request`);
    seen.add(resourceKey(r));
  };
  const constrained = (type: string): boolean => bundle.schema.resourceTypes[type]?.constrained === true;
  const items: Item[] = []; const direct: Resource[] = []; const review: Review[] = []; const retired: Resource[] = [];
  const log = rt.store.retired;
  const reasons = new Set<string>();
  upserts.forEach((input, i) => {
    const where = single ? 'resource' : `resources[${i}]`;
    const parsed = parseResource(bundle, input, where);
    bound(caller, parsed.type, where); once(parsed, where);
    // placing a record under a parent links it to the parent's need-to-know: only under a type this PEP owns too
    if (parsed.parent) bound(caller, parsed.parent.type, `${where}.parent`);
    const ref = { type: parsed.type, id: parsed.id };
    const live = findRef(state.resources, parsed.id, parsed.type);
    if (live && sameContent(live, parsed) && (parsed.version === undefined || parsed.version === (live.version ?? 0))) {
      items.push({ ...ref, status: 'unchanged', version: live.version ?? 0 }); return;
    }
    // Clark-Wilson: a constrained data item changes only through a certified procedure (decision token, consumed with
    // its post-state), never by a registration; creating one is allowed, its IVPs must hold (checkResources)
    if (live && constrained(parsed.type)) {
      throw new HttpError(409, 'certified_command_required', `${where} is a constrained data item: change it with a certified command (decision token consumed with postState), not by registration`);
    }
    // an id that was retired never comes back by the PEP alone: whatever it was, a second person sees it is reused
    const gone = live ? undefined : log.get(parsed.type, parsed.id);
    const floor = live ? live.version ?? 0 : gone?.version;
    if (parsed.version !== undefined && floor !== undefined && parsed.version <= floor) throw new HttpError(409, 'conflict', `${where}.version must be above the stored version ${floor}`);
    const next: Resource = { ...parsed, version: parsed.version ?? (floor === undefined ? 1 : floor + 1) };
    const why = gone ? ['retired id registered again'] : reviewReasons(bundle, live, next);
    if (why.length) {
      for (const reason of why) reasons.add(reason);
      review.push({ next, basis: storedBasis(state, log, ref) });
      items.push({ ...ref, status: 'proposed', version: next.version! });
    } else {
      direct.push(next);
      items.push({ ...ref, status: live ? 'updated' : 'created', version: next.version! });
    }
  });
  retires.forEach((input, i) => {
    const where = single ? 'resource' : `retire[${i}]`;
    const ref = parseRef(input, where, bundle);
    bound(caller, ref.type, where); once(ref, where);
    const live = findRef(state.resources, ref.id, ref.type);
    if (!live) {
      if (log.get(ref.type, ref.id)) { items.push({ ...ref, status: 'unchanged' }); return; }
      throw new HttpError(404, 'not_found', `${where} is not a registered resource`);
    }
    // deleting a constrained data item is a transformation the PDP cannot see certified: a second person decides
    if (constrained(ref.type)) {
      reasons.add('constrained item retired');
      review.push({ retire: { type: ref.type, id: ref.id }, basis: storedBasis(state, log, ref) });
      items.push({ ...ref, status: 'proposed', version: live.version ?? 0 });
      return;
    }
    retired.push(live);
    items.push({ ...ref, status: 'retired', version: live.version ?? 0 });
  });
  let after: typeof state;
  if (review.length) {
    after = applyResources(state, direct, retired);
    checkResources(after, direct);
    // the queued part must hold on top of the direct part too: refused now rather than at approval
    const queued = review.flatMap((x) => x.next ? [x.next] : []);
    checkResources(applyResources(after, queued, review.flatMap((x) => x.retire ? [x.retire] : [])), queued);
  } else {
    checkResourceChanges(state, direct, retired);
    after = applyResourcesInPlace(state, direct, retired);
  }
  rt.store.state = after;
  let proposed: Map<string, string>;
  try { proposed = review.length ? queue(rt, caller, review, [...reasons]) : new Map(); }
  catch (err) { rt.store.state = state; throw err; }
  // the retired ids go to their own append-only log (committed with the state with PostgreSQL), never into the document
  for (const r of retired) log.append(retiredId(r, rt.now()));
  if (after !== state) rt.store.save();
  return items.map((x) => x.status === 'proposed' ? { ...x, changeId: proposed.get(resourceKey(x))! } : x);
}

const reviewKey = (x: Review): string => resourceKey(x.next ?? x.retire!);

/** One pending change for the resources of this call that no pending change already proposes as they are: an
 *  application syncing the same record again does not fill the approvers' queue. */
function queue(rt: Runtime, caller: PepCaller, review: readonly Review[], reasons: readonly string[]): Map<string, string> {
  const pending = rt.store.changes.filter((c) => c.status === 'pending' && c.kind === 'register_resources');
  const found = new Map<string, string>(); const fresh: Review[] = [];
  for (const x of review) {
    const match = pending.find((c) => x.next
      ? (c.payload.resources as Resource[]).some((r, i) => canonical(r) === canonical(x.next) && (c.payload.basis as string[])[i] === x.basis)
      : ((c.payload.retire ?? []) as Ref[]).some((r, i) => canonical(r) === canonical(x.retire) && (c.payload.retireBasis as string[])[i] === x.basis));
    if (match) found.set(reviewKey(x), match.id); else fresh.push(x);
  }
  if (fresh.length) {
    const limit = pendingPerPep();
    if (pending.filter((c) => c.pepCredential?.id === caller.credential).length >= limit) {
      throw new HttpError(409, 'proposal_limit', `This PEP credential already has ${limit} registration changes awaiting review (RESOURCE_PENDING_PROPOSALS_PER_PEP): nothing was kept`);
    }
    const upserts = fresh.filter((x) => x.next); const gone = fresh.filter((x) => x.retire);
    const change = propose(rt, registrar(caller), { kind: 'register_resources',
      payload: { resources: upserts.map((x) => x.next), basis: upserts.map((x) => x.basis),
        ...(gone.length ? { retire: gone.map((x) => x.retire), retireBasis: gone.map((x) => x.basis) } : {}) },
      reason: `PEP resource registration awaiting two-person review: ${reasons.join(', ')}` }, false, undefined,
    { id: caller.credential, ...(caller.issuedBy ? { issuedBy: caller.issuedBy } : {}) });
    for (const x of fresh) found.set(reviewKey(x), change.id);
  }
  return found;
}

/** The registered ids of one bound type, in id order, a page at a time: what an application diffs its records against
 *  (then registers what is missing or different and retires what it no longer has). */
function list(rt: Runtime, b: Record<string, unknown>, caller: PepCaller): unknown {
  only(b, ['type', 'cursor', 'limit']);
  const bundle = rt.store.state.bundle;
  if (typeof b.type !== 'string' || !knownType(bundle, b.type)) bad('type must be a resource type of the policy');
  const type = b.type as string;
  bound(caller, type, 'type');
  const limit = b.limit ?? 100;
  if (!Number.isInteger(limit) || (limit as number) < 1 || (limit as number) > MAX_BATCH) bad(`limit must be an integer 1..${MAX_BATCH}`);
  let after: string | undefined;
  if (b.cursor !== undefined && b.cursor !== '') {
    const decoded = typeof b.cursor === 'string' ? Buffer.from(b.cursor, 'base64url').toString() : '';
    if (!decoded.startsWith('r:') || Buffer.from(decoded).toString('base64url') !== b.cursor) bad('Invalid cursor');
    after = decoded.slice(2);
  }
  const all = rt.store.state.resources.filter((r) => r.type === type && (after === undefined || r.id > after)).sort((x, y) => x.id < y.id ? -1 : x.id > y.id ? 1 : 0);
  const page = all.slice(0, limit as number);
  const next = all.length > page.length ? Buffer.from(`r:${page.at(-1)!.id}`).toString('base64url') : '';
  return { resources: page.map((r) => ({ type, id: r.id, version: r.version ?? 0 })), next_cursor: next };
}
