import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import { ownerIds } from '../runtime.ts';
import { ownerOnly } from '../auth.ts';
import { HttpError } from '../http.ts';
import { knownType } from '../resource-registry.ts';

const bad = (message: string): never => { throw new HttpError(400, 'bad_request', message); };
const byId = (a: { id: string }, b: { id: string }): number => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/** GET /admin/v1/resources/inventory and /resources/retired: the registered resources of one type with their labels,
 *  or the ids retired from it, in id order, a page at a time (docs/API.md §3.3). Read-only, like the other model
 *  reads; a resource owner sees only the resources it answers for, and no retired ids (the log keeps no owner). */
export function inventory(rt: Runtime, user: User, url: URL, retired: boolean): unknown {
  const type = url.searchParams.get('type') ?? '';
  if (!knownType(rt.store.state.bundle, type)) bad('type must be a resource type of the policy');
  const limit = Number(url.searchParams.get('limit') ?? 50);
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) bad('limit must be an integer 1..500');
  const cursor = url.searchParams.get('cursor') ?? '';
  if (cursor.length > 256) bad('Invalid cursor');
  if (retired && ownerOnly(user)) throw new HttpError(403, 'forbidden', 'Retired ids carry no owner: not in a resource owner scope');
  const live = rt.store.state.resources.filter((r) => r.type === type);
  const owners = ownerOnly(user) ? ownerIds(rt, user) : undefined;
  const liveIds = new Set(live.map((r) => r.id));
  const all = retired
    ? rt.store.retired.list(type).map((r) => ({ id: r.id, version: r.version, retiredAt: r.at, registeredAgain: liveIds.has(r.id) }))
    : live.filter((r) => !owners || (typeof r.owner === 'string' && owners.has(r.owner))).map((r) => ({
      id: r.id, title: r.attrs?.title ?? r.id, level: r.level, compartments: r.compartments, integrity: r.integrity, owner: r.owner ?? null,
      contentClasses: r.contentClasses ?? [], version: r.version ?? 0, ...(r.parent ? { parent: r.parent } : {}),
    }));
  const after = all.filter((r) => !cursor || r.id > cursor).sort(byId);
  const items = after.slice(0, limit);
  return { type, total: all.length, items, next: after.length > items.length ? items.at(-1)!.id : null };
}
