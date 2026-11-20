import type { Runtime } from '../runtime.ts';
import type { Auth, User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { HttpError, string } from '../http.ts';
import { visibleChange } from './changes.ts';

/** How an approver decides: one change at a time (default), or a list with one shared note (docs/API.md §3.5.1). */
export type ApprovalMode = 'individual' | 'list';
/** The `approval_prefs` document: modes set by an administrator, and each user's own snoozed queue items. A snooze keeps
 *  the item's version when it was snoozed; a different version (the item changed) or a passed date un-snoozes it. */
export interface ApprovalPrefs {
  modes: Record<string, { mode: ApprovalMode; setBy: string; at: string }>;
  snoozes: Record<string, Record<string, { until: string; version: string }>>;
}
export const BULK_MAX = 50;
const SNOOZE_MAX_DAYS = 30;
const SNOOZES_PER_USER = 500;
const ADMINS = ['access_admin', 'security_officer'];
const RESERVED = ['__proto__', 'constructor', 'prototype'];

const own = <T>(record: Readonly<Record<string, T>>, key: string): T | undefined => (Object.hasOwn(record, key) ? record[key] : undefined);
// read on every request, never cached: a follower that takes the lead serves what the old leader committed
function prefsOf(rt: Runtime): ApprovalPrefs {
  const stored = rt.approvalPrefs?.load();
  return { modes: stored?.modes ?? {}, snoozes: stored?.snoozes ?? {} };
}
function save(rt: Runtime, prefs: ApprovalPrefs): void {
  if (!rt.approvalPrefs) throw new HttpError(503, 'unavailable', 'Approval preferences are unavailable on this node');
  rt.approvalPrefs.save(prefs);
}
export const modeOf = (rt: Runtime, id: string): ApprovalMode => own(prefsOf(rt).modes, id)?.mode ?? 'individual';

/** A console user id as the sign-in layers bound it (oidc.ts: 1..256 characters, no surrounding space). */
function userId(raw: string): string {
  let id: string;
  try { id = decodeURIComponent(raw); } catch { throw new HttpError(400, 'bad_request', 'Invalid user id'); }
  if (!id || id.length > 256 || id.trim() !== id || /\p{Cc}/u.test(id) || RESERVED.includes(id)) throw new HttpError(422, 'unprocessable', 'Invalid user id');
  return id;
}

export function approvalModes(rt: Runtime, user: User, auth?: Auth): { items: Array<{ id: string; mode: ApprovalMode; setBy?: string; at?: string }> } {
  allowed(user, ADMINS);
  const { modes } = prefsOf(rt);
  const known = new Set([...auth?.holders('approver') ?? [], ...auth?.holders('security_officer') ?? [], ...Object.keys(modes)]);
  return { items: [...known].sort().map((id) => {
    const set = own(modes, id);
    return set ? { id, ...set } : { id, mode: 'individual' as const };
  }) };
}
/** Immediate (not a two-person change) and audited: the mode only chooses how a checker decides, every decision keeps
 *  every four-eyes check (owner decision). */
export function setApprovalMode(rt: Runtime, user: User, rawId: string, b: Record<string, unknown>): { id: string; mode: ApprovalMode; setBy: string; at: string } {
  allowed(user, ADMINS);
  const id = userId(rawId);
  const mode = b.mode;
  if (mode !== 'individual' && mode !== 'list') throw new HttpError(422, 'unprocessable', 'mode must be individual or list');
  const prefs = prefsOf(rt);
  const set = { mode: mode as ApprovalMode, setBy: user.id, at: rt.now() };
  // audited first (the target as the row's subject, pseudonymised like any person id): a refused append leaves the mode as it was
  rt.audit.append({ type: 'security', actor: user.id, action: 'approval_mode_set', subject: id, details: { from: own(prefs.modes, id)?.mode ?? 'individual', to: mode } });
  save(rt, { ...prefs, modes: { ...prefs.modes, [id]: set } });
  return { id, ...set };
}

/** The queue item a key names, as this user may see it, and its version; undefined when there is none. */
function itemVersion(rt: Runtime, user: User, key: string): string | undefined {
  const parsed = /^(change|emergency):(\S{1,256})$/.exec(key);
  if (!parsed) return undefined;
  if (parsed[1] === 'change') {
    const change = rt.store.changes.find((c) => c.id === parsed[2]);
    return change && visibleChange(rt, user, change) ? `${change.status}:${change.decidedAt ?? ''}` : undefined;
  }
  if (!user.roles.some((r) => ADMINS.includes(r))) return undefined;
  const emergency = rt.store.emergencies.find((e) => e.id === parsed[2]);
  return emergency ? `${emergency.status}:${emergency.reviewedBy ?? ''}` : undefined;
}
const today = (rt: Runtime): string => rt.now().slice(0, 10);
/** This user's snoozes still in force: date not reached and item unchanged. */
function activeSnoozes(rt: Runtime, user: User, prefs: ApprovalPrefs): Record<string, { until: string; version: string }> {
  return Object.fromEntries(Object.entries(own(prefs.snoozes, user.id) ?? {})
    .filter(([key, s]) => s.until > today(rt) && itemVersion(rt, user, key) === s.version));
}

export function inbox(rt: Runtime, user: User): { approvalMode: ApprovalMode; snoozes: Array<{ item: string; until: string }> } {
  const prefs = prefsOf(rt);
  return { approvalMode: own(prefs.modes, user.id)?.mode ?? 'individual',
    snoozes: Object.entries(activeSnoozes(rt, user, prefs)).map(([item, s]) => ({ item, until: s.until })) };
}

/** YYYY-MM-DD, strictly after today and at most 30 days ahead (the business clock, UTC). */
function snoozeDate(rt: Runtime, value: unknown): string {
  const day = typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) ? Date.parse(`${value}T00:00:00Z`) : NaN;
  const start = Date.parse(`${today(rt)}T00:00:00Z`);
  if (!Number.isFinite(day) || new Date(day).toISOString().slice(0, 10) !== value || day <= start || day > start + SNOOZE_MAX_DAYS * 86_400_000) {
    throw new HttpError(422, 'unprocessable', `until must be a date after today and at most ${SNOOZE_MAX_DAYS} days ahead`);
  }
  return value as string;
}
export function snooze(rt: Runtime, user: User, b: Record<string, unknown>): { item: string; until: string } {
  const item = typeof b.item === 'string' ? b.item : '';
  const version = itemVersion(rt, user, item);
  if (version === undefined) throw new HttpError(404, 'not_found');
  const until = snoozeDate(rt, b.until);
  const prefs = prefsOf(rt);
  const { [item]: _replaced, ...kept } = activeSnoozes(rt, user, prefs); // expired and changed items are pruned on write
  if (Object.keys(kept).length >= SNOOZES_PER_USER) throw new HttpError(422, 'unprocessable', `At most ${SNOOZES_PER_USER} snoozed items`);
  rt.audit.append({ type: 'change', actor: user.id, action: 'snooze', details: { item, until } });
  save(rt, { ...prefs, snoozes: { ...prefs.snoozes, [user.id]: { ...kept, [item]: { until, version } } } });
  return { item, until };
}
export function unsnooze(rt: Runtime, user: User, raw: string): { item: string } {
  let item: string;
  try { item = decodeURIComponent(raw); } catch { throw new HttpError(400, 'bad_request'); }
  const prefs = prefsOf(rt);
  const mine = activeSnoozes(rt, user, prefs);
  if (!Object.hasOwn(mine, item)) throw new HttpError(404, 'not_found');
  const { [item]: _removed, ...kept } = mine;
  rt.audit.append({ type: 'change', actor: user.id, action: 'unsnooze', details: { item } });
  save(rt, { ...prefs, snoozes: { ...prefs.snoozes, [user.id]: kept } });
  return { item };
}

export interface BulkResult { id: string; ok: boolean; status?: string; error?: string; message?: string }
/** List mode: up to 50 changes decided with one note, one by one through the single-decision path (`decideOne`), so
 *  each keeps every check and its own audit row; a refused item does not stop the others and is audited with the batch. */
export async function decideMany(rt: Runtime, user: User, b: Record<string, unknown>,
  decideOne: (id: string, approve: boolean, body: Record<string, unknown>) => unknown): Promise<{ approve: boolean; results: BulkResult[] }> {
  allowed(user, ['approver', 'security_officer']);
  if (modeOf(rt, user.id) !== 'list') throw new HttpError(403, 'individual_mode', 'Bulk decisions need list mode, set by an administrator');
  const ids = b.ids;
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > BULK_MAX || !ids.every((id) => typeof id === 'string' && id.length > 0 && id.length <= 256) || new Set(ids).size !== ids.length) {
    throw new HttpError(422, 'unprocessable', `ids must be 1 to ${BULK_MAX} distinct change ids`);
  }
  const approve = b.approve;
  if (typeof approve !== 'boolean') throw new HttpError(422, 'unprocessable', 'approve must be true or false');
  const note = { reason: string(b.reason) }; // the same rule as a single decision note
  const results: BulkResult[] = [];
  // strictly one after the other: an erasure approval snapshots and restores the change list
  for (const id of ids as string[]) {
    try {
      const decided = await decideOne(id, approve, note) as { status?: unknown };
      results.push({ id, ok: true, ...(typeof decided.status === 'string' ? { status: decided.status } : {}) });
    } catch (err) {
      if (!(err instanceof HttpError)) throw err;
      results.push({ id, ok: false, error: err.code, message: err.message });
    }
  }
  // the refused items in one row per batch (each decided item has its own approve or reject row)
  const refused = results.filter((r) => !r.ok).map((r) => ({ changeId: r.id, error: r.error }));
  if (refused.length) rt.audit.append({ type: 'change', actor: user.id, action: 'refused', effect: 'deny', details: { route: '/admin/v1/changes/decide', approve, refused } });
  return { approve, results };
}

/** After an erasure: the erased id keeps no mode or snooze, and modes it set name its pseudonym instead. */
export function forgetApprover(rt: Runtime, id: string, pseudonym: string): void {
  const prefs = prefsOf(rt);
  if (!rt.approvalPrefs || !(Object.hasOwn(prefs.modes, id) || Object.hasOwn(prefs.snoozes, id) || Object.values(prefs.modes).some((m) => m.setBy === id))) return;
  const { [id]: _mode, ...modes } = prefs.modes; const { [id]: _snoozes, ...snoozes } = prefs.snoozes;
  save(rt, { modes: Object.fromEntries(Object.entries(modes).map(([k, m]) => [k, m.setBy === id ? { ...m, setBy: pseudonym } : m])), snoozes });
}
