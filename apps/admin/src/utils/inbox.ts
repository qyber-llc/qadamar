import type { BreakGlassListResponse, BreakGlassRecord, ChangeRecord, SessionUser } from '../api/types';
import { canDecideChange } from './permissions';

/** The Approvals inbox (docs/API.md §3.5.1): tabs, the queue each shows, and the keyboard map. Pure, so tested alone. */
export const INBOX_TABS = ['awaiting', 'pending', 'snoozed', 'applied', 'rejected', 'all'] as const;
export type InboxTab = typeof INBOX_TABS[number];
export const BULK_MAX = 50;
export const SNOOZE_MAX_DAYS = 30;

export type QueueItem =
  | { readonly kind: 'change'; readonly key: string; readonly change: ChangeRecord }
  | { readonly kind: 'emergency'; readonly key: string; readonly emergency: BreakGlassRecord };
export const changeKey = (id: string): string => `change:${id}`;
export const emergencyKey = (id: string): string => `emergency:${id}`;

/** Why the server would refuse this user's decision (changes.ts decideChange): `both` blocks approve and reject,
 *  `approve` only approval. Not mirrored, as the record does not carry them: removing a break-glass tuple and a
 *  certifier who could run the procedure; the server still refuses those with 403. */
export type DecisionBlock = 'selfMaker' | 'credentialHolder' | 'beneficiary' | 'breakGlass' | 'officerOnly';
export function decisionBlocks(change: ChangeRecord, user: SessionUser): { both?: DecisionBlock; approve?: DecisionBlock } {
  const p = change.payload as unknown as Record<string, unknown>;
  if (change.makerId === user.id) return { both: 'selfMaker' };
  if (change.kind === 'scim_subjects' && (!change.scimCredential || change.scimCredential.rotatedBy === user.id)) return { both: 'credentialHolder' };
  if (change.kind === 'register_resources' && (!change.pepCredential?.issuedBy || change.pepCredential.issuedBy === user.id)) return { both: 'credentialHolder' };
  if (p.breakGlass === true) return { approve: 'breakGlass' };
  const subjectId = (value: unknown): unknown => (value && typeof value === 'object' ? (value as { id?: unknown }).id : undefined);
  if ((change.kind === 'add_tuple' && subjectId(p.subject) === user.id) || (change.kind === 'update_subject' && p.id === user.id) ||
    (change.kind === 'scim_subjects' && Array.isArray(p.subjects) && p.subjects.some((s) => subjectId(s) === user.id))) return { approve: 'beneficiary' };
  const officerOnly = (change.kind === 'publish_policy' && (change.weakensMandatory?.length ?? 0) > 0) || change.impact.contextAnalysis?.incomplete === true;
  if (officerOnly && !user.roles.includes('security_officer')) return { approve: 'officerOnly' };
  return {};
}

/** Pending, not refused outright to this user, and their role decides changes: what "Awaiting you" lists. */
export function awaitsUser(change: ChangeRecord, user: SessionUser): boolean {
  return change.status === 'pending' && canDecideChange(user.roles) && !decisionBlocks(change, user).both;
}

/** Emergencies this user may review or revoke (admin/break-glass.ts reviewerRole): never the opener or the subject. */
export function emergenciesAwaiting(list: BreakGlassListResponse | null, user: SessionUser): BreakGlassRecord[] {
  if (!list) return [];
  return list.toReview.filter((e) => (user.roles.includes('security_officer') && e.openedBy !== user.id && e.subjectId !== user.id) ||
    (list.fallbackReview ?? []).includes(e.id));
}

export function buildQueue(tab: InboxTab, changes: readonly ChangeRecord[], emergencies: readonly BreakGlassRecord[], snoozed: ReadonlySet<string>, user: SessionUser): QueueItem[] {
  const urgent: QueueItem[] = emergencies.map((emergency) => ({ kind: 'emergency', key: emergencyKey(emergency.id), emergency }));
  const rows: QueueItem[] = changes.map((change) => ({ kind: 'change', key: changeKey(change.id), change }));
  const awake = (item: QueueItem): boolean => !snoozed.has(item.key);
  switch (tab) {
    case 'awaiting': return [...urgent, ...rows.filter((r) => r.kind === 'change' && awaitsUser(r.change, user))].filter(awake);
    case 'pending': return [...urgent, ...rows.filter((r) => r.kind === 'change' && r.change.status === 'pending')].filter(awake);
    case 'snoozed': return [...urgent, ...rows].filter((item) => !awake(item));
    case 'applied': case 'rejected': return rows.filter((r) => r.kind === 'change' && r.change.status === tab);
    case 'all': return [...urgent, ...rows];
  }
}

/** A day as the server compares it (UTC, YYYY-MM-DD), `days` after the day of `nowMs`. */
export const dayAfter = (nowMs: number, days: number): string => new Date(nowMs + days * 86_400_000).toISOString().slice(0, 10);

export type InboxKey = { readonly type: 'move'; readonly delta: 1 | -1; readonly extend: boolean } | { readonly type: 'toggle' | 'snooze' | 'primary' | 'open' };
interface KeyInput {
  readonly key: string; readonly shiftKey: boolean; readonly ctrlKey: boolean; readonly metaKey: boolean; readonly altKey: boolean;
  readonly target: { readonly tagName?: string; readonly type?: string; readonly isContentEditable?: boolean } | null;
}
const TYPING = ['INPUT', 'TEXTAREA', 'SELECT'];
/** J/K move (Shift extends the selection in list mode), X selects (list mode), S snoozes, A opens the decision form,
 *  Enter opens the item. Nothing while typing, with a modifier held, or for Enter on a control that takes it itself. */
export function inboxKey(e: KeyInput, listMode: boolean): InboxKey | null {
  if (e.ctrlKey || e.metaKey || e.altKey) return null;
  const tag = e.target?.tagName?.toUpperCase() ?? '';
  // a ticked checkbox keeps the shortcuts (Space still toggles it); text fields do not
  if ((TYPING.includes(tag) && !(tag === 'INPUT' && e.target?.type === 'checkbox')) || e.target?.isContentEditable) return null;
  if (e.key === 'Enter') return tag === 'BUTTON' || tag === 'A' ? null : { type: 'open' };
  const key = e.key.toLowerCase();
  if (key === 'j' || key === 'k') return { type: 'move', delta: key === 'j' ? 1 : -1, extend: listMode && e.shiftKey };
  if (e.shiftKey) return null;
  if (key === 'x') return listMode ? { type: 'toggle' } : null;
  if (key === 's') return { type: 'snooze' };
  if (key === 'a') return { type: 'primary' };
  return null;
}
