import type { ChangeRecord } from '../api/types';
import { LevelBadge } from '../components/UiStates';
import { msgs } from '../i18n';
import { formatTupleShort, summarizeChangePayload } from '../utils/expr';

export function changeLabel(change: ChangeRecord): string {
  const m = msgs().approvals;
  if (change.kind === 'remove_tuple') {
    const affected = change.impact.lost[0];
    return affected ? m.revokeAccess(affected.subject, affected.resource) : m.revokeGrant;
  }
  if ((change.kind === 'update_subject' || change.kind === 'update_resource') && 'id' in change.payload) {
    return change.kind === 'update_subject' ? m.updateSubject(change.payload.id) : m.updateResource(change.payload.id);
  }
  if (change.kind === 'add_tuple' && 'object' in change.payload) return m.grantAccess(formatTupleShort(change.payload));
  return summarizeChangePayload(change.kind, change.payload);
}

export function statusLabel(status: ChangeRecord['status']): string {
  const m = msgs().approvals;
  return status === 'applied' ? m.applied : status === 'rejected' ? m.rejected : m.pending;
}

export function ChangeLevel({ change }: { readonly change: ChangeRecord }) {
  if (!('set' in change.payload)) return null;
  const fields = change.payload.set;
  const level = 'clearance' in fields ? fields.clearance : 'level' in fields ? fields.level : undefined;
  return level === undefined ? null : <LevelBadge level={level} />;
}
