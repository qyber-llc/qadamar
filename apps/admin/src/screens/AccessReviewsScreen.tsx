import { useEffect, useState, useCallback, useMemo } from 'react';
import { api, getServerNowMs } from '../api/client';
import type { Ref, ReviewItem, RoleAssignmentReview, SessionUser } from '../api/types';
import { ImpactTables } from '../components/ImpactTables';
import { DateText, EmptyState, ErrorAlert, LoadingState } from '../components/UiStates';
import { formatRef } from '../utils/expr';
import { canReviewAccess } from '../utils/permissions';
import '../styles/operations.css';
import { buildHref } from '../utils/router';
import { useChangePreview, type CandidateChange } from '../utils/useChangePreview';
import { msgs, useT } from '../i18n';

function reviewLabel(item: ReviewItem): string {
  const subject = toRef(item.subject, 'user').id;
  const resource = toRef(item.resource, 'case').id;
  return `${subject} → ${resource}`;
}

const DAY_MS = 86_400_000;

function defaultNewValidTo(): string {
  return new Date(getServerNowMs() + 89 * DAY_MS).toISOString().slice(0, 10);
}

function toRef(refOrStr: Ref | string, fallbackType: string): Ref {
  if (typeof refOrStr === 'object' && refOrStr !== null) return { type: refOrStr.type, id: refOrStr.id };
  const idx = refOrStr.indexOf(':');
  return idx > 0 ? { type: refOrStr.slice(0, idx), id: refOrStr.slice(idx + 1) } : { type: fallbackType, id: refOrStr };
}

function resolveCertificationDate(rawDate: string, currentValidTo?: string): { readonly ok: true; readonly iso: string } | { readonly ok: false; readonly message: string } {
  const m = msgs().reviews;
  if (!rawDate) return { ok: false, message: m.dateMissing };
  const nowMs = getServerNowMs();
  const maxMs = nowMs + 90 * DAY_MS;
  const parsedMs = Date.parse(rawDate.includes('T') ? rawDate : `${rawDate}T23:59:59Z`);
  if (Number.isNaN(parsedMs)) return { ok: false, message: m.dateInvalid };
  const startOfDayMs = Date.parse(rawDate.includes('T') ? rawDate : `${rawDate}T00:00:00Z`);
  if (startOfDayMs > maxMs) return { ok: false, message: m.dateTooFar };
  const clampedMs = Math.min(parsedMs, maxMs);
  if (clampedMs <= nowMs) return { ok: false, message: m.datePast };
  if (currentValidTo && clampedMs <= Date.parse(currentValidTo)) return { ok: false, message: m.dateNotExtended };
  return { ok: true, iso: new Date(clampedMs).toISOString() };
}

function buildReviewCandidate(item: ReviewItem, action: 'certify' | 'revoke', validToIso: string): CandidateChange {
  if (action === 'revoke') return { kind: 'remove_tuple', payload: { tupleId: item.tupleId } };
  return { kind: 'add_tuple', payload: { object: toRef(item.resource, 'case'), subject: toRef(item.subject, 'user'), relation: item.relation, notAfter: validToIso } };
}

export function AccessReviewsScreen(props: {
  readonly user: SessionUser;
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
  readonly onChangeCreated: () => void;
}) {
  const r = useT().reviews;
  const [items, setItems] = useState<readonly ReviewItem[]>([]);
  const [roleAssignments, setRoleAssignments] = useState<readonly RoleAssignmentReview[] | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [newDates, setNewDates] = useState<Record<string, string>>({});
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [selectedDecision, setSelectedDecision] = useState<Record<string, 'certify' | 'revoke'>>({});
  const [activeTupleId, setActiveTupleId] = useState<string | null>(null);

  const filterBucket = props.params.filter ?? 'all';
  const searchQuery = props.params.q ?? '';

  const loadReviews = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getReviews();
      setItems(res.items);
      setRoleAssignments(res.roleAssignments);
      const fallbackDate = defaultNewValidTo();
      const initialDates: Record<string, string> = {};
      for (const item of res.items) initialDates[item.tupleId] = fallbackDate;
      setNewDates((prev) => ({ ...initialDates, ...prev }));
      if (res.items[0] && !activeTupleId) setActiveTupleId(res.items[0].tupleId);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [activeTupleId]);

  useEffect(() => {
    void loadReviews();
  }, [loadReviews]);

  const filteredItems = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return items.filter((item) => {
      if (filterBucket === '7d' && (item.daysLeft === undefined || item.daysLeft > 7)) return false;
      if (filterBucket === '30d' && (item.daysLeft === undefined || item.daysLeft > 30)) return false;
      if (filterBucket === 'old' && item.daysLeft !== undefined && item.daysLeft <= 30) return false;
      if (!q) return true;
      const hay = `${item.tupleId} ${formatRef(item.subject)} ${formatRef(item.resource)} ${item.relation} ${item.reason ?? ''}`.toLowerCase();
      return hay.includes(q);
    });
  }, [items, filterBucket, searchQuery]);

  const activeItem = useMemo(() => items.find((i) => i.tupleId === activeTupleId) ?? null, [items, activeTupleId]);
  const activeAction = activeItem ? (selectedDecision[activeItem.tupleId] ?? 'certify') : 'certify';
  const activeDateCheck = useMemo(() => {
    if (!activeItem || activeAction !== 'certify') return { ok: true as const, iso: '' };
    return resolveCertificationDate(newDates[activeItem.tupleId] ?? defaultNewValidTo(), activeItem.validTo);
  }, [activeItem, activeAction, newDates]);

  const candidate = useMemo<CandidateChange | null>(() => {
    if (!activeItem || !activeDateCheck.ok) return null;
    return buildReviewCandidate(activeItem, activeAction, activeDateCheck.iso);
  }, [activeItem, activeAction, activeDateCheck]);

  const { impact, hasValidPreview, simulating, submitting, error: actionError, submittedChange: createdChange, runPreview, submitPreviewedChange } = useChangePreview(candidate);

  const handleSubmitDecision = async (item: ReviewItem) => {
    if (activeTupleId !== item.tupleId || !hasValidPreview) return;
    const action = selectedDecision[item.tupleId] ?? 'certify';
    const reasonText = (reasons[item.tupleId] ?? '').trim();
    if (reasonText.length < 20) return;
    const dateCheck = action === 'certify' ? resolveCertificationDate(newDates[item.tupleId] ?? defaultNewValidTo(), item.validTo) : { ok: true as const, iso: '' };
    if (!dateCheck.ok) return;

    const chg = await submitPreviewedChange(reasonText, async ({ reason }) =>
      api.decideReview(item.tupleId, { decision: action, ...(action === 'certify' ? { newValidTo: dateCheck.iso } : {}), reason }),
    );
    if (chg) {
      setReasons((prev) => ({ ...prev, [item.tupleId]: '' }));
      props.onChangeCreated();
      await loadReviews();
    }
  };

  const canAct = canReviewAccess(props.user.roles);

  return (
    <section className="operations-screen" aria-labelledby="title-reviews">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-reviews">{r.title}</h1>
          <p className="screen-subtitle">
            {r.subtitle}
          </p>
        </div>
      </div>

      <div className="card">
        <div className="filter-bar">
          <div className="form-group" style={{ maxWidth: '240px' }}>
            <label htmlFor="rev-bucket-select">{r.horizon}</label>
            <select id="rev-bucket-select" value={filterBucket} onChange={(e) => props.setParams({ filter: e.target.value === 'all' ? undefined : e.target.value })}>
              <option value="all">{r.allCandidates(items.length)}</option>
              <option value="7d">{r.within7}</option>
              <option value="30d">{r.within30}</option>
              <option value="old">{r.older90}</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="rev-search-input">{r.search}</label>
            <input id="rev-search-input" type="search" placeholder={r.searchPlaceholder} value={searchQuery} onChange={(e) => props.setParams({ q: e.target.value || undefined })} />
          </div>
        </div>

        {createdChange ? (
          <div className="alert-success" role="status" aria-live="polite" title={createdChange.id}>
            {r.queued}{' '}
            <a href={buildHref('approvals', { id: createdChange.id })}>{r.openApprovals}</a>
          </div>
        ) : null}

        {actionError ? <ErrorAlert error={actionError} contextTitle={r.actionError} /> : null}
        {loading ? <LoadingState label={r.loading} /> : null}
        {error ? <ErrorAlert error={error} contextTitle={r.loadError} onRetry={() => void loadReviews()} /> : null}

        {!loading && !error ? (
          filteredItems.length === 0 ? (
            <EmptyState title={r.empty} detail={r.emptyDetail} />
          ) : (
            <div>
              <div className="table-wrap" tabIndex={0} role="region" aria-label={r.candidates}>
                <table className="operations-review-table">
                  <thead>
                    <tr>
                      <th>{r.colGrant}</th>
                      <th>{r.colRelationship}</th>
                      <th>{r.colValidUntil}</th>
                      <th className="num">{r.colDaysLeft}</th>
                      <th>{r.colGrantedBy}</th>
                      <th>{r.colDecision}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredItems.map((item) => {
                      const reasonVal = reasons[item.tupleId] ?? '';
                      const validReason = reasonVal.trim().length >= 20;
                      const isUrgent = item.daysLeft !== undefined && item.daysLeft <= 7;
                      const rowAction = selectedDecision[item.tupleId] ?? 'certify';
                      const rowDateCheck = rowAction === 'certify' ? resolveCertificationDate(newDates[item.tupleId] ?? defaultNewValidTo(), item.validTo) : { ok: true as const, iso: '' };
                      const isRowPreviewed = activeTupleId === item.tupleId && hasValidPreview;

                      return (
                        <tr key={item.tupleId}>
                          <td title={`${reviewLabel(item)} · ${item.tupleId}`}><strong>{reviewLabel(item)}</strong></td>
                          <td>
                            <span title={`${formatRef(item.subject)} → ${item.relation} → ${formatRef(item.resource)}`}>{item.relation.replace(/_/g, ' ')}</span>
                          </td>
                          <td className="operations-meta">{item.validTo ? <DateText iso={item.validTo} /> : <span className="metric-sub">{r.noExpiry}</span>}</td>
                          <td className="num"><span className={isUrgent ? 'badge badge-deny' : 'badge badge-warn'}>{r.days(item.daysLeft)}</span></td>
                          <td>
                            <div className="mono metric-sub">{r.grantedBy(item.grantedBy ?? r.system)}</div>
                            <div title={item.reason}>{item.reason ?? '—'}</div>
                          </td>
                          <td>
                            {canAct ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', minWidth: '310px' }}>
                                <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                                  <select
                                    aria-label={r.decisionFor(reviewLabel(item))}
                                    value={rowAction}
                                    onChange={(e) => {
                                      setActiveTupleId(item.tupleId);
                                      setSelectedDecision((prev) => ({ ...prev, [item.tupleId]: e.target.value as 'certify' | 'revoke' }));
                                    }}
                                    style={{ width: '115px' }}
                                  >
                                    <option value="certify">{r.certify}</option>
                                    <option value="revoke">{r.revoke}</option>
                                  </select>
                                  {rowAction === 'certify' ? (
                                    <>
                                      <label htmlFor={`rev-date-${item.tupleId}`} className="metric-sub" style={{ margin: 0 }}>{r.until}</label>
                                      <input
                                        id={`rev-date-${item.tupleId}`}
                                        type="date"
                                        value={newDates[item.tupleId] ?? defaultNewValidTo()}
                                        onChange={(e) => { setActiveTupleId(item.tupleId); setNewDates((prev) => ({ ...prev, [item.tupleId]: e.target.value })); }}
                                        style={{ width: '140px' }}
                                      />
                                    </>
                                  ) : null}
                                </div>
                                {!rowDateCheck.ok ? <div className="metric-sub" style={{ color: 'var(--deny-text)' }}>{rowDateCheck.message}</div> : null}
                                <input
                                  type="text"
                                  aria-label={r.justificationFor(reviewLabel(item))}
                                  value={reasonVal}
                                  onChange={(e) => setReasons((prev) => ({ ...prev, [item.tupleId]: e.target.value }))}
                                  placeholder={r.justificationPlaceholder}
                                />
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '6px' }}>
                                  <span className="mono metric-sub">{r.chars(reasonVal.trim().length)}</span>
                                  <div style={{ display: 'flex', gap: '6px' }}>
                                    <button
                                      type="button"
                                      className="btn btn-sm"
                                      disabled={!rowDateCheck.ok || (simulating && activeTupleId === item.tupleId)}
                                      onClick={() => { if (!rowDateCheck.ok) return; setActiveTupleId(item.tupleId); void runPreview(buildReviewCandidate(item, rowAction, rowDateCheck.iso)); }}
                                    >
                                      {simulating && activeTupleId === item.tupleId ? r.simulating : r.preview}
                                    </button>
                                    <button
                                      type="button"
                                      className={rowAction === 'certify' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-danger'}
                                      disabled={!isRowPreviewed || !validReason || !rowDateCheck.ok || submitting}
                                      title={!isRowPreviewed ? r.previewFirst : undefined}
                                      onClick={() => void handleSubmitDecision(item)}
                                    >
                                      {rowAction === 'certify' ? r.certify : r.revoke}
                                    </button>
                                  </div>
                                </div>
                              </div>
                            ) : <span className="badge">{r.readOnly}</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {impact && activeItem ? (
                <div style={{ marginTop: '16px' }}>
                  <div className="metric-sub" style={{ marginBottom: '6px' }}>
                    {r.impactFor} <strong title={activeItem.tupleId}>{reviewLabel(activeItem)}</strong> ({activeAction === 'certify' ? r.certify : r.revoke})
                  </div>
                  <ImpactTables impact={impact} />
                </div>
              ) : null}
            </div>
          )
        ) : null}
      </div>

      {roleAssignments ? (
        <div className="card" aria-labelledby="title-role-assignments">
          <h2 className="card-title" id="title-role-assignments">{r.roleAssignmentsTitle}</h2>
          <p className="metric-sub">{r.roleAssignmentsHint}</p>
          {roleAssignments.length === 0 ? <p className="metric-sub">{r.roleAssignmentsEmpty}</p> : (
            <ul className="mono">
              {roleAssignments.map((a) => (
                <li key={`${a.subject.type}:${a.subject.id}:${a.role}:${a.notAfter}`}>
                  {a.subject.id} · {a.role} · {a.notBefore?.slice(0, 10) ?? '…'} → {a.notAfter.slice(0, 10)} ({a.daysLeft} d)
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </section>
  );
}
