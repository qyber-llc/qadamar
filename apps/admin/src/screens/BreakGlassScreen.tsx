import { useEffect, useState, useCallback } from 'react';
import { api, ApiError, getServerNowMs } from '../api/client';
import type { AdminResource, AdminSubject, BreakGlassListResponse, BreakGlassRecord, ConsoleRole, SchemaResponse, SessionUser } from '../api/types';
import { DateText, EmptyState, ErrorAlert, LevelBadge, LoadingState } from '../components/UiStates';
import '../styles/operations.css';
import { canManageBreakGlass, canOpenBreakGlass } from '../utils/permissions';
import { useT } from '../i18n';

/** null once the grant has expired. */
function formatRemaining(expiresAt: string, serverNowMs: number): string | null {
  const diffSec = Math.floor((Date.parse(expiresAt) - serverNowMs) / 1000);
  if (Number.isNaN(diffSec) || diffSec <= 0) return null;
  const hh = String(Math.floor(diffSec / 3600)).padStart(2, '0');
  const mm = String(Math.floor((diffSec % 3600) / 60)).padStart(2, '0');
  const ss = String(diffSec % 60).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

export function mandatoryRestrictionRules(details: unknown): readonly string[] {
  if (!Array.isArray(details)) return [];
  return details.filter((rule): rule is string => typeof rule === 'string' && /(?:^|\.)(?:BLP\.|MAC\.|NET\.|BIBA\.)/.test(rule));
}

/** The server refuses review and revoke to whoever opened the emergency and to its subject (break-glass.ts). */
export function breakGlassManageBlocked(grant: Pick<BreakGlassRecord, 'openedBy' | 'subjectId'>, userId: string): boolean {
  return grant.openedBy === userId || grant.subjectId === userId;
}

/** Review and revoke: a security officer, or an access_admin for the emergencies the server lists in fallbackReview
 *  (no security officer other than the opener and the subject exists, break-glass.ts). */
export function breakGlassCanManage(roles: readonly ConsoleRole[], list: Pick<BreakGlassListResponse, 'fallbackReview'>, id: string): boolean {
  return canManageBreakGlass(roles) || (roles.includes('access_admin') && (list.fallbackReview ?? []).includes(id));
}

export function breakGlassHoursCap(bundleMaxHours?: number): number {
  return Math.min(4, bundleMaxHours ?? 4);
}

export function BreakGlassScreen(props: { readonly user: SessionUser; readonly onBreakGlassChanged: () => void }) {
  const t = useT();
  const b = t.breakGlass;
  const [bgData, setBgData] = useState<BreakGlassListResponse | null>(null);
  const [subjects, setSubjects] = useState<readonly AdminSubject[]>([]);
  const [resources, setResources] = useState<readonly AdminResource[]>([]);
  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const [subjectId, setSubjectId] = useState('');
  const [resourceId, setResourceId] = useState('');
  const [hours, setHours] = useState<number>(4);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [mandatoryDenyRules, setMandatoryDenyRules] = useState<readonly string[]>([]);
  const [mandatoryDenyMsg, setMandatoryDenyMsg] = useState<string | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const [revokeReason, setRevokeReason] = useState<Record<string, string>>({});
  const [reviewNote, setReviewNote] = useState<Record<string, string>>({});
  const [nowMs, setNowMs] = useState(() => getServerNowMs());

  const canOpen = canOpenBreakGlass(props.user.roles);
  const canManage = canManageBreakGlass(props.user.roles);
  const manages = (id: string): boolean => breakGlassCanManage(props.user.roles, bgData ?? {}, id);
  const maxHours = breakGlassHoursCap(schema?.needToKnow.breakGlassMaxHours);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [bg, sub, res, schemaResponse] = await Promise.all([api.getBreakGlass(), api.getSubjects(), api.getResources(), api.getSchema()]);
      setBgData(bg);
      setSubjects(sub.items);
      setResources(res.items);
      setSchema(schemaResponse);
      setHours((value) => Math.min(value, breakGlassHoursCap(schemaResponse.needToKnow.breakGlassMaxHours)));
      setNowMs(getServerNowMs());
      if (!subjectId && sub.items[0]) setSubjectId(sub.items[0].id);
      if (!resourceId && res.items[0]) setResourceId(res.items[0].id);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [subjectId, resourceId]);

  useEffect(() => { void loadAll(); }, []);
  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(getServerNowMs()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const handleOpen = async () => {
    if (!canOpen || !subjectId || !resourceId || reason.trim().length < 20 || hours < 1 || hours > maxHours) return;
    setSubmitting(true);
    setActionError(null);
    setMandatoryDenyRules([]);
    setMandatoryDenyMsg(null);
    try {
      await api.openBreakGlass({ subjectId, resourceId, reason: reason.trim(), hours });
      setReason('');
      props.onBreakGlassChanged();
      await loadAll();
    } catch (err) {
      const rules = err instanceof ApiError && err.status === 422 ? mandatoryRestrictionRules(err.details) : [];
      if (rules.length > 0) {
        setMandatoryDenyRules(rules);
        setMandatoryDenyMsg(b.neverClearance);
      } else {
        setActionError(err);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (id: string) => {
    const target = bgData?.active.find((x) => x.id === id);
    if (!manages(id) || !target || breakGlassManageBlocked(target, props.user.id)) return;
    const r = (revokeReason[id] ?? '').trim();
    if (!r) return;
    setActionError(null);
    try {
      await api.revokeBreakGlass(id, r);
      setRevokeReason((prev) => ({ ...prev, [id]: '' }));
      props.onBreakGlassChanged();
      await loadAll();
    } catch (err) {
      setActionError(err);
    }
  };

  const handleReview = async (id: string, outcome: 'justified' | 'escalated') => {
    const target = bgData?.toReview.find((x) => x.id === id);
    if (!manages(id) || !target || breakGlassManageBlocked(target, props.user.id)) return;
    const note = (reviewNote[id] ?? '').trim();
    if (!note) return;
    setActionError(null);
    try {
      await api.reviewBreakGlass(id, outcome, note);
      setReviewNote((prev) => ({ ...prev, [id]: '' }));
      props.onBreakGlassChanged();
      await loadAll();
    } catch (err) {
      setActionError(err);
    }
  };

  const subjectName = (id: string) => subjects.find((subject) => subject.id === id)?.name ?? id;
  const resourceName = (id: string) => {
    const resource = resources.find((entry) => entry.id === id);
    return resource ? `${resource.title} (${resource.id})` : id;
  };
  const grantLabel = (grant: BreakGlassRecord) => b.grantLabel(subjectName(grant.subjectId), resourceName(grant.resourceId));
  const selectedSubject = subjects.find((subject) => subject.id === subjectId);
  const selectedResource = resources.find((resource) => resource.id === resourceId);

  const renderQueueRow = (bg: BreakGlassRecord, isReviewed: boolean) => {
    const isOpener = bg.openedBy === props.user.id;
    const blocked = breakGlassManageBlocked(bg, props.user.id);
    const noteText = (reviewNote[bg.id] ?? '').trim();
    const manage = manages(bg.id);
    const canSubmitReview = manage && !blocked && noteText.length > 0;
    return (
      <tr key={bg.id}>
        <td title={`${grantLabel(bg)} · ${bg.id}`}><strong>{grantLabel(bg)}</strong></td>
        <td className="operations-meta" title={bg.openedBy}>
          {subjectName(bg.openedBy)}
          {isOpener ? <span className="badge" style={{ marginInlineStart: '6px' }}>{t.common.you}</span> : null}
        </td>
        <td title={bg.reason}>{bg.reason}</td>
        <td className="operations-meta"><DateText iso={bg.openedAt} /> {t.common.arrow} <DateText iso={bg.expiresAt} /></td>
        <td>
          {isReviewed ? (
            <div>
              <span className={bg.outcome === 'escalated' ? 'badge badge-deny' : 'badge badge-allow'}>
                {bg.outcome === 'escalated' ? b.escalated : b.justified}
              </span>
              {bg.note ? <div className="metric-sub" title={bg.note}>{bg.note}</div> : null}
            </div>
          ) : blocked ? (
            <span className="badge badge-lock">{b.cannotReviewOwn}</span>
          ) : manage ? (
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
              {canManage ? null : <div className="metric-sub" style={{ flexBasis: '100%' }}>{b.fallbackReview}</div>}
              <input
                type="text"
                aria-label={b.reviewNoteFor(grantLabel(bg))}
                placeholder={b.reviewNotePlaceholder}
                value={reviewNote[bg.id] ?? ''}
                onChange={(e) => setReviewNote((prev) => ({ ...prev, [bg.id]: e.target.value }))}
                style={{ width: '160px' }}
              />
              <button type="button" className="btn btn-sm btn-primary" disabled={!canSubmitReview} onClick={() => void handleReview(bg.id, 'justified')}>
                {b.justified}
              </button>
              <button type="button" className="btn btn-sm btn-danger" disabled={!canSubmitReview} onClick={() => void handleReview(bg.id, 'escalated')}>
                {b.escalated}
              </button>
            </div>
          ) : (
            <span className="badge badge-warn">{b.pendingReview}</span>
          )}
        </td>
      </tr>
    );
  };

  return (
    <section className="operations-screen" aria-labelledby="title-breakglass">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-breakglass">{b.title}</h1>
          <p className="screen-subtitle">
            {b.subtitle}
          </p>
        </div>
      </div>

      {loading ? <LoadingState label={b.loading} /> : null}
      {error ? <ErrorAlert error={error} contextTitle={b.loadError} onRetry={() => void loadAll()} /> : null}
      {actionError ? <ErrorAlert error={actionError} contextTitle={b.actionError} /> : null}

      {!loading && !error && bgData ? (
        <div>
          <div className="operations-grants-layout">
            <div className="card operations-active-grants">
              <h2 className="card-title">
                <span>{b.activeGrants}</span>
                <span className="badge badge-warn">{b.activeCount(bgData.active.length)}</span>
              </h2>
              {bgData.active.length === 0 ? (
                <EmptyState
                  title={b.noActive}
                  detail={b.noActiveDetail}
                />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {bgData.active.map((bg) => {
                    const remaining = formatRemaining(bg.expiresAt, nowMs);
                    const isExpired = remaining === null;
                    const isOpener = bg.openedBy === props.user.id;
                    const blocked = breakGlassManageBlocked(bg, props.user.id);
                    const revReason = (revokeReason[bg.id] ?? '').trim();
                    return (
                      <div key={bg.id} className="operations-grant">
                        <div className="operations-grant-heading">
                          <h3 title={`${grantLabel(bg)} · ${bg.id}`}>{grantLabel(bg)}</h3>
                          <div className="operations-countdown-block">
                            <span className="operations-label">{isExpired ? b.grantExpired : b.timeRemaining}</span>
                            <div className={`operations-countdown${isExpired ? ' operations-meta' : ''}`} role="timer" aria-label={b.timeRemainingFor(grantLabel(bg))}>
                              {remaining ?? b.expired}
                            </div>
                          </div>
                        </div>
                        <div title={bg.reason} style={{ marginBottom: 'var(--space-1)' }}>{bg.reason}</div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                          <span className="metric-sub">
                            {b.openedBy} <span title={bg.openedBy}>{subjectName(bg.openedBy)}</span>
                            {isOpener ? <span className="badge" style={{ marginInlineStart: '6px' }}>{t.common.you}</span> : null} · <DateText iso={bg.openedAt} />
                          </span>
                          {manages(bg.id) ? (
                            blocked ? (
                              <span className="badge badge-lock">{b.cannotRevokeOwn}</span>
                            ) : (
                              <div className="operations-revoke">
                                {canManage ? null : <div className="metric-sub" style={{ flexBasis: '100%' }}>{b.fallbackReview}</div>}
                                <input
                                  type="text"
                                  aria-label={b.revokeReasonFor(grantLabel(bg))}
                                  placeholder={b.revokeReasonPlaceholder}
                                  value={revokeReason[bg.id] ?? ''}
                                  onChange={(e) => setRevokeReason((prev) => ({ ...prev, [bg.id]: e.target.value }))}
                                  style={{ width: '160px' }}
                                />
                                <button
                                  type="button"
                                  className="btn btn-sm btn-danger"
                                  disabled={revReason.length === 0}
                                  onClick={() => void handleRevoke(bg.id)}
                                >
                                  {b.revokeEarly}
                                </button>
                              </div>
                            )
                          ) : null}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
            <div className="card operations-open-grant">
              <h2 className="card-title">
                <span>{b.openTitle}</span>
                <span className="badge badge-warn">{b.hoursBadge}</span>
              </h2>
              <p className="metric-sub" style={{ marginBottom: '12px' }}>
                {b.openDetail}
              </p>

              {mandatoryDenyRules.length > 0 ? (
                <div className="alert-error" role="alert" aria-live="assertive">
                  <div style={{ fontWeight: 600, marginBottom: '4px' }}>{b.neverClearanceTitle}</div>
                  <div style={{ marginBottom: '6px' }}>{mandatoryDenyMsg}</div>
                  <div className="badge-group">
                    <span>{b.stillDenying}</span>
                    {mandatoryDenyRules.map((r) => <span key={r} className="rule-tag">{r}</span>)}
                  </div>
                </div>
              ) : null}

              {canOpen ? (
                <div>
                  <div className="operations-fields">
                    <div className="form-group">
                      <label htmlFor="bg-subject-select">{b.subject}</label>
                      <select title={selectedSubject?.name} id="bg-subject-select" value={subjectId} onChange={(e) => setSubjectId(e.target.value)}>
                        {subjects.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                      </select>
                      {selectedSubject ? <div className="operations-selection" title={selectedSubject.id}><span>{b.clearance}</span><LevelBadge level={selectedSubject.clearance} /></div> : null}
                    </div>
                    <div className="form-group">
                      <label htmlFor="bg-resource-select">{b.resource}</label>
                      <select title={resourceName(resourceId)} id="bg-resource-select" value={resourceId} onChange={(e) => setResourceId(e.target.value)}>
                        {resources.map((r) => <option key={r.id} value={r.id}>{r.title} ({r.id})</option>)}
                      </select>
                      {selectedResource ? <div className="operations-selection" title={resourceName(resourceId)}><span>{b.classification}</span><LevelBadge level={selectedResource.level} /></div> : null}
                    </div>
                    <div className="form-group">
                      <label htmlFor="bg-hours-input">{b.hours}</label>
                      <input id="bg-hours-input" type="number" min={1} max={maxHours} value={hours} onChange={(e) => setHours(Math.min(maxHours, Math.max(1, Number(e.target.value) || 1)))} />
                    </div>
                  </div>

                  <div className="form-group" style={{ marginBottom: '12px' }}>
                    <label htmlFor="bg-reason-input">{b.justification}</label>
                    <textarea id="bg-reason-input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder={b.justificationPlaceholder} />
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <span className="mono metric-sub">{b.counter(reason.trim().length, hours)}</span>
                    <button type="button" className="btn btn-danger" disabled={reason.trim().length < 20 || submitting} onClick={() => void handleOpen()}>
                      {submitting ? b.opening : b.open}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="notice-box" style={{ marginBottom: 0 }}>{b.cannotOpen}</div>
              )}
            </div>
          </div>

          <div className="card">
            <h2 className="card-title">
              <span>{b.reviewQueue}</span>
              <span className="badge">{b.pendingCount(bgData.toReview.length)}</span>
            </h2>
            {bgData.toReview.length === 0 && bgData.reviewed.length === 0 ? (
              <EmptyState title={b.noReview} />
            ) : (
              <div className="table-wrap" tabIndex={0} role="region" aria-label={b.reviews}>
                <table className="operations-incident-table">
                  <thead>
                    <tr><th>{b.colGrant}</th><th>{b.colOpenedBy}</th><th>{b.colReason}</th><th>{b.colWindow}</th><th>{b.colReview}</th></tr>
                  </thead>
                  <tbody>
                    {bgData.toReview.map((bg) => renderQueueRow(bg, false))}
                    {bgData.reviewed.map((bg) => renderQueueRow(bg, true))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : null}
    </section>
  );
}
