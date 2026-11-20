import { useEffect, useState, useCallback } from 'react';
import { api } from '../api/client';
import type { AuditRecord, AuditVerifyResponse, ConsoleRole } from '../api/types';
import { DateText, EmptyState, ErrorAlert, LoadingState } from '../components/UiStates';
import { formatRef } from '../utils/expr';
import { canUseSimulator } from '../utils/permissions';
import type { ExplainTarget } from '../components/ExplainDrawer';
import { useT } from '../i18n';

const AUDIT_TYPES = ['decision', 'change', 'break_glass', 'session', 'security', 'simulation'] as const;
const typeLabel = (types: Readonly<Record<string, string>>, type: string): string => types[type] ?? type;

function extractId(refOrStr: AuditRecord['subject']): string | null {
  if (!refOrStr) return null;
  return typeof refOrStr === 'string' ? refOrStr : refOrStr.id;
}

export function AuditExplorerScreen(props: {
  readonly roles?: readonly ConsoleRole[];
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
  readonly onExplain?: (target: ExplainTarget) => void;
}) {
  const t = useT();
  const a = t.audit;
  const explainCallback = !props.roles || canUseSimulator(props.roles) ? props.onExplain : undefined;
  const [items, setItems] = useState<readonly AuditRecord[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [verifyState, setVerifyState] = useState<AuditVerifyResponse | null>(null);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const { type: filterType = '', effect: filterEffect = '', rule: filterRule = '', subject: filterSubject = '', resource: filterResource = '', cursor = '' } = props.params;

  const loadAudit = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [auditRes, verifyRes] = await Promise.all([
        api.getAudit({
          ...(filterType ? { type: filterType } : {}),
          ...(filterEffect ? { effect: filterEffect } : {}),
          ...(filterRule ? { rule: filterRule } : {}),
          ...(filterSubject ? { subject: filterSubject } : {}),
          ...(filterResource ? { resource: filterResource } : {}),
          ...(cursor ? { cursor } : {}),
          limit: 50,
        }),
        api.verifyAuditChain(),
      ]);
      setItems(auditRes.items);
      setNextCursor(auditRes.next);
      setVerifyState(verifyRes);
      // Functional update keeps selectedSeq out of the deps: selecting a row must not refetch and unmount it.
      const first = auditRes.items[0];
      if (first) setSelectedSeq((prev) => prev ?? first.seq);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [filterType, filterEffect, filterRule, filterSubject, filterResource, cursor]);

  useEffect(() => {
    void loadAudit();
  }, [loadAudit]);

  const handleReverify = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyAuditChain();
      setVerifyState(res);
    } catch (err) {
      setError(err);
    } finally {
      setVerifying(false);
    }
  };

  const selectedRecord = items.find((r) => r.seq === selectedSeq) ?? items[0] ?? null;

  return (
    <section aria-labelledby="title-audit">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-audit">{a.title}</h1>
          <p className="screen-subtitle">
            {a.subtitle}
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }} aria-live="polite">
          {verifyState ? (
            verifyState.verified ? (
              <span className="badge badge-allow" title={a.verifiedTitle(verifyState.length)}>
                {a.verified(verifyState.length)}
              </span>
            ) : (
              <span className="badge badge-deny">
                {a.brokenAt(String(verifyState.brokenAt ?? '?'))}
              </span>
            )
          ) : null}
          <button type="button" className="btn btn-sm" disabled={verifying} onClick={() => void handleReverify()}>
            {verifying ? a.verifying : a.verify}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="filter-bar">
          <div className="form-group">
            <label htmlFor="audit-type-select">{a.type}</label>
            <select id="audit-type-select" value={filterType} onChange={(e) => props.setParams({ type: e.target.value || undefined, cursor: undefined })}>
              <option value="">{a.allTypes}</option>
              {AUDIT_TYPES.map((type) => <option key={type} value={type}>{a.types[type]}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="audit-effect-select">{a.outcome}</label>
            <select id="audit-effect-select" value={filterEffect} onChange={(e) => props.setParams({ effect: e.target.value || undefined, cursor: undefined })}>
              <option value="">{a.allOutcomes}</option>
              <option value="allow">{t.common.allow}</option>
              <option value="deny">{t.common.deny}</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="audit-rule-input">{a.rule}</label>
            <input id="audit-rule-input" type="search" placeholder={a.rulePlaceholder} value={filterRule} onChange={(e) => props.setParams({ rule: e.target.value || undefined, cursor: undefined })} />
          </div>
          <div className="form-group">
            <label htmlFor="audit-subject-input">{a.subject}</label>
            <input id="audit-subject-input" type="search" placeholder={a.subjectPlaceholder} value={filterSubject} onChange={(e) => props.setParams({ subject: e.target.value || undefined, cursor: undefined })} />
          </div>
          <div className="form-group">
            <label htmlFor="audit-resource-input">{a.resource}</label>
            <input id="audit-resource-input" type="search" placeholder={a.resourcePlaceholder} value={filterResource} onChange={(e) => props.setParams({ resource: e.target.value || undefined, cursor: undefined })} />
          </div>
        </div>

        {loading ? <LoadingState label={a.loading} /> : null}
        {error ? <ErrorAlert error={error} contextTitle={a.loadFailed} onRetry={() => void loadAudit()} /> : null}

        <div className="sr-only" role="status">
          {!loading && !error ? a.shown(items.length) : ''}
        </div>

        {/* Keep the previous page mounted while reloading so focus on paging controls is not lost. */}
        {!error && (!loading || items.length > 0) ? (
          items.length === 0 ? (
            <EmptyState
              title={a.empty}
              detail={a.emptyDetail}
            />
          ) : (
            <div className="grid-2-1" aria-busy={loading}>
              <div>
                <div className="table-wrap">
                  <table aria-label={a.tableLabel}>
                    <thead>
                      <tr>
                        <th scope="col" className="num">{a.seq}</th>
                        <th scope="col">{a.time}</th>
                        <th scope="col">{a.type}</th>
                        <th scope="col">{a.subjectActor}</th>
                        <th scope="col">{a.actionResource}</th>
                        <th scope="col">{a.outcome}</th>
                        <th scope="col">{a.rules}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {items.map((rec) => {
                        const isSelected = selectedRecord?.seq === rec.seq;
                        const sid = extractId(rec.subject);
                        const rid = extractId(rec.resource);
                        return (
                          <tr
                            key={rec.seq}
                            className={isSelected ? 'clickable-row selected-row' : 'clickable-row'}
                            onClick={() => {
                              setSelectedSeq(rec.seq);
                              if (explainCallback && rec.type === 'decision' && sid && rid) {
                                explainCallback({
                                  subjectId: sid,
                                  resourceId: rid,
                                  action: rec.action || 'read',
                                  network: 'trusted',
                                });
                              }
                            }}
                          >
                            <td className="num mono">
                              <button
                                type="button"
                                className="row-action-btn mono"
                                aria-pressed={isSelected}
                                aria-label={a.selectRecord(rec.seq)}
                                onClick={(e) => { e.stopPropagation(); setSelectedSeq(rec.seq); }}
                              >
                                #{rec.seq}
                              </button>
                            </td>
                            <td><DateText iso={rec.ts} /></td>
                            <td><span className="badge" title={rec.type}>{typeLabel(a.types, rec.type)}</span></td>
                            <td className="mono">{rec.subject ? formatRef(rec.subject) : rec.actor || '—'}</td>
                            <td className="mono">{rec.action || '—'} → {rec.resource ? formatRef(rec.resource) : '—'}</td>
                            <td>
                              {rec.effect ? (
                                <span className={rec.effect === 'allow' ? 'badge badge-allow' : 'badge badge-deny'}>
                                  {rec.effect === 'allow' ? t.common.allow : t.common.deny}
                                </span>
                              ) : '—'}
                            </td>
                            <td>
                              <div className="badge-group">
                                {(rec.rules ?? []).map((r) => <span key={r} className="rule-tag">{r}</span>)}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px' }}>
                  <span className="metric-sub">
                    {a.showing(items.length, cursor)}
                  </span>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    {cursor ? (
                      <button type="button" className="btn btn-sm" onClick={() => props.setParams({ cursor: undefined })}>
                        {a.firstPage}
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      disabled={!nextCursor}
                      onClick={() => { if (nextCursor) props.setParams({ cursor: nextCursor }); }}
                    >
                      {a.nextPage}
                    </button>
                  </div>
                </div>
              </div>

              {selectedRecord ? (
                <div className="card" style={{ marginBottom: 0 }} role="region" aria-labelledby="audit-detail-title">
                  <h2 className="card-title" id="audit-detail-title">
                    <span>{a.record(selectedRecord.seq)}</span>
                    <span className="badge" title={selectedRecord.type}>{typeLabel(a.types, selectedRecord.type)}</span>
                  </h2>
                  <div className="kv-row"><span className="kv-label">{a.time}</span><span><DateText iso={selectedRecord.ts} /></span></div>
                  <div className="kv-row"><span className="kv-label">{a.actor}</span><span className="mono">{selectedRecord.actor || '—'}</span></div>
                  <div className="kv-row"><span className="kv-label">{a.subject}</span><span className="mono">{formatRef(selectedRecord.subject)}</span></div>
                  <div className="kv-row"><span className="kv-label">{a.action}</span><span className="mono">{selectedRecord.action || '—'}</span></div>
                  <div className="kv-row"><span className="kv-label">{a.resource}</span><span className="mono">{formatRef(selectedRecord.resource)}</span></div>
                  <div className="kv-row"><span className="kv-label">{a.policyVersion}</span><span className="mono">{selectedRecord.policyVersion ?? '—'}</span></div>
                  <div className="kv-row"><span className="kv-label">{a.prevHash}</span><span className="mono" title={selectedRecord.prevHash}>{selectedRecord.prevHash.slice(0, 20)}…</span></div>
                  <div className="kv-row"><span className="kv-label">{a.hash}</span><span className="mono" title={selectedRecord.hash}><strong>{selectedRecord.hash.slice(0, 20)}…</strong></span></div>

                  {selectedRecord.details ? (
                    <div style={{ marginTop: '10px' }}>
                      <div className="metric-label" style={{ marginBottom: '4px' }}>{a.details}</div>
                      <pre className="code-block" style={{ maxHeight: '140px', overflowY: 'auto' }}>
                        {JSON.stringify(selectedRecord.details, null, 2)}
                      </pre>
                    </div>
                  ) : null}

                  {explainCallback && extractId(selectedRecord.subject) && extractId(selectedRecord.resource) ? (
                    <div style={{ marginTop: '12px' }}>
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        onClick={() => {
                          const sid = extractId(selectedRecord.subject);
                          const rid = extractId(selectedRecord.resource);
                          if (sid && rid) {
                            explainCallback({
                              subjectId: sid,
                              resourceId: rid,
                              action: selectedRecord.action || 'read',
                              network: 'trusted',
                            });
                          }
                        }}
                      >
                        {a.explain}
                      </button>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
          )
        ) : null}
      </div>
    </section>
  );
}
