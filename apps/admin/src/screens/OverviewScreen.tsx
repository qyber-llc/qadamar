// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — cards/Hero.jsx, cards/Metrics.jsx (hero, KPI tiles).
import { useEffect, useState, useCallback, type CSSProperties } from 'react';
import { api, getSessionGeneration } from '../api/client';
import type { AuditRecord, ConsoleRole, OverviewResponse } from '../api/types';
import { DateText, EmptyState, ErrorAlert, LoadingState } from '../components/UiStates';
import { formatRef } from '../utils/expr';
import { canAccessRoute, canViewAuditAndCompliance } from '../utils/permissions';
import { buildHref, navigate, type RoutePath } from '../utils/router';
import { NavIcon } from '../components/NavIcons';
import { Odometer, Words } from '../components/v24/Odometer';
import { Ring } from '../components/v24/Ring';
import { useT, type Messages } from '../i18n';
import '../styles/overview.css';
import '../styles/v24-overview.css';

export function OverviewScreen(props: {
  readonly roles: readonly ConsoleRole[];
  readonly userName: string;
  readonly onOverviewLoaded: (ov: OverviewResponse, reqGen: number) => void;
}) {
  const t = useT();
  const o = t.overview;
  const [data, setData] = useState<OverviewResponse | null>(null);
  const [recentAudit, setRecentAudit] = useState<readonly AuditRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [copied, setCopied] = useState(false);

  const canSeeAudit = canViewAuditAndCompliance(props.roles);

  const load = useCallback(async (silent = false) => {
    const reqGen = getSessionGeneration();
    if (!silent) setLoading(true);
    setError(null);
    try {
      const ovPromise = api.getOverview();
      const auditPromise = canSeeAudit
        ? api.getAudit({ limit: 8 }).catch(() => ({ items: [] as readonly AuditRecord[], next: null }))
        : Promise.resolve(null);
      const [ov, auditRes] = await Promise.all([ovPromise, auditPromise]);
      if (getSessionGeneration() !== reqGen) return;
      setData(ov);
      props.onOverviewLoaded(ov, reqGen);
      if (auditRes) setRecentAudit(auditRes.items.slice(0, 8));
    } catch (err) {
      if (getSessionGeneration() !== reqGen) return;
      setError(err);
    } finally {
      if (!silent && getSessionGeneration() === reqGen) setLoading(false);
    }
  }, [canSeeAudit, props.onOverviewLoaded]);

  useEffect(() => {
    void load(false);
    const onFocus = () => {
      void load(true);
    };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [load]);

  const cardHref = (target: RoutePath, params?: Record<string, string>) =>
    canAccessRoute(props.roles, target) ? buildHref(target, params) : buildHref('overview');

  const handleCopyVersion = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore clipboard errors
    }
  };

  const today = new Date().toLocaleDateString(o.locale, { weekday: 'long', month: 'long', day: 'numeric' });

  return (
    <section className="overview-screen" aria-labelledby="title-overview">
      <div className="screen-header">
        <div>
          <h1 className="screen-title ov-greeting" id="title-overview">
            <Words text={o.greeting(new Date().getHours(), props.userName)} />
          </h1>
          <p className="screen-subtitle v24-sub">
            {o.subtitle(today)}
          </p>
        </div>
      </div>

      {loading ? <LoadingState label={o.loading} /> : null}
      {error ? <ErrorAlert error={error} contextTitle={o.unavailable} onRetry={() => void load(false)} /> : null}
      {!loading && !error && !data ? <EmptyState title={o.noData} /> : null}

      {data && !loading ? (
        <div className="v24-bento">
          <AttentionHero data={data} roles={props.roles} cardHref={cardHref} t={t} />

          <div className="v24-kpis">
            {metricTiles(data, canSeeAudit, cardHref, t).map((m, i) => (
              <a
                key={m.label}
                href={m.href}
                className="v24-kpi v24-tilt v24-press"
                data-reveal
                data-attention={m.attention ? 'true' : undefined}
              >
                <div className="kpi-top">
                  <span className="kpi-ic"><NavIcon path={m.icon} /></span>
                  {m.attention ? <span className="kpi-flag">{o.actionNeeded}</span> : null}
                </div>
                <div className="kpi-num"><Odometer value={m.value} delay={i * 90} /></div>
                <div className="kpi-foot">
                  <strong>{m.label}</strong>
                  <small>{m.sub}</small>
                </div>
              </a>
            ))}
          </div>

          <div className={canSeeAudit ? 'grid-2' : undefined}>
            <div className="card" data-reveal>
              <h2 className="card-title">
                <span>{o.publishedPolicy}</span>
                <a href={cardHref('policies')} className="btn btn-sm">
                  {o.viewPolicies}
                </a>
              </h2>
              <div className="ov-kv-row">
                <span className="ov-kv-label">{o.bundleName}</span>
                <span className="ov-kv-value" title={data.policy.name}>{data.policy.name}</span>
              </div>
              <div className="ov-kv-row">
                <span className="ov-kv-label">{o.versionFingerprint}</span>
                <span className="ov-kv-value">
                  <span className="ov-fingerprint">
                    <span className="mono" title={data.policy.version}>
                      {data.policy.version.slice(0, 16)}
                    </span>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => void handleCopyVersion(data.policy.version)}
                    >
                      {copied ? t.common.copied : t.common.copy}
                    </button>
                  </span>
                </span>
              </div>
              <div className="ov-kv-row">
                <span className="ov-kv-label">{o.ntkMode}</span>
                <span className="ov-kv-value">
                  <span
                    className={
                      data.needToKnowMode === 'enforce'
                        ? 'badge badge-allow'
                        : data.needToKnowMode === 'dry_run'
                          ? 'badge badge-warn'
                          : 'badge badge-deny'
                    }
                  >
                    {data.needToKnowMode === 'enforce'
                      ? o.ntkEnforce
                      : data.needToKnowMode === 'dry_run'
                        ? o.ntkDryRun
                        : o.ntkOff}
                  </span>
                </span>
              </div>
              <div className="ov-kv-row">
                <span className="ov-kv-label">{o.publishedBy}</span>
                <span className="ov-kv-value" title={data.policy.publishedBy}>{data.policy.publishedBy}</span>
              </div>
              <div className="ov-kv-row">
                <span className="ov-kv-label">{o.approvedBy}</span>
                <span className="ov-kv-value" title={data.policy.approvedBy}>{data.policy.approvedBy}</span>
              </div>
              <div className="ov-kv-row">
                <span className="ov-kv-label">{o.publishedAt}</span>
                <span className="ov-kv-value"><DateText iso={data.policy.publishedAt} /></span>
              </div>
            </div>

            {canSeeAudit ? (
              <div className="card" data-reveal>
                <h2 className="card-title">
                  <span>{o.recentActivity}</span>
                  <a href={buildHref('audit')} className="btn btn-sm">
                    {o.openAudit}
                  </a>
                </h2>
                {recentAudit.length === 0 ? (
                  <EmptyState title={o.noRecentAudit} />
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th className="num">{o.colSeq}</th>
                          <th>{o.colTime}</th>
                          <th>{o.colType}</th>
                          <th>{o.colSummary}</th>
                          <th>{o.colOutcome}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentAudit.map((rec) => (
                          <tr
                            key={rec.seq}
                            className="clickable-row"
                            onClick={() => navigate('audit', { type: rec.type })}
                          >
                            <td className="num mono">
                              <a
                                href={buildHref('audit', { type: rec.type })}
                                onClick={(e) => e.stopPropagation()}
                                aria-label={o.inspectRecord(rec.seq, rec.type)}
                              >
                                #{rec.seq}
                              </a>
                            </td>
                            <td><DateText iso={rec.ts} /></td>
                            <td><span className="badge">{rec.type}</span></td>
                            <td className="mono">
                              {rec.subject ? formatRef(rec.subject) : rec.actor}{' '}
                              {rec.action ? `→ ${rec.action}` : ''}{' '}
                              {rec.resource ? `(${formatRef(rec.resource)})` : ''}
                            </td>
                            <td>
                              {rec.effect ? (
                                <span className={rec.effect === 'allow' ? 'badge badge-allow' : 'badge badge-deny'}>
                                  {rec.effect === 'allow' ? t.common.allow : t.common.deny}
                                </span>
                              ) : (
                                <span className="metric-sub">—</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function openItems(data: OverviewResponse): number {
  return data.counts.pendingChanges + data.counts.activeBreakGlass + data.counts.breakGlassToReview;
}

type CardHref = (target: RoutePath, params?: Record<string, string>) => string;

/** The four figures as tiles, each a link to the screen that acts on it. */
interface Tile { readonly label: string; readonly value: number; readonly sub: string; readonly icon: RoutePath; readonly href: string; readonly attention: boolean }

function metricTiles(data: OverviewResponse, canSeeAudit: boolean, cardHref: CardHref, t: Messages): readonly Tile[] {
  const c = data.counts;
  const m = t.overview.tiles;
  return [
    { label: m.pending, value: c.pendingChanges, sub: m.pendingSub, icon: 'approvals', href: cardHref('approvals', { status: 'pending' }), attention: c.pendingChanges > 0 },
    { label: m.breakGlass, value: c.activeBreakGlass, sub: m.breakGlassSub(c.breakGlassToReview), icon: 'break-glass', href: cardHref('break-glass'), attention: c.breakGlassToReview > 0 },
    { label: m.expiring, value: c.expiringGrants30d, sub: m.expiringSub, icon: 'reviews', href: cardHref('reviews'), attention: false },
    { label: m.decisions, value: data.pdp.decisions, sub: m.decisionsSub(data.pdp.status), icon: 'simulator', href: canSeeAudit ? cardHref('audit') : cardHref('simulator'), attention: false },
  ];
}

/** "Needs your attention": the v24 hero card, green on carbon, with the open items rolling in. */
function AttentionHero(props: { readonly data: OverviewResponse; readonly roles: readonly ConsoleRole[]; readonly cardHref: CardHref; readonly t: Messages }) {
  const h = props.t.overview.hero;
  const c = props.data.counts;
  const open = openItems(props.data);
  const parts = [
    c.pendingChanges > 0 ? h.pendingPart(c.pendingChanges) : '',
    c.activeBreakGlass > 0 ? h.activePart(c.activeBreakGlass) : '',
    c.breakGlassToReview > 0 ? h.reviewPart(c.breakGlassToReview) : '',
  ].filter(Boolean);
  const stats = [
    { value: c.pendingChanges, label: h.statAwaiting },
    { value: c.activeBreakGlass, label: h.statActive },
    { value: c.breakGlassToReview, label: h.statReview },
  ];
  const canBreakGlass = canAccessRoute(props.roles, 'break-glass');
  return (
    <section className="v24-hero" data-reveal aria-label={h.label}>
      <div className="hero-copy">
        <span className="hero-tag"><i aria-hidden="true" /> {open > 0 ? h.tagAttention : h.tagClear}</span>
        <h2>
          {open > 0 ? (
            <>{h.items(open)} <em>{h.need(open)}</em> {h.youToday}</>
          ) : (
            <>{h.calmBefore} <em>{h.calm}</em> {h.calmAfter}</>
          )}
        </h2>
        <p>{open > 0 ? `${parts.join(' · ')}.` : h.clearDetail}</p>
        <div className="hero-stats">
          {stats.map((s, i) => (
            <span key={s.label} className="h-stat" style={{ '--s': i } as CSSProperties}>
              <b><Odometer value={s.value} delay={250 + i * 120} /></b>
              <small>{s.label}</small>
            </span>
          ))}
        </div>
        <div className="hero-cta">
          {c.pendingChanges > 0 ? (
            <a href={props.cardHref('approvals', { status: 'pending' })} className="btn v24-btn-light v24-mag">{h.reviewApprovals}</a>
          ) : null}
          {(c.activeBreakGlass > 0 || c.breakGlassToReview > 0) && canBreakGlass ? (
            <a href={props.cardHref('break-glass')} className="btn v24-btn-outline v24-mag">{h.reviewBreakGlass}</a>
          ) : null}
          {open === 0 ? (
            <a href={props.cardHref('policies')} className="btn v24-btn-light v24-mag">{props.t.overview.viewPolicies}</a>
          ) : null}
        </div>
      </div>
      <div className="hero-orbit" aria-hidden="true">
        <Ring value={1} size={168} stroke={12}>
          <b><Odometer value={open} delay={200} /></b>
          <span>{h.open}</span>
        </Ring>
      </div>
    </section>
  );
}
