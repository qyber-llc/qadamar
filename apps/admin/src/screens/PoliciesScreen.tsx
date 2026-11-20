import { useEffect, useState, useCallback } from 'react';
import { api } from '../api/client';
import type { ConsoleRole, PolicyResponse } from '../api/types';
import { DateText, EmptyState, ErrorAlert, LoadingState } from '../components/UiStates';
import { formatExpr } from '../utils/expr';
import { contentRules } from '../api/coreTypes';
import { canProposePolicyChange } from '../utils/permissions';
import { buildHref } from '../utils/router';
import { PolicyEditorPane } from './PolicyEditorPane';
import { IntegrityPanel } from './IntegrityCards';
import { useT } from '../i18n';

type PolicyTab = 'pipeline' | 'rules' | 'history' | 'editor';

export function PoliciesScreen(props: {
  readonly roles: readonly ConsoleRole[];
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
}) {
  const t = useT();
  const p = t.policies;
  const activeTab: PolicyTab =
    props.params.tab === 'rules' || props.params.tab === 'history' || props.params.tab === 'editor'
      ? props.params.tab
      : 'pipeline';

  const [policyData, setPolicyData] = useState<PolicyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [copied, setCopied] = useState(false);

  const loadPolicy = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPolicyData(await api.getPolicy());
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadPolicy();
  }, [loadPolicy]);

  const b = policyData?.current.bundle;

  const pipelineCards = b
    ? [
        { title: p.stage.inactiveTitle, rule: 'CORE.INACTIVE', desc: p.stage.inactiveDesc, status: p.systemLocked },
        { title: p.stage.eligibilityTitle, rule: 'RBAC.* / ABAC.*', desc: p.stage.eligibilityDesc(Object.keys(b.rbac.roles).length), status: p.systemLocked },
        { title: p.stage.mandatoryTitle, rule: 'BLP.*, MAC.COMPARTMENT, NET.*, BIBA.*', desc: p.stage.mandatoryDesc(b.mandatory.trustedRoles.join(', '), b.mandatory.untrustedNetworkMaxLevel, b.mandatory.compartmentsRequireTrustedNetwork ? p.yes : p.no), status: p.systemLocked },
        { title: p.stage.delegationTitle, rule: 'DELEGATION.*', desc: p.stage.delegationDesc, status: p.systemLocked },
        { title: p.stage.ntkTitle, rule: 'NTK.*', desc: p.stage.ntkDesc(b.needToKnow.mode, Object.entries(b.needToKnow.protect).map(([ty, pr]) => `${ty}#${pr.relation}`).join(', ') || p.none, b.needToKnow.breakGlassMaxHours), status: p.modeStatus(b.needToKnow.mode) },
        { title: p.stage.abacTitle, rule: 'ABAC.*', desc: p.stage.abacDesc(b.abac.length), status: p.tenantRules },
        { title: p.stage.contentTitle, rule: 'ABAC.CONTENT_*', desc: p.stage.contentDesc(contentRules(b).length), status: p.tenantRules },
        { title: p.stage.contextTitle, rule: 'CBAC.*', desc: p.stage.contextDesc((b.context ?? []).length), status: p.tenantRules },
        { title: p.stage.cwTitle, rule: 'CW.*', desc: p.stage.cwDesc(b.clarkWilson.tokenTtlSeconds), status: p.systemLocked },
        { title: p.stage.sodTitle, rule: 'SOD.*', desc: p.stage.sodDesc(b.sod.length), status: p.systemLocked },
      ]
    : [];

  const handleCopyVersion = async (ver: string) => {
    try {
      await navigator.clipboard.writeText(ver);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore clipboard errors
    }
  };

  return (
    <section aria-labelledby="title-policies">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-policies">{p.title}</h1>
          <p className="screen-subtitle">
            {p.subtitle}
          </p>
        </div>
        {policyData ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="metric-sub">{p.publishedFingerprint}</span>
            <span className="badge mono">{policyData.current.version.slice(0, 16)}</span>
            <button type="button" className="btn btn-sm" aria-label={p.copyFingerprint} onClick={() => void handleCopyVersion(policyData.current.version)}>
              {copied ? t.common.copied : t.common.copy}
            </button>
            <span className="sr-only" role="status">{copied ? p.fingerprintCopied : ''}</span>
          </div>
        ) : null}
      </div>

      <div className="tab-bar" role="group" aria-label={p.sections}>
        {(['pipeline', 'rules', 'history', 'editor'] as const).map((tab) => (
          <button key={tab} type="button" className="tab-btn" aria-pressed={activeTab === tab} onClick={() => props.setParams({ tab })}>
            {tab === 'pipeline' && p.tabPipeline}
            {tab === 'rules' && p.tabRules(b ? b.abac.length + contentRules(b).length + (b.context ?? []).length + b.sod.length : 0)}
            {tab === 'history' && p.tabHistory(policyData?.history.length ?? 0)}
            {tab === 'editor' && p.tabEditor}
          </button>
        ))}
      </div>

      {loading ? <LoadingState label={p.loading} /> : null}
      {error ? <ErrorAlert error={error} contextTitle={p.loadError} onRetry={() => void loadPolicy()} /> : null}

      {!loading && !error && policyData && b && activeTab === 'pipeline' ? (
        <div className="grid-3">
          {pipelineCards.map((c) => (
            <div key={c.title} className="card">
              <h2 className="card-title">
                <span>{c.title}</span>
                <span className="badge badge-lock">{c.status}</span>
              </h2>
              <div style={{ marginBottom: '8px' }}>
                <span className="rule-tag">{c.rule}</span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{c.desc}</div>
            </div>
          ))}
        </div>
      ) : null}

      {!loading && !error && policyData && b && activeTab === 'rules' ? (
        <div>
          <div className="card">
            <h2 className="card-title">
              <span>{p.stage.abacTitle}</span>
              <span className="badge">{p.rulesCount(b.abac.length)}</span>
            </h2>
            {b.abac.length === 0 ? (
              <EmptyState
                title={p.noAbac}
                detail={p.noAbacDetail}
                actionLabel={canProposePolicyChange(props.roles) ? p.openEditor : undefined}
                actionHref={canProposePolicyChange(props.roles) ? buildHref('policies', { tab: 'editor' }) : undefined}
              />
            ) : (
              <div className="table-wrap">
                <table aria-label={p.stage.abacTitle}>
                  <thead>
                    <tr>
                      <th scope="col">{p.colRuleId}</th>
                      <th scope="col">{p.colEffect}</th>
                      <th scope="col">{p.colScope}</th>
                      <th scope="col">{p.colCondition}</th>
                      <th scope="col">{p.colDescObligations}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {b.abac.map((r) => (
                      <tr key={r.id}>
                        <td><span className="rule-tag">{r.id}</span></td>
                        <td>
                          <span className={r.effect === 'forbid' ? 'badge badge-deny' : r.effect === 'permit' ? 'badge badge-allow' : 'badge badge-warn'}>
                            {r.effect}
                          </span>
                        </td>
                        <td className="mono">{p.scope(r.resourceTypes?.join(', ') ?? '*', r.actions?.join(', ') ?? '*')}</td>
                        <td className="mono">{formatExpr(r.when)}</td>
                        <td>
                          <div>{r.description}</div>
                          {r.obligations ? <div className="mono metric-sub">{p.obligations} {JSON.stringify(r.obligations)}</div> : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <h2 className="card-title">
              <span>{p.stage.contentTitle}</span>
              <span className="badge">{p.rulesCount(contentRules(b).length)}</span>
            </h2>
            {b.cbac ? <div className="alert-warn" role="status">{p.legacyContentField}</div> : null}
            {contentRules(b).length === 0 ? (
              <EmptyState title={p.noContent} />
            ) : (
              <div className="table-wrap">
                <table aria-label={p.contentRules}>
                  <thead>
                    <tr>
                      <th scope="col">{p.colRuleId}</th>
                      <th scope="col">{p.colContentClass}</th>
                      <th scope="col">{p.colEffectFields}</th>
                      <th scope="col">{p.colUnless}</th>
                      <th scope="col">{p.colDescription}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {contentRules(b).map((r) => (
                      <tr key={r.id}>
                        <td><span className="rule-tag">{r.id}</span></td>
                        <td className="mono">{r.contentClass}</td>
                        <td className="mono">
                          <span className={r.effect === 'deny' ? 'badge badge-deny' : 'badge badge-warn'}>{r.effect}</span>{' '}
                          {r.fields?.length ? p.fields(r.fields.join(', ')) : ''}
                        </td>
                        <td className="mono">{r.unless ? p.unless(formatExpr(r.unless)) : p.alwaysApplies}</td>
                        <td>{r.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <h2 className="card-title">
              <span>{p.stage.contextTitle}</span>
              <span className="badge">{p.rulesCount((b.context ?? []).length)}</span>
            </h2>
            {(b.context ?? []).length === 0 ? <EmptyState title={p.noContext} /> : (
              <div className="table-wrap">
                <table aria-label={p.contextRules}>
                  <thead>
                    <tr><th scope="col">{p.colRuleId}</th><th scope="col">{p.colScope}</th><th scope="col">{p.colRequirements}</th><th scope="col">{p.colDescription}</th></tr>
                  </thead>
                  <tbody>
                    {(b.context ?? []).map((r) => (
                      <tr key={r.id}>
                        <td><span className="rule-tag">{r.id}</span></td>
                        <td className="mono">
                          {p.scope(r.resourceTypes?.join(', ') ?? '*', r.actions?.join(', ') ?? r.actionKinds?.join(', ') ?? '*')}
                          {r.minResourceLevel !== undefined ? ` · min L${r.minResourceLevel}` : ''}
                          {r.contentClasses ? ` · [${r.contentClasses.join(', ')}]` : ''}
                        </td>
                        <td className="mono">{JSON.stringify({ network: r.network, countries: r.countries, ipRanges: r.ipRanges, timeWindows: r.timeWindows,
                          device: r.device, mfaMaxAgeSeconds: r.mfaMaxAgeSeconds, authMaxAgeSeconds: r.authMaxAgeSeconds,
                          authMethodsAny: r.authMethodsAny, maxRiskScore: r.maxRiskScore })}</td>
                        <td>{r.description ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="grid-2">
            <div className="card">
              <h2 className="card-title">
                <span>{p.sodRules}</span>
                <span className="badge">{p.rulesCount(b.sod.length)}</span>
              </h2>
              {b.sod.length === 0 ? <EmptyState title={p.noSod} /> : (
                <div className="table-wrap">
                  <table aria-label={p.sodRules}>
                    <thead>
                      <tr><th scope="col">{p.colRuleId}</th><th scope="col">{p.colConflicting}</th><th scope="col">{p.colDescription}</th></tr>
                    </thead>
                    <tbody>
                      {b.sod.map((r) => (
                        <tr key={r.id}>
                          <td><span className="rule-tag">{r.id}</span></td>
                          <td className="mono">[{r.conflicting.join(', ')}]</td>
                          <td>{r.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="card">
              <h2 className="card-title">
                <span>{p.roleMatrix}</span>
                <span className="badge">{p.rolesCount(Object.keys(b.rbac.roles).length)}</span>
              </h2>
              <div className="table-wrap">
                <table aria-label={p.roleMatrix}>
                  <thead>
                    <tr><th scope="col">{p.colRole}</th><th scope="col">{p.colInherits}</th><th scope="col">{p.colGrants}</th></tr>
                  </thead>
                  <tbody>
                    {Object.entries(b.rbac.roles).map(([roleName, def]) => (
                      <tr key={roleName}>
                        <td className="mono"><strong>{roleName}</strong></td>
                        <td className="mono">{def.inherits?.join(', ') || '—'}</td>
                        <td className="mono">{def.grants.map((g) => `${g.resourceType}:[${g.actions.join(', ')}]`).join('; ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <IntegrityPanel roles={props.roles} />
        </div>
      ) : null}

      {!loading && !error && policyData && activeTab === 'history' ? (
        <div className="card">
          <h2 className="card-title">
            <span>{p.versionHistory}</span>
            <span className="badge mono">{policyData.current.version.slice(0, 16)}</span>
          </h2>
          {policyData.history.length === 0 ? <EmptyState title={p.noHistory} /> : (
            <div className="table-wrap">
              <table aria-label={p.historyTable}>
                <thead>
                  <tr><th scope="col">{p.colFingerprint}</th><th scope="col">{p.colPublished}</th><th scope="col">{p.colPublishedBy}</th><th scope="col">{p.colApprovedBy}</th><th scope="col">{p.colReason}</th></tr>
                </thead>
                <tbody>
                  {policyData.history.map((h) => (
                    <tr key={`${h.version}-${h.publishedAt}`}>
                      <td className="mono">
                        <strong>{h.version}</strong>
                        {h.version === policyData.current.version ? <span className="badge badge-allow" style={{ marginInlineStart: '6px' }}>{p.published}</span> : null}
                      </td>
                      <td><DateText iso={h.publishedAt} /></td>
                      <td className="mono">{h.publishedBy}</td>
                      <td className="mono">{h.approvedBy}</td>
                      <td>{h.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : null}

      {!loading && !error && policyData && b && activeTab === 'editor' ? (
        <PolicyEditorPane roles={props.roles} currentVersion={policyData.current.version} currentBundle={b} />
      ) : null}
    </section>
  );
}
