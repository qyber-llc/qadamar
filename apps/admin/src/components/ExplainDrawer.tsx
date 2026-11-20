import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../api/client';
import type { Decision, Level, StageName, TraceStep } from '../api/types';
import { FocusTrapModal } from './FocusTrapModal';
import { DecisionBadge, ErrorAlert, LoadingState, OutcomeBadge, RelationPathChain } from './UiStates';
import { useT } from '../i18n';

export interface ExplainTarget {
  readonly subjectId: string;
  readonly resourceId: string;
  readonly action: string;
  readonly network: 'trusted' | 'untrusted';
}

/** What the decision depends on besides the target, as sent to the server. */
export interface ExplainInputs {
  readonly network: 'trusted' | 'untrusted';
  readonly sessionLevel?: Level;
  readonly makerId?: string;
  readonly priorActions: readonly string[];
}

export function explainInputs(network: 'trusted' | 'untrusted', sessionLevel: string, makerId: string, priorRaw: string): ExplainInputs {
  const level = sessionLevel !== '' && [0, 1, 2, 3].includes(Number(sessionLevel)) ? (Number(sessionLevel) as Level) : undefined;
  const maker = makerId.trim();
  const priorActions = priorRaw.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
  return { network, ...(level !== undefined ? { sessionLevel: level } : {}), ...(maker ? { makerId: maker } : {}), priorActions };
}

export function sameExplainInputs(a: ExplainInputs, b: ExplainInputs): boolean {
  return a.network === b.network && a.sessionLevel === b.sessionLevel && a.makerId === b.makerId &&
    a.priorActions.length === b.priorActions.length && a.priorActions.every((action, i) => action === b.priorActions[i]);
}

interface EvaluatedExplain {
  readonly target: ExplainTarget;
  readonly inputs: ExplainInputs;
  readonly decision: Decision;
}

/** Stage labels come from the catalogue (t.explain.stages). */
const STAGE_ORDER: readonly StageName[] = [
  'inactive', 'rbac', 'mandatory', 'delegation', 'need_to_know', 'abac', 'cbac', 'clark_wilson', 'sod', 'engine',
];

export function ExplainDrawer(props: {
  readonly target: ExplainTarget | null;
  readonly onClose: () => void;
}) {
  const t = useT();
  const x = t.explain;
  const [network, setNetwork] = useState<'trusted' | 'untrusted'>('trusted');
  const [sessionLevel, setSessionLevel] = useState<string>('');
  const [makerId, setMakerId] = useState<string>('');
  const [priorActionsRaw, setPriorActionsRaw] = useState<string>('');
  const [evaluated, setEvaluated] = useState<EvaluatedExplain | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<unknown>(null);
  const reqGenRef = useRef(0);

  const executeExplain = useCallback(
    async (
      target: ExplainTarget,
      net: 'trusted' | 'untrusted',
      sessLvl: string,
      maker: string,
      priorRaw: string,
    ) => {
      const gen = ++reqGenRef.current;
      const snapshotTarget: ExplainTarget = {
        subjectId: target.subjectId,
        resourceId: target.resourceId,
        action: target.action,
        network: net,
      };
      const inputs = explainInputs(net, sessLvl, maker, priorRaw);
      setLoading(true);
      setError(null);
      try {
        const res = await api.explain({
          subjectId: snapshotTarget.subjectId,
          resourceId: snapshotTarget.resourceId,
          action: snapshotTarget.action,
          network: snapshotTarget.network,
          ...(inputs.sessionLevel !== undefined ? { sessionLevel: inputs.sessionLevel } : {}),
          ...(inputs.makerId ? { makerId: inputs.makerId } : {}),
          ...(inputs.priorActions.length > 0 ? { priorActions: inputs.priorActions } : {}),
        });
        if (reqGenRef.current !== gen) return;
        setEvaluated({ target: snapshotTarget, inputs, decision: res });
      } catch (err) {
        if (reqGenRef.current !== gen) return;
        setEvaluated(null);
        setError(err);
      } finally {
        if (reqGenRef.current === gen) {
          setLoading(false);
        }
      }
    },
    [],
  );

  useEffect(() => {
    reqGenRef.current += 1;
    setEvaluated(null);
    setError(null);
    if (props.target) {
      setNetwork(props.target.network);
      setSessionLevel('');
      setMakerId('');
      setPriorActionsRaw('');
      void executeExplain(props.target, props.target.network, '', '', '');
    } else {
      setLoading(false);
    }
  }, [props.target, executeExplain]);

  const runExplain = useCallback(
    async (overrideNetwork?: 'trusted' | 'untrusted') => {
      if (!props.target) return;
      await executeExplain(
        props.target,
        overrideNetwork ?? network,
        sessionLevel,
        makerId,
        priorActionsRaw,
      );
    },
    [props.target, network, sessionLevel, makerId, priorActionsRaw, executeExplain],
  );

  const sameTarget =
    !!evaluated &&
    !!props.target &&
    evaluated.target.subjectId === props.target.subjectId &&
    evaluated.target.resourceId === props.target.resourceId &&
    evaluated.target.action === props.target.action;
  // a decision is shown only for the inputs it was evaluated with; edited inputs wait for Re-evaluate
  const current = sameTarget && !!evaluated && sameExplainInputs(evaluated.inputs, explainInputs(network, sessionLevel, makerId, priorActionsRaw));
  const decision = current && evaluated ? evaluated.decision : null;
  const stale = sameTarget && !current && !loading;

  const groupedTrace = new Map<StageName, TraceStep[]>();
  if (decision) {
    for (const step of decision.trace) {
      const list = groupedTrace.get(step.stage) ?? [];
      list.push(step);
      groupedTrace.set(step.stage, list);
    }
  }
  const relationPaths = decision
    ? decision.trace.filter((s) => s.path && s.path.length > 0).flatMap((s) => s.path ?? [])
    : [];

  return (
    <FocusTrapModal
      open={props.target !== null}
      onClose={props.onClose}
      titleId="explain-drawer-title"
      title={
        props.target
          ? x.titleFor(props.target.subjectId, props.target.resourceId, props.target.action)
          : x.title
      }
      variant="drawer"
    >
      {props.target ? (
        <div>
          <div className="notice-box">
            <div className="form-row" style={{ marginBottom: '8px' }}>
              <div className="form-group">
                <label htmlFor="explain-network-select">{x.network}</label>
                <select
                  id="explain-network-select"
                  value={network}
                  onChange={(e) => {
                    const nextNet = e.target.value as 'trusted' | 'untrusted';
                    setNetwork(nextNet);
                    void runExplain(nextNet);
                  }}
                >
                  <option value="trusted">{x.trusted}</option>
                  <option value="untrusted">{x.untrusted}</option>
                </select>
              </div>
              <div className="form-group">
                <label htmlFor="explain-session-level">{x.sessionLevel}</label>
                <select id="explain-session-level" value={sessionLevel} onChange={(e) => setSessionLevel(e.target.value)}>
                  <option value="">{x.defaultLevel}</option>
                  <option value="0">{t.common.levels[0]}</option>
                  <option value="1">{t.common.levels[1]}</option>
                  <option value="2">{t.common.levels[2]}</option>
                  <option value="3">{t.common.levels[3]}</option>
                </select>
              </div>
            </div>
            <div className="form-row" style={{ marginBottom: 0 }}>
              <div className="form-group">
                <label htmlFor="explain-maker-input">{x.makerId}</label>
                <input id="explain-maker-input" type="text" value={makerId} onChange={(e) => setMakerId(e.target.value)} placeholder={x.makerPlaceholder} />
              </div>
              <div className="form-group">
                <label htmlFor="explain-prior-input">{x.priorActions}</label>
                <input id="explain-prior-input" type="text" value={priorActionsRaw} onChange={(e) => setPriorActionsRaw(e.target.value)} placeholder={x.priorPlaceholder} />
              </div>
              <button type="button" className="btn btn-primary" onClick={() => void runExplain()}>
                {x.reevaluate}
              </button>
            </div>
          </div>

          <div className="sr-only" role="status">
            {loading
              ? x.evaluatingStatus
              : decision
                ? x.evaluated(!decision.decision ? t.common.deny : decision.wouldDeny.length > 0 ? t.common.wouldDeny : t.common.allow)
                : ''}
          </div>
          {loading ? <LoadingState label={x.loading} /> : null}
          {error ? <ErrorAlert error={error} contextTitle={x.failed} onRetry={() => void runExplain()} /> : null}
          {stale ? <div className="alert-warn" role="status">{x.staleInputs}</div> : null}

          {decision && evaluated && !loading ? (
            <div>
              <div className="card">
                <h3 className="card-title">
                  <span>{x.outcome}</span>
                  <DecisionBadge decision={decision.decision} wouldDeny={decision.wouldDeny} />
                </h3>
                <div className="kv-row">
                  <span className="kv-label">{x.input}</span>
                  <span className="mono">
                    {evaluated.target.subjectId} → {evaluated.target.resourceId} ({evaluated.target.action}, {evaluated.target.network})
                  </span>
                </div>
                {evaluated.inputs.sessionLevel !== undefined ? (
                  <div className="kv-row">
                    <span className="kv-label">{x.sessionLevel}</span>
                    <span>{t.common.levels[evaluated.inputs.sessionLevel]}</span>
                  </div>
                ) : null}
                {evaluated.inputs.makerId ? (
                  <div className="kv-row">
                    <span className="kv-label">{x.makerId}</span>
                    <span className="mono">{evaluated.inputs.makerId}</span>
                  </div>
                ) : null}
                {evaluated.inputs.priorActions.length > 0 ? (
                  <div className="kv-row">
                    <span className="kv-label">{x.priorActions}</span>
                    <span className="mono">{evaluated.inputs.priorActions.join(', ')}</span>
                  </div>
                ) : null}
                <div className="kv-row">
                  <span className="kv-label">{x.policyVersion}</span>
                  <span className="mono">{decision.policyVersion}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">{x.rulesMatched}</span>
                  <div className="badge-group">
                    {decision.rules.length > 0
                      ? decision.rules.map((r) => <span key={r} className="rule-tag">{r}</span>)
                      : <span className="metric-sub">{x.none}</span>}
                  </div>
                </div>
                {decision.wouldDeny.length > 0 ? (
                  <div className="kv-row">
                    <span className="kv-label">{x.wouldDenyEnforce}</span>
                    <div className="badge-group">
                      {decision.wouldDeny.map((r) => <span key={r} className="badge badge-would-deny">{r}</span>)}
                    </div>
                  </div>
                ) : null}
                {decision.reasons.length > 0 ? (
                  <div className="kv-row">
                    <span className="kv-label">{x.summary}</span>
                    <span>{decision.reasons.join('; ')}</span>
                  </div>
                ) : null}
              </div>

              <div className="card">
                <h3 className="card-title">{x.relationPath}</h3>
                {relationPaths.length > 0 ? (
                  <RelationPathChain path={relationPaths} />
                ) : (
                  <div className="metric-sub">{x.noRelation}</div>
                )}
              </div>

              <div className="card">
                <h3 className="card-title">{x.traceByStage}</h3>
                {STAGE_ORDER.map((st) => {
                  const steps = groupedTrace.get(st);
                  const label = x.stages[st];
                  if (!steps || steps.length === 0) return null;
                  return (
                    <div key={st} style={{ marginBottom: '12px' }}>
                      <h4 style={{ margin: '0 0 4px 0', fontWeight: 600, fontSize: '12px', color: 'var(--text-secondary)' }}>
                        {label}
                      </h4>
                      <div className="table-wrap">
                        <table aria-label={x.stageTrace(label)}>
                          <thead>
                            <tr><th scope="col">{x.colOutcome}</th><th scope="col">{x.colRule}</th><th scope="col">{x.colReasonPath}</th></tr>
                          </thead>
                          <tbody>
                            {steps.map((s, idx) => (
                              <tr key={`${s.rule}-${idx}`}>
                                <td><OutcomeBadge outcome={s.outcome} /></td>
                                <td>
                                  <span className="rule-tag">{s.rule}</span>
                                  {s.policyRule ? <div className="metric-sub mono">{s.kind === 'content' ? x.contentRule(s.policyRule) : s.policyRule}</div> : null}
                                </td>
                                <td>
                                  <div>{s.reason}</div>
                                  {s.path && s.path.length > 0 ? (
                                    <div style={{ marginTop: '4px' }}><RelationPathChain path={s.path} /></div>
                                  ) : null}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="card">
                <h3 className="card-title">{x.obligations}</h3>
                <div className="kv-row">
                  <span className="kv-label">{x.fieldAllowlist}</span>
                  <span className="mono">
                    {decision.obligations.fieldAllowlist ? decision.obligations.fieldAllowlist.join(', ') : x.allFields}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">{x.redacted}</span>
                  <span className="mono">{decision.obligations.redact.join(', ') || x.none}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">{x.masked}</span>
                  <span className="mono">{decision.obligations.maskClasses.join(', ') || x.none}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">{x.notifications}</span>
                  <span className="mono">{decision.obligations.notify.join(', ') || x.none}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-label">{x.decisionToken}</span>
                  <span className="mono">
                    {decision.obligations.decisionToken ? x.tokenRequired(decision.obligations.decisionToken.ttlSeconds) : x.tokenNotRequired}
                  </span>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </FocusTrapModal>
  );
}
