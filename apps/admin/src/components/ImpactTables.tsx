import type { Impact } from '../api/types';
import type { ExplainTarget } from './ExplainDrawer';
import { EmptyState } from './UiStates';
import { ObligationChanges } from './ObligationChanges';
import { ContextImpact } from './ContextImpact';
import { useT } from '../i18n';

export function ImpactTables(props: {
  readonly impact: Impact;
  readonly network?: 'trusted' | 'untrusted';
  readonly onExplain?: (target: ExplainTarget) => void;
}) {
  const t = useT();
  const m = t.explain.impact;
  const net = props.network ?? 'trusted';

  return (
    <div>
      <div className="notice-box" role="status" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
        <div>
          {m.evaluated} <strong
            className="mono"
            title={props.impact.analysis ? t.common.affectedCells(props.impact.analysis.affectedCells, props.impact.analysis.reasons.join('; ')) : undefined}
          >{props.impact.evaluated}</strong> {m.accessPairs}
          {props.impact.policyVersionBefore ? (
            <span className="metric-sub">
              {' '}({t.common.versions(props.impact.policyVersionBefore.slice(0, 12), (props.impact.policyVersionAfter || m.candidate).slice(0, 12))})
            </span>
          ) : null}
        </div>
        <div className="badge-group">
          <span className="badge badge-allow">{m.gainedCount(props.impact.gained.length)}</span>
          <span className="badge badge-deny">{m.lostCount(props.impact.lost.length)}</span>
          {props.impact.obligationsLost?.length ? <span className="badge badge-warn">{m.obligationsLostCount(props.impact.obligationsLost.length)}</span> : null}
        </div>
      </div>

      <div className="grid-2">
        <div>
          <h3 className="card-title">
            <span>{m.gained}</span>
            <span className="badge badge-allow">+{props.impact.gained.length}</span>
          </h3>
          {props.impact.gained.length === 0 ? (
            <EmptyState title={m.noGained} />
          ) : (
            <div className="table-wrap">
              <table aria-label={m.gained}>
                <thead>
                  <tr>
                    <th scope="col">{m.subject}</th>
                    <th scope="col">{m.resource}</th>
                    <th scope="col">{m.action}</th>
                    <th scope="col">{m.previouslyDenied}</th>
                    {props.onExplain ? <th scope="col">{m.explain}</th> : null}
                  </tr>
                </thead>
                <tbody>
                  {props.impact.gained.map((g, i) => {
                    const target: ExplainTarget = {
                      subjectId: g.subject,
                      resourceId: g.resource,
                      action: g.action,
                      network: net,
                    };
                    return (
                      <tr
                        key={`${g.subject}-${g.resource}-${g.action}-${i}`}
                        className={props.onExplain ? 'clickable-row' : undefined}
                        onClick={() => props.onExplain?.(target)}
                      >
                        <td className="mono"><strong>{g.subject}</strong></td>
                        <td className="mono"><strong>{g.resource}</strong></td>
                        <td className="mono">{g.action}</td>
                        <td>
                          <div className="badge-group">
                            {g.rules.map((r) => (
                              <span key={r} className="rule-tag">{r}</span>
                            ))}
                          </div>
                        </td>
                        {props.onExplain ? (
                          <td>
                            <button
                              type="button"
                              className="btn btn-sm"
                              aria-label={m.explainRow(g.subject, g.action, g.resource)}
                              onClick={(e) => {
                                e.stopPropagation();
                                props.onExplain?.(target);
                              }}
                            >
                              {m.explain}
                            </button>
                          </td>
                        ) : null}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div>
          <h3 className="card-title">
            <span>{m.lost}</span>
            <span className="badge badge-deny">−{props.impact.lost.length}</span>
          </h3>
          {props.impact.lost.length === 0 ? (
            <EmptyState title={m.noLost} />
          ) : (
            <div className="table-wrap">
              <table aria-label={m.lost}>
                <thead>
                  <tr>
                    <th scope="col">{m.subject}</th>
                    <th scope="col">{m.resource}</th>
                    <th scope="col">{m.action}</th>
                    <th scope="col">{m.newlyDenied}</th>
                    {props.onExplain ? <th scope="col">{m.explain}</th> : null}
                  </tr>
                </thead>
                <tbody>
                  {props.impact.lost.map((l, i) => {
                    const target: ExplainTarget = {
                      subjectId: l.subject,
                      resourceId: l.resource,
                      action: l.action,
                      network: net,
                    };
                    return (
                      <tr
                        key={`${l.subject}-${l.resource}-${l.action}-${i}`}
                        className={props.onExplain ? 'clickable-row' : undefined}
                        onClick={() => props.onExplain?.(target)}
                      >
                        <td className="mono"><strong>{l.subject}</strong></td>
                        <td className="mono"><strong>{l.resource}</strong></td>
                        <td className="mono">{l.action}</td>
                        <td>
                          <div className="badge-group">
                            {l.rules.map((r) => (
                              <span key={r} className="rule-tag">{r}</span>
                            ))}
                          </div>
                        </td>
                        {props.onExplain ? (
                          <td>
                            <button
                              type="button"
                              className="btn btn-sm"
                              aria-label={m.explainRow(l.subject, l.action, l.resource)}
                              onClick={(e) => {
                                e.stopPropagation();
                                props.onExplain?.(target);
                              }}
                            >
                              {m.explain}
                            </button>
                          </td>
                        ) : null}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
      <ObligationChanges impact={props.impact} />
      {props.impact.contextAnalysis ? <ContextImpact analysis={props.impact.contextAnalysis} /> : null}
    </div>
  );
}
