import type { WhatCanItem, WhoCanItem } from '../api/types';
import type { ExplainTarget } from '../components/ExplainDrawer';
import {
  DecisionBadge,
  EmptyState,
  LevelBadge,
  RelationPathChain,
} from '../components/UiStates';
import { useT } from '../i18n';

export interface WhatCanSnapshot {
  readonly subjectId: string;
  readonly action: string;
  readonly network: 'trusted' | 'untrusted';
  readonly items: readonly WhatCanItem[];
}

export interface WhoCanSnapshot {
  readonly resourceId: string;
  readonly action: string;
  readonly network: 'trusted' | 'untrusted';
  readonly items: readonly WhoCanItem[];
}

export function WhatCanResultsTable(props: {
  readonly snapshot: WhatCanSnapshot;
  readonly onExplain: (target: ExplainTarget) => void;
}) {
  const { snapshot, onExplain } = props;
  const m = useT().simulator;
  if (snapshot.items.length === 0) {
    return <EmptyState title={m.noResources} />;
  }

  return (
    <div className="table-wrap" aria-live="polite">
      <table>
        <thead>
          <tr>
            <th>{m.resource}</th>
            <th>{m.level}</th>
            <th>{m.decision}</th>
            <th>{m.rules}</th>
            <th>{m.pathAndReasons}</th>
            <th>{m.obligations}</th>
            <th>{m.explain}</th>
          </tr>
        </thead>
        <tbody>
          {snapshot.items.map((item) => {
            const target: ExplainTarget = {
              subjectId: snapshot.subjectId,
              resourceId: item.resource.id,
              action: snapshot.action,
              network: snapshot.network,
            };
            return (
              <tr
                key={`${item.resource.type}:${item.resource.id}`}
                className="clickable-row"
                onClick={() => onExplain(target)}
              >
                <td>
                  <strong className="mono">{item.resource.id}</strong>{' '}
                  <span className="metric-sub">({item.resource.type})</span>
                  <div className="metric-sub">{item.resource.title}</div>
                </td>
                <td><LevelBadge level={item.resource.level} /></td>
                <td><DecisionBadge decision={item.decision} wouldDeny={item.wouldDeny} /></td>
                <td>
                  <div className="badge-group">
                    {item.rules.map((r) => (
                      <span key={r} className="rule-tag">{r}</span>
                    ))}
                  </div>
                </td>
                <td>
                  {item.path && item.path.length > 0 ? <RelationPathChain path={item.path} /> : null}
                  {item.reasons.length > 0 ? <div className="metric-sub">{item.reasons.join('; ')}</div> : null}
                </td>
                <td className="mono">
                  {item.obligations.redact.length > 0 ? `${m.chips.redact} ${item.obligations.redact.join(', ')} ` : ''}
                  {item.obligations.maskClasses.length > 0 ? `${m.chips.mask} ${item.obligations.maskClasses.join(', ')} ` : ''}
                  {item.obligations.notify.length > 0 ? `${m.chips.notify} ${item.obligations.notify.join(', ')} ` : ''}
                  {item.obligations.decisionToken ? `${m.chips.decisionToken} ` : ''}
                  {item.obligations.redact.length === 0 &&
                  item.obligations.maskClasses.length === 0 &&
                  item.obligations.notify.length === 0 &&
                  !item.obligations.decisionToken
                    ? '—'
                    : ''}
                </td>
                <td>
                  <button
                    type="button"
                    className="btn btn-sm"
                    aria-label={m.explainAria(snapshot.subjectId, snapshot.action, item.resource.id)}
                    onClick={(e) => {
                      e.stopPropagation();
                      onExplain(target);
                    }}
                  >
                    {m.explain}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function WhoCanResultsTable(props: {
  readonly snapshot: WhoCanSnapshot;
  readonly onExplain: (target: ExplainTarget) => void;
}) {
  const { snapshot, onExplain } = props;
  const m = useT().simulator;
  if (snapshot.items.length === 0) {
    return <EmptyState title={m.noSubjects} />;
  }

  return (
    <div className="table-wrap" aria-live="polite">
      <table>
        <thead>
          <tr>
            <th>{m.subject}</th>
            <th>{m.decision}</th>
            <th>{m.rules}</th>
            <th>{m.pathAndReasons}</th>
            <th>{m.explain}</th>
          </tr>
        </thead>
        <tbody>
          {snapshot.items.map((item) => {
            const target: ExplainTarget = {
              subjectId: item.subject.id,
              resourceId: snapshot.resourceId,
              action: snapshot.action,
              network: snapshot.network,
            };
            return (
              <tr
                key={`${item.subject.type}:${item.subject.id}`}
                className="clickable-row"
                onClick={() => onExplain(target)}
              >
                <td>
                  <strong>{item.subject.name}</strong>{' '}
                  <span className="mono metric-sub">({item.subject.id})</span>
                </td>
                <td><DecisionBadge decision={item.decision} wouldDeny={item.wouldDeny} /></td>
                <td>
                  <div className="badge-group">
                    {item.rules.map((r) => (
                      <span key={r} className="rule-tag">{r}</span>
                    ))}
                  </div>
                </td>
                <td>
                  {item.path && item.path.length > 0 ? <RelationPathChain path={item.path} /> : null}
                  {item.reasons.length > 0 ? <div className="metric-sub">{item.reasons.join('; ')}</div> : null}
                </td>
                <td>
                  <button
                    type="button"
                    className="btn btn-sm"
                    aria-label={m.explainAria(item.subject.id, snapshot.action, snapshot.resourceId)}
                    onClick={(e) => {
                      e.stopPropagation();
                      onExplain(target);
                    }}
                  >
                    {m.explain}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
