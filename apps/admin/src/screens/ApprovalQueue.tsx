import type { ChangeRecord, SessionUser } from '../api/types';
import { DateText } from '../components/UiStates';
import { useT } from '../i18n';
import { awaitsUser, type QueueItem } from '../utils/inbox';
import { buildHref } from '../utils/router';
import { ChangeLevel, changeLabel, statusLabel } from './approvalLabels';

/** The Approvals queue: change rows (selectable in list mode) and break-glass rows that link to their own screen. */
export function ApprovalQueue(props: {
  readonly items: readonly QueueItem[];
  readonly user: SessionUser;
  readonly activeId: string | undefined;
  readonly cursor: string | null;
  readonly listMode: boolean;
  readonly selected: ReadonlySet<string>;
  readonly failures: ReadonlyMap<string, string>;
  readonly snoozedUntil: ReadonlyMap<string, string>;
  readonly busy: boolean;
  readonly rowRef: (key: string, el: HTMLElement | null) => void;
  readonly onOpen: (change: ChangeRecord) => void;
  readonly onCursor: (key: string) => void;
  readonly onToggle: (id: string) => void;
  readonly onSnooze: (key: string) => void;
  readonly onUnsnooze: (key: string) => void;
}) {
  const t = useT();
  const a = t.approvals;
  const snoozeCell = (key: string) => {
    const until = props.snoozedUntil.get(key);
    return until ? (
      <span className="operations-meta">
        {a.snoozedUntil(until)}{' '}
        <button type="button" className="btn btn-sm" disabled={props.busy} onClick={(e) => { e.stopPropagation(); props.onUnsnooze(key); }}>{a.unsnooze}</button>
      </span>
    ) : null;
  };
  return (
    <div className="table-wrap operations-change-queue" tabIndex={0} role="region" aria-label={a.register}>
      <table>
        <thead>
          <tr>
            {props.listMode ? <th className="operations-select-col"><span className="sr-only">{a.colSelect}</span></th> : null}
            <th className="operations-change-col">{a.colChange}</th>
            <th>{a.colMaker}</th>
            <th>{a.colCreated}</th>
            <th>{a.colImpact}</th>
            <th>{a.colStatus}</th>
          </tr>
        </thead>
        <tbody>
          {props.items.map((item) => {
            const atCursor = props.cursor === item.key;
            if (item.kind === 'emergency') {
              const e = item.emergency;
              const label = a.emergencyRow(e.subjectId, e.resourceId);
              return (
                <tr key={item.key} className={atCursor ? 'clickable-row selected-row' : 'clickable-row'} onClick={() => props.onCursor(item.key)}>
                  {props.listMode ? <td /> : null}
                  <td>
                    <a ref={(el) => props.rowRef(item.key, el)} href={buildHref('break-glass')} className="row-action-btn" aria-current={atCursor ? 'true' : undefined}
                      title={a.openBreakGlass} onFocus={() => props.onCursor(item.key)}>{label}</a>
                  </td>
                  <td className="operations-meta" title={e.openedBy}>{e.openedBy === props.user.id ? t.common.you : e.openedBy}</td>
                  <td className="operations-meta"><DateText iso={e.openedAt} /></td>
                  <td><span className="badge badge-warn">{a.emergencyBadge}</span></td>
                  <td>
                    {snoozeCell(item.key) ?? (
                      <span className="operations-meta">
                        {a.emergencyStatus}{' '}
                        <button type="button" className="btn btn-sm" disabled={props.busy} aria-label={a.snoozeItem(label)}
                          onClick={(ev) => { ev.stopPropagation(); props.onSnooze(item.key); }}>{a.snooze}</button>
                      </span>
                    )}
                  </td>
                </tr>
              );
            }
            const c = item.change;
            const label = changeLabel(c);
            const selectable = props.listMode && awaitsUser(c, props.user);
            const failure = props.failures.get(c.id);
            const rowClass = ['clickable-row', props.activeId === c.id || atCursor ? 'selected-row' : ''].join(' ').trim();
            return (
              <tr key={item.key} className={rowClass} onClick={() => props.onOpen(c)}>
                {props.listMode ? (
                  <td onClick={(e) => e.stopPropagation()}>
                    {selectable ? (
                      <input type="checkbox" checked={props.selected.has(c.id)} disabled={props.busy} aria-label={a.selectRow(label)}
                        onChange={() => props.onToggle(c.id)} />
                    ) : null}
                  </td>
                ) : null}
                <td>
                  <button
                    ref={(el) => props.rowRef(item.key, el)}
                    type="button"
                    className="row-action-btn"
                    aria-pressed={props.activeId === c.id}
                    aria-label={a.inspect(label)}
                    title={`${label} · ${c.id}`}
                    onFocus={() => props.onCursor(item.key)}
                    onClick={(e) => { e.stopPropagation(); props.onOpen(c); }}
                  >
                    {label}
                  </button>
                  <ChangeLevel change={c} />
                  {failure ? <div className="operations-meta" role="note">{a.bulkItemFailed(failure)}</div> : null}
                </td>
                <td className="operations-meta" title={c.makerId}>{c.makerId === props.user.id ? t.common.you : c.makerId}</td>
                <td className="operations-meta"><DateText iso={c.createdAt} /></td>
                <td>
                  {c.broadens ? (
                    <span className="badge badge-warn">{a.broadens(c.impact.gained.length + (c.impact.obligationsLost?.length ?? 0))}</span>
                  ) : (
                    <span className="badge">{a.narrows}</span>
                  )}
                </td>
                <td>
                  {snoozeCell(item.key) ?? (
                    <span className={c.status === 'applied' ? 'badge badge-allow' : c.status === 'rejected' ? 'badge badge-deny' : 'badge badge-warn'}>
                      {statusLabel(c.status)}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
