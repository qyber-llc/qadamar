import type { Impact, ObligationDelta } from '../api/types';
import { useT } from '../i18n';

/** KIMI-02: requests allowed before and after whose obligations changed. A loss is a broadening, shown first. */
export function ObligationChanges(props: { readonly impact: Impact }) {
  const m = useT().explain.impact;
  const lost = props.impact.obligationsLost ?? [];
  const gained = props.impact.obligationsGained ?? [];
  if (lost.length === 0 && gained.length === 0) return null;
  const list = (xs: readonly string[] | null): string => (xs === null ? m.allFields : xs.join(', '));
  const describe = (o: ObligationDelta): string[] => [
    ...(o.redact.length ? [m.redacted(o.redact.join(', '))] : []),
    ...(o.maskClasses.length ? [m.masked(o.maskClasses.join(', '))] : []),
    ...(o.notify.length ? [m.notified(o.notify.join(', '))] : []),
    ...(o.fieldAllowlist ? [m.allowlist(list(o.fieldAllowlist.before), list(o.fieldAllowlist.after))] : []),
    ...(o.decisionToken ? [m.decisionToken] : []),
  ];
  const table = (label: string, rows: typeof lost, tone: 'warn' | 'allow') => (
    <div>
      <h3 className="card-title">
        <span>{label}</span>
        <span className={`badge badge-${tone} tabular`}>{rows.length}</span>
      </h3>
      <div className="table-wrap">
        <table aria-label={label}>
          <thead>
            <tr>
              <th scope="col">{m.subject}</th>
              <th scope="col">{m.resource}</th>
              <th scope="col">{m.action}</th>
              <th scope="col">{m.obligationsChanged}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.subject}-${r.resource}-${r.action}-${i}`}>
                <td className="mono"><strong>{r.subject}</strong></td>
                <td className="mono"><strong>{r.resource}</strong></td>
                <td className="mono">{r.action}</td>
                <td>
                  <div className="badge-group">
                    {describe(r.obligations).map((d) => <span key={d} className="rule-tag">{d}</span>)}
                    {r.rules.map((rule) => <span key={rule} className="rule-tag mono">{rule}</span>)}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
  return (
    <div>
      {lost.length ? (
        <>
          <p className="notice-box" role="status">{m.obligationsLostHint}</p>
          {table(m.obligationsLost, lost, 'warn')}
        </>
      ) : null}
      {gained.length ? table(m.obligationsGained, gained, 'allow') : null}
    </div>
  );
}
