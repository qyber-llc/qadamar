import type { Context, ImpactContextAnalysis, ImpactEntry } from '../api/types';
import { useT } from '../i18n';

function contextText(context: Context, missing: string, labels: ReturnType<typeof useT>['explain']['impact']['context']): string {
  const value = (input: unknown): string => input === undefined ? missing : String(input);
  return [
    labels.network(context.network),
    `${labels.country}: ${value(context.country)}`,
    `${labels.ip}: ${value(context.ip)}`,
    `${labels.device}: ${context.device ? labels.posture(context.device.managed, context.device.compliant) : missing}`,
    `${labels.now}: ${context.now}`,
    `${labels.mfa}: ${value(context.mfaTime)}`,
    `${labels.auth}: ${value(context.authTime)}`,
    `${labels.methods}: ${context.authMethods === undefined ? missing : `[${context.authMethods.join(', ')}]`}`,
    `${labels.risk}: ${value(context.riskScore)}`,
    context.sessionExpired === undefined ? '' : labels.session(context.sessionExpired),
  ].filter(Boolean).join(' · ');
}

function ClassRows({ gained, lost, action, subject, resource, direction }: {
  readonly gained: readonly ImpactEntry[];
  readonly lost: readonly ImpactEntry[];
  readonly action: string;
  readonly subject: string;
  readonly resource: string;
  readonly direction: (gained: boolean) => string;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th scope="col">{direction(true)} / {direction(false)}</th><th scope="col">{subject}</th><th scope="col">{resource}</th><th scope="col">{action}</th></tr></thead>
        <tbody>
          {[...gained.map((row) => ({ row, gained: true })), ...lost.map((row) => ({ row, gained: false }))].map(({ row, gained }) => (
            <tr key={`${gained}-${row.subject}-${row.resource}-${row.action}`}>
              <td><span className={`badge ${gained ? 'badge-allow' : 'badge-deny'}`}>{direction(gained)}</span></td>
              <td className="mono">{row.subject}</td><td className="mono">{row.resource}</td><td className="mono">{row.action}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ContextImpact({ analysis }: { readonly analysis: ImpactContextAnalysis }) {
  const m = useT().explain.impact;
  return (
    <section className="operations-evidence" aria-label={m.context.title}>
      <h3 className="card-title">{m.context.title}</h3>
      <p className="operations-meta">{m.context.summary(analysis.evaluatedClasses, analysis.classes.length)}</p>
      {(analysis.incomplete ?? analysis.truncated) ? <p className="alert-warn" role="status">{analysis.truncated ? m.context.truncated(analysis.cap) : m.context.incomplete}</p> : null}
      {analysis.unsupported?.length ? <p className="operations-meta">{analysis.unsupported.join('; ')}</p> : null}
      {analysis.classes.map((item) => (
        <details key={JSON.stringify(item.context)}>
          <summary>
            <span className="badge badge-allow">{m.gainedCount(item.gained.length)}</span>{' '}
            <span className="badge badge-deny">{m.lostCount(item.lost.length)}</span>
            {item.obligationsLost.length ? <> <span className="badge badge-warn">{m.obligationsLostCount(item.obligationsLost.length)}</span></> : null}
          </summary>
          <p className="operations-meta">{contextText(item.context, m.context.missing, m.context)}</p>
          <ClassRows gained={item.gained} lost={item.lost} action={m.action} subject={m.subject} resource={m.resource} direction={m.context.direction} />
        </details>
      ))}
    </section>
  );
}
