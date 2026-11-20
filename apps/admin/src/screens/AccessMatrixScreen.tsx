import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import type { MatrixCell, MatrixLayer, MatrixResponse } from '../api/types';
import type { ExplainTarget } from '../components/ExplainDrawer';
import { ErrorAlert, LevelBadge, LoadingState } from '../components/UiStates';
import '../styles/matrix.css';
import { msgs, useT } from '../i18n';

/** The layers in the engine's order (docs/ARCHITECTURE.md §3.2): each one can only narrow what the previous allowed.
 *  Labels and hints come from the catalogue (t.matrix.layers). */
const LAYER_MODEL: Readonly<Record<MatrixLayer, string>> = {
  rights: 'RBAC', clearance: 'MAC', needToKnow: 'ReBAC', conditions: 'ABAC', content: 'ABAC · content', context: 'CBAC', controls: 'SoD · CW',
};
const ORDER = Object.keys(LAYER_MODEL) as MatrixLayer[];

type Lens = 'all' | MatrixLayer;
type LayerCell = NonNullable<MatrixCell['layers']>[MatrixLayer];

function word(rule: string | undefined): string {
  if (!rule) return '—';
  const bare = rule.replace(/^DELEGATION\./, '');
  // Plain words for the rules that come up most; anything else shows the tail of its rule id.
  const known = (msgs().matrix.ruleWords as Readonly<Record<string, string>>)[bare];
  if (known) return known;
  return (bare.split('.').at(-1) ?? bare).replace(/_/g, ' ').toLowerCase();
}

/** The rule that decided this layer: the blocking one for a block, else the one that granted or conditioned it. */
function layerWord(cell: LayerCell): string {
  if (cell.o === 'none') return '—';
  if (cell.o === 'obligation') return word(cell.rules.find((r) => r !== 'NTK.knows') ?? cell.rules[0]);
  const pick = cell.o === 'deny' ? cell.rules.find((r) => /NO_|NOT_|INACTIVE|SELF|UNKNOWN|UNCERTIFIED|BLP|COMP|NET|BIBA|ABAC\.|CBAC\.|SOD\./.test(r)) : undefined;
  return word(pick ?? cell.rules[0]);
}

/** How many pairs survive each layer in turn: the funnel of access. */
function funnel(cells: readonly MatrixCell[]): number[] {
  const live = cells.filter((c) => c.applicable && c.layers);
  return ORDER.map((_, i) => live.filter((c) => ORDER.slice(0, i + 1).every((l) => c.layers?.[l].o !== 'deny')).length);
}

export function AccessMatrixScreen(props: {
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
  readonly onExplain: (target: ExplainTarget) => void;
}) {
  const t = useT();
  const m = t.matrix;
  const action = props.params.action ?? 'read';
  const network: 'trusted' | 'untrusted' = props.params.net === 'untrusted' ? 'untrusted' : 'trusted';
  const lensParam = props.params.lens;
  const lens: Lens = lensParam !== undefined && (ORDER as string[]).includes(lensParam) ? (lensParam as MatrixLayer) : 'all';

  const [data, setData] = useState<MatrixResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [hover, setHover] = useState<{ readonly s: string; readonly r: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.simulateMatrix({ action, network }));
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [action, network]);

  useEffect(() => { void load(); }, [load]);

  const byKey = useMemo(() => new Map((data?.cells ?? []).map((c) => [`${c.subject}|${c.resource}`, c])), [data]);
  const steps = useMemo(() => (data ? funnel(data.cells) : []), [data]);
  const applicable = data ? data.cells.filter((c) => c.applicable).length : 0;
  const granted = data ? data.cells.filter((c) => c.decision).length : 0;

  return (
    <section aria-labelledby="title-matrix" className="mx">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-matrix">{m.title}</h1>
          <p className="screen-subtitle">
            {m.subtitle}
          </p>
        </div>
        <div className="mx-controls">
          <label className="mx-field">
            <span>{m.action}</span>
            <select value={action} onChange={(e) => props.setParams({ action: e.target.value })}>
              {(data?.actions ?? [action]).map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
          </label>
          <div className="segmented-control" role="group" aria-label={m.network}>
            {(['trusted', 'untrusted'] as const).map((n) => (
              <button key={n} type="button" className="segmented-btn" aria-pressed={network === n}
                onClick={() => props.setParams({ net: n === 'trusted' ? undefined : n })}>
                {n === 'trusted' ? m.trusted : m.untrusted}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading && !data ? <LoadingState label={m.loading} /> : null}
      {error ? <ErrorAlert error={error} contextTitle={m.loadError} onRetry={() => void load()} /> : null}

      {data ? (
        <>
          <ol className="mx-funnel" aria-label={m.funnel}>
            <li>
              <button type="button" className="mx-step mx-step-all" aria-pressed={lens === 'all'} onClick={() => props.setParams({ lens: undefined })}>
                <span className="mx-step-model">{m.allLayers}</span>
                <b>{applicable}</b>
                <span className="mx-step-label">{m.pairsWhere(action)}</span>
              </button>
            </li>
            {ORDER.map((l, i) => (
              <li key={l}>
                <button type="button" className="mx-step" aria-pressed={lens === l} title={m.layers[l].hint}
                  onClick={() => props.setParams({ lens: l })}>
                  <span className="mx-step-model">{i + 1} · {LAYER_MODEL[l]}</span>
                  <b>{steps[i]}</b>
                  <span className="mx-step-label">{m.layers[l].label}</span>
                  <span className="mx-step-bar" aria-hidden="true"><i style={{ width: `${applicable ? (100 * (steps[i] ?? 0)) / applicable : 0}%` }} /></span>
                </button>
              </li>
            ))}
            <li className="mx-granted">
              <span className="mx-step-model">{m.granted}</span>
              <b>{granted}</b>
              <span className="mx-step-label">{m.of(applicable)}</span>
            </li>
          </ol>

          <p className="mx-lens-hint">
            {lens === 'all'
              ? m.hintAll
              : `${m.layers[lens].label} (${LAYER_MODEL[lens]}): ${m.layers[lens].hint}`}
          </p>

          <div className="mx-scroll" data-lens={lens}>
            <table className="mx-table">
              <caption className="sr-only">{m.caption(action, m.networkWord[network])}</caption>
              <thead>
                <tr>
                  <th scope="col" className="mx-corner">{m.corner}</th>
                  {data.resources.map((r) => (
                    <th key={r.id} scope="col" className={hover?.r === r.id ? 'mx-col is-hot' : 'mx-col'}>
                      <span className="mx-res-id">{r.id}</span>
                      <span className="mx-res-title">{r.title}</span>
                      <span className="mx-tags">
                        <LevelBadge level={r.level} />
                        {r.compartments.map((c) => <span key={c} className="mx-tag mx-tag-comp">{c}</span>)}
                        {r.contentClasses.map((c) => <span key={c} className="mx-tag mx-tag-content">{c}</span>)}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.subjects.map((s) => (
                  <tr key={s.id} className={hover?.s === s.id ? 'is-hot' : undefined}>
                    <th scope="row" className="mx-row">
                      <span className="mx-person">{s.name}{s.type === 'agent' ? <span className="mx-tag">{m.aiAgent}</span> : null}</span>
                      <span className="mx-roles">{s.roles.join(', ')}</span>
                      {s.roleAssignments?.map((a) => <span key={`${a.role}${a.notBefore ?? ''}${a.notAfter ?? ''}`} className="mx-roles">{t.model.tables.roleWindow(a.role, a.notBefore?.slice(0, 10) ?? '…', a.notAfter?.slice(0, 10) ?? t.model.tables.noExpiry)}</span>)}
                      <span className="mx-tags">
                        <LevelBadge level={s.clearance} />
                        {s.compartments.map((c) => <span key={c} className="mx-tag mx-tag-comp">{c}</span>)}
                      </span>
                    </th>
                    {data.resources.map((r) => {
                      const c = byKey.get(`${s.id}|${r.id}`);
                      return (
                        <td key={r.id} onMouseEnter={() => setHover({ s: s.id, r: r.id })} onMouseLeave={() => setHover(null)}>
                          {c ? <Cell cell={c} lens={lens} who={s.name} what={r.id}
                            onOpen={() => props.onExplain({ subjectId: s.id, resourceId: r.id, action, network })} /> : null}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <ul className="mx-legend" aria-label={m.legend}>
            <li><i className="o-pass" /> {m.legendPass}</li>
            <li><i className="o-obligation" /> {m.legendObligation}</li>
            <li><i className="o-would_deny" /> {m.legendWouldDeny}</li>
            <li><i className="o-deny" /> {m.legendDeny}</li>
            <li><i className="o-none" /> {m.legendNone}</li>
          </ul>
        </>
      ) : null}
    </section>
  );
}

function Cell(props: { readonly cell: MatrixCell; readonly lens: Lens; readonly who: string; readonly what: string; readonly onOpen: () => void }) {
  const m = useT().matrix;
  const { cell, lens } = props;
  const layers = cell.layers;
  if (!cell.applicable || !layers) {
    return <span className="mx-na" title={m.naTitle}>{m.na}</span>;
  }
  const masked = cell.decision === true && ((cell.obligations?.maskClasses.length ?? 0) > 0 || (cell.obligations?.redact.length ?? 0) > 0);
  const verdict = cell.decision ? (masked ? m.verdictMasked : m.verdictGranted) : m.verdictDenied;

  if (lens !== 'all') {
    const one = layers[lens];
    return (
      <button type="button" className={`mx-cell mx-one o-${one.o}`} onClick={props.onOpen} title={one.reason ?? ''}
        aria-label={m.cellOne(props.who, props.what, m.layers[lens].label, m.outcomes[one.o], one.reason ?? '', verdict)}>
        {layerWord(one)}
      </button>
    );
  }
  const summary = ORDER.map((l) => `${m.layers[l].label} ${m.outcomes[layers[l].o]}`).join(', ');
  const tip = ORDER.filter((l) => layers[l].o !== 'none').map((l) => `${m.layers[l].label}: ${layers[l].reason ?? layerWord(layers[l])}`).join('\n');
  return (
    <button type="button" className={`mx-cell ${cell.decision ? (masked ? 'v-partial' : 'v-allow') : 'v-deny'}`} onClick={props.onOpen}
      title={tip} aria-label={m.cellAll(props.who, props.what, verdict, summary)}>
      <span className="mx-stack" aria-hidden="true">
        {ORDER.map((l) => <i key={l} className={`o-${layers[l].o}`} />)}
      </span>
      <span className="mx-verdict" aria-hidden="true">{cell.decision ? (masked ? '◐' : '✓') : '✕'}</span>
    </button>
  );
}
