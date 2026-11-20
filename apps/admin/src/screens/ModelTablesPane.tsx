import type {
  AdminResource,
  AdminSubject,
  AdminTuple,
  ConsoleRole,
  Level,
  SchemaResponse,
} from '../api/types';
import { windowOf } from '../api/types';
import { DateText, EmptyState, LevelBadge } from '../components/UiStates';
import { formatRef, LEVEL_LABELS } from '../utils/expr';
import { canProposeChangeKind, canUseSimulator } from '../utils/permissions';
import { buildHref } from '../utils/router';
import { useT } from '../i18n';

export function ModelTablesPane(props: {
  readonly activeTab: 'subjects' | 'resources' | 'tuples';
  readonly roles: readonly ConsoleRole[];
  readonly schema: SchemaResponse | null;
  readonly subjects: readonly AdminSubject[];
  readonly resources: readonly AdminResource[];
  readonly tuples: readonly AdminTuple[];
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
}) {
  const m = useT().model.tables;
  const query = props.params.q ?? '';
  const levelFilter = props.params.level ?? '';
  const compFilter = props.params.comp ?? '';
  const statusFilter = props.params.status ?? '';
  const qLower = query.trim().toLowerCase();

  const filteredSubjects = props.subjects.filter((s) => {
    if (levelFilter !== '' && String(s.clearance) !== levelFilter) return false;
    if (compFilter !== '' && !s.compartments.includes(compFilter)) return false;
    if (statusFilter === 'active' && !s.active) return false;
    if (statusFilter === 'inactive' && s.active) return false;
    if (qLower && !`${s.id} ${s.name} ${s.unit} ${s.roles.join(' ')} ${s.integrity}`.toLowerCase().includes(qLower)) return false;
    return true;
  });

  const filteredResources = props.resources.filter((r) => {
    if (levelFilter !== '' && String(r.level) !== levelFilter) return false;
    if (compFilter !== '' && !r.compartments.includes(compFilter)) return false;
    if (statusFilter !== '' && r.status !== statusFilter) return false;
    if (qLower && !`${r.id} ${r.type} ${r.title} ${r.owner} ${r.status} ${r.contentClasses.join(' ')}`.toLowerCase().includes(qLower)) return false;
    return true;
  });

  const filteredTuples = props.tuples.filter((t) => {
    if (statusFilter === 'break_glass' && !t.breakGlass) return false;
    if (statusFilter === 'standard' && t.breakGlass) return false;
    if (qLower && !`${t.id} ${formatRef(t.object)} ${t.relation} ${formatRef(t.subject)} ${t.subjectRelation ?? ''} ${t.grantedBy ?? ''} ${t.reason ?? ''}`.toLowerCase().includes(qLower)) return false;
    return true;
  });

  return (
    <div className="card">
      <div className="sr-only" role="status">
        {m.shown(
          props.activeTab === 'subjects' ? filteredSubjects.length : props.activeTab === 'resources' ? filteredResources.length : filteredTuples.length,
          props.activeTab,
        )}
      </div>
      <div className="form-row">
        <div className="form-group">
          <label htmlFor="model-search-input">{m.search}</label>
          <input
            id="model-search-input"
            type="search"
            value={query}
            onChange={(e) => props.setParams({ q: e.target.value || undefined })}
            placeholder={m.searchPlaceholder}
          />
        </div>

        {props.activeTab !== 'tuples' ? (
          <>
            <div className="form-group">
              <label htmlFor="model-level-select">{m.level}</label>
              <select id="model-level-select" value={levelFilter} onChange={(e) => props.setParams({ level: e.target.value || undefined })}>
                <option value="">{m.allLevels}</option>
                {([0, 1, 2, 3] as Level[]).map((l) => (
                  <option key={l} value={String(l)}>{LEVEL_LABELS[l]}</option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="model-comp-select">{m.compartment}</label>
              <select id="model-comp-select" value={compFilter} onChange={(e) => props.setParams({ comp: e.target.value || undefined })}>
                <option value="">{m.allCompartments}</option>
                {(props.schema?.compartments ?? []).map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
          </>
        ) : null}

        <div className="form-group">
          <label htmlFor="model-status-select">{m.status}</label>
          <select id="model-status-select" value={statusFilter} onChange={(e) => props.setParams({ status: e.target.value || undefined })}>
            <option value="">{m.all}</option>
            {props.activeTab === 'subjects' ? (
              <>
                <option value="active">{m.active}</option>
                <option value="inactive">{m.inactive}</option>
              </>
            ) : null}
            {props.activeTab === 'resources' ? (
              <>
                <option value="open">{m.open}</option>
                <option value="closed">{m.closed}</option>
              </>
            ) : null}
            {props.activeTab === 'tuples' ? (
              <>
                <option value="standard">{m.standard}</option>
                <option value="break_glass">{m.breakGlassGrants}</option>
              </>
            ) : null}
          </select>
        </div>
      </div>

      {props.activeTab === 'subjects' ? (
        filteredSubjects.length === 0 ? (
          <EmptyState
            title={m.noSubjects}
            detail={m.noSubjectsDetail}
          />
        ) : (
          <div className="table-wrap">
            <table aria-label={m.subjects}>
              <thead>
                <tr>
                  <th scope="col">{m.subject}</th>
                  <th scope="col">{m.nameUnit}</th>
                  <th scope="col">{m.status}</th>
                  <th scope="col">{m.roles}</th>
                  <th scope="col">{m.clearance}</th>
                  <th scope="col">{m.compartments}</th>
                  <th scope="col">{m.integrity}</th>
                  <th scope="col">{m.actions}</th>
                </tr>
              </thead>
              <tbody>
                {filteredSubjects.map((s) => (
                  <tr key={`${s.type}:${s.id}`}>
                    <td className="mono"><strong>{s.id}</strong> <span className="metric-sub">({s.type})</span></td>
                    <td>{s.name} · <span className="metric-sub">{s.unit}</span></td>
                    <td><span className={s.active ? 'badge badge-allow' : 'badge badge-deny'}>{s.active ? m.active : m.inactive}</span></td>
                    <td className="mono">
                      {s.roles.join(', ') || (s.roleAssignments?.length ? '' : '—')}
                      {s.roleAssignments?.map((a) => <div key={`${a.role}${a.notBefore ?? ''}${a.notAfter ?? ''}`} className="metric-sub">{m.roleWindow(a.role, a.notBefore?.slice(0, 10) ?? '…', a.notAfter?.slice(0, 10) ?? m.noExpiry)}</div>)}
                    </td>
                    <td><LevelBadge level={s.clearance} /></td>
                    <td>
                      <div className="badge-group">
                        {s.compartments.length > 0
                          ? s.compartments.map((c) => <span key={c} className="badge">{c}</span>)
                          : <span className="metric-sub">{m.none}</span>}
                      </div>
                    </td>
                    <td className="mono">{s.integrity}{s.delegatedBy ? m.delegatedBy(s.delegatedBy) : ''}</td>
                    <td>
                      <div className="badge-group">
                        {canUseSimulator(props.roles) ? (
                          <a href={buildHref('simulator', { mode: 'what-can', subjectId: s.id })} className="btn btn-sm" aria-label={m.simulateId(s.id)}>{m.simulate}</a>
                        ) : null}
                        {canProposeChangeKind(props.roles, 'update_subject') ? (
                          <a href={buildHref('simulator', { mode: 'impact', kind: 'update_subject', subjectId: s.id })} className="btn btn-sm" aria-label={m.editId(s.id)}>{m.edit}</a>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : null}

      {props.activeTab === 'resources' ? (
        filteredResources.length === 0 ? (
          <EmptyState
            title={m.noResources}
            detail={m.noResourcesDetail}
          />
        ) : (
          <div className="table-wrap">
            <table aria-label={m.resources}>
              <thead>
                <tr>
                  <th scope="col">{m.resource}</th>
                  <th scope="col">{m.resourceTitle}</th>
                  <th scope="col">{m.status}</th>
                  <th scope="col">{m.level}</th>
                  <th scope="col">{m.compartments}</th>
                  <th scope="col">{m.integrityOwner}</th>
                  <th scope="col">{m.contentClasses}</th>
                  <th scope="col">{m.actions}</th>
                </tr>
              </thead>
              <tbody>
                {filteredResources.map((r) => (
                  <tr key={`${r.type}:${r.id}`}>
                    <td className="mono"><strong>{r.id}</strong> <span className="metric-sub">({r.type})</span></td>
                    <td>{r.title}</td>
                    <td className="mono">{r.status}</td>
                    <td><LevelBadge level={r.level} /></td>
                    <td>
                      <div className="badge-group">
                        {r.compartments.length > 0
                          ? r.compartments.map((c) => <span key={c} className="badge">{c}</span>)
                          : <span className="metric-sub">{m.none}</span>}
                      </div>
                    </td>
                    <td className="mono">{r.integrity} · {r.owner}</td>
                    <td className="mono">{r.contentClasses.join(', ') || '—'}</td>
                    <td>
                      <div className="badge-group">
                        {canUseSimulator(props.roles) ? (
                          <a href={buildHref('simulator', { mode: 'who-can', resourceId: r.id })} className="btn btn-sm" aria-label={m.simulateId(r.id)}>{m.simulate}</a>
                        ) : null}
                        {canProposeChangeKind(props.roles, 'update_resource') ? (
                          <a href={buildHref('simulator', { mode: 'impact', kind: 'update_resource', resourceId: r.id })} className="btn btn-sm" aria-label={m.editId(r.id)}>{m.edit}</a>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : null}

      {props.activeTab === 'tuples' ? (
        filteredTuples.length === 0 ? (
          <EmptyState
            title={m.noTuples}
            detail={m.noTuplesDetail}
            actionLabel={canProposeChangeKind(props.roles, 'add_tuple') ? m.proposeGrant : undefined}
            actionHref={canProposeChangeKind(props.roles, 'add_tuple') ? buildHref('simulator', { mode: 'impact', kind: 'add_tuple' }) : undefined}
          />
        ) : (
          <div className="table-wrap">
            <table aria-label={m.tuples}>
              <thead>
                <tr>
                  <th scope="col">{m.id}</th>
                  <th scope="col">{m.relationship}</th>
                  <th scope="col">{m.validUntil}</th>
                  <th scope="col">{m.grantedBy}</th>
                  <th scope="col">{m.actions}</th>
                </tr>
              </thead>
              <tbody>
                {filteredTuples.map((t) => (
                  <tr key={t.id}>
                    <td className="mono">
                      <strong>{t.id}</strong>
                      {t.breakGlass ? <span className="badge badge-warn" style={{ marginInlineStart: '6px' }}>{m.breakGlass}</span> : null}
                    </td>
                    <td>
                      <span className="hop-chain">
                        <span className="hop-item mono">
                          {formatRef(t.subject)}{t.subjectRelation ? `#${t.subjectRelation}` : ''}
                        </span>
                        <span className="hop-arrow" aria-hidden="true">→</span>
                        <span className="hop-item">{t.relation}</span>
                        <span className="hop-arrow" aria-hidden="true">→</span>
                        <span className="hop-item mono">{formatRef(t.object)}</span>
                      </span>
                    </td>
                    <td>
                      {windowOf(t).to ? <DateText iso={windowOf(t).to!} /> : <span className="metric-sub">{m.noExpiry}</span>}
                    </td>
                    <td>{t.grantedBy ? <span className="mono">{t.grantedBy}: </span> : null}{t.reason ?? '—'}</td>
                    <td>
                      {canProposeChangeKind(props.roles, 'remove_tuple') ? (
                        <a href={buildHref('simulator', { mode: 'impact', kind: 'remove_tuple', tupleId: t.id })} className="btn btn-sm btn-danger" aria-label={m.revokeId(t.id)}>{m.revoke}</a>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : null}
    </div>
  );
}
