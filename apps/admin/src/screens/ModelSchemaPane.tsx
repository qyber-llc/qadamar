import type { SchemaResponse } from '../api/types';
import { LevelBadge } from '../components/UiStates';
import { formatRelationDef } from '../utils/expr';
import { useT } from '../i18n';

export function ModelSchemaPane(props: { readonly schema: SchemaResponse }) {
  const { schema } = props;
  const m = useT().model.schema;

  return (
    <div>
      <div className="grid-2">
        <div className="card">
          <h2 className="card-title">
            <span>{m.levels}</span>
            <span className="badge badge-lock">Bell-LaPadula</span>
          </h2>
          <div className="table-wrap">
            <table aria-label={m.levelsTable}>
              <thead>
                <tr>
                  <th scope="col">{m.level}</th>
                  <th scope="col">{m.network}</th>
                  <th scope="col">{m.mandatoryRule}</th>
                </tr>
              </thead>
              <tbody>
                {([0, 1, 2, 3] as const).map((lvl) => {
                  const trustedOnly = lvl > schema.mandatory.untrustedNetworkMaxLevel;
                  return (
                    <tr key={lvl}>
                      <td>
                        <LevelBadge level={lvl} />
                      </td>
                      <td>
                        {trustedOnly ? (
                          <span className="badge badge-warn">{m.trustedOnly}</span>
                        ) : (
                          <span className="badge">{m.anyNetwork}</span>
                        )}
                      </td>
                      <td>
                        {m.noReadUp}<span className="rule-tag">BLP.NO_READ_UP</span>{m.noWriteDown}
                        <span className="rule-tag">BLP.NO_WRITE_DOWN</span>{m.unlessRole}{' '}
                        <span className="mono">[{schema.mandatory.trustedRoles.join(', ')}]</span>.
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <h2 className="card-title">
            <span>{m.compartmentsTitle}</span>
            <span className="badge badge-lock">MAC &amp; Biba</span>
          </h2>
          <div style={{ marginBottom: '12px' }}>
            <div className="metric-label">{m.declaredCompartments(schema.compartments.length)}</div>
            <div className="badge-group" style={{ marginBottom: '6px' }}>
              {schema.compartments.length > 0 ? (
                schema.compartments.map((c) => (
                  <span key={c} className="badge badge-warn">
                    {c}
                  </span>
                ))
              ) : (
                <span className="metric-sub">{m.noCompartments}</span>
              )}
            </div>
            <div className="metric-sub">
              {schema.mandatory.compartmentsRequireTrustedNetwork
                ? m.compartmentsTrusted
                : m.compartmentsAny}
            </div>
          </div>

          <div className="notice-box" style={{ marginBottom: 0 }}>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
              {m.integrityTitle}
            </div>
            <div className="mono" style={{ marginBottom: '4px' }}>
              derived (0) &lt; extracted (1) &lt; system (2) &lt; verified (3)
            </div>
            <div className="metric-sub">
              {m.noWriteUp}<span className="rule-tag">BIBA.NO_WRITE_UP</span>{m.noWriteUpRest}<span className="rule-tag">BIBA.NO_READ_DOWN</span>{m.readDownOn}{' '}
              <span className="mono">[{schema.mandatory.bibaNoReadDownActions.join(', ') || m.none}]</span>.
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">
          <span>{m.typesTitle}</span>
          <span className="badge badge-lock">Clark-Wilson</span>
        </h2>
        <div className="table-wrap">
          <table aria-label={m.typesTable}>
            <thead>
              <tr>
                <th scope="col">{m.resourceType}</th>
                <th scope="col">{m.integrityConstraint}</th>
                <th scope="col">{m.ntkProtection}</th>
                <th scope="col">{m.declaredActions}</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(schema.resourceTypes).map(([typeName, def]) => {
                const ntk = schema.needToKnow.protect[typeName];
                return (
                  <tr key={typeName}>
                    <td className="mono">
                      <strong>{typeName}</strong>
                    </td>
                    <td>
                      {def.constrained ? (
                        <span className="badge badge-warn">{m.constrained}</span>
                      ) : (
                        <span className="badge">{m.unconstrained}</span>
                      )}
                    </td>
                    <td className="mono">
                      {ntk
                        ? m.requires(ntk.relation, ntk.minLevel ?? 0, schema.needToKnow.mode)
                        : m.notRequired}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {Object.entries(def.actions).map(([actName, actDef]) => (
                          <div key={actName} className="badge-group">
                            <span className="mono">
                              <strong>{actName}</strong> ({actDef.kind})
                            </span>
                            {actDef.certified ? (
                              <span className="badge badge-allow">{m.certified}</span>
                            ) : null}
                            {actDef.requiresSecondPerson ? (
                              <span className="badge badge-warn">{m.twoPerson}</span>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">
          <span>{m.relationsTitle}</span>
          <span className="badge badge-lock">ReBAC</span>
        </h2>
        <div className="table-wrap">
          <table aria-label={m.relationsTitle}>
            <thead>
              <tr>
                <th scope="col">{m.scope}</th>
                <th scope="col">{m.objectType}</th>
                <th scope="col">{m.relation}</th>
                <th scope="col">{m.resolution}</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(schema.resourceTypes).flatMap(([typeName, def]) =>
                Object.entries(def.relations ?? {}).map(([relName, relDef]) => (
                  <tr key={`res-${typeName}-${relName}`}>
                    <td>{m.resource}</td>
                    <td className="mono">{typeName}</td>
                    <td className="mono">
                      <strong>{relName}</strong>
                    </td>
                    <td className="mono">{formatRelationDef(relDef)}</td>
                  </tr>
                )),
              )}
              {Object.entries(schema.subjectRelations ?? {}).flatMap(([subType, relMap]) =>
                Object.entries(relMap).map(([relName, relDef]) => (
                  <tr key={`sub-${subType}-${relName}`}>
                    <td>{m.subject}</td>
                    <td className="mono">{subType}</td>
                    <td className="mono">
                      <strong>{relName}</strong>
                    </td>
                    <td className="mono">{formatRelationDef(relDef)}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
