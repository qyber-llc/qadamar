import { ObligationChanges } from '../components/ObligationChanges';
import { useState, useEffect, useMemo } from 'react';
import { getServerNowMs } from '../api/client';
import type {
  AdminResource,
  AdminSubject,
  AdminTuple,
  ConsoleRole,
  Impact,
  ImpactEntry,
  Integrity,
  Level,
  SchemaResponse,
} from '../api/types';
import type { ExplainTarget } from '../components/ExplainDrawer';
import { EmptyState, ErrorAlert, LevelBadge } from '../components/UiStates';
import { canProposeChangeKind, canUseSimulator } from '../utils/permissions';
import { buildHref } from '../utils/router';
import { useT } from '../i18n';
import { useChangePreview, type CandidateChange } from '../utils/useChangePreview';
import {
  formatGrantRecognizable,
  SimulatorImpactFields,
  type ImpactKind,
} from './SimulatorImpactFields';

function defaultValidTo(days: number): string {
  return new Date(getServerNowMs() + days * 86_400_000).toISOString().slice(0, 10);
}

function ImpactDeltaTable(props: {
  readonly entries: readonly ImpactEntry[];
  readonly ruleColumnLabel: string;
  readonly network: 'trusted' | 'untrusted';
  readonly subjectsById: ReadonlyMap<string, AdminSubject>;
  readonly resourcesById: ReadonlyMap<string, AdminResource>;
  readonly onExplain?: (target: ExplainTarget) => void;
}) {
  const m = useT().simulator;
  return (
    <div className="sim-table-scroller">
      <table className="sim-table">
        <thead>
          <tr>
            <th scope="col">{m.subject}</th>
            <th scope="col">{m.resource}</th>
            <th scope="col">{m.action}</th>
            <th scope="col">{props.ruleColumnLabel}</th>
            {props.onExplain ? <th scope="col" className="sim-col-action">{m.explain}</th> : null}
          </tr>
        </thead>
        <tbody>
          {props.entries.map((entry, idx) => {
            const sub = props.subjectsById.get(entry.subject);
            const res = props.resourcesById.get(entry.resource);
            const target: ExplainTarget = {
              subjectId: entry.subject,
              resourceId: entry.resource,
              action: entry.action,
              network: props.network,
            };
            return (
              <tr
                key={`${entry.subject}-${entry.resource}-${entry.action}-${idx}`}
                className={props.onExplain ? 'clickable-row' : undefined}
                onClick={() => props.onExplain?.(target)}
              >
                <td data-label={m.subject}>
                  <div className="sim-entity-cell">
                    <div className="sim-entity-head">
                      <strong className="sim-value-primary" title={sub ? `${sub.name} (${sub.id})` : entry.subject}>
                        {sub ? sub.name : entry.subject}
                      </strong>
                      {sub ? (
                        <span className="sim-meta-id" title={m.subjectIdTitle(sub.id)}>
                          ({sub.id})
                        </span>
                      ) : null}
                    </div>
                    {sub?.unit ? (
                      <div className="sim-resource-title" title={sub.unit}>
                        {sub.unit}
                      </div>
                    ) : null}
                  </div>
                </td>
                <td data-label={m.resource}>
                  <div className="sim-entity-cell">
                    <div className="sim-entity-head">
                      <strong className="sim-resource-id">{entry.resource}</strong>
                      {res ? <span className="sim-resource-type">({res.type})</span> : null}
                      {res ? <LevelBadge level={res.level} /> : null}
                    </div>
                    {res ? (
                      <div className="sim-resource-title" title={res.title}>
                        {res.title}
                      </div>
                    ) : null}
                  </div>
                </td>
                <td data-label={m.action} className="mono">
                  {entry.action}
                </td>
                <td data-label={props.ruleColumnLabel}>
                  <div className="badge-group">
                    {entry.rules.map((r) => (
                      <span key={r} className="rule-tag">
                        {r}
                      </span>
                    ))}
                  </div>
                </td>
                {props.onExplain ? (
                  <td data-label={m.explain} className="sim-col-action">
                    <button
                      type="button"
                      className="btn btn-sm"
                      aria-label={m.explainAria(sub ? sub.name : entry.subject, entry.action, entry.resource)}
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
  );
}

function SimulatorImpactResults(props: {
  readonly impact: Impact;
  readonly network: 'trusted' | 'untrusted';
  readonly subjectsById: ReadonlyMap<string, AdminSubject>;
  readonly resourcesById: ReadonlyMap<string, AdminResource>;
  readonly onExplain?: (target: ExplainTarget) => void;
}) {
  const { impact } = props;
  const t = useT();
  const m = t.simulator.impact;
  return (
    <div aria-live="polite">
      <div className="sim-docket-bar">
        <div className="sim-docket-entity">
          <span>
            {m.evaluatedBefore} <strong
              className="mono tabular"
              title={impact.analysis ? t.common.affectedCells(impact.analysis.affectedCells, impact.analysis.reasons.join('; ')) : undefined}
            >{impact.evaluated}</strong> {m.evaluatedAfter}
          </span>
          {impact.policyVersionBefore ? (
            <span
              className="sim-meta-id"
              title={t.common.versions(impact.policyVersionBefore, impact.policyVersionAfter || m.candidate)}
            >
              ({t.common.versions(impact.policyVersionBefore.slice(0, 12), (impact.policyVersionAfter || m.candidate).slice(0, 12))})
            </span>
          ) : null}
        </div>
        <div className="sim-docket-counts">
          <span className="badge badge-allow tabular">{m.gained(impact.gained.length)}</span>
          <span className="badge badge-deny tabular">{m.lost(impact.lost.length)}</span>
          {impact.obligationsLost?.length ? <span className="badge badge-warn tabular">{t.explain.impact.obligationsLostCount(impact.obligationsLost.length)}</span> : null}
        </div>
      </div>

      <div className="sim-impact-grid">
        <div>
          <h3 className="card-title">
            <span>{m.gainedAccess}</span>
            <span className="badge badge-allow tabular">+{impact.gained.length}</span>
          </h3>
          {impact.gained.length === 0 ? (
            <EmptyState title={m.noGained} />
          ) : (
            <ImpactDeltaTable
              entries={impact.gained}
              ruleColumnLabel={m.previouslyDenied}
              network={props.network}
              subjectsById={props.subjectsById}
              resourcesById={props.resourcesById}
              onExplain={props.onExplain}
            />
          )}
        </div>

        <div>
          <h3 className="card-title">
            <span>{m.lostAccess}</span>
            <span className="badge badge-deny tabular">−{impact.lost.length}</span>
          </h3>
          {impact.lost.length === 0 ? (
            <EmptyState title={m.noLost} />
          ) : (
            <ImpactDeltaTable
              entries={impact.lost}
              ruleColumnLabel={m.newlyDenied}
              network={props.network}
              subjectsById={props.subjectsById}
              resourcesById={props.resourcesById}
              onExplain={props.onExplain}
            />
          )}
        </div>
      </div>
      <ObligationChanges impact={impact} />
    </div>
  );
}

export function SimulatorImpactPane(props: {
  readonly roles: readonly ConsoleRole[];
  readonly schema: SchemaResponse;
  readonly subjects: readonly AdminSubject[];
  readonly resources: readonly AdminResource[];
  readonly tuples: readonly AdminTuple[];
  readonly network: 'trusted' | 'untrusted';
  readonly onToggleNetwork: (trusted: boolean) => void;
  readonly initialKind?: string;
  readonly initialSubjectId?: string;
  readonly initialResourceId?: string;
  readonly initialTupleId?: string;
  readonly onExplain: (target: ExplainTarget) => void;
}) {
  const t = useT();
  const m = t.simulator.impact;
  const KIND_LABELS = m.kinds;
  const allowedKinds = (['add_tuple', 'remove_tuple', 'update_subject', 'update_resource'] as const).filter((k) =>
    canProposeChangeKind(props.roles, k),
  );

  const [kind, setKind] = useState<ImpactKind>(() => {
    if (
      props.initialKind &&
      (['add_tuple', 'remove_tuple', 'update_subject', 'update_resource'] as const).includes(
        props.initialKind as ImpactKind,
      )
    ) {
      return props.initialKind as ImpactKind;
    }
    return allowedKinds[0] ?? 'add_tuple';
  });

  const [tupleResId, setTupleResId] = useState(props.initialResourceId ?? props.resources[0]?.id ?? '');
  const [tupleSubId, setTupleSubId] = useState(props.initialSubjectId ?? props.subjects[0]?.id ?? '');
  const [tupleRelation, setTupleRelation] = useState('granted');
  const [tupleSubRel, setTupleSubRel] = useState('');
  const [tupleValidTo, setTupleValidTo] = useState(() => defaultValidTo(30));
  const [removeTupleId, setRemoveTupleId] = useState(props.initialTupleId ?? props.tuples[0]?.id ?? '');

  const [updSubId, setUpdSubId] = useState(props.initialSubjectId ?? props.subjects[0]?.id ?? '');
  const [updSubClearance, setUpdSubClearance] = useState<Level>(2);
  const [updSubComps, setUpdSubComps] = useState<readonly string[]>([]);
  const [updSubRoles, setUpdSubRoles] = useState('');
  const [updSubActive, setUpdSubActive] = useState(true);

  const [updResId, setUpdResId] = useState(props.initialResourceId ?? props.resources[0]?.id ?? '');
  const [updResLevel, setUpdResLevel] = useState<Level>(2);
  const [updResComps, setUpdResComps] = useState<readonly string[]>([]);
  const [updResIntegrity, setUpdResIntegrity] = useState<Integrity>('verified');

  const [reason, setReason] = useState('');

  const subjectsById = useMemo(
    () => new Map(props.subjects.map((s) => [s.id, s] as const)),
    [props.subjects],
  );
  const resourcesById = useMemo(
    () => new Map(props.resources.map((r) => [r.id, r] as const)),
    [props.resources],
  );

  useEffect(() => {
    const s = props.subjects.find((x) => x.id === updSubId);
    if (s) {
      setUpdSubClearance(s.clearance);
      setUpdSubComps(s.compartments);
      setUpdSubRoles(s.roles.join(', '));
      setUpdSubActive(s.active);
    }
  }, [updSubId, props.subjects]);

  useEffect(() => {
    const r = props.resources.find((x) => x.id === updResId);
    if (r) {
      setUpdResLevel(r.level);
      setUpdResComps(r.compartments);
      setUpdResIntegrity(r.integrity);
    }
  }, [updResId, props.resources]);

  const candidate = useMemo<CandidateChange | null>(() => {
    if (kind === 'add_tuple') {
      const resObj = props.resources.find((r) => r.id === tupleResId);
      const subObj = props.subjects.find((s) => s.id === tupleSubId);
      if (!resObj || !subObj) return null;
      let validToIso: string | undefined;
      if (tupleValidTo) {
        const parsed = Date.parse(`${tupleValidTo}T23:59:59Z`);
        if (Number.isNaN(parsed)) return null;
        validToIso = new Date(parsed).toISOString();
      }
      return {
        kind: 'add_tuple',
        payload: {
          object: { type: resObj.type, id: resObj.id },
          relation: tupleRelation,
          subject: { type: subObj.type, id: subObj.id },
          ...(tupleSubRel.trim() ? { subjectRelation: tupleSubRel.trim() } : {}),
          ...(validToIso ? { notAfter: validToIso } : {}),
        },
      };
    }
    if (kind === 'remove_tuple') {
      return removeTupleId ? { kind: 'remove_tuple', payload: { tupleId: removeTupleId } } : null;
    }
    if (kind === 'update_subject') {
      if (!updSubId) return null;
      const roles = updSubRoles
        .split(',')
        .map((x) => x.trim())
        .filter((x) => x.length > 0);
      return {
        kind: 'update_subject',
        payload: {
          id: updSubId,
          set: { clearance: updSubClearance, compartments: updSubComps, roles, active: updSubActive },
        },
      };
    }
    return updResId
      ? {
          kind: 'update_resource',
          payload: {
            id: updResId,
            set: { level: updResLevel, compartments: updResComps, integrity: updResIntegrity },
          },
        }
      : null;
  }, [
    kind,
    props.resources,
    props.subjects,
    tupleResId,
    tupleSubId,
    tupleRelation,
    tupleSubRel,
    tupleValidTo,
    removeTupleId,
    updSubId,
    updSubClearance,
    updSubComps,
    updSubRoles,
    updSubActive,
    updResId,
    updResLevel,
    updResComps,
    updResIntegrity,
  ]);

  const candidateLabel = useMemo(() => {
    if (!candidate) return '';
    if (candidate.kind === 'add_tuple' && 'object' in candidate.payload) {
      return m.grant(formatGrantRecognizable(candidate.payload, props.subjects, props.resources));
    }
    if (candidate.kind === 'remove_tuple' && 'tupleId' in candidate.payload) {
      const tupleId = candidate.payload.tupleId;
      const tup = props.tuples.find((t) => t.id === tupleId);
      return tup
        ? m.revoke(formatGrantRecognizable(tup, props.subjects, props.resources))
        : m.revokeId(tupleId);
    }
    if (candidate.kind === 'update_subject' && 'id' in candidate.payload) {
      const sub = subjectsById.get(candidate.payload.id);
      return m.updateSubject(sub ? `${sub.name} (${sub.id})` : candidate.payload.id);
    }
    if (candidate.kind === 'update_resource' && 'id' in candidate.payload) {
      const res = resourcesById.get(candidate.payload.id);
      return m.updateResource(res ? `${res.title} (${res.id})` : candidate.payload.id);
    }
    return '';
  }, [candidate, props.subjects, props.resources, props.tuples, subjectsById, resourcesById, m]);

  const {
    impact,
    hasValidPreview,
    simulating,
    submitting,
    error,
    submittedChange,
    runPreview,
    submitPreviewedChange,
  } = useChangePreview(candidate);

  const canExplain = canUseSimulator(props.roles) ? props.onExplain : undefined;
  const canSubmit = hasValidPreview && reason.trim().length >= 20 && !submitting && !simulating && !submittedChange;

  return (
    <div className="card">
      <div className="sim-impact-header-grid">
        <div className="form-group">
          <label htmlFor="impact-kind-select">{m.changeType}</label>
          <select
            id="impact-kind-select"
            value={kind}
            title={KIND_LABELS[kind]}
            onChange={(e) => setKind(e.target.value as ImpactKind)}
          >
            <option value="add_tuple">{KIND_LABELS.add_tuple}</option>
            <option value="remove_tuple">{KIND_LABELS.remove_tuple}</option>
            <option value="update_subject">{KIND_LABELS.update_subject}</option>
            <option value="update_resource">{KIND_LABELS.update_resource}</option>
          </select>
        </div>
        <div className="sim-switch-wrap">
          <label className="switch-toggle" htmlFor="impact-trusted-switch">
            <input
              id="impact-trusted-switch"
              type="checkbox"
              role="switch"
              aria-checked={props.network === 'trusted'}
              checked={props.network === 'trusted'}
              onChange={(e) => props.onToggleNetwork(e.target.checked)}
            />
            <span>{t.simulator.trustedNetwork}</span>
          </label>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!candidate || simulating}
          onClick={() => void runPreview()}
        >
          {simulating ? m.calculating : m.preview}
        </button>
      </div>

      <SimulatorImpactFields
        kind={kind}
        schema={props.schema}
        subjects={props.subjects}
        resources={props.resources}
        tuples={props.tuples}
        tupleResId={tupleResId}
        onTupleResId={setTupleResId}
        tupleSubId={tupleSubId}
        onTupleSubId={setTupleSubId}
        tupleRelation={tupleRelation}
        onTupleRelation={setTupleRelation}
        tupleSubRel={tupleSubRel}
        onTupleSubRel={setTupleSubRel}
        tupleValidTo={tupleValidTo}
        onTupleValidTo={setTupleValidTo}
        removeTupleId={removeTupleId}
        onRemoveTupleId={setRemoveTupleId}
        updSubId={updSubId}
        onUpdSubId={setUpdSubId}
        updSubClearance={updSubClearance}
        onUpdSubClearance={setUpdSubClearance}
        updSubComps={updSubComps}
        onUpdSubComps={setUpdSubComps}
        updSubRoles={updSubRoles}
        onUpdSubRoles={setUpdSubRoles}
        updSubActive={updSubActive}
        onUpdSubActive={setUpdSubActive}
        updResId={updResId}
        onUpdResId={setUpdResId}
        updResLevel={updResLevel}
        onUpdResLevel={setUpdResLevel}
        updResComps={updResComps}
        onUpdResComps={setUpdResComps}
        updResIntegrity={updResIntegrity}
        onUpdResIntegrity={setUpdResIntegrity}
      />

      {error ? <ErrorAlert error={error} contextTitle={m.failed} /> : null}

      {submittedChange ? (
        <div className="alert-success" role="status" aria-live="polite">
          <span>
            {candidateLabel ? <strong>{candidateLabel}</strong> : m.change}{' '}
            <span className="sim-meta-id" title={m.changeIdTitle(submittedChange.id)}>
              ({submittedChange.id})
            </span>{' '}
            {m.submitted}{' '}
          </span>
          <a href={buildHref('approvals', { id: submittedChange.id })}>{m.openInApprovals}</a>
        </div>
      ) : null}

      {impact ? (
        <div>
          <SimulatorImpactResults
            impact={impact}
            network={props.network}
            subjectsById={subjectsById}
            resourcesById={resourcesById}
            onExplain={canExplain}
          />
          {canProposeChangeKind(props.roles, kind) ? (
            <div className="sim-submit-box">
              <div className="sim-submit-grid">
                <div className="form-group">
                  <label htmlFor="impact-submit-reason">{m.reasonLabel}</label>
                  <input
                    id="impact-submit-reason"
                    type="text"
                    value={reason}
                    title={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder={m.reasonPlaceholder}
                  />
                </div>
                <span className="sim-char-counter">{m.charCount(reason.trim().length)}</span>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!canSubmit}
                  onClick={() => void submitPreviewedChange(reason)}
                >
                  {submitting ? m.submitting : m.submit}
                </button>
              </div>
            </div>
          ) : (
            <div className="sim-submit-box">
              {m.cannotPropose}
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}
