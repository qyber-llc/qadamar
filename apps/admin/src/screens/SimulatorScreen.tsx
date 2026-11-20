import { Fragment, useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { api } from '../api/client';
import type {
  AdminResource,
  AdminSubject,
  AdminTuple,
  ConsoleRole,
  Obligations,
  SchemaResponse,
  WhatCanItem,
  WhoCanItem,
} from '../api/types';
import type { ExplainTarget } from '../components/ExplainDrawer';
import {
  DecisionBadge,
  EmptyState,
  ErrorAlert,
  LevelBadge,
  LoadingState,
} from '../components/UiStates';
import { formatDateHuman, LEVEL_LABELS } from '../utils/expr';
import { msgs, useT } from '../i18n';
import { SimulatorImpactPane } from './SimulatorImpactPane';
import type { WhatCanSnapshot, WhoCanSnapshot } from './SimulatorQueryTables';
import '../styles/simulator.css';

type SimMode = 'what-can' | 'who-can' | 'impact';

interface ParsedTupleHop {
  readonly raw: string;
  readonly objectType?: string;
  readonly objectId: string;
  readonly relation: string;
  readonly subjectType?: string;
  readonly subjectId: string;
  readonly subjectRelation?: string;
  readonly breakGlass: boolean;
  readonly validUntil?: string;
}

const TUPLE_HOP_RE =
  /^(?:([^#:]+):)?([^#]+)#([^@]+)@(?:([^#:]+):)?([^#\s]+)(?:#([^\s]+))?(?:\s+\[(break-glass)\])?(?:\s+until\s+(\S+))?$/;

function capitalizeWord(word: string): string {
  if (!word) return word;
  return word.charAt(0).toUpperCase() + word.slice(1);
}

function parseTupleHop(raw: string): ParsedTupleHop | null {
  const m = TUPLE_HOP_RE.exec(raw.trim());
  if (!m || !m[2] || !m[3] || !m[5]) return null;
  return {
    raw: raw.trim(),
    ...(m[1] ? { objectType: m[1] } : {}),
    objectId: m[2],
    relation: m[3],
    ...(m[4] ? { subjectType: m[4] } : {}),
    subjectId: m[5],
    ...(m[6] ? { subjectRelation: m[6] } : {}),
    breakGlass: Boolean(m[7]),
    ...(m[8] ? { validUntil: m[8] } : {}),
  };
}

function resolveNodeDisplay(
  id: string,
  type: string | undefined,
  subjectsById: ReadonlyMap<string, AdminSubject>,
): { readonly label: string; readonly rawId: string; readonly type?: string } {
  const knownSubject = subjectsById.get(id);
  if (knownSubject) {
    return { label: knownSubject.name, rawId: id, type: knownSubject.type };
  }
  if (type === 'user') {
    return { label: capitalizeWord(id), rawId: id, type };
  }
  return { label: id, rawId: id, ...(type ? { type } : {}) };
}

function formatRelationConnector(relation: string): string {
  const clean = relation.replace(/_/g, ' ').trim();
  const c = msgs().simulator.connector;
  switch (clean) {
    case 'allocated':
      return c.allocated;
    case 'granted':
      return c.granted;
    default:
      return c.other(clean);
  }
}

function formatHopQualifier(hop: ParsedTupleHop): { readonly text: string; readonly raw: string } | null {
  const parts: string[] = [];
  const rawParts: string[] = [];
  const c = msgs().common.changes;
  if (hop.breakGlass) {
    parts.push(c.breakGlass);
    rawParts.push(c.breakGlass);
  }
  if (hop.validUntil) {
    parts.push(c.until(formatDateHuman(hop.validUntil)));
    rawParts.push(c.until(hop.validUntil));
  }
  if (parts.length === 0) return null;
  return { text: parts.join(' · '), raw: rawParts.join(', ') };
}

function SimulatorRelationChain(props: {
  readonly path: readonly string[] | undefined;
  readonly subjectsById: ReadonlyMap<string, AdminSubject>;
}) {
  const { path, subjectsById } = props;
  const t = useT();
  if (!path || path.length === 0) return null;

  const rawEntries = path.flatMap((entry) =>
    entry.includes(' -> ')
      ? entry
          .split(' -> ')
          .map((s) => s.trim())
          .filter((s) => s.length > 0)
      : [entry.trim()],
  );
  if (rawEntries.length === 0) return null;

  const parsed = rawEntries.map(parseTupleHop);
  if (parsed.every((p): p is ParsedTupleHop => p !== null)) {
    // Engine traces in packages/core/src/relations.ts record hops from the target object back to the subject.
    // Reverse into reasoning direction: subject first, intermediate hops in order, target record last.
    const needsReverse =
      parsed.length <= 1 ||
      (parsed[0] !== undefined &&
        parsed[1] !== undefined &&
        parsed[0].subjectId === parsed[1].objectId);
    const ordered = needsReverse ? [...parsed].reverse() : parsed;
    const firstHop = ordered[0];
    if (!firstHop) return null;

    const startNode = resolveNodeDisplay(firstHop.subjectId, firstHop.subjectType, subjectsById);
    const steps = ordered.map((hop) => ({
      raw: hop.raw,
      connector: formatRelationConnector(hop.relation),
      target: resolveNodeDisplay(hop.objectId, hop.objectType, subjectsById),
      qualifier: formatHopQualifier(hop),
    }));

    const fullText = [
      startNode.label,
      ...steps.map(
        (s) => `${s.connector} ${s.target.label}${s.qualifier ? ` (${s.qualifier.text})` : ''}`,
      ),
    ].join(' → ');

    return (
      <span className="sim-chain" aria-label={t.common.relationPath} title={fullText}>
        <span
          className="sim-chain-node sim-chain-node-subject"
          title={startNode.type ? `${startNode.type}:${startNode.rawId}` : startNode.rawId}
        >
          {startNode.label}
        </span>
        {steps.map((step, idx) => (
          <Fragment key={`${step.raw}-${idx}`}>
            <span className="sim-chain-arrow" aria-hidden="true">
              {' → '}
            </span>
            <span className="sim-chain-rel">{step.connector} </span>
            <span
              className={
                idx === steps.length - 1
                  ? 'sim-chain-node sim-chain-node-record'
                  : 'sim-chain-node'
              }
              title={step.target.type ? `${step.target.type}:${step.target.rawId}` : step.target.rawId}
            >
              {step.target.label}
            </span>
            {step.qualifier ? (
              <span className="sim-chain-qualifier" title={step.qualifier.raw}>
                {' '}({step.qualifier.text})
              </span>
            ) : null}
          </Fragment>
        ))}
      </span>
    );
  }

  const fallbackText = rawEntries.join(' → ');
  return (
    <span className="sim-chain" aria-label={t.common.relationPath} title={fallbackText}>
      {rawEntries.map((entry, idx) => (
        <Fragment key={`${entry}-${idx}`}>
          {idx > 0 ? (
            <span className="sim-chain-arrow" aria-hidden="true">
              {' → '}
            </span>
          ) : null}
          <span className="sim-chain-node">{entry}</span>
        </Fragment>
      ))}
    </span>
  );
}

function formatSingleDenyReason(
  rawReason: string,
  subjectsById: ReadonlyMap<string, AdminSubject>,
): string {
  const trimmed = rawReason.trim();
  if (!trimmed) return '';
  const m = msgs().simulator.reasons;

  // Check for delegator prefix "<subjectId>: <reason>"
  const prefixMatch = /^([a-z0-9_-]+):\s+(.+)$/i.exec(trimmed);
  if (prefixMatch && prefixMatch[1] && prefixMatch[2] && subjectsById.has(prefixMatch[1])) {
    const delegator = subjectsById.get(prefixMatch[1])!;
    return `${delegator.name}: ${formatSingleDenyReason(prefixMatch[2], subjectsById)}`;
  }

  // "no knows relation to case:CASE-11" -> "No reason to know CASE-11"
  const ntkMatch = /^no\s+\S+\s+relation\s+to\s+(?:[^:\s]+:)?(\S+?)(\s+\(dry run\))?$/i.exec(trimmed);
  if (ntkMatch && ntkMatch[1]) {
    return m.noReasonToKnow(ntkMatch[1], Boolean(ntkMatch[2]));
  }

  // "compartment not held: FALCON" -> "Compartment FALCON not held"
  const compMatch = /^compartment\s+not\s+held:\s*(.+)$/i.exec(trimmed);
  if (compMatch && compMatch[1]) {
    const comps = compMatch[1].trim();
    return m.compartmentsNotHeld(comps, comps.includes(','));
  }

  // "working level L2 is below the resource level L3" -> "Working level L2 is below resource level L3"
  const blpReadMatch = /^working level (L\d+) is below the resource level (L\d+)$/i.exec(trimmed);
  if (blpReadMatch && blpReadMatch[1] && blpReadMatch[2]) {
    return m.workingLevelBelow(blpReadMatch[1], blpReadMatch[2]);
  }

  // "L3 is reachable only from a trusted network (untrusted max L2)"
  const netLvlMatch =
    /^(L\d+) is reachable only from a trusted network \(untrusted max (L\d+)\)$/i.exec(trimmed);
  if (netLvlMatch && netLvlMatch[1] && netLvlMatch[2]) {
    return m.requiresTrusted(netLvlMatch[1], netLvlMatch[2]);
  }

  // "compartmented resources are reachable only from a trusted network"
  if (/^compartmented resources are reachable only from a trusted network$/i.test(trimmed)) {
    return m.compartmentedTrusted;
  }

  // "writing L1 from a session at L2 could leak higher data down"
  const blpWriteMatch =
    /^writing (L\d+) from a session at (L\d+) could leak higher data down$/i.exec(trimmed);
  if (blpWriteMatch && blpWriteMatch[1] && blpWriteMatch[2]) {
    return m.cannotWriteDown(blpWriteMatch[1], blpWriteMatch[2]);
  }

  // "a derived writer cannot change verified data"
  const bibaWriteMatch = /^a (\S+) writer cannot change (\S+) data$/i.exec(trimmed);
  if (bibaWriteMatch && bibaWriteMatch[1] && bibaWriteMatch[2]) {
    return m.bibaWrite(bibaWriteMatch[1], bibaWriteMatch[2]);
  }

  // "approve cannot rely on derived data"
  const bibaReadMatch = /^(\S+) cannot rely on (\S+) data$/i.exec(trimmed);
  if (bibaReadMatch && bibaReadMatch[1] && bibaReadMatch[2]) {
    return m.bibaRead(bibaReadMatch[1], bibaReadMatch[2]);
  }

  // "no role or permit rule allows read on payment"
  const rbacMatch = /^no role or permit rule allows (\S+) on (\S+)$/i.exec(trimmed);
  if (rbacMatch && rbacMatch[1] && rbacMatch[2]) {
    return m.noRole(rbacMatch[1], rbacMatch[2]);
  }

  // "edit is not a certified command for a constrained payment"
  const cwMatch = /^(\S+) is not a certified command for a constrained (\S+)$/i.exec(trimmed);
  if (cwMatch && cwMatch[1] && cwMatch[2]) {
    return m.notCertified(cwMatch[1], cwMatch[2]);
  }

  // "two-person rule: the maker is not known, so the check fails closed"
  if (/^two-person rule:\s*the maker is not known/i.test(trimmed)) {
    return m.makerUnknown;
  }

  // "two-person rule: the maker cannot perform this action"
  if (/^two-person rule:\s*the maker cannot perform this action/i.test(trimmed)) {
    return m.makerSelf;
  }

  // "frank is inactive" -> "Frank is inactive"
  const inactiveMatch = /^(\S+) is inactive$/i.exec(trimmed);
  if (inactiveMatch && inactiveMatch[1]) {
    const sub = subjectsById.get(inactiveMatch[1]);
    return m.inactive(sub ? sub.name : capitalizeWord(inactiveMatch[1]));
  }

  // "<action> on <type> is not declared"
  const undeclaredMatch = /^(\S+) on (\S+) is not declared$/i.exec(trimmed);
  if (undeclaredMatch && undeclaredMatch[1] && undeclaredMatch[2]) {
    return m.undeclared(undeclaredMatch[1], undeclaredMatch[2]);
  }

  return capitalizeWord(trimmed);
}

interface ObligationChipItem {
  readonly key: string;
  readonly label: string;
  readonly value: string;
  readonly title: string;
}

function extractObligationChips(obligations: Obligations | undefined): readonly ObligationChipItem[] {
  if (!obligations) return [];
  const m = msgs().simulator.chips;
  const chips: ObligationChipItem[] = [];
  for (const field of obligations.redact) {
    chips.push({
      key: `redact-${field}`,
      label: m.redact,
      value: field,
      title: m.redactTitle(field),
    });
  }
  for (const cls of obligations.maskClasses) {
    chips.push({
      key: `mask-${cls}`,
      label: m.mask,
      value: cls,
      title: m.maskTitle(cls),
    });
  }
  for (const target of obligations.notify) {
    chips.push({
      key: `notify-${target}`,
      label: m.notify,
      value: target,
      title: m.notifyTitle(target),
    });
  }
  if (obligations.decisionToken) {
    chips.push({
      key: 'decision-token',
      label: m.decisionToken,
      value: `${obligations.decisionToken.ttlSeconds}s`,
      title: m.decisionTokenTitle(obligations.decisionToken.ttlSeconds),
    });
  }
  if (obligations.fieldAllowlist && obligations.fieldAllowlist.length > 0) {
    chips.push({
      key: 'allowlist',
      label: m.fields,
      value: obligations.fieldAllowlist.join(', '),
      title: m.fieldsTitle(obligations.fieldAllowlist.join(', ')),
    });
  }
  return chips;
}

function InlineObligationChips(props: { readonly obligations: Obligations | undefined }) {
  const t = useT();
  const chips = extractObligationChips(props.obligations);
  if (chips.length === 0) return null;
  return (
    <div className="sim-obligation-list" aria-label={t.simulator.obligations}>
      {chips.map((c) => (
        <span key={c.key} className="sim-obligation-chip" title={c.title}>
          <span>{c.label}</span>
          <span className="mono">{c.value}</span>
        </span>
      ))}
    </div>
  );
}

function ReasonAndPathCell(props: {
  readonly decision: boolean;
  readonly path: readonly string[] | undefined;
  readonly reasons: readonly string[];
  readonly rules: readonly string[];
  readonly subjectsById: ReadonlyMap<string, AdminSubject>;
}) {
  const t = useT();
  const hasPath = Boolean(props.path && props.path.length > 0);
  const hasReasons = props.reasons.length > 0;

  if (!hasPath && !hasReasons) {
    if (props.decision) {
      const viaOwner = props.rules.some((r) => r.includes('owner-read'));
      return (
        <div className="sim-reason-cell">
          <span className="sim-reason-muted">
            {viaOwner ? t.simulator.viaOwner : t.simulator.viaRole}
          </span>
        </div>
      );
    }
    return (
      <div className="sim-reason-cell">
        <span className="sim-reason-muted">—</span>
      </div>
    );
  }

  return (
    <div className="sim-reason-cell">
      {hasPath ? (
        <SimulatorRelationChain path={props.path} subjectsById={props.subjectsById} />
      ) : null}
      {hasReasons ? (
        <div className="sim-reasons-list">
          {props.reasons.map((raw, idx) => {
            const formatted = formatSingleDenyReason(raw, props.subjectsById);
            return (
              <div key={`${raw}-${idx}`} className="sim-reason-sentence" title={raw}>
                {formatted}
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function WhatCanResultsView(props: {
  readonly snapshot: WhatCanSnapshot;
  readonly subjectsById: ReadonlyMap<string, AdminSubject>;
  readonly onExplain: (target: ExplainTarget) => void;
}) {
  const { snapshot, subjectsById, onExplain } = props;
  const t = useT();
  const m = t.simulator;
  if (snapshot.items.length === 0) {
    return <EmptyState title={m.noResources} />;
  }

  return (
    <div className="sim-table-scroller" aria-live="polite">
      <table className="sim-table">
        <thead>
          <tr>
            <th scope="col" className="sim-col-entity">{m.resource}</th>
            <th scope="col" className="sim-col-level">{m.level}</th>
            <th scope="col" className="sim-col-decision">{m.decision}</th>
            <th scope="col" className="sim-col-reason">{m.pathAndReasons}</th>
            <th scope="col" className="sim-col-rules">{m.rules}</th>
            <th scope="col" className="sim-col-action">{m.explain}</th>
          </tr>
        </thead>
        <tbody>
          {snapshot.items.map((item: WhatCanItem) => {
            const target: ExplainTarget = {
              subjectId: snapshot.subjectId,
              resourceId: item.resource.id,
              action: snapshot.action,
              network: snapshot.network,
            };
            const subjectLabel = subjectsById.get(snapshot.subjectId)?.name ?? snapshot.subjectId;
            return (
              <tr
                key={`${item.resource.type}:${item.resource.id}`}
                className="clickable-row"
                onClick={() => onExplain(target)}
              >
                <td data-label={m.resource} className="sim-col-entity">
                  <div className="sim-entity-cell">
                    <div className="sim-entity-head">
                      <strong className="sim-resource-id">{item.resource.id}</strong>
                      <span className="sim-resource-type">({item.resource.type})</span>
                    </div>
                    <div className="sim-resource-title" title={item.resource.title}>
                      {item.resource.title}
                    </div>
                  </div>
                </td>
                <td data-label={m.level} className="sim-col-level">
                  <LevelBadge level={item.resource.level} />
                </td>
                <td data-label={m.decision} className="sim-col-decision">
                  <div className="sim-decision-stack">
                    <DecisionBadge decision={item.decision} wouldDeny={item.wouldDeny} />
                    <InlineObligationChips obligations={item.obligations} />
                  </div>
                </td>
                <td data-label={m.pathAndReasons} className="sim-col-reason">
                  <ReasonAndPathCell
                    decision={item.decision}
                    path={item.path}
                    reasons={item.reasons}
                    rules={item.rules}
                    subjectsById={subjectsById}
                  />
                </td>
                <td data-label={m.rules} className="sim-col-rules">
                  <div className="badge-group">
                    {item.rules.map((r) => (
                      <span key={r} className="rule-tag" title={r}>
                        {r}
                      </span>
                    ))}
                  </div>
                </td>
                <td data-label={m.explain} className="sim-col-action">
                  <button
                    type="button"
                    className="btn btn-sm"
                    aria-label={m.explainAria(subjectLabel, snapshot.action, item.resource.id)}
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

function WhoCanResultsView(props: {
  readonly snapshot: WhoCanSnapshot;
  readonly subjectsById: ReadonlyMap<string, AdminSubject>;
  readonly onExplain: (target: ExplainTarget) => void;
}) {
  const { snapshot, subjectsById, onExplain } = props;
  const t = useT();
  const m = t.simulator;
  if (snapshot.items.length === 0) {
    return <EmptyState title={m.noSubjects} />;
  }

  return (
    <div className="sim-table-scroller" aria-live="polite">
      <table className="sim-table">
        <thead>
          <tr>
            <th scope="col" className="sim-col-entity">{m.subject}</th>
            <th scope="col" className="sim-col-decision">{m.decision}</th>
            <th scope="col" className="sim-col-reason">{m.pathAndReasons}</th>
            <th scope="col" className="sim-col-rules">{m.rules}</th>
            <th scope="col" className="sim-col-action">{m.explain}</th>
          </tr>
        </thead>
        <tbody>
          {snapshot.items.map((item: WhoCanItem) => {
            const target: ExplainTarget = {
              subjectId: item.subject.id,
              resourceId: snapshot.resourceId,
              action: snapshot.action,
              network: snapshot.network,
            };
            const fullSubject = subjectsById.get(item.subject.id);
            const delegator = fullSubject?.delegatedBy
              ? subjectsById.get(fullSubject.delegatedBy)?.name ?? fullSubject.delegatedBy
              : undefined;
            const subjectMeta = fullSubject
              ? delegator
                ? m.delegatedBy(delegator, LEVEL_LABELS[fullSubject.clearance])
                : `${fullSubject.unit || fullSubject.type} · ${LEVEL_LABELS[fullSubject.clearance]}`
              : item.subject.type;

            return (
              <tr
                key={`${item.subject.type}:${item.subject.id}`}
                className="clickable-row"
                onClick={() => onExplain(target)}
              >
                <td data-label={m.subject} className="sim-col-entity">
                  <div className="sim-entity-cell">
                    <div className="sim-entity-head">
                      <strong className="sim-value-primary" title={`${item.subject.name} (${item.subject.id})`}>
                        {item.subject.name}
                      </strong>
                      <span className="sim-meta-id" title={m.subjectIdTitle(item.subject.id)}>
                        ({item.subject.id})
                      </span>
                    </div>
                    <div className="sim-resource-title" title={subjectMeta}>
                      {subjectMeta}
                    </div>
                  </div>
                </td>
                <td data-label={m.decision} className="sim-col-decision">
                  <div className="sim-decision-stack">
                    <DecisionBadge decision={item.decision} wouldDeny={item.wouldDeny} />
                    <InlineObligationChips obligations={item.obligations} />
                  </div>
                </td>
                <td data-label={m.pathAndReasons} className="sim-col-reason">
                  <ReasonAndPathCell
                    decision={item.decision}
                    path={item.path}
                    reasons={item.reasons}
                    rules={item.rules}
                    subjectsById={subjectsById}
                  />
                </td>
                <td data-label={m.rules} className="sim-col-rules">
                  <div className="badge-group">
                    {item.rules.map((r) => (
                      <span key={r} className="rule-tag" title={r}>
                        {r}
                      </span>
                    ))}
                  </div>
                </td>
                <td data-label={m.explain} className="sim-col-action">
                  <button
                    type="button"
                    className="btn btn-sm"
                    aria-label={m.explainAria(item.subject.name, snapshot.action, snapshot.resourceId)}
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

export function SimulatorScreen(props: {
  readonly roles: readonly ConsoleRole[];
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
  readonly onExplain: (target: ExplainTarget) => void;
}) {
  const t = useT();
  const m = t.simulator;
  const mode: SimMode =
    props.params.mode === 'who-can' || props.params.mode === 'impact' ? props.params.mode : 'what-can';
  const network: 'trusted' | 'untrusted' = props.params.network === 'untrusted' ? 'untrusted' : 'trusted';

  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [subjects, setSubjects] = useState<readonly AdminSubject[]>([]);
  const [resources, setResources] = useState<readonly AdminResource[]>([]);
  const [tuples, setTuples] = useState<readonly AdminTuple[]>([]);
  const [metaLoading, setMetaLoading] = useState(true);
  const [metaError, setMetaError] = useState<unknown>(null);

  const [subjectId, setSubjectId] = useState(props.params.subjectId ?? '');
  const [resourceId, setResourceId] = useState(props.params.resourceId ?? '');
  const [action, setAction] = useState(props.params.action ?? 'read');

  const [whatSnapshot, setWhatSnapshot] = useState<WhatCanSnapshot | null>(null);
  const [whoSnapshot, setWhoSnapshot] = useState<WhoCanSnapshot | null>(null);
  const [simLoading, setSimLoading] = useState(false);
  const [simError, setSimError] = useState<unknown>(null);
  const simReqGenRef = useRef(0);

  const subjectsById = useMemo(
    () => new Map(subjects.map((s) => [s.id, s] as const)),
    [subjects],
  );
  const resourcesById = useMemo(
    () => new Map(resources.map((r) => [r.id, r] as const)),
    [resources],
  );

  const loadMetadata = useCallback(async () => {
    setMetaLoading(true);
    setMetaError(null);
    try {
      const [sc, sub, res, tup] = await Promise.all([
        api.getSchema(),
        api.getSubjects(),
        api.getResources(),
        api.getTuples(),
      ]);
      setSchema(sc);
      setSubjects(sub.items);
      setResources(res.items);
      setTuples(tup.items);
      if (!subjectId && sub.items[0]) setSubjectId(sub.items[0].id);
      if (!resourceId && res.items[0]) setResourceId(res.items[0].id);
    } catch (err) {
      setMetaError(err);
    } finally {
      setMetaLoading(false);
    }
  }, [subjectId, resourceId]);

  useEffect(() => {
    void loadMetadata();
  }, []);

  const allActions = useMemo(() => {
    if (!schema) return ['read', 'write', 'approve', 'delete'];
    const set = new Set<string>();
    for (const def of Object.values(schema.resourceTypes)) {
      for (const act of Object.keys(def.actions)) set.add(act);
    }
    return set.size > 0 ? Array.from(set) : ['read', 'write'];
  }, [schema]);

  const runWhatCan = useCallback(async () => {
    if (!subjectId) return;
    const gen = ++simReqGenRef.current;
    const snap = { subjectId, action, network };
    setSimLoading(true);
    setSimError(null);
    try {
      const res = await api.simulateWhatCan(snap);
      if (simReqGenRef.current !== gen) return;
      setWhatSnapshot({ ...snap, items: res.items });
    } catch (err) {
      if (simReqGenRef.current !== gen) return;
      setWhatSnapshot(null);
      setSimError(err);
    } finally {
      if (simReqGenRef.current === gen) {
        setSimLoading(false);
      }
    }
  }, [subjectId, action, network]);

  const runWhoCan = useCallback(async () => {
    if (!resourceId) return;
    const gen = ++simReqGenRef.current;
    const snap = { resourceId, action, network };
    setSimLoading(true);
    setSimError(null);
    try {
      const res = await api.simulateWhoCan(snap);
      if (simReqGenRef.current !== gen) return;
      setWhoSnapshot({ ...snap, items: res.items });
    } catch (err) {
      if (simReqGenRef.current !== gen) return;
      setWhoSnapshot(null);
      setSimError(err);
    } finally {
      if (simReqGenRef.current === gen) {
        setSimLoading(false);
      }
    }
  }, [resourceId, action, network]);

  useEffect(() => {
    if (metaLoading) return;
    if (mode === 'what-can' && subjectId) void runWhatCan();
    else if (mode === 'who-can' && resourceId) void runWhoCan();
  }, [metaLoading, mode, subjectId, resourceId, action, network, runWhatCan, runWhoCan]);

  const activeWhatSnapshot =
    whatSnapshot &&
    whatSnapshot.subjectId === subjectId &&
    whatSnapshot.action === action &&
    whatSnapshot.network === network
      ? whatSnapshot
      : null;

  const activeWhoSnapshot =
    whoSnapshot &&
    whoSnapshot.resourceId === resourceId &&
    whoSnapshot.action === action &&
    whoSnapshot.network === network
      ? whoSnapshot
      : null;

  const selectedSubject = subjectsById.get(subjectId);
  const selectedResource = resourcesById.get(resourceId);

  const renderNetworkSwitch = (id: string) => (
    <div className="sim-switch-wrap">
      <label className="switch-toggle" htmlFor={id}>
        <input
          id={id}
          type="checkbox"
          role="switch"
          aria-checked={network === 'trusted'}
          checked={network === 'trusted'}
          onChange={(e) => props.setParams({ network: e.target.checked ? 'trusted' : 'untrusted' })}
        />
        <span>{m.trustedNetwork}</span>
      </label>
    </div>
  );

  const whatAllowedCount = activeWhatSnapshot
    ? activeWhatSnapshot.items.filter((i) => i.decision).length
    : 0;
  const whatDeniedCount = activeWhatSnapshot
    ? activeWhatSnapshot.items.length - whatAllowedCount
    : 0;

  const whoAllowedCount = activeWhoSnapshot
    ? activeWhoSnapshot.items.filter((i) => i.decision).length
    : 0;
  const whoDeniedCount = activeWhoSnapshot
    ? activeWhoSnapshot.items.length - whoAllowedCount
    : 0;

  const selectedSubjectTitle = selectedSubject
    ? `${selectedSubject.name} — ${selectedSubject.unit || selectedSubject.type} (${LEVEL_LABELS[selectedSubject.clearance]}${selectedSubject.compartments.length ? ` · ${selectedSubject.compartments.join(', ')}` : ''})`
    : subjectId;

  const selectedResourceTitle = selectedResource
    ? `${selectedResource.title} (${selectedResource.id}) · ${LEVEL_LABELS[selectedResource.level]}${selectedResource.compartments.length ? ` · ${selectedResource.compartments.join(', ')}` : ''}`
    : resourceId;

  return (
    <section className="sim-screen" aria-labelledby="title-simulator">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-simulator">{m.title}</h1>
          <p className="screen-subtitle">
            {m.subtitle}
          </p>
        </div>

        <div className="segmented-control" role="tablist" aria-label={m.modes}>
          <button
            type="button"
            role="tab"
            className="segmented-btn"
            aria-selected={mode === 'what-can'}
            onClick={() => props.setParams({ mode: 'what-can' })}
          >
            {m.modeWhatCan}
          </button>
          <button
            type="button"
            role="tab"
            className="segmented-btn"
            aria-selected={mode === 'who-can'}
            onClick={() => props.setParams({ mode: 'who-can' })}
          >
            {m.modeWhoCan}
          </button>
          <button
            type="button"
            role="tab"
            className="segmented-btn"
            aria-selected={mode === 'impact'}
            onClick={() => props.setParams({ mode: 'impact' })}
          >
            {m.modeImpact}
          </button>
        </div>
      </div>

      {metaLoading ? <LoadingState label={m.loading} /> : null}
      {metaError ? (
        <ErrorAlert
          error={metaError}
          contextTitle={m.unavailable}
          onRetry={() => void loadMetadata()}
        />
      ) : null}

      {!metaLoading && !metaError && mode === 'what-can' ? (
        <div className="card">
          <div className="sim-controls-grid">
            <div className="form-group">
              <label htmlFor="sim-what-subject">{m.personOrService}</label>
              <select
                id="sim-what-subject"
                value={subjectId}
                title={selectedSubjectTitle}
                onChange={(e) => {
                  setSubjectId(e.target.value);
                  props.setParams({ subjectId: e.target.value });
                }}
              >
                {subjects.map((s) => {
                  const label = `${s.name} — ${s.unit || s.type} (${LEVEL_LABELS[s.clearance]}${s.compartments.length ? ` · ${s.compartments.join(', ')}` : ''})`;
                  return (
                    <option key={s.id} value={s.id} title={`${label} [${s.id}]`}>
                      {label}
                    </option>
                  );
                })}
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="sim-what-action">{m.action}</label>
              <select
                id="sim-what-action"
                value={action}
                title={action}
                onChange={(e) => {
                  setAction(e.target.value);
                  props.setParams({ action: e.target.value });
                }}
              >
                {allActions.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
            {renderNetworkSwitch('sim-trusted-switch')}
          </div>

          {selectedSubject ? (
            <div className="sim-docket-bar">
              <div className="sim-docket-entity">
                <strong className="sim-value-primary">{selectedSubject.name}</strong>
                <span className="sim-meta-id" title={m.subjectIdTitle(selectedSubject.id)}>
                  ({selectedSubject.id})
                </span>
                <LevelBadge level={selectedSubject.clearance} />
                {selectedSubject.compartments.map((c) => (
                  <span key={c} className="rule-tag" title={m.heldCompartment(c)}>
                    {c}
                  </span>
                ))}
                {!selectedSubject.active ? (
                  <span className="badge badge-deny">{m.inactive}</span>
                ) : null}
                {selectedSubject.roles.length > 0 ? (
                  <span className="sim-meta">
                    {m.rolesLabel} <span className="mono">{selectedSubject.roles.join(', ')}</span>
                  </span>
                ) : null}
              </div>
              {activeWhatSnapshot ? (
                <div className="sim-docket-counts">
                  <span className="badge badge-allow tabular">{m.allowedCount(whatAllowedCount)}</span>
                  <span className="badge badge-deny tabular">{m.deniedCount(whatDeniedCount)}</span>
                </div>
              ) : null}
            </div>
          ) : null}

          {simLoading ? <LoadingState label={m.evaluatingResources} /> : null}
          {simError ? <ErrorAlert error={simError} onRetry={() => void runWhatCan()} /> : null}

          {!simLoading && !simError && activeWhatSnapshot ? (
            <WhatCanResultsView
              snapshot={activeWhatSnapshot}
              subjectsById={subjectsById}
              onExplain={props.onExplain}
            />
          ) : null}
        </div>
      ) : null}

      {!metaLoading && !metaError && mode === 'who-can' ? (
        <div className="card">
          <div className="sim-controls-grid">
            <div className="form-group">
              <label htmlFor="sim-who-resource">{m.resource}</label>
              <select
                id="sim-who-resource"
                value={resourceId}
                title={selectedResourceTitle}
                onChange={(e) => {
                  setResourceId(e.target.value);
                  props.setParams({ resourceId: e.target.value });
                }}
              >
                {resources.map((r) => {
                  const label = `${r.title} (${r.id}) · ${LEVEL_LABELS[r.level]}${r.compartments.length ? ` · ${r.compartments.join(', ')}` : ''}`;
                  return (
                    <option key={r.id} value={r.id} title={label}>
                      {label}
                    </option>
                  );
                })}
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="sim-who-action">{m.action}</label>
              <select
                id="sim-who-action"
                value={action}
                title={action}
                onChange={(e) => {
                  setAction(e.target.value);
                  props.setParams({ action: e.target.value });
                }}
              >
                {allActions.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
            {renderNetworkSwitch('sim-who-trusted-switch')}
          </div>

          {selectedResource ? (
            <div className="sim-docket-bar">
              <div className="sim-docket-entity">
                <strong className="sim-value-primary">{selectedResource.title}</strong>
                <span className="sim-resource-id">{selectedResource.id}</span>
                <span className="sim-meta">({selectedResource.type})</span>
                <LevelBadge level={selectedResource.level} />
                {selectedResource.compartments.map((c) => (
                  <span key={c} className="rule-tag" title={m.requiredCompartment(c)}>
                    {c}
                  </span>
                ))}
                {selectedResource.owner ? (
                  <span className="sim-meta">
                    {m.owner(subjectsById.get(selectedResource.owner)?.name ?? selectedResource.owner)}
                  </span>
                ) : null}
              </div>
              {activeWhoSnapshot ? (
                <div className="sim-docket-counts">
                  <span className="badge badge-allow tabular">{m.allowedCount(whoAllowedCount)}</span>
                  <span className="badge badge-deny tabular">{m.deniedCount(whoDeniedCount)}</span>
                </div>
              ) : null}
            </div>
          ) : null}

          {simLoading ? <LoadingState label={m.evaluatingSubjects} /> : null}
          {simError ? <ErrorAlert error={simError} onRetry={() => void runWhoCan()} /> : null}

          {!simLoading && !simError && activeWhoSnapshot ? (
            <WhoCanResultsView
              snapshot={activeWhoSnapshot}
              subjectsById={subjectsById}
              onExplain={props.onExplain}
            />
          ) : null}
        </div>
      ) : null}

      {!metaLoading && !metaError && schema && mode === 'impact' ? (
        <SimulatorImpactPane
          roles={props.roles}
          schema={schema}
          subjects={subjects}
          resources={resources}
          tuples={tuples}
          network={network}
          onToggleNetwork={(trusted) => props.setParams({ network: trusted ? 'trusted' : 'untrusted' })}
          initialKind={props.params.kind}
          initialSubjectId={props.params.subjectId}
          initialResourceId={props.params.resourceId}
          initialTupleId={props.params.tupleId}
          onExplain={props.onExplain}
        />
      ) : null}
    </section>
  );
}
