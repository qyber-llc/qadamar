import type {
  AdminResource,
  AdminSubject,
  AdminTuple,
  Integrity,
  Level,
  SchemaResponse,
  Tuple,
} from '../api/types';
import { windowOf } from '../api/types';
import { LevelBadge } from '../components/UiStates';
import { formatDateHuman, LEVEL_LABELS } from '../utils/expr';
import { msgs, useT } from '../i18n';

export type ImpactKind = 'add_tuple' | 'remove_tuple' | 'update_subject' | 'update_resource';

export function formatGrantRecognizable(
  t: Tuple,
  subjects: readonly AdminSubject[],
  resources: readonly AdminResource[],
): string {
  const subObj = subjects.find((s) => s.id === t.subject.id);
  const subRes = !subObj ? resources.find((r) => r.id === t.subject.id) : undefined;
  const subBase = subObj ? subObj.name : subRes ? `${subRes.title} (${subRes.id})` : t.subject.id;
  const subLabel = t.subjectRelation ? `${subBase} (${t.subjectRelation})` : subBase;

  const objRes = resources.find((r) => r.id === t.object.id);
  const objSub = !objRes ? subjects.find((s) => s.id === t.object.id) : undefined;
  const objLabel = objRes
    ? `${objRes.title} (${objRes.id})`
    : objSub
      ? `${objSub.name} (${objSub.id})`
      : t.object.id;

  const rel = t.relation.replace(/_/g, ' ');
  const c = msgs().common.changes;
  const bg = t.breakGlass ? ` · ${c.breakGlass}` : '';
  const until = windowOf(t).to;
  const valid = until ? ` · ${c.until(formatDateHuman(until.slice(0, 10)))}` : '';
  return `${subLabel} → ${objLabel} — ${rel}${bg}${valid}`;
}

export function SimulatorImpactFields(props: {
  readonly kind: ImpactKind;
  readonly schema: SchemaResponse;
  readonly subjects: readonly AdminSubject[];
  readonly resources: readonly AdminResource[];
  readonly tuples: readonly AdminTuple[];
  readonly tupleResId: string;
  readonly onTupleResId: (v: string) => void;
  readonly tupleSubId: string;
  readonly onTupleSubId: (v: string) => void;
  readonly tupleRelation: string;
  readonly onTupleRelation: (v: string) => void;
  readonly tupleSubRel: string;
  readonly onTupleSubRel: (v: string) => void;
  readonly tupleValidTo: string;
  readonly onTupleValidTo: (v: string) => void;
  readonly removeTupleId: string;
  readonly onRemoveTupleId: (v: string) => void;
  readonly updSubId: string;
  readonly onUpdSubId: (v: string) => void;
  readonly updSubClearance: Level;
  readonly onUpdSubClearance: (v: Level) => void;
  readonly updSubComps: readonly string[];
  readonly onUpdSubComps: (v: readonly string[]) => void;
  readonly updSubRoles: string;
  readonly onUpdSubRoles: (v: string) => void;
  readonly updSubActive: boolean;
  readonly onUpdSubActive: (v: boolean) => void;
  readonly updResId: string;
  readonly onUpdResId: (v: string) => void;
  readonly updResLevel: Level;
  readonly onUpdResLevel: (v: Level) => void;
  readonly updResComps: readonly string[];
  readonly onUpdResComps: (v: readonly string[]) => void;
  readonly updResIntegrity: Integrity;
  readonly onUpdResIntegrity: (v: Integrity) => void;
}) {
  const m = useT().simulator;
  const f = m.fields;
  const selectedTupleRes = props.resources.find((r) => r.id === props.tupleResId);
  const selectedTupleSub = props.subjects.find((s) => s.id === props.tupleSubId);
  const selectedResType = selectedTupleRes?.type;
  const declaredRelations = selectedResType
    ? Object.keys(props.schema.resourceTypes[selectedResType]?.relations ?? {})
    : ['granted', 'allocated'];
  const relationOptions = declaredRelations.length > 0 ? declaredRelations : ['granted', 'allocated'];

  if (props.kind === 'add_tuple') {
    const resTitle = selectedTupleRes
      ? `${selectedTupleRes.title} (${selectedTupleRes.id}) · ${LEVEL_LABELS[selectedTupleRes.level]}`
      : props.tupleResId;
    const subTitle = selectedTupleSub
      ? `${selectedTupleSub.name} (${selectedTupleSub.unit || selectedTupleSub.type}) · ${LEVEL_LABELS[selectedTupleSub.clearance]}`
      : props.tupleSubId;

    return (
      <div className="sim-fields-grid">
        <div className="form-group">
          <label htmlFor="add-tuple-sub">{m.subject}</label>
          <select
            id="add-tuple-sub"
            value={props.tupleSubId}
            title={subTitle}
            onChange={(e) => props.onTupleSubId(e.target.value)}
          >
            {props.subjects.map((s) => (
              <option key={s.id} value={s.id} title={`${s.name} (${s.id})`}>
                {s.name} — {s.unit || s.type} ({LEVEL_LABELS[s.clearance]})
              </option>
            ))}
          </select>
          {selectedTupleSub ? (
            <div className="sim-field-caption">
              <LevelBadge level={selectedTupleSub.clearance} />
              <span className="sim-meta-id" title={m.subjectIdTitle(selectedTupleSub.id)}>
                {selectedTupleSub.id}
              </span>
            </div>
          ) : null}
        </div>
        <div className="form-group">
          <label htmlFor="add-tuple-rel">{f.relation}</label>
          <select
            id="add-tuple-rel"
            value={props.tupleRelation}
            title={props.tupleRelation}
            onChange={(e) => props.onTupleRelation(e.target.value)}
          >
            {relationOptions.map((rel) => (
              <option key={rel} value={rel}>
                {rel}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="add-tuple-res">{m.resource}</label>
          <select
            id="add-tuple-res"
            value={props.tupleResId}
            title={resTitle}
            onChange={(e) => props.onTupleResId(e.target.value)}
          >
            {props.resources.map((r) => (
              <option key={r.id} value={r.id} title={`${r.title} (${r.id})`}>
                {r.title} ({r.id}) · {LEVEL_LABELS[r.level]}
              </option>
            ))}
          </select>
          {selectedTupleRes ? (
            <div className="sim-field-caption">
              <LevelBadge level={selectedTupleRes.level} />
              <span className="sim-meta">({selectedTupleRes.type})</span>
            </div>
          ) : null}
        </div>
        <div className="form-group">
          <label htmlFor="add-tuple-subrel">{f.subjectRelation}</label>
          <input
            id="add-tuple-subrel"
            type="text"
            value={props.tupleSubRel}
            title={props.tupleSubRel || f.subjectRelationTitle}
            onChange={(e) => props.onTupleSubRel(e.target.value)}
            placeholder={f.subjectRelationPlaceholder}
          />
        </div>
        <div className="form-group">
          <label htmlFor="add-tuple-validto">{f.validUntil}</label>
          <input
            id="add-tuple-validto"
            type="date"
            className="tabular"
            value={props.tupleValidTo}
            title={props.tupleValidTo}
            onChange={(e) => props.onTupleValidTo(e.target.value)}
          />
        </div>
      </div>
    );
  }

  if (props.kind === 'remove_tuple') {
    const selectedTuple = props.tuples.find((t) => t.id === props.removeTupleId);
    const selectedLabel = selectedTuple
      ? formatGrantRecognizable(selectedTuple, props.subjects, props.resources)
      : props.removeTupleId;

    return (
      <div className="sim-fields-grid-single">
        <div className="form-group">
          <label htmlFor="remove-tuple-select">{f.grantToRevoke}</label>
          <select
            id="remove-tuple-select"
            value={props.removeTupleId}
            title={selectedTuple ? `${selectedLabel} (${selectedTuple.id})` : selectedLabel}
            onChange={(e) => props.onRemoveTupleId(e.target.value)}
          >
            {props.tuples.map((t) => {
              const label = formatGrantRecognizable(t, props.subjects, props.resources);
              return (
                <option key={t.id} value={t.id} title={`${label} (${t.id})`}>
                  {label}
                </option>
              );
            })}
          </select>
          {selectedTuple ? (
            <div className="sim-field-caption">
              <span>{selectedLabel}</span>
              <span className="sim-meta-id" title={f.tupleIdTitle(selectedTuple.id)}>
                ({selectedTuple.id})
              </span>
              {selectedTuple.reason ? (
                <span className="sim-meta" title={selectedTuple.reason}>
                  {f.reason(selectedTuple.reason)}
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    );
  }

  if (props.kind === 'update_subject') {
    const selectedSub = props.subjects.find((s) => s.id === props.updSubId);
    const subSelectTitle = selectedSub
      ? `${selectedSub.name} — ${selectedSub.unit || selectedSub.type} (${LEVEL_LABELS[selectedSub.clearance]})`
      : props.updSubId;

    return (
      <div>
        <div className="sim-fields-grid">
          <div className="form-group">
            <label htmlFor="upd-sub-select">{m.subject}</label>
            <select
              id="upd-sub-select"
              value={props.updSubId}
              title={subSelectTitle}
              onChange={(e) => props.onUpdSubId(e.target.value)}
            >
              {props.subjects.map((s) => (
                <option key={s.id} value={s.id} title={`${s.name} (${s.id})`}>
                  {s.name} — {s.unit || s.type} ({LEVEL_LABELS[s.clearance]})
                </option>
              ))}
            </select>
            {selectedSub ? (
              <div className="sim-field-caption">
                <LevelBadge level={selectedSub.clearance} />
                <span className="sim-meta-id" title={m.subjectIdTitle(selectedSub.id)}>
                  {selectedSub.id}
                </span>
              </div>
            ) : null}
          </div>
          <div className="form-group">
            <label htmlFor="upd-sub-clearance">{f.clearance}</label>
            <select
              id="upd-sub-clearance"
              value={String(props.updSubClearance)}
              title={LEVEL_LABELS[props.updSubClearance]}
              onChange={(e) => props.onUpdSubClearance(Number(e.target.value) as Level)}
            >
              {([0, 1, 2, 3] as Level[]).map((l) => (
                <option key={l} value={String(l)}>
                  {LEVEL_LABELS[l]}
                </option>
              ))}
            </select>
            <div className="sim-field-caption">
              <LevelBadge level={props.updSubClearance} />
            </div>
          </div>
          <div className="form-group">
            <label htmlFor="upd-sub-roles">{f.roles}</label>
            <input
              id="upd-sub-roles"
              type="text"
              value={props.updSubRoles}
              title={props.updSubRoles}
              onChange={(e) => props.onUpdSubRoles(e.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="upd-sub-active">{f.status}</label>
            <select
              id="upd-sub-active"
              value={props.updSubActive ? 'true' : 'false'}
              title={props.updSubActive ? m.active : m.inactive}
              onChange={(e) => props.onUpdSubActive(e.target.value === 'true')}
            >
              <option value="true">{m.active}</option>
              <option value="false">{m.inactive}</option>
            </select>
          </div>
        </div>
        <div className="sim-compartments-box" role="group" aria-label={f.subjectCompartments}>
          <span className="sim-compartments-title">{f.compartments}</span>
          {props.schema.compartments.map((c) => (
            <label key={c} className="sim-check-label">
              <input
                type="checkbox"
                checked={props.updSubComps.includes(c)}
                onChange={(e) =>
                  props.onUpdSubComps(
                    e.target.checked ? [...props.updSubComps, c] : props.updSubComps.filter((x) => x !== c),
                  )
                }
              />
              <span className="mono">{c}</span>
            </label>
          ))}
        </div>
      </div>
    );
  }

  const selectedRes = props.resources.find((r) => r.id === props.updResId);
  const resSelectTitle = selectedRes
    ? `${selectedRes.title} (${selectedRes.id}) · ${LEVEL_LABELS[selectedRes.level]}`
    : props.updResId;

  return (
    <div>
      <div className="sim-fields-grid">
        <div className="form-group">
          <label htmlFor="upd-res-select">{m.resource}</label>
          <select
            id="upd-res-select"
            value={props.updResId}
            title={resSelectTitle}
            onChange={(e) => props.onUpdResId(e.target.value)}
          >
            {props.resources.map((r) => (
              <option key={r.id} value={r.id} title={`${r.title} (${r.id})`}>
                {r.title} ({r.id}) · {LEVEL_LABELS[r.level]}
              </option>
            ))}
          </select>
          {selectedRes ? (
            <div className="sim-field-caption">
              <LevelBadge level={selectedRes.level} />
              <span className="sim-meta">({selectedRes.type})</span>
            </div>
          ) : null}
        </div>
        <div className="form-group">
          <label htmlFor="upd-res-level">{f.classification}</label>
          <select
            id="upd-res-level"
            value={String(props.updResLevel)}
            title={LEVEL_LABELS[props.updResLevel]}
            onChange={(e) => props.onUpdResLevel(Number(e.target.value) as Level)}
          >
            {([0, 1, 2, 3] as Level[]).map((l) => (
              <option key={l} value={String(l)}>
                {LEVEL_LABELS[l]}
              </option>
            ))}
          </select>
          <div className="sim-field-caption">
            <LevelBadge level={props.updResLevel} />
          </div>
        </div>
        <div className="form-group">
          <label htmlFor="upd-res-integrity">{f.integrity}</label>
          <select
            id="upd-res-integrity"
            value={props.updResIntegrity}
            title={props.updResIntegrity}
            onChange={(e) => props.onUpdResIntegrity(e.target.value as Integrity)}
          >
            <option value="verified">verified</option>
            <option value="system">system</option>
            <option value="extracted">extracted</option>
            <option value="derived">derived</option>
          </select>
        </div>
      </div>
      <div className="sim-compartments-box" role="group" aria-label={f.resourceCompartments}>
        <span className="sim-compartments-title">{f.compartments}</span>
        {props.schema.compartments.map((c) => (
          <label key={c} className="sim-check-label">
            <input
              type="checkbox"
              checked={props.updResComps.includes(c)}
              onChange={(e) =>
                props.onUpdResComps(
                  e.target.checked ? [...props.updResComps, c] : props.updResComps.filter((x) => x !== c),
                )
              }
            />
            <span className="mono">{c}</span>
          </label>
        ))}
      </div>
    </div>
  );
}
