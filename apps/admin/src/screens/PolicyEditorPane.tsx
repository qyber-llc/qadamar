import { useState, useMemo, useEffect } from 'react';
import type { ConsoleRole, PolicyBundle } from '../api/types';
import { ImpactTables } from '../components/ImpactTables';
import { ErrorAlert } from '../components/UiStates';
import { extractTenantSections, validateTenantCandidate } from '../utils/expr';
import { canProposePolicyChange } from '../utils/permissions';
import { buildHref } from '../utils/router';
import { useChangePreview, type CandidateChange } from '../utils/useChangePreview';
import { useLang, useT } from '../i18n';

export function PolicyEditorPane(props: {
  readonly roles: readonly ConsoleRole[];
  readonly currentVersion: string;
  readonly currentBundle: PolicyBundle;
}) {
  const t = useT();
  const lang = useLang();
  const e = t.policies.editor;
  const [draftJson, setDraftJson] = useState(() =>
    JSON.stringify(extractTenantSections(props.currentBundle), null, 2),
  );
  const [reason, setReason] = useState('');

  const lockedSectionsJson = useMemo(
    () =>
      JSON.stringify(
        {
          schema: props.currentBundle.schema,
          mandatory: props.currentBundle.mandatory,
          needToKnow: props.currentBundle.needToKnow,
          clarkWilson: props.currentBundle.clarkWilson,
        },
        null,
        2,
      ),
    [props.currentBundle],
  );

  const validation = useMemo(() => {
    if (!draftJson.trim()) return { ok: false as const, errors: [t.policies.validation.empty] };
    let parsed: unknown;
    try {
      parsed = JSON.parse(draftJson);
    } catch (err) {
      return {
        ok: false as const,
        errors: [t.policies.validation.syntax(err instanceof Error ? err.message : t.policies.validation.parseError)],
      };
    }
    return validateTenantCandidate(parsed, props.currentBundle);
  }, [draftJson, props.currentBundle, lang, t]); // lang: rebuild the messages when the console language changes

  const candidate = useMemo<CandidateChange | null>(
    () =>
      validation.ok
        ? {
            kind: 'publish_policy',
            payload: { bundle: validation.bundle },
          }
        : null,
    [validation],
  );

  const {
    impact: simImpact,
    hasValidPreview,
    simulating,
    submitting,
    error: actionError,
    submittedChange,
    runPreview,
    submitPreviewedChange,
    resetPreview,
  } = useChangePreview(candidate);

  useEffect(() => {
    setDraftJson(JSON.stringify(extractTenantSections(props.currentBundle), null, 2));
    resetPreview();
  }, [props.currentBundle, resetPreview]);

  const canAuthor = canProposePolicyChange(props.roles);
  const canSubmit = validation.ok && hasValidPreview && reason.trim().length >= 20 && !submitting && !simulating && !submittedChange;

  return (
    <div className="card">
      <div className="card-title">
        <div>
          <h2 style={{ display: 'inline', margin: 0, font: 'inherit' }}>{e.title}</h2>
          <span className="metric-sub" style={{ marginInlineStart: '10px', fontWeight: 400 }}>
            {e.baseVersion} <span className="mono">{props.currentVersion.slice(0, 16)}</span> ({props.currentBundle.name})
          </span>
        </div>
        <div className="badge-group">
          <span role="status">
            {validation.ok ? (
              <span className="badge badge-allow">{e.valid}</span>
            ) : (
              <span className="badge badge-deny">{e.errorCount(validation.errors.length)}</span>
            )}
          </span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              setDraftJson(JSON.stringify(extractTenantSections(props.currentBundle), null, 2));
              resetPreview();
            }}
          >
            {e.reset}
          </button>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: '12px' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label htmlFor="policy-locked-sections">
            {e.lockedLabel} (<span className="mono">schema, mandatory, needToKnow, clarkWilson</span>)
          </label>
          <textarea
            id="policy-locked-sections"
            className="code-editor"
            value={lockedSectionsJson}
            readOnly
            aria-readonly="true"
            style={{ backgroundColor: 'var(--bg-code)', color: 'var(--text-secondary)' }}
          />
          <span className="metric-sub">
            {e.lockedHint}
          </span>
        </div>

        <div className="form-group" style={{ marginBottom: 0 }}>
          <label htmlFor="policy-json-editor">
            {e.editableLabel} (<span className="mono">rbac, abac, abacContent, context, sod</span>)
          </label>
          <textarea
            id="policy-json-editor"
            className="code-editor"
            value={draftJson}
            onChange={(e) => {
              setDraftJson(e.target.value);
            }}
            readOnly={!canAuthor}
            aria-invalid={!validation.ok}
            aria-describedby={validation.ok ? 'policy-json-hint' : 'policy-json-errors policy-json-hint'}
          />
          <span className="metric-sub" id="policy-json-hint">
            {e.editableHint}
          </span>
        </div>
      </div>

      {!validation.ok ? (
        <div className="alert-error" role="alert" id="policy-json-errors">
          <strong>{e.errorsTitle}</strong>
          <ul className="mono" style={{ margin: '6px 0 0 0', paddingInlineStart: '20px', fontSize: '12px' }}>
            {validation.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        </div>
      ) : validation.warnings.length > 0 ? (
        <div className="alert-warn" role="status">
          {validation.warnings.map((w) => <div key={w} className="mono">{w}</div>)}
        </div>
      ) : null}

      {actionError ? <ErrorAlert error={actionError} contextTitle={e.actionError} /> : null}

      {submittedChange ? (
        <div className="alert-success" role="status" aria-live="polite">
          {e.submitted} <strong className="mono">{submittedChange.id}</strong>.{' '}
          <a href={buildHref('approvals', { id: submittedChange.id })}>{e.viewApprovals}</a>
        </div>
      ) : null}

      {simImpact ? <ImpactTables impact={simImpact} /> : null}

      {canAuthor ? (
        <div className="form-row" style={{ marginTop: '12px', marginBottom: 0 }}>
          <div className="form-group">
            <label htmlFor="policy-submit-reason">
              {e.reasonLabel}
            </label>
            <input
              id="policy-submit-reason"
              type="text"
              value={reason}
              aria-describedby="policy-reason-count"
              onChange={(e) => setReason(e.target.value)}
              placeholder={e.reasonPlaceholder}
            />
          </div>
          <span className="mono metric-sub" id="policy-reason-count">{e.reasonCount(reason.trim().length)}</span>
          <button
            type="button"
            className="btn"
            disabled={!validation.ok || simulating}
            onClick={() => void runPreview()}
          >
            {simulating ? e.simulating : e.preview}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canSubmit}
            title={!hasValidPreview ? e.previewFirst : undefined}
            onClick={() => void submitPreviewedChange(reason)}
          >
            {submitting ? e.submitting : e.submit}
          </button>
        </div>
      ) : (
        <div className="notice-box" style={{ marginBottom: 0 }}>
          {e.readOnly}
        </div>
      )}
    </div>
  );
}
