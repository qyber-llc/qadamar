import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../api/client';
import type { ComplianceFramework, EvidenceFrameworkRef, Json } from '../api/types';
import { DateText, EmptyState, ErrorAlert, LoadingState } from '../components/UiStates';
import { buildHref } from '../utils/router';
import { useT } from '../i18n';
import { EvidencePackCard } from './EvidencePackCard';

interface ExportPackResult {
  readonly pack: Readonly<Record<string, Json>>;
  readonly signature: string;
}

export function ComplianceScreen(props: {
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
}) {
  const c = useT().compliance;
  const [frameworks, setFrameworks] = useState<readonly ComplianceFramework[]>([]);
  const [evidenceFrameworks, setEvidenceFrameworks] = useState<readonly EvidenceFrameworkRef[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const [exporting, setExporting] = useState(false);
  const [exportPack, setExportPack] = useState<ExportPackResult | null>(null);
  const [exportError, setExportError] = useState<unknown>(null);

  const exportBtnRef = useRef<HTMLButtonElement | null>(null);
  const selectedFwId = props.params.framework ?? '';

  const loadCompliance = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getCompliance();
      setFrameworks(res.frameworks);
      setEvidenceFrameworks(res.evidenceFrameworks ?? []);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCompliance();
  }, [loadCompliance]);

  const handleExport = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const res = await api.exportCompliance();
      setExportPack(res);
    } catch (err) {
      setExportError(err);
    } finally {
      setExporting(false);
    }
  };

  const handleDownloadJson = () => {
    if (!exportPack) return;
    const ver = String(exportPack.pack.policyVersion ?? 'bundle');
    const blob = new Blob([JSON.stringify(exportPack, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compliance-evidence-pack-${ver}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const visibleFrameworks = selectedFwId
    ? frameworks.filter((fw) => fw.id === selectedFwId)
    : frameworks;

  return (
    <section aria-labelledby="title-compliance">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-compliance">{c.title}</h1>
          <p className="screen-subtitle">
            {c.subtitle}
          </p>
        </div>
        <button ref={exportBtnRef} type="button" className="btn btn-primary" disabled={exporting} onClick={() => void handleExport()}>
          {exporting ? c.exporting : c.export}
        </button>
      </div>

      <div className="sr-only" role="status">
        {exporting ? c.exportingStatus : exportPack ? c.ready : ''}
      </div>

      {exportError ? <ErrorAlert error={exportError} contextTitle={c.exportError} /> : null}

      {exportPack ? (
        <div className="card" role="region" aria-label={c.packRegion}>
          <div className="card-title">
            <h2 style={{ margin: 0, font: 'inherit' }}>{c.packTitle(String(exportPack.pack.policyVersion ?? c.active))}</h2>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button type="button" className="btn btn-sm btn-primary" onClick={handleDownloadJson}>
                {c.download}
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  setExportPack(null);
                  exportBtnRef.current?.focus();
                }}
              >
                {c.dismiss}
              </button>
            </div>
          </div>
          <div className="grid-3" style={{ marginBottom: '12px' }}>
            <div className="kv-row">
              <span className="kv-label">{c.generated}</span>
              <span><DateText iso={typeof exportPack.pack.generatedAt === 'string' ? exportPack.pack.generatedAt : null} /></span>
            </div>
            <div className="kv-row">
              <span className="kv-label">{c.fingerprint}</span>
              <span className="mono">{String(exportPack.pack.policyFingerprint ?? '—').slice(0, 16)}</span>
            </div>
            <div className="kv-row">
              <span className="kv-label">{c.chainHead}</span>
              <span className="mono">{String(exportPack.pack.auditHead ?? '—').slice(0, 16)}</span>
            </div>
          </div>
          <div className="kv-row" style={{ marginBottom: '10px' }}>
            <span className="kv-label">{c.signature}</span>
            <span className="mono">{exportPack.signature}</span>
          </div>
          <pre className="code-block" style={{ maxHeight: '220px', overflowY: 'auto' }}>
            {JSON.stringify(exportPack, null, 2)}
          </pre>
        </div>
      ) : null}

      {!loading && !error && evidenceFrameworks.length > 0 ? <EvidencePackCard frameworks={evidenceFrameworks} /> : null}

      {loading ? <LoadingState label={c.loading} /> : null}
      {error ? <ErrorAlert error={error} contextTitle={c.loadError} onRetry={() => void loadCompliance()} /> : null}

      {!loading && !error ? (
        <div>
          <div className="tabs" role="group" aria-label={c.frameworks}>
            <button
              type="button"
              aria-pressed={selectedFwId === ''}
              className={selectedFwId === '' ? 'tab-btn active' : 'tab-btn'}
              onClick={() => props.setParams({ framework: undefined })}
            >
              {c.allFrameworks(frameworks.length)}
            </button>
            {frameworks.map((fw) => (
              <button
                key={fw.id}
                type="button"
                aria-pressed={selectedFwId === fw.id}
                className={selectedFwId === fw.id ? 'tab-btn active' : 'tab-btn'}
                onClick={() => props.setParams({ framework: fw.id })}
              >
                {fw.name} ({fw.controls.length})
              </button>
            ))}
          </div>

          {visibleFrameworks.length === 0 ? (
            <EmptyState title={c.noFrameworks} />
          ) : (
            visibleFrameworks.map((fw) => (
              <div key={fw.id} className="card">
                <h2 className="card-title">
                  <span>{fw.name}</span>
                  <span className="badge">{c.controlsCount(fw.controls.length)}</span>
                </h2>
                {fw.controls.length === 0 ? (
                  <EmptyState
                    title={c.noControls(fw.name)}
                    detail={c.noControlsDetail}
                  />
                ) : (
                  <div className="table-wrap">
                    <table aria-label={c.controlsTable(fw.name)}>
                      <thead>
                        <tr>
                          <th scope="col">{c.colControl}</th>
                          <th scope="col">{c.colTitle}</th>
                          <th scope="col">{c.colRules}</th>
                          <th scope="col" className="num">{c.colDecisions}</th>
                          <th scope="col" className="num">{c.colDenies}</th>
                          <th scope="col">{c.colLastSeen}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {fw.controls.map((ctrl) => (
                          <tr key={ctrl.id}>
                            <td className="mono"><strong>{ctrl.id}</strong></td>
                            <td>{ctrl.title}</td>
                            <td>
                              <div className="badge-group">
                                {ctrl.enforcedBy.map((rule) => (
                                  <a
                                    key={rule}
                                    href={buildHref('audit', { rule: rule.replace(/\.\*$/, '') })}
                                    className="rule-tag"
                                  >
                                    {rule}
                                  </a>
                                ))}
                              </div>
                            </td>
                            <td className="num mono">{ctrl.evidence.decisions}</td>
                            <td className="num">
                              <span className={ctrl.evidence.denies > 0 ? 'badge badge-deny' : 'badge'}>
                                {ctrl.evidence.denies}
                              </span>
                            </td>
                            <td><DateText iso={ctrl.evidence.lastSeen} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      ) : null}
    </section>
  );
}
