import { useState } from 'react';
import { api } from '../api/client';
import type { EvidenceFrameworkRef, EvidencePackResult } from '../api/types';
import { DateText, ErrorAlert } from '../components/UiStates';
import { useT } from '../i18n';

/** Per-framework evidence pack: live sections, a manifest of their hashes and its detached signature (docs/API.md §3.8). */
export function EvidencePackCard(props: { readonly frameworks: readonly EvidenceFrameworkRef[] }) {
  const c = useT().compliance;
  const [framework, setFramework] = useState(props.frameworks[0]?.id ?? '');
  const [pseudonymise, setPseudonymise] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<EvidencePackResult | null>(null);
  const [error, setError] = useState<unknown>(null);

  const handleExport = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.exportEvidencePack(framework, pseudonymise));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `evidence-pack-${result.manifest.framework}-${result.manifest.generatedAt.replace(/[^0-9TZ]/g, '')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="card" role="region" aria-labelledby="evidence-pack-title">
      <h2 className="card-title" id="evidence-pack-title">{c.evidenceTitle}</h2>
      <p className="screen-subtitle">{c.evidenceIntro}</p>
      <p className="screen-subtitle">{c.evidenceDisclaimer}</p>
      <div className="filter-bar">
        <div className="form-group">
          <label htmlFor="evidence-framework-select">{c.evidenceFramework}</label>
          <select id="evidence-framework-select" value={framework} onChange={(e) => { setFramework(e.target.value); setResult(null); }}>
            {props.frameworks.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="evidence-pseudonymise">
            <input id="evidence-pseudonymise" type="checkbox" checked={pseudonymise} onChange={(e) => { setPseudonymise(e.target.checked); setResult(null); }} />
            {' '}{c.evidencePseudonymise}
          </label>
        </div>
        <button type="button" className="btn btn-primary" disabled={busy || !framework} onClick={() => void handleExport()}>
          {busy ? c.evidenceExporting : c.evidenceExport}
        </button>
      </div>
      <div className="sr-only" role="status">{busy ? c.evidenceExporting : result ? c.evidenceReady : ''}</div>
      {error ? <ErrorAlert error={error} contextTitle={c.evidenceError} /> : null}
      {result ? (
        <div role="region" aria-label={c.evidenceRegion}>
          <div className="grid-3" style={{ marginBottom: '12px' }}>
            <div className="kv-row">
              <span className="kv-label">{c.generated}</span>
              <span><DateText iso={result.manifest.generatedAt} /></span>
            </div>
            <div className="kv-row">
              <span className="kv-label">{c.evidencePackHash}</span>
              <span className="mono">{result.manifest.packSha256.slice(0, 16)}</span>
            </div>
            <button type="button" className="btn btn-sm btn-primary" onClick={handleDownload}>{c.download}</button>
          </div>
          <div className="kv-row" style={{ marginBottom: '10px' }}>
            <span className="kv-label">{c.signature}</span>
            <span className="mono">{result.signature}</span>
          </div>
          <div className="table-wrap">
            <table aria-label={c.evidenceSections(result.manifest.framework)}>
              <thead>
                <tr>
                  <th scope="col">{c.evidenceSection}</th>
                  <th scope="col">{c.evidenceHash}</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(result.manifest.sections).map(([name, hash]) => (
                  <tr key={name}>
                    <td className="mono">{name}</td>
                    <td className="mono">{hash}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}
