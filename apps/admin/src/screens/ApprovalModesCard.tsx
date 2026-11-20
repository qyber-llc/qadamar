import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { ApprovalMode, ApprovalModeItem } from '../api/types';
import { DateText, EmptyState, ErrorAlert, LoadingState } from '../components/UiStates';
import { useT } from '../i18n';

/** docs/API.md §3.5.1: each approver decides one change at a time (individual) or several with one note (list). Access
 *  admins and security officers switch it, at once and audited; the server enforces it on the bulk route. */
export function ApprovalModesCard() {
  const s = useT().security.modes;
  const [items, setItems] = useState<readonly ApprovalModeItem[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');

  const load = useCallback(async () => {
    setLoadError(null);
    try { setItems((await api.getApprovalModes()).items); } catch (err) { setLoadError(err); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const change = async (id: string, mode: ApprovalMode) => {
    setBusy(true);
    setActionError(null);
    setNotice('');
    try {
      await api.setApprovalMode(id, mode);
      setNotice(s.setNotice(id, mode === 'list' ? s.list : s.individual));
      await load();
    } catch (err) {
      setActionError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" role="region" aria-labelledby="approval-modes-title">
      <h2 className="card-title" id="approval-modes-title"><span>{s.title}</span></h2>
      <p className="metric-sub">{s.intro}</p>
      <div className="sr-only" role="status">{notice}</div>
      {actionError ? <ErrorAlert error={actionError} contextTitle={s.title} /> : null}
      {loadError ? <ErrorAlert error={loadError} contextTitle={s.title} onRetry={() => void load()} /> : !items ? <LoadingState label={s.loading} /> : items.length === 0 ? (
        <EmptyState title={s.empty} />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>{s.colApprover}</th><th>{s.colMode}</th><th>{s.colSetBy}</th></tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td className="mono">{item.id}</td>
                  <td>
                    <select aria-label={s.modeFor(item.id)} value={item.mode} disabled={busy} onChange={(e) => void change(item.id, e.target.value as ApprovalMode)}>
                      <option value="individual">{s.individual}</option>
                      <option value="list">{s.list}</option>
                    </select>
                  </td>
                  <td className="operations-meta">{item.setBy ? <><span className="mono">{item.setBy}</span> · <DateText iso={item.at} /></> : s.never}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
