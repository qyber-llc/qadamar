import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../api/client';
import { QrCode } from '../components/QrCode';
import { ErrorAlert, LoadingState } from '../components/UiStates';
import { useT } from '../i18n';
import '../styles/operations.css';

type Status = { readonly active: boolean; readonly pending: boolean; readonly available: boolean };
type Loaded = { readonly status: Status } | { readonly sso: true } | { readonly error: unknown };

const isStatus = (err: unknown, status: number) => err instanceof ApiError && err.status === status;
const secretOf = (uri: string): string => {
  try {
    return new URL(uri).searchParams.get('secret') ?? '';
  } catch {
    return '';
  }
};

/** docs/API.md §3.1.2: TOTP for the signed-in local account. The otpauth URI and the recovery codes come back once:
 *  they live in this screen's state only and leave it when the setup ends or the screen unmounts. */
export function TwoStepScreen() {
  const t = useT();
  const s = t.twoStep;
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [uri, setUri] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<readonly string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [fieldError, setFieldError] = useState<{ readonly field: 'password' | 'code'; readonly text: string } | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState('');
  const [copy, setCopy] = useState<'idle' | 'copied' | 'failed'>('idle');
  const stepRef = useRef<HTMLHeadingElement | null>(null);
  const recoveryRef = useRef<HTMLHeadingElement | null>(null);
  const codesRef = useRef<HTMLTextAreaElement | null>(null);

  const load = useCallback(async () => {
    try {
      setLoaded({ status: await api.getTotpStatus() });
    } catch (err) {
      setLoaded(isStatus(err, 403) ? { sso: true } : { error: err });
    }
  }, []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (uri) stepRef.current?.focus(); }, [uri]);
  useEffect(() => { if (recovery) recoveryRef.current?.focus(); }, [recovery]);

  /** Runs one request; onRefused shows a refusal it knows at its field (true), anything else becomes the alert. */
  const run = async (action: () => Promise<void>, onRefused: (err: unknown) => boolean) => {
    setBusy(true);
    setActionError(null);
    setFieldError(null);
    setNotice('');
    try {
      await action();
    } catch (err) {
      if (!onRefused(err)) setActionError(err);
    } finally {
      setBusy(false);
    }
  };

  const start = () => {
    if (!password) {
      setFieldError({ field: 'password', text: s.passwordRequired });
      document.getElementById('two-step-password')?.focus();
      return;
    }
    void run(async () => {
      const res = await api.enrolTotp(password);
      setPassword('');
      setCode('');
      setUri(res.otpauthUri);
      setNotice(s.startedNotice);
    }, (err) => {
      if (!isStatus(err, 403)) return false;
      setFieldError({ field: 'password', text: s.wrongPassword });
      document.getElementById('two-step-password')?.focus();
      return true;
    });
  };

  const activate = () => {
    const digits = code.replace(/\s/g, '');
    if (!/^\d{6}$/.test(digits)) {
      setFieldError({ field: 'code', text: s.codeFormat });
      document.getElementById('two-step-code')?.focus();
      return;
    }
    void run(async () => {
      const res = await api.activateTotp(digits);
      setUri(null);
      setCode('');
      setRecovery(res.recoveryCodes);
      setCopy('idle');
      setNotice(s.enabledNotice);
      await load();
    }, (err) => {
      if (!isStatus(err, 422)) return false;
      setFieldError({ field: 'code', text: s.wrongCode });
      document.getElementById('two-step-code')?.focus();
      return true;
    });
  };

  const copyCodes = async () => {
    try {
      await navigator.clipboard.writeText((recovery ?? []).join('\n'));
      setCopy('copied');
    } catch {
      codesRef.current?.select();
      setCopy('failed');
    }
  };

  const status = loaded && 'status' in loaded ? loaded.status : null;
  const describe = (field: 'password' | 'code', hint?: string) =>
    [fieldError?.field === field ? `two-step-${field}-error` : '', hint ?? ''].filter(Boolean).join(' ') || undefined;
  const fieldErrorFor = (field: 'password' | 'code') =>
    fieldError?.field === field ? <p id={`two-step-${field}-error`} className="field-error" role="alert">{fieldError.text}</p> : null;

  return (
    <section className="operations-screen" aria-labelledby="title-two-step">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-two-step">{s.title}</h1>
          <p className="screen-subtitle">{s.subtitle}</p>
        </div>
      </div>

      <div className="sr-only" role="status">{notice}</div>
      {actionError ? <ErrorAlert error={actionError} contextTitle={s.actionFailed} /> : null}

      {recovery ? (
        <div className="alert-warn secret-panel" role="region" aria-labelledby="two-step-recovery-title">
          <h2 className="card-title" id="two-step-recovery-title" tabIndex={-1} ref={recoveryRef}>{s.recoveryTitle}</h2>
          <p className="secret-warning">{s.recoveryIntro}</p>
          <label htmlFor="two-step-recovery-codes">{s.recoveryLabel}</label>
          <textarea
            id="two-step-recovery-codes"
            ref={codesRef}
            className="mono two-step-codes"
            readOnly
            rows={recovery.length}
            value={recovery.join('\n')}
            spellCheck={false}
          />
          <div className="secret-row">
            <button type="button" className="btn btn-sm btn-primary" onClick={() => void copyCodes()}>{copy === 'copied' ? t.common.copied : s.copyAll}</button>
            <button type="button" className="btn btn-sm" onClick={() => setRecovery(null)}>{s.done}</button>
          </div>
          <div className="metric-sub" role="status" aria-live="polite">
            {copy === 'copied' ? s.copied : copy === 'failed' ? s.copyFailed : ''}
          </div>
        </div>
      ) : null}

      {!loaded ? <LoadingState label={s.loading} /> : 'sso' in loaded ? (
        <div className="notice-box" role="status">{s.sso}</div>
      ) : 'error' in loaded ? (
        <ErrorAlert error={loaded.error} contextTitle={s.loadFailed} onRetry={() => void load()} />
      ) : (
        <div className="card" role="region" aria-labelledby="two-step-status-title">
          <h2 className="card-title" id="two-step-status-title">
            <span>{s.statusTitle}</span>
            <span className={status?.active ? 'badge badge-allow' : status?.pending ? 'badge badge-warn' : 'badge'}>
              {status?.active ? s.on : status?.pending ? s.pending : s.off}
            </span>
          </h2>
          <p className="metric-sub">{status?.active ? s.onDetail : s.offDetail}</p>
          {status?.active ? <p className="metric-sub">{s.lostDevice}</p> : null}
          {!status?.active && !status?.available ? <div className="notice-box" role="status">{s.unavailable}</div> : null}
          {!status?.active && status?.available && status.pending && !uri ? <div className="notice-box">{s.pendingLost}</div> : null}

          {!status?.active && status?.available && !uri ? (
            <form className="two-step-form" noValidate onSubmit={(e) => { e.preventDefault(); start(); }}>
              <h3 className="two-step-step">{s.step1}</h3>
              <p className="metric-sub">{s.step1Intro}</p>
              <div className="form-group">
                <label htmlFor="two-step-password">{s.password}</label>
                <input
                  id="two-step-password"
                  type="password"
                  autoComplete="current-password"
                  required
                  aria-invalid={fieldError?.field === 'password'}
                  aria-describedby={describe('password')}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  readOnly={busy}
                />
                {fieldErrorFor('password')}
              </div>
              <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? s.starting : status.pending ? s.restart : s.start}</button>
            </form>
          ) : null}

          {uri ? (
            <form className="two-step-form" noValidate onSubmit={(e) => { e.preventDefault(); activate(); }}>
              <h3 className="two-step-step" tabIndex={-1} ref={stepRef}>{s.step2}</h3>
              <p className="metric-sub">{s.step2Intro}</p>
              <div className="two-step-enrol">
                <div className="two-step-qr">
                  <QrCode text={uri} label={s.qrLabel} />
                </div>
                <div className="two-step-keys">
                  <p className="secret-warning">{s.secretWarning}</p>
                  <div className="form-group">
                    <label htmlFor="two-step-key">{s.key}</label>
                    <input id="two-step-key" className="mono" type="text" readOnly value={secretOf(uri)} spellCheck={false} autoComplete="off" onFocus={(e) => e.currentTarget.select()} />
                  </div>
                  <div className="form-group">
                    <label htmlFor="two-step-uri">{s.uri}</label>
                    <input id="two-step-uri" className="mono" type="text" readOnly value={uri} spellCheck={false} autoComplete="off" onFocus={(e) => e.currentTarget.select()} />
                  </div>
                </div>
              </div>
              <h3 className="two-step-step">{s.step3}</h3>
              <div className="form-group">
                <label htmlFor="two-step-code">{s.code}</label>
                <input
                  id="two-step-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={7}
                  required
                  aria-invalid={fieldError?.field === 'code'}
                  aria-describedby={describe('code', 'two-step-code-hint')}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  readOnly={busy}
                />
                <p id="two-step-code-hint" className="metric-sub">{s.codeHint}</p>
                {fieldErrorFor('code')}
              </div>
              <div className="secret-row">
                <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? s.activating : s.activate}</button>
                <button type="button" className="btn" disabled={busy} onClick={() => { setUri(null); setCode(''); setFieldError(null); }}>{s.cancel}</button>
              </div>
            </form>
          ) : null}
        </div>
      )}
    </section>
  );
}
