import { useEffect, useRef, useState } from 'react';
import { useT } from '../i18n';

/** A secret the server returns once. It lives only in the screen's state: "I have stored it", a new secret or
 *  leaving the screen (unmount) clears it; it never reaches the URL or storage. */
export function SecretPanel(props: { readonly name: string; readonly secret: string; readonly onDone: () => void }) {
  const t = useT();
  const [copy, setCopy] = useState<'idle' | 'copied' | 'failed'>('idle');
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    setCopy('idle');
    headingRef.current?.focus();
  }, [props.secret]);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(props.secret);
      setCopy('copied');
    } catch {
      // no clipboard (plain http, denied): select the text for a manual copy
      inputRef.current?.select();
      setCopy('failed');
    }
  };

  return (
    <div className="alert-warn secret-panel" role="region" aria-labelledby="secret-panel-title">
      <h2 className="card-title" id="secret-panel-title" tabIndex={-1} ref={headingRef}>{t.security.secret.heading(props.name)}</h2>
      <p className="secret-warning">{t.security.secret.warning}</p>
      <label htmlFor="secret-panel-value">{t.security.secret.label}</label>
      <div className="secret-row">
        <input
          id="secret-panel-value"
          ref={inputRef}
          className="mono"
          type="text"
          readOnly
          value={props.secret}
          autoComplete="off"
          spellCheck={false}
          onFocus={(e) => e.currentTarget.select()}
        />
        <button type="button" className="btn btn-sm btn-primary" onClick={() => void onCopy()}>
          {copy === 'copied' ? t.common.copied : t.common.copy}
        </button>
        <button type="button" className="btn btn-sm" onClick={props.onDone}>{t.security.secret.done}</button>
      </div>
      <div className="metric-sub" role="status" aria-live="polite">
        {copy === 'copied' ? t.security.secret.copied : copy === 'failed' ? t.security.secret.copyFailed : ''}
      </div>
    </div>
  );
}
