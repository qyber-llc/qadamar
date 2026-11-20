import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { api, ApiError } from '../api/client';
import { errorText } from '../api/errorText';
import type { SessionResponse } from '../api/types';
import { GateEmblem } from '../components/GateEmblem';
import '../styles/gate-skin.css';
import { PRODUCT_NAME, PRODUCT_PUBLISHER } from '../brand';
import { useT } from '../i18n';

type AuthMethods = { password: boolean; sso: boolean; saml: boolean };
/** One link per identity provider sign-in the server offers (OIDC, SAML), above the password form when there is one. */
export function IdpSignInLinks({ methods }: { readonly methods: AuthMethods }) {
  const t = useT();
  const links = [methods.sso ? { href: '/admin/v1/oidc/login', label: t.signIn.sso } : null, methods.saml ? { href: '/admin/v1/saml/login', label: t.signIn.saml } : null]
    .filter((l): l is { href: string; label: string } => l !== null);
  return (
    <>
      {links.map((l, i) => (
        <a key={l.href} className="btn btn-primary" href={l.href} style={{ display: 'block', width: '100%', textAlign: 'center', marginBottom: methods.password || i < links.length - 1 ? '16px' : 0 }}>
          {l.label}
        </a>
      ))}
    </>
  );
}

export function SignInScreen(props: {
  readonly onSignedIn: (session: SessionResponse) => void;
  /** Inside the session-expired dialog: no page chrome, the page behind keeps what was typed. */
  readonly embedded?: boolean;
}) {
  const t = useT();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isLockedOut, setIsLockedOut] = useState(false);
  const [retryDeadlineMs, setRetryDeadlineMs] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [invalid, setInvalid] = useState({ username: false, password: false });
  const [methods, setMethods] = useState<AuthMethods>({ password: true, sso: false, saml: false });

  useEffect(() => {
    void api.authMethods().then(setMethods).catch(() => undefined); // unknown: keep the password form
    const code = new URLSearchParams(window.location.search).get('sso_error');
    if (!code) return;
    const errors: Readonly<Record<string, string>> = t.signIn.ssoErrors;
    setErrorMessage(errors[code] ?? t.signIn.ssoErrors.sso_failed);
    window.history.replaceState(null, '', window.location.pathname + window.location.hash);
  }, []);

  useEffect(() => {
    if (retryDeadlineMs === null) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => {
      const current = Date.now();
      setNowMs(current);
      if (current >= retryDeadlineMs) {
        window.clearInterval(timer);
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [retryDeadlineMs]);

  const retrySeconds =
    retryDeadlineMs !== null ? Math.max(0, Math.ceil((retryDeadlineMs - nowMs) / 1000)) : null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmedUser = username.trim();
    if (!trimmedUser || !password) {
      setErrorMessage(t.signIn.missingFields);
      setIsLockedOut(false);
      setInvalid({ username: !trimmedUser, password: !password });
      document.getElementById(!trimmedUser ? 'signin-username' : 'signin-password')?.focus();
      return;
    }

    setSubmitting(true);
    setInvalid({ username: false, password: false });
    setErrorMessage(null);
    setIsLockedOut(false);
    setRetryDeadlineMs(null);

    try {
      const session = await api.signIn(trimmedUser, password, code.trim());
      setPassword(''); setCode('');
      props.onSignedIn(session);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429 || err.code === 'rate_limited') {
          setIsLockedOut(true);
          const deadline =
            err.retryDeadlineMs ??
            (err.retryAfter !== null ? Date.now() + err.retryAfter * 1000 : null);
          setRetryDeadlineMs(deadline);
          setNowMs(Date.now());
          setErrorMessage(t.signIn.lockedDetail);
        } else if (err.code !== 'password_login_disabled' && (err.status === 401 || err.status === 400 || err.status === 403)) {
          setErrorMessage(t.signIn.invalidCredentials);
          setInvalid({ username: true, password: true });
        } else {
          setErrorMessage(errorText(t, err).text);
        }
      } else {
        setErrorMessage(t.signIn.unreachable);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Wrapper embedded={props.embedded === true}>
        {props.embedded ? (
          <p className="metric-sub" style={{ margin: '0 0 16px 0' }}>
            {t.signIn.expiredIntro}
          </p>
        ) : (
        <div style={{ marginBottom: '20px' }}>
          <div className="brand" style={{ marginBottom: '8px' }}>
            <span>{PRODUCT_NAME}</span>
            <span className="brand-tag">by {PRODUCT_PUBLISHER}</span>
          </div>
          <h1 id="signin-title" className="signin-title">
            {t.signIn.title}
          </h1>
          <p className="metric-sub" style={{ margin: '4px 0 0 0' }}>
            {t.signIn.intro}
          </p>
        </div>
        )}

        {errorMessage ? (
          <div className={isLockedOut ? 'alert-warn' : 'alert-error'}>
            <div role="alert" id="signin-error">
              <div style={{ fontWeight: 600, marginBottom: '2px' }}>
                {isLockedOut ? t.signIn.locked : t.signIn.failed}
              </div>
              <div>{errorMessage}</div>
            </div>
            {retrySeconds !== null ? (
              <div className="mono" role="timer" style={{ marginTop: '6px', fontSize: '12px' }}>
                {t.signIn.retryIn(retrySeconds)}
              </div>
            ) : null}
          </div>
        ) : null}

        <IdpSignInLinks methods={methods} />

        {methods.password ? (
        <form onSubmit={(e) => void handleSubmit(e)} noValidate>
          <div className="form-group" style={{ marginBottom: '12px' }}>
            <label htmlFor="signin-username">{t.signIn.username}</label>
            <input
              id="signin-username"
              name="username"
              type="text"
              autoComplete="username"
              required
              aria-invalid={invalid.username}
              aria-describedby={invalid.username ? 'signin-error' : undefined}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              readOnly={submitting}
            />
          </div>

          <div className="form-group" style={{ marginBottom: '16px' }}>
            <label htmlFor="signin-password">{t.signIn.password}</label>
            <input
              id="signin-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              aria-invalid={invalid.password}
              aria-describedby={invalid.password ? 'signin-error' : undefined}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              readOnly={submitting}
            />
          </div>

          <div className="form-group" style={{ marginBottom: '16px' }}>
            <label htmlFor="signin-code">{t.signIn.code}</label>
            <input
              id="signin-code"
              name="code"
              type="text"
              inputMode="text"
              autoComplete="one-time-code"
              aria-describedby="signin-code-hint"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              readOnly={submitting}
            />
            <p id="signin-code-hint" className="metric-sub" style={{ margin: '4px 0 0 0' }}>
              {t.signIn.codeHint}
            </p>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%' }}
            disabled={submitting}
          >
            {submitting ? t.signIn.submitting : methods.sso || methods.saml ? t.signIn.submitLocal : t.signIn.submit}
          </button>
        </form>
        ) : null}

        <p className="metric-sub" style={{ margin: '20px 0 0 0', paddingTop: '12px', borderTop: '1px solid var(--border-color)' }}>
          {t.signIn.footer}
        </p>
    </Wrapper>
  );
}

function Wrapper(props: { readonly embedded: boolean; readonly children: ReactNode }) {
  if (props.embedded) return <div>{props.children}</div>;
  return (
    <main className="signin-wrap signin-splash" aria-labelledby="signin-title">
      <div className="signin-card">{props.children}</div>
      <GateEmblem name={PRODUCT_NAME} />
    </main>
  );
}
