import { useEffect, useRef, useState, useCallback } from 'react';
import {
  api,
  ApiError,
  getSessionGeneration,
  onUnauthenticated,
  resetSessionGeneration,
  setCsrfToken,
} from './api/client';
import type { OverviewResponse, SessionResponse, SessionUser } from './api/types';
import { AppShell } from './components/AppShell';
import { ExplainDrawer, type ExplainTarget } from './components/ExplainDrawer';
import { FocusTrapModal } from './components/FocusTrapModal';
import { ErrorAlert, LoadingState } from './components/UiStates';
import { CATALOGUES, I18nProvider, readLang, writeLang, type Lang } from './i18n';
import { AccessReviewsScreen } from './screens/AccessReviewsScreen';
import { ApprovalsScreen } from './screens/ApprovalsScreen';
import { AttributeModelScreen } from './screens/AttributeModelScreen';
import { AuditExplorerScreen } from './screens/AuditExplorerScreen';
import { BreakGlassScreen } from './screens/BreakGlassScreen';
import { ComplianceScreen } from './screens/ComplianceScreen';
import { CredentialsScreen } from './screens/CredentialsScreen';
import { TwoStepScreen } from './screens/TwoStepScreen';
import { OverviewScreen } from './screens/OverviewScreen';
import { PoliciesScreen } from './screens/PoliciesScreen';
import { SignInScreen } from './screens/SignInScreen';
import { SimulatorScreen } from './screens/SimulatorScreen';
import { AccessMatrixScreen } from './screens/AccessMatrixScreen';
import { canAccessRoute, canUseSimulator } from './utils/permissions';
import { useHashRoute } from './utils/router';

// The server ends a session after 15 min without a request. Typing never reaches the server, so recent typing or
// clicks send a keep-alive often enough to stay inside that window.
const ACTIVITY_WINDOW_MS = 5 * 60_000;
const KEEP_ALIVE_EVERY_MS = 4 * 60_000;
const ACTIVITY_TICK_MS = 60_000;

function useKeepAlive(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    let lastActivity = Date.now();
    let lastPing = Date.now();
    const mark = () => { lastActivity = Date.now(); };
    const events = ['keydown', 'pointerdown', 'input'] as const;
    for (const e of events) window.addEventListener(e, mark, { capture: true, passive: true });
    const timer = window.setInterval(() => {
      const now = Date.now();
      if (now - lastActivity < ACTIVITY_WINDOW_MS && now - lastPing >= KEEP_ALIVE_EVERY_MS) {
        lastPing = now;
        // A 401 here opens the sign-in dialog through onUnauthenticated; other errors retry on the next tick.
        api.keepAlive().catch(() => undefined);
      }
    }, ACTIVITY_TICK_MS);
    return () => {
      window.clearInterval(timer);
      for (const e of events) window.removeEventListener(e, mark, { capture: true });
    };
  }, [active]);
}

export function App() {
  const { route, setParams } = useHashRoute();
  const [user, setUser] = useState<SessionUser | null>(null);
  const [bootstrapping, setBootstrapping] = useState(true);
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [explainTarget, setExplainTarget] = useState<ExplainTarget | null>(null);
  const [signOutError, setSignOutError] = useState<unknown>(null);
  // Expired while signed in: the screens stay mounted under a sign-in dialog, so nothing typed is lost.
  const [expired, setExpired] = useState(false);
  const [lang, setLang] = useState<Lang>(() => readLang());
  const t = CATALOGUES[lang];
  const userRef = useRef<SessionUser | null>(null);
  useEffect(() => { userRef.current = user; }, [user]);
  useKeepAlive(user !== null && !expired);
  useEffect(() => { document.documentElement.lang = lang; document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr'; }, [lang]);
  // each person keeps their own language on a shared browser
  const userId = user?.id;
  useEffect(() => { if (userId) setLang(readLang(userId)); }, [userId]);
  const changeLang = useCallback((next: Lang) => {
    setLang(next);
    if (userId) writeLang(userId, next);
  }, [userId]);

  useEffect(() => {
    onUnauthenticated(() => {
      resetSessionGeneration();
      if (userRef.current) {
        setExpired(true);
        return;
      }
      setUser(null);
      setOverview(null);
      setExplainTarget(null);
      setSignOutError(null);
    });
    return () => {
      onUnauthenticated(null);
    };
  }, []);

  const refreshOverview = useCallback(async () => {
    const gen = getSessionGeneration();
    try {
      const ov = await api.getOverview();
      if (getSessionGeneration() === gen) {
        setOverview(ov);
      }
    } catch {
      // Overview error handled inside OverviewScreen if active
    }
  }, []);

  const handleOverviewLoaded = useCallback((ov: OverviewResponse, reqGen: number) => {
    if (getSessionGeneration() === reqGen) {
      setOverview(ov);
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    const onFocus = () => {
      void refreshOverview();
    };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [user, refreshOverview]);

  useEffect(() => {
    let active = true;
    const gen = getSessionGeneration();
    (async () => {
      try {
        const sess = await api.getSession();
        if (!active || getSessionGeneration() !== gen) return;
        setUser(sess.user);
        const ov = await api.getOverview();
        if (active && getSessionGeneration() === gen) {
          setOverview(ov);
        }
      } catch {
        if (active && getSessionGeneration() === gen) {
          setUser(null);
        }
      } finally {
        if (active) setBootstrapping(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const handleSignedIn = useCallback(
    (session: SessionResponse) => {
      setExpired(false);
      setSignOutError(null);
      // Same person after an expiry: keep the page as it is. Someone else: AppShell's key remounts every screen.
      if (userRef.current?.id !== session.user.id) {
        setOverview(null);
        setExplainTarget(null);
      }
      setUser(session.user);
      void refreshOverview();
    },
    [refreshOverview],
  );

  const handleSignOut = useCallback(async () => {
    setSignOutError(null);
    try {
      await api.signOut();
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) {
        setSignOutError(err);
        return;
      }
      resetSessionGeneration();
      setCsrfToken(null);
    }
    setExpired(false);
    setUser(null);
    setOverview(null);
    setExplainTarget(null);
  }, []);

  const handleCloseExplain = useCallback(() => {
    setExplainTarget(null);
  }, []);

  if (bootstrapping) {
    return (
      <I18nProvider lang={lang}>
        <div className="signin-layout">
          <div className="signin-card">
            <LoadingState label={t.signIn.loading} />
          </div>
        </div>
      </I18nProvider>
    );
  }

  if (!user) {
    return <I18nProvider lang={lang}><SignInScreen onSignedIn={handleSignedIn} /></I18nProvider>;
  }

  const allowed = canAccessRoute(user.roles, route.path);
  const allowSimulator = canUseSimulator(user.roles);

  return (
    <I18nProvider lang={lang}>
      <AppShell
        key={user.id}
        user={user}
        currentPath={route.path}
        overview={overview}
        onSignOut={() => void handleSignOut()}
        lang={lang}
        onLang={changeLang}
      >
        {signOutError ? (
          <ErrorAlert
            error={signOutError}
            contextTitle={t.shell.signOutFailed}
            onRetry={() => void handleSignOut()}
          />
        ) : null}

        {!allowed ? (
          <ErrorAlert
            error={new Error(t.shell.signedInAs(user.roles.map((r) => t.common.roles[r] ?? r).join(t.shell.and)))}
            contextTitle={t.shell.notYourRole}
          />
        ) : route.path === 'overview' ? (
          <OverviewScreen roles={user.roles} userName={user.name} onOverviewLoaded={handleOverviewLoaded} />
        ) : route.path === 'model' ? (
          <AttributeModelScreen roles={user.roles} params={route.params} setParams={setParams} />
        ) : route.path === 'policies' ? (
          <PoliciesScreen roles={user.roles} params={route.params} setParams={setParams} />
        ) : route.path === 'matrix' ? (
          <AccessMatrixScreen params={route.params} setParams={setParams} onExplain={setExplainTarget} />
        ) : route.path === 'simulator' ? (
          <SimulatorScreen
            roles={user.roles}
            params={route.params}
            setParams={setParams}
            onExplain={setExplainTarget}
          />
        ) : route.path === 'approvals' ? (
          <ApprovalsScreen
            user={user}
            params={route.params}
            setParams={setParams}
            onExplain={allowSimulator ? setExplainTarget : undefined}
            onApprovalChanged={() => void refreshOverview()}
          />
        ) : route.path === 'break-glass' ? (
          <BreakGlassScreen user={user} onBreakGlassChanged={() => void refreshOverview()} />
        ) : route.path === 'reviews' ? (
          <AccessReviewsScreen
            user={user}
            params={route.params}
            setParams={setParams}
            onChangeCreated={() => void refreshOverview()}
          />
        ) : route.path === 'credentials' ? (
          <CredentialsScreen roles={user.roles} />
        ) : route.path === 'two-step' ? (
          <TwoStepScreen />
        ) : route.path === 'audit' ? (
          <AuditExplorerScreen
            roles={user.roles}
            params={route.params}
            setParams={setParams}
            onExplain={allowSimulator ? setExplainTarget : undefined}
          />
        ) : (
          <ComplianceScreen params={route.params} setParams={setParams} />
        )}
      </AppShell>

      <ExplainDrawer target={allowSimulator && !expired ? explainTarget : null} onClose={handleCloseExplain} />

      <FocusTrapModal
        open={expired}
        titleId="reauth-title"
        title={t.shell.sessionExpired}
        variant="modal"
      >
        <SignInScreen embedded onSignedIn={handleSignedIn} />
      </FocusTrapModal>
    </I18nProvider>
  );
}
