// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — App.jsx (intro timing, page travel, rail state).
import { useState, useEffect, useLayoutEffect, useRef, useCallback, type CSSProperties, type ReactNode } from 'react';
import '../styles/a11y.css';
import '../styles/v24-shell.css';
import '../styles/gate-skin.css';
import type { OverviewResponse, SessionUser } from '../api/types';
import { buildHref, navigate, type RoutePath } from '../utils/router';
import { PRODUCT_NAME } from '../brand';
import { useT, type Lang } from '../i18n';
import { SpatialRail } from './SpatialRail';
import { Boot } from './v24/Boot';
import { useStageFx } from './v24/fx';
import { BOOT_BASE, BOOT_MS, prefersReduced, readMotionPref, useReveal, writeMotionPref } from './v24/motion';
import { V24Sidebar } from './v24/Sidebar';

const RAIL_KEY = 'qadamar-rail';
const readRail = (): boolean => {
  try {
    return window.localStorage.getItem(RAIL_KEY) !== 'folded';
  } catch {
    return true;
  }
};

/** The console in one glass window on carbon, with the Glassy Dashboard v24 sidebar floating on its left (open or
 *  folded into a dock), the key figures as pills in the header, the page and the at-a-glance column inside the
 *  window. An intro plays when the console opens; screens sink away and rise in as you move between them. */
export function AppShell(props: {
  readonly user: SessionUser;
  readonly currentPath: RoutePath;
  readonly overview: OverviewResponse | null;
  readonly onSignOut: () => void;
  readonly lang: Lang;
  readonly onLang: (lang: Lang) => void;
  readonly children: ReactNode;
}) {
  const sh = useT().shell;
  const [reduceMotion, setReduceMotion] = useState(readMotionPref);
  const [railOpen, setRailOpen] = useState(readRail);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [infoOpen, setInfoOpen] = useState(false);
  const [booting, setBooting] = useState(() => !prefersReduced());
  const [leaving, setLeaving] = useState(false);
  const infoBtnRef = useRef<HTMLButtonElement | null>(null);
  const mainRef = useRef<HTMLElement | null>(null);
  const leaveTimer = useRef(0);

  useStageFx();
  useReveal(mainRef, props.currentPath);

  useLayoutEffect(() => {
    document.documentElement.dataset.booting = booting ? '1' : '0';
  }, [booting]);
  useEffect(() => {
    if (!booting) return undefined;
    const t = window.setTimeout(() => setBooting(false), BOOT_MS);
    return () => window.clearTimeout(t);
  }, [booting]);

  useEffect(() => {
    try {
      window.localStorage.setItem(RAIL_KEY, railOpen ? 'open' : 'folded');
    } catch {
      // storage blocked: the choice lasts for this page only
    }
  }, [railOpen]);

  useEffect(() => {
    window.clearTimeout(leaveTimer.current);
    setLeaving(false);
    setMobileOpen(false);
    setInfoOpen(false);
  }, [props.currentPath]);
  useEffect(() => () => window.clearTimeout(leaveTimer.current), []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (infoOpen) infoBtnRef.current?.focus();
      setInfoOpen(false);
      setMobileOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [infoOpen]);

  const toggleRail = useCallback(() => setRailOpen((o) => !o), []);

  const onReduceMotion = useCallback((reduced: boolean) => {
    writeMotionPref(reduced);
    setReduceMotion(reduced);
    if (reduced) setBooting(false);
  }, []);

  /** The old screen's cards sink away, then the new screen rises in (straight there under reduced motion). */
  const travel = useCallback((path: RoutePath) => {
    setMobileOpen(false);
    if (path === props.currentPath || prefersReduced()) {
      navigate(path);
      return;
    }
    setLeaving(true);
    window.clearTimeout(leaveTimer.current);
    leaveTimer.current = window.setTimeout(() => {
      navigate(path);
      window.scrollTo({ top: 0 });
    }, 230);
  }, [props.currentPath]);

  const ov = props.overview;
  const chainVerified = ov ? ov.audit.verified : true;
  const rootClass = ['v24', railOpen ? 'rail-open' : 'rail-folded', booting ? 'booting' : ''].filter(Boolean).join(' ');

  return (
    <>
      {booting ? <Boot /> : null}
      <div id="app-shell-root" className={rootClass} style={{ '--base': booting ? `${BOOT_BASE}ms` : '0ms' } as CSSProperties}>
        <a
          href="#mainContent"
          className="skip-link"
          onClick={(e) => {
            e.preventDefault();
            const main = document.getElementById('mainContent');
            if (main instanceof HTMLElement) main.focus();
          }}
        >
          {sh.skip}
        </a>

        <V24Sidebar
          user={props.user}
          currentPath={props.currentPath}
          overview={ov}
          open={railOpen}
          onToggle={toggleRail}
          mobileOpen={mobileOpen}
          onNavigate={travel}
          onSignOut={props.onSignOut}
          reduceMotion={reduceMotion}
          onReduceMotion={onReduceMotion}
          lang={props.lang}
          onLang={props.onLang}
        />

        <header className="topbar" role="banner">
          <div className="topbar-left">
            <div className="brand v24-phone-only">
              <span>{PRODUCT_NAME}</span>
            </div>
          </div>

          <div className="topbar-right">
            {ov ? (
              <ul className="hdr-pills desktop-only" aria-label={sh.keyFigures}>
                <li>
                  <a className="hdr-pill" href={buildHref('approvals')}>
                    <span className="hdr-pill-dot" aria-hidden="true" />
                    <span><small>{sh.pendingApprovals}</small><b>{ov.counts.pendingChanges}</b></span>
                  </a>
                </li>
                <li>
                  <a className="hdr-pill" href={buildHref('break-glass')}>
                    <span className="hdr-pill-dot" data-tone={ov.counts.activeBreakGlass > 0 ? 'warn' : undefined} aria-hidden="true" />
                    <span><small>{sh.breakGlass}</small><b>{ov.counts.activeBreakGlass}</b></span>
                  </a>
                </li>
                <li>
                  <a className="hdr-pill" href={buildHref('audit')} title={chainVerified ? sh.chainVerified : sh.chainIntegrityError}>
                    <span className="hdr-pill-dot" data-tone={chainVerified ? 'ok' : 'bad'} aria-hidden="true" />
                    <span><small>{chainVerified ? sh.chainVerified : sh.chainBroken}</small><b>{ov.audit.length}</b></span>
                  </a>
                </li>
              </ul>
            ) : null}
            {ov ? <span className="sr-only" role="status">{chainVerified ? sh.chainVerified : sh.chainBroken}</span> : null}

            <div className="popover-wrap desktop-only">
              <button
                ref={infoBtnRef}
                type="button"
                className="btn btn-sm v24-mag"
                aria-expanded={infoOpen}
                aria-haspopup="dialog"
                onClick={() => setInfoOpen((prev) => !prev)}
              >
                {sh.invariants}
              </button>
              {infoOpen ? (
                <div className="popover-panel" role="dialog" aria-label={sh.invariantsLabel}>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>{sh.invariantsTitle}</div>
                  <p style={{ margin: '0 0 8px 0' }}>
                    {sh.invariantsMetadata}
                  </p>
                  <p style={{ margin: 0 }}>
                    {sh.invariantsScope}
                  </p>
                </div>
              ) : null}
            </div>

            <button
              type="button"
              className="menu-toggle"
              aria-expanded={mobileOpen}
              aria-controls="appSidebar"
              onClick={() => setMobileOpen((prev) => !prev)}
            >
              {sh.menu}
            </button>
          </div>
        </header>

        <div className="layout">
          <main aria-label={sh.nav[props.currentPath]} className={leaving ? 'main-content leaving' : 'main-content'} id="mainContent" tabIndex={-1} ref={mainRef}>
            <div className="v24-page" key={props.currentPath}>
              {props.children}
            </div>
          </main>
          {props.currentPath === 'overview' ? <SpatialRail overview={ov} /> : null}
        </div>
      </div>
    </>
  );
}
