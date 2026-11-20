// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — components/Rail.jsx.
// Visual direction (no code) after CodeXR's Glassy Sidebar V7, at the owner's request.
import {
  useCallback, useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore,
  type CSSProperties, type KeyboardEvent as ReactKeyboardEvent, type MouseEvent, type PointerEvent as ReactPointerEvent,
} from 'react';
import type { OverviewResponse, SessionUser } from '../../api/types';
import { PRODUCT_NAME } from '../../brand';
import { LANG_NAMES, LANGS, useT, type Lang } from '../../i18n';
import { canAccessRoute, ROLE_LABELS } from '../../utils/permissions';
import { buildHref, type RoutePath } from '../../utils/router';
import { NavIcon } from '../NavIcons';
import { GateMark } from './Boot';
import { dockStep, newDock, resetDock } from './dock';
import { EASE, prefersReduced } from './motion';

interface NavItem {
  readonly path: RoutePath;
  readonly tile: string; // the iOS-style squircle's colour (white glyph on it)
  readonly badge?: (ov: OverviewResponse | null) => number | undefined;
}

const NAV_GROUPS: readonly { readonly id: 'govern' | 'operate' | 'assure'; readonly items: readonly NavItem[] }[] = [
  {
    id: 'govern',
    items: [
      { path: 'overview', tile: '#0a72e8' },
      { path: 'model', tile: '#5b57e0' },
      { path: 'policies', tile: '#008235' },
      { path: 'matrix', tile: '#0b8f6a' },
      { path: 'simulator', tile: '#9b4fd0' },
    ],
  },
  {
    id: 'operate',
    items: [
      { path: 'approvals', tile: '#d9530b', badge: (ov) => (ov && ov.counts.pendingChanges > 0 ? ov.counts.pendingChanges : undefined) },
      { path: 'break-glass', tile: '#d63336', badge: (ov) => (ov && ov.counts.breakGlassToReview > 0 ? ov.counts.breakGlassToReview : undefined) },
      { path: 'reviews', tile: '#0b8585' },
      { path: 'credentials', tile: '#3d63c9' },
    ],
  },
  {
    id: 'assure',
    items: [
      { path: 'audit', tile: '#5c6673' },
      { path: 'compliance', tile: '#b06f00' },
      { path: 'two-step', tile: '#4a5a6e' },
    ],
  },
];

const PHONE = '(max-width: 860px)';
const watchPhone = (cb: () => void) => {
  const mq = window.matchMedia(PHONE);
  mq.addEventListener('change', cb);
  return () => mq.removeEventListener('change', cb);
};
const isPhone = () => window.matchMedia(PHONE).matches;
const typingInField = (el: EventTarget | null) =>
  el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable);

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2 && parts[0] && parts[1]) return `${parts[0][0] ?? ''}${parts[1][0] ?? ''}`.toUpperCase();
  return name.slice(0, 2).toUpperCase() || 'OP';
}

const Svg = (props: { readonly d: string }) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d={props.d} /></svg>
);
const ICON_SEARCH = 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z M20 20l-4-4';
const ICON_SIGNOUT = 'M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3 M10 17l-5-5 5-5 M5 12h11';
const ICON_CHEVRON = 'M15 6l-6 6 6 6';
const ICON_CHAIN = 'M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z M9 12l2 2 4-4';

/** The whole navigation as one floating glass card: open, a labelled panel (search, sections, the audit chain, the
 *  motion switch, you); folded, a slim pill whose icon tiles swell like the macOS Dock as the pointer nears.
 *  A glass pill glides (and stretches like a drop) to the current screen in both. On a phone it opens as a menu. */
export function V24Sidebar(props: {
  readonly user: SessionUser;
  readonly currentPath: RoutePath;
  readonly overview: OverviewResponse | null;
  readonly open: boolean;
  readonly onToggle: () => void;
  readonly mobileOpen: boolean;
  readonly onNavigate: (path: RoutePath) => void;
  readonly onSignOut: () => void;
  readonly reduceMotion: boolean;
  readonly onReduceMotion: (reduced: boolean) => void;
  readonly lang: Lang;
  readonly onLang: (lang: Lang) => void;
}) {
  const t = useT();
  const sh = t.shell;
  const phone = useSyncExternalStore(watchPhone, isPhone);
  const open = props.open || phone;
  const [query, setQuery] = useState('');
  const pill = useRef<HTMLElement | null>(null);
  const list = useRef<HTMLDivElement | null>(null);
  const ind = useRef<HTMLSpanElement | null>(null);
  const search = useRef<HTMLInputElement | null>(null);
  const last = useRef<{ x: number; y: number } | null>(null);
  const pathNow = useRef(props.currentPath);
  const focusAfterOpen = useRef(false);
  const dk = useRef(newDock());
  const ov = props.overview;

  const q = query.trim().toLowerCase();
  const groups = NAV_GROUPS.map((g) => ({
    id: g.id,
    title: sh.groups[g.id],
    items: g.items.map((it) => ({ ...it, label: sh.nav[it.path] }))
      .filter((it) => canAccessRoute(props.user.roles, it.path) && (!q || it.label.toLowerCase().includes(q))),
  })).filter((g) => g.items.length > 0);
  const firstMatch = groups[0]?.items[0];

  useLayoutEffect(() => {
    pathNow.current = props.currentPath;
  }, [props.currentPath]);

  /* the glass pill: glides to the current screen and stretches on the way like a drop */
  const place = useCallback((animate: boolean) => {
    const el = ind.current;
    const root = list.current;
    if (!el || !root) return;
    const btn = root.querySelector<HTMLElement>(`[data-rail="${pathNow.current}"]`);
    if (!btn || btn.offsetParent !== root) {
      el.style.opacity = '0';
      last.current = null;
      return;
    }
    const x = props.lang === 'ar' ? btn.offsetLeft + btn.offsetWidth - root.clientWidth : btn.offsetLeft;
    const y = btn.offsetTop;
    const w = btn.offsetWidth;
    const m = parseFloat(btn.style.getPropertyValue('--m')) || 1;
    const to = `translate(${x}px, ${y}px) scale(${m})`;
    const from = last.current;
    el.style.opacity = '1';
    el.style.width = `${w}px`;
    el.style.height = `${btn.offsetHeight}px`;
    el.style.transform = to;
    if (animate && from && (Math.abs(from.y - y) > 2 || Math.abs(from.x - x) > 2) && !prefersReduced()) {
      const wide = w > 60;
      const stretch = wide ? 'scale(0.96, 1.4)' : 'scale(0.8, 1.38)';
      const settle = wide ? 'scale(1.01, 0.92)' : 'scale(1.08, 0.92)';
      el.animate(
        [
          { transform: `translate(${from.x}px, ${from.y}px)` },
          { transform: `translate(${(from.x + x) / 2}px, ${(from.y + y) / 2}px) ${stretch}`, offset: 0.45 },
          { transform: `translate(${x}px, ${y}px) ${settle}`, offset: 0.8 },
          { transform: to },
        ],
        { duration: 680, easing: EASE },
      );
    }
    last.current = { x, y };
  }, [props.lang]);

  useLayoutEffect(() => {
    place(true);
    // follows the buttons while the sidebar opens or folds (the rail resizes every frame)
    const root = list.current;
    const ro = new ResizeObserver(() => place(false));
    if (root) ro.observe(root);
    const t = window.setTimeout(() => place(false), 760);
    return () => {
      ro.disconnect();
      window.clearTimeout(t);
    };
  }, [props.currentPath, open, phone, q, place]);

  /* ---------------- dock loop (folded only) ---------------- */
  const runDock = useCallback(() => {
    const d = dk.current;
    if (d.raf) return;
    const frame = (t: number) => {
      const root = pill.current;
      const moving = root ? dockStep(root, d, t) : false;
      place(false);
      d.raf = moving ? requestAnimationFrame(frame) : 0;
    };
    d.raf = requestAnimationFrame(frame);
  }, [place]);

  // straight back to rest whenever the sidebar opens or folds
  useEffect(() => {
    const d = dk.current;
    resetDock(pill.current, d);
    return () => cancelAnimationFrame(d.raf);
  }, [open]);

  const onMove = (e: ReactPointerEvent) => {
    if (open || e.pointerType !== 'mouse' || prefersReduced()) return;
    dk.current.y = e.clientY;
    runDock();
  };
  const onLeave = () => {
    if (!dk.current.m.size) return;
    dk.current.y = null;
    runDock();
  };

  /* ---------------- search: filters the screens, ⌘K / Ctrl+K focuses it ---------------- */
  const focusSearch = useCallback(() => {
    if (open) search.current?.focus();
    else {
      focusAfterOpen.current = true;
      props.onToggle();
    }
  }, [open, props.onToggle]);

  useEffect(() => {
    if (open && focusAfterOpen.current) {
      focusAfterOpen.current = false;
      search.current?.focus();
    }
  }, [open]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === 'k' && !isPhone()) {
        e.preventDefault();
        focusSearch();
        return;
      }
      if (e.key === '[' && !e.metaKey && !e.ctrlKey && !e.altKey && !typingInField(e.target) && !isPhone()) {
        if (document.querySelector('[aria-modal="true"]')) return;
        props.onToggle();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [focusSearch, props.onToggle]);

  const onSearchKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      if (query) setQuery('');
      else e.currentTarget.blur();
    } else if (e.key === 'Enter' && firstMatch) {
      e.preventDefault();
      setQuery('');
      props.onNavigate(firstMatch.path);
    }
  };

  const go = (path: RoutePath) => (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    props.onNavigate(path);
  };

  const rolesText = props.user.roles.map((r) => ROLE_LABELS[r] ?? r).join(' · ');
  const auditHref = canAccessRoute(props.user.roles, 'audit') ? buildHref('audit') : undefined;
  let order = 0;

  return (
    <aside
      id="appSidebar"
      className={`v24-rail${open ? ' open' : ''}${props.mobileOpen ? ' mobile-open' : ''}`}
      aria-label={sh.sidebar}
    >
      <nav className="v24-rail-pill" ref={pill} aria-label={sh.primaryNav} onPointerMove={onMove} onPointerLeave={onLeave}>
        <div className="rail-brand">
          <span className="rail-logo"><GateMark size={24} /></span>
          <b>{PRODUCT_NAME}</b>
          <span className="rail-chip">{sh.airGapped}</span>
        </div>

        {open ? (
          <div className="rail-search">
            <Svg d={ICON_SEARCH} />
            <label className="sr-only" htmlFor="v24-nav-search">{sh.findScreen}</label>
            <input
              ref={search}
              id="v24-nav-search"
              type="search"
              placeholder={sh.findScreen}
              autoComplete="off"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onSearchKey}
            />
            <kbd className="rail-kbd" aria-hidden="true">⌘K</kbd>
          </div>
        ) : (
          <button type="button" className="v24-rail-btn rail-find" data-dock data-tip={`${sh.findScreen}  ⌘K`} aria-label={sh.findScreen} onClick={focusSearch}>
            <span className="v24-tile glass"><Svg d={ICON_SEARCH} /></span>
          </button>
        )}

        <div className="rail-list" ref={list}>
          <span className="v24-rail-ind" ref={ind} aria-hidden="true" />
          {groups.map((g) => (
            <div key={g.id} className="rail-group">
              <p className="rail-title" id={`v24-nav-${g.id}`}>{g.title}</p>
              <ul aria-labelledby={`v24-nav-${g.id}`}>
                {g.items.map((it) => {
                  const badge = it.badge?.(ov);
                  const current = props.currentPath === it.path;
                  const name = badge !== undefined ? sh.pending(it.label, badge) : it.label;
                  return (
                    <li key={it.path}>
                      <a
                        href={buildHref(it.path)}
                        data-rail={it.path}
                        data-dock
                        data-tip={badge !== undefined ? `${it.label} · ${badge}` : it.label}
                        className={`v24-rail-btn${current ? ' on' : ''}`}
                        style={{ '--i': ++order } as CSSProperties}
                        aria-label={name}
                        aria-current={current ? 'page' : undefined}
                        onClick={go(it.path)}
                      >
                        <span className="v24-tile" style={{ '--tile': it.tile } as CSSProperties}><NavIcon path={it.path} /></span>
                        <span className="rail-label">{it.label}</span>
                        {badge !== undefined ? <i className="rail-badge" aria-hidden="true">{badge}</i> : null}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
          {groups.length === 0 ? <p className="rail-empty" role="status">{sh.noMatch(query.trim())}</p> : null}
        </div>

        {ov ? (
          auditHref ? (
            <a className="rail-status" href={auditHref} onClick={go('audit')} data-tone={ov.audit.verified ? 'ok' : 'bad'}>
              <span className="v24-tile"><Svg d={ICON_CHAIN} /></span>
              <span><b>{ov.audit.verified ? sh.chainVerified : sh.chainBroken}</b><small>{sh.records(ov.audit.length)}</small></span>
            </a>
          ) : (
            <div className="rail-status" data-tone={ov.audit.verified ? 'ok' : 'bad'}>
              <span className="v24-tile"><Svg d={ICON_CHAIN} /></span>
              <span><b>{ov.audit.verified ? sh.chainVerified : sh.chainBroken}</b><small>{sh.records(ov.audit.length)}</small></span>
            </div>
          )
        ) : null}

        <div className="rail-switch">
          <span id="v24-motion-label">{sh.reduceMotion}</span>
          <button
            type="button"
            role="switch"
            aria-checked={props.reduceMotion}
            aria-labelledby="v24-motion-label"
            className="v24-switch"
            onClick={() => props.onReduceMotion(!props.reduceMotion)}
          >
            <i />
          </button>
        </div>

        <div className="rail-switch">
          <span id="v24-lang-label">{sh.language}</span>
          <div className="v24-lang" role="group" aria-labelledby="v24-lang-label">
            {LANGS.map((l) => (
              <button key={l} type="button" lang={l} aria-label={LANG_NAMES[l]} aria-pressed={props.lang === l} onClick={() => props.onLang(l)}>
                {l === 'ar' ? 'العربية' : l.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="rail-foot">
          <div className="v24-rail-btn rail-user" data-dock data-tip={props.user.name} title={props.user.id}>
            <span className="rail-avatar" aria-hidden="true">{initials(props.user.name)}</span>
            <span className="rail-label rail-who"><b>{props.user.name}</b><small>{rolesText}</small></span>
          </div>
          <button type="button" className="v24-rail-btn rail-signout" data-dock data-tip={sh.signOut} aria-label={sh.signOut} onClick={props.onSignOut}>
            <Svg d={ICON_SIGNOUT} />
          </button>
        </div>
      </nav>

      <button
        type="button"
        className="rail-toggle v24-mag"
        onClick={props.onToggle}
        aria-label={open ? sh.foldSidebar : sh.openSidebar}
        aria-expanded={open}
        aria-controls="appSidebar"
        title={open ? sh.foldTip : sh.openTip}
      >
        <Svg d={ICON_CHEVRON} />
      </button>
    </aside>
  );
}
