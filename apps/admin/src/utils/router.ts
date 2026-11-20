import { useEffect, useState, useCallback } from 'react';

export type RoutePath =
  | 'overview'
  | 'model'
  | 'policies'
  | 'simulator'
  | 'matrix'
  | 'approvals'
  | 'break-glass'
  | 'reviews'
  | 'credentials'
  | 'two-step'
  | 'audit'
  | 'compliance';

const VALID_PATHS: ReadonlySet<string> = new Set<RoutePath>([
  'overview',
  'model',
  'policies',
  'simulator',
  'matrix',
  'approvals',
  'break-glass',
  'reviews',
  'credentials',
  'two-step',
  'audit',
  'compliance',
]);

export interface ParsedRoute {
  readonly path: RoutePath;
  readonly params: Readonly<Record<string, string>>;
}

export function parseHash(rawHash: string): ParsedRoute {
  const cleaned = rawHash.replace(/^#\/?/, '');
  const qIndex = cleaned.indexOf('?');
  const rawPath = (qIndex === -1 ? cleaned : cleaned.slice(0, qIndex)).replace(/\/+$/, '');
  const queryString = qIndex === -1 ? '' : cleaned.slice(qIndex + 1);

  const path: RoutePath = VALID_PATHS.has(rawPath) ? (rawPath as RoutePath) : 'overview';
  const searchParams = new URLSearchParams(queryString);
  const params: Record<string, string> = {};
  searchParams.forEach((value, key) => {
    if (value !== '') {
      params[key] = value;
    }
  });

  return { path, params };
}

export function buildHref(
  path: RoutePath,
  params?: Readonly<Record<string, string | undefined>>,
): string {
  if (!params) {
    return `#/${path}`;
  }
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') {
      search.set(k, v);
    }
  }
  const qs = search.toString();
  return qs ? `#/${path}?${qs}` : `#/${path}`;
}

export function navigate(
  path: RoutePath,
  params?: Readonly<Record<string, string | undefined>>,
): void {
  const nextHash = buildHref(path, params);
  if (window.location.hash !== nextHash) {
    window.location.hash = nextHash;
  }
}

export function useHashRoute(): {
  readonly route: ParsedRoute;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
} {
  const [route, setRoute] = useState<ParsedRoute>(() => parseHash(window.location.hash));

  useEffect(() => {
    const onHashChange = () => {
      if (window.location.hash === '#mainContent') return;
      setRoute(parseHash(window.location.hash));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const setParams = useCallback((updates: Readonly<Record<string, string | undefined>>) => {
    const current = route;
    const merged: Record<string, string | undefined> = { ...current.params, ...updates };
    navigate(current.path, merged);
  }, [route]);

  return { route, setParams };
}
