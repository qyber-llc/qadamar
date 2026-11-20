import type { RoutePath } from '../utils/router';

/** Line icons for the glass sidebar (24 × 24, drawn with the current colour). */
const PATHS: Partial<Record<RoutePath, string>> = {
  overview: 'M4 4h7v7H4z M13 4h7v7h-7z M4 13h7v7H4z M13 13h7v7h-7z',
  model: 'M4 6h16 M4 12h11 M4 18h7 M18 15l3 3-3 3',
  policies: 'M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z M9 12l2 2 4-4',
  matrix: 'M3 4h18v16H3z M3 9.5h18 M3 15h18 M9 4v16 M15 4v16',
  simulator: 'M9 3h6 M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3 M7.5 15h9',
  approvals: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M8 12l3 3 5-6',
  'break-glass': 'M13 2L4 14h7l-1 8 9-12h-7z',
  reviews: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  credentials: 'M8 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M12 12h9 M18 12v3 M21 12v3',
  audit: 'M9 6h11 M9 12h11 M9 18h11 M4.5 6h.01 M4.5 12h.01 M4.5 18h.01',
  'two-step': 'M7 11V8a5 5 0 0 1 10 0v3 M5 11h14v10H5z M12 15v2',
  compliance: 'M12 3l2.5 2 3-.5.5 3 2 2.5-2 2.5-.5 3-3-.5L12 21l-2.5-2-3 .5-.5-3-2-2.5 2-2.5.5-3 3 .5z M9 12l2 2 4-4',
};

export function NavIcon(props: { readonly path: RoutePath }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={PATHS[props.path] ?? 'M5 12h14'} />
    </svg>
  );
}
