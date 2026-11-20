// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — components/Rail.jsx (macOS Dock).

const DOCK_RANGE = 150; // px from the pointer an icon still grows
const DOCK_GROW = 22; // extra room a row takes at full size, so the rail stretches with its icons
const DOCK_MAX = 1.5; // biggest an icon gets
const DOCK_EASE = 0.12; // share of the way to its target size an icon moves each 60fps frame

export interface DockState { y: number | null; m: Map<Element, number>; raf: number; t: number }

export const newDock = (): DockState => ({ y: null, m: new Map(), raf: 0, t: 0 });

/** One frame: ease each icon toward its size for the pointer and give its row room. Returns whether anything moves. */
export function dockStep(root: HTMLElement, d: DockState, t: number): boolean {
  const dt = d.t ? Math.min(64, t - d.t) : 16.7;
  d.t = t;
  const k = 1 - (1 - DOCK_EASE) ** (dt / 16.7);
  const rows = [...root.querySelectorAll<HTMLElement>('[data-dock]')].filter((el) => el.offsetParent);
  const rects = rows.map((el) => el.getBoundingClientRect());
  const grown = rows.map((el) => ((d.m.get(el) ?? 1) - 1) * DOCK_GROW);
  let above = 0;
  let moving = false;
  rows.forEach((el, i) => {
    const rect = rects[i];
    const g = grown[i] ?? 0;
    if (!rect) return;
    // measured from where the icon sits with nothing magnified, so the magnification never feeds back and jitters
    const rest = rect.top + rect.height / 2 - above - g / 2;
    above += g;
    const dist = d.y === null ? Infinity : Math.abs(d.y - rest);
    const pull = dist < DOCK_RANGE ? (Math.cos((Math.PI * dist) / DOCK_RANGE) + 1) / 2 : 0;
    const goal = 1 + (DOCK_MAX - 1) * pull;
    const now = d.m.get(el) ?? 1;
    let m = now + (goal - now) * k;
    if (Math.abs(goal - m) < 0.002) m = goal;
    else moving = true;
    d.m.set(el, m);
  });
  rows.forEach((el) => {
    const m = d.m.get(el);
    if (m === undefined || m === 1) {
      el.style.removeProperty('--m');
      el.style.removeProperty('--g');
    } else {
      el.style.setProperty('--m', m.toFixed(4));
      el.style.setProperty('--g', `${((m - 1) * DOCK_GROW).toFixed(2)}px`);
    }
  });
  if (!moving) {
    d.t = 0;
    if (d.y === null) d.m.clear();
  }
  return moving;
}

export function resetDock(root: HTMLElement | null, d: DockState): void {
  cancelAnimationFrame(d.raf);
  Object.assign(d, { y: null, raf: 0, t: 0 });
  d.m.clear();
  root?.querySelectorAll<HTMLElement>('[data-dock]').forEach((el) => {
    el.style.removeProperty('--m');
    el.style.removeProperty('--g');
  });
}
