// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — lib/motion.js.
import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from 'react';

/** Intro timing (ms): when the first card lands, and when the intro has fully settled. */
export const BOOT_BASE = 1500;
export const BOOT_MS = 3600;

export const MOTION_KEY = 'qadamar-motion';

/** The system setting, or the console's own "Reduce motion" switch (html[data-motion="reduced"]). */
export const prefersReduced = (): boolean =>
  document.documentElement.dataset.motion === 'reduced' ||
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export const EASE = 'cubic-bezier(0.22, 1, 0.36, 1)';

/** Reads the stored switch and mirrors it on <html>, before anything checks prefersReduced(). */
export function readMotionPref(): boolean {
  let reduced = false;
  try {
    reduced = window.localStorage.getItem(MOTION_KEY) === 'reduced';
  } catch {
    // storage blocked: the system setting still applies
  }
  if (reduced) document.documentElement.dataset.motion = 'reduced';
  else delete document.documentElement.dataset.motion;
  return reduced;
}

export function writeMotionPref(reduced: boolean): void {
  try {
    if (reduced) window.localStorage.setItem(MOTION_KEY, 'reduced');
    else window.localStorage.removeItem(MOTION_KEY);
  } catch {
    // storage blocked: the switch lasts for this page only
  }
  if (reduced) document.documentElement.dataset.motion = 'reduced';
  else delete document.documentElement.dataset.motion;
}

/** Cards come in as they reach the screen: everything visible lands in one staggered wave, anything further down
 *  rises in when it is scrolled to. Cards added later (data arriving) get the same treatment. */
export function useReveal(rootRef: RefObject<HTMLElement | null>, dep: unknown): void {
  useLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return undefined;
    const showAll = (els: Iterable<Element>) => {
      for (const el of els) el.classList.add('in', 'shown');
    };
    if (prefersReduced() || !('IntersectionObserver' in window)) {
      showAll(root.querySelectorAll('[data-reveal]'));
      const mo = new MutationObserver(() => showAll(root.querySelectorAll('[data-reveal]:not(.shown)')));
      mo.observe(root, { childList: true, subtree: true });
      return () => mo.disconnect();
    }
    let wave = 0;
    let waveAt = 0;
    const io = new IntersectionObserver(
      (entries) => {
        const now = performance.now();
        if (now - waveAt > 180) {
          wave = 0;
          waveAt = now;
        }
        entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top || a.boundingClientRect.left - b.boundingClientRect.left)
          .forEach((e) => {
            const el = e.target as HTMLElement;
            el.style.setProperty('--i', String(wave++));
            el.classList.add('in');
            io.unobserve(el);
            // once landed, drop the entrance so hover transforms (tilt) are free to act
            el.addEventListener('animationend', function end(ev) {
              if (ev.target !== el || ev.pseudoElement) return;
              el.removeEventListener('animationend', end);
              el.classList.add('shown');
            });
          });
      },
      { rootMargin: '0px 0px -6% 0px', threshold: 0.04 },
    );
    root.querySelectorAll('[data-reveal]').forEach((el) => io.observe(el));
    const mo = new MutationObserver((muts) => {
      for (const m of muts) {
        m.addedNodes.forEach((n) => {
          if (!(n instanceof Element)) return;
          const found = n.matches('[data-reveal]') ? [n] : [];
          found.push(...n.querySelectorAll('[data-reveal]'));
          found.filter((el) => !el.classList.contains('in')).forEach((el) => io.observe(el));
        });
      }
    });
    mo.observe(root, { childList: true, subtree: true });
    return () => {
      io.disconnect();
      mo.disconnect();
    };
  }, [rootRef, dep]);
}

/** True once the element has been on screen (plus a delay): starts number rolls and ring sweeps. */
export function useSeen<T extends HTMLElement>(delay = 0): [RefObject<T | null>, boolean] {
  const ref = useRef<T | null>(null);
  const [seen, setSeen] = useState(prefersReduced);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return undefined;
    let t = 0;
    const io = new IntersectionObserver(
      ([e]) => {
        if (!e?.isIntersecting) return;
        io.disconnect();
        // wait for the card around it to land (the intro holds everything back a little longer)
        const card = el.closest<HTMLElement>('[data-reveal]');
        const extra = document.documentElement.dataset.booting === '1' ? 1700 : 380;
        const i = Number(card?.style.getPropertyValue('--i') || 0);
        t = window.setTimeout(() => setSeen(true), prefersReduced() ? 0 : delay + extra + i * 70);
      },
      { threshold: 0.15 },
    );
    io.observe(el);
    return () => {
      io.disconnect();
      window.clearTimeout(t);
    };
  }, [delay, seen]);
  return [ref, seen];
}
