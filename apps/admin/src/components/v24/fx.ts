// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — lib/fx.js.
import { useEffect } from 'react';
import { prefersReduced } from './motion';

/* One global pointer listener for the tactile effects:
   - tilt:     tiles lean toward the cursor in 3D
   - magnetic: buttons drift toward the cursor just before you reach them
   - ripple:   a press blooms out of the exact point you touched
   Only transforms are written, so the glass never has to re-blur while the mouse moves. */
const TILT = '.v24-tilt';
const MAG = '.v24-mag';
const RIPPLE = '#app-shell-root .btn, .v24-press';
const MAX_TILT = 6;

interface Tilt { x: number; y: number; z: number; tx: number; ty: number; tz: number }

export function useStageFx(): void {
  useEffect(() => {
    const root = document.documentElement;

    const onDown = (e: PointerEvent) => {
      const host = (e.target as Element | null)?.closest?.<HTMLElement>(RIPPLE);
      if (!host || (host as HTMLButtonElement).disabled || prefersReduced()) return;
      const r = host.getBoundingClientRect();
      const size = Math.max(r.width, r.height) * 2.4;
      const dot = document.createElement('span');
      dot.className = 'v24-ripple';
      dot.setAttribute('aria-hidden', 'true');
      dot.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - r.left - size / 2}px;top:${e.clientY - r.top - size / 2}px`;
      host.appendChild(dot);
      dot.animate([{ transform: 'scale(0)', opacity: 0.3 }, { transform: 'scale(1)', opacity: 0 }], {
        duration: 620,
        easing: 'cubic-bezier(.22,1,.36,1)',
      }).onfinish = () => dot.remove();
    };
    document.addEventListener('pointerdown', onDown);

    if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
      return () => document.removeEventListener('pointerdown', onDown);
    }

    let px = 0;
    let py = 0;
    let target: Element | null = null;
    let queued = false;
    let magnet: HTMLElement | null = null;
    const tilts = new Map<HTMLElement, Tilt>();
    let tiltRaf = 0;

    const stepTilts = () => {
      tiltRaf = 0;
      for (const [el, s] of tilts) {
        s.x += (s.tx - s.x) * 0.15;
        s.y += (s.ty - s.y) * 0.15;
        s.z += (s.tz - s.z) * 0.15;
        const done = Math.abs(s.x - s.tx) < 0.01 && Math.abs(s.y - s.ty) < 0.01 && Math.abs(s.z - s.tz) < 0.01;
        if (done && s.tx === 0 && s.ty === 0 && s.tz === 0) {
          el.style.removeProperty('transform');
          el.style.removeProperty('will-change');
          tilts.delete(el);
        } else {
          el.style.transform = `perspective(900px) rotateX(${s.x.toFixed(2)}deg) rotateY(${s.y.toFixed(2)}deg) translateZ(${s.z.toFixed(1)}px)`;
        }
      }
      if (tilts.size && !tiltRaf) tiltRaf = requestAnimationFrame(stepTilts);
    };

    const releaseMagnet = () => {
      if (!magnet) return;
      magnet.style.removeProperty('--mg-x');
      magnet.style.removeProperty('--mg-y');
      magnet = null;
    };

    const frame = () => {
      queued = false;
      if (prefersReduced()) {
        releaseMagnet();
        for (const s of tilts.values()) Object.assign(s, { tx: 0, ty: 0, tz: 0 });
        if (tilts.size && !tiltRaf) tiltRaf = requestAnimationFrame(stepTilts);
        return;
      }

      const hit = target?.closest<HTMLElement>(TILT) ?? null;
      for (const [el, s] of tilts) if (el !== hit) Object.assign(s, { tx: 0, ty: 0, tz: 0 });
      // a card still playing its entrance is left alone until it lands
      if (hit && !(hit.hasAttribute('data-reveal') && !hit.classList.contains('shown'))) {
        const r = hit.getBoundingClientRect();
        let s = tilts.get(hit);
        if (!s) {
          s = { x: 0, y: 0, z: 0, tx: 0, ty: 0, tz: 0 };
          hit.style.willChange = 'transform';
        }
        s.tx = ((py - r.top) / r.height - 0.5) * -2 * MAX_TILT;
        s.ty = ((px - r.left) / r.width - 0.5) * 2 * MAX_TILT;
        s.tz = 10;
        tilts.set(hit, s);
      }
      if (tilts.size && !tiltRaf) tiltRaf = requestAnimationFrame(stepTilts);

      const mag = target?.closest<HTMLElement>(MAG) ?? null;
      if (mag !== magnet) releaseMagnet();
      if (mag && !(mag as HTMLButtonElement).disabled) {
        const r = mag.getBoundingClientRect();
        const cx = r.left + r.width / 2 - (parseFloat(mag.style.getPropertyValue('--mg-x')) || 0);
        const cy = r.top + r.height / 2 - (parseFloat(mag.style.getPropertyValue('--mg-y')) || 0);
        mag.style.setProperty('--mg-x', `${((px - cx) * 0.2).toFixed(1)}px`);
        mag.style.setProperty('--mg-y', `${((py - cy) * 0.26).toFixed(1)}px`);
        magnet = mag;
      }
    };

    const queue = () => {
      if (!queued) {
        queued = true;
        requestAnimationFrame(frame);
      }
    };
    const onMove = (e: PointerEvent) => {
      if (e.pointerType !== 'mouse') return;
      px = e.clientX;
      py = e.clientY;
      target = e.target as Element | null;
      queue();
    };
    const onLeave = () => {
      target = null;
      queue();
    };
    window.addEventListener('pointermove', onMove, { passive: true });
    root.addEventListener('pointerleave', onLeave);

    return () => {
      document.removeEventListener('pointerdown', onDown);
      window.removeEventListener('pointermove', onMove);
      root.removeEventListener('pointerleave', onLeave);
      cancelAnimationFrame(tiltRaf);
      releaseMagnet();
      for (const el of tilts.keys()) {
        el.style.removeProperty('transform');
        el.style.removeProperty('will-change');
      }
    };
  }, []);
}
