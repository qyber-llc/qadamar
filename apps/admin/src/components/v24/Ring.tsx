// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — components/Charts.jsx (Ring).
import { useId, type ReactNode } from 'react';
import { useSeen } from './motion';

/** A ring whose arc sweeps round once it is on screen; the figure sits in the middle. */
export function Ring(props: { readonly value: number; readonly size?: number; readonly stroke?: number; readonly children?: ReactNode }) {
  const id = useId();
  const [ref, seen] = useSeen<HTMLDivElement>(200);
  const size = props.size ?? 150;
  const stroke = props.stroke ?? 12;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const v = seen ? Math.min(1, Math.max(0, props.value)) : 0;
  return (
    <div className="ring light" ref={ref} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <defs>
          <linearGradient id={`${id}g`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#ffffff" />
            <stop offset="1" stopColor="var(--v24-accent-2)" />
          </linearGradient>
        </defs>
        <circle className="ring-track" cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} />
        <circle
          className="ring-arc"
          cx={size / 2}
          cy={size / 2}
          r={r}
          strokeWidth={stroke}
          stroke={`url(#${id}g)`}
          strokeDasharray={c}
          strokeDashoffset={c * (1 - v)}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <g className="ring-head" style={{ transform: `rotate(${v * 360}deg)`, transformOrigin: '50% 50%' }}>
          <circle cx={size / 2} cy={stroke / 2} r={stroke / 2 + 3} className="ring-glow" />
          <circle cx={size / 2} cy={stroke / 2} r={stroke / 2 - 2.5} className="ring-dot" />
        </g>
      </svg>
      <div className="ring-mid">{props.children}</div>
    </div>
  );
}
