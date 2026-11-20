// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — components/ui.jsx (Odometer, Words).
import { useEffect, useState, type CSSProperties } from 'react';
import { prefersReduced, useSeen } from './motion';

const REEL = Array.from({ length: 30 }, (_, i) => i % 10);
const fmt = (v: number) => Number(v).toLocaleString('en-US', { maximumFractionDigits: 0 });

type Vars = CSSProperties & Record<`--${string}`, string | number>;

/** A number that rolls into place like slot reels, one reel per digit. Screen readers get the plain number. */
export function Odometer(props: { readonly value: number; readonly suffix?: string; readonly delay?: number }) {
  const [ref, seen] = useSeen<HTMLSpanElement>(props.delay ?? 0);
  // the first roll is long and dramatic; later changes tick over quickly
  const [settled, setSettled] = useState(false);
  useEffect(() => {
    if (!seen) return undefined;
    const t = window.setTimeout(() => setSettled(true), prefersReduced() ? 0 : 2600);
    return () => window.clearTimeout(t);
  }, [seen]);
  const text = fmt(props.value);
  const chars = [...text];
  return (
    <span ref={ref} dir="ltr" className={settled ? 'odo settled' : 'odo'}>
      <span className="sr-only">{text}{props.suffix ?? ''}</span>
      {chars.map((c, i) => {
        const pos = chars.length - i;
        if (!/\d/.test(c)) {
          return <span key={`s${pos}`} className="odo-sep" aria-hidden="true">{c}</span>;
        }
        const style: Vars = { '--n': seen ? Number(c) + 20 : 0, '--k': i };
        return (
          <span key={`d${pos}`} className="odo-col" aria-hidden="true">
            <span className="odo-reel" style={style}>
              {REEL.map((d, j) => <span key={j}>{d}</span>)}
            </span>
          </span>
        );
      })}
      {props.suffix ? <span className="odo-fix" aria-hidden="true">{props.suffix}</span> : null}
    </span>
  );
}

/** Words that rise in one after another (the page title). */
export function Words(props: { readonly text: string }) {
  return (
    <span className="words">
      <span className="sr-only">{props.text}</span>
      {props.text.split(' ').map((w, i) => (
        <span key={i} className="w" aria-hidden="true" style={{ '--w': i } as Vars}>
          {w}{' '}
        </span>
      ))}
    </span>
  );
}
