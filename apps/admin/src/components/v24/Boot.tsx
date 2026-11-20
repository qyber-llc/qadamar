// Adapted from CodeXR Glassy Dashboard v24 (purchased by the owner) — components/Boot.jsx.
import type { CSSProperties } from 'react';
import { PRODUCT_NAME } from '../../brand';
import { useT } from '../../i18n';

/** H Portal: a geometric H and doorway, inspired by the Hadamard gate. */
export function GateMark(props: { readonly size?: number; readonly className?: string }) {
  const size = props.size ?? 26;
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" focusable="false" className={props.className}>
      <path className="logo-stroke" pathLength={1} d="M14 54V10h10v17h16V10h10v44H40V37H24v17Z" fill="currentColor" />
      <path d="M28 54V43h8v11Z" fill="#83d7b4" />
    </svg>
  );
}

/** The intro: on a dark veil the mark draws itself and the name rises letter by letter, then an iris opens from
 *  the centre onto the carbon and the glass settles. Never rendered under reduced motion. */
export function Boot() {
  const t = useT();
  return (
    <div className="v24-boot" aria-hidden="true">
      <div className="boot-stage">
        <GateMark size={84} className="boot-logo" />
        <p className="boot-word">
          {[...PRODUCT_NAME.toUpperCase()].map((c, i) => (
            <span key={i} style={{ '--c': i } as CSSProperties}>{c === ' ' ? ' ' : c}</span>
          ))}
        </p>
        <p className="boot-tag">{t.signIn.bootTag}</p>
        <span className="boot-bar"><i /></span>
      </div>
    </div>
  );
}
