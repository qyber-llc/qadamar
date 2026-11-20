import { encodeQr } from '../utils/qr';

/** A QR code drawn as SVG, dark on white in every theme (scanners need it), with a 4-module quiet zone.
 *  Null when the text does not fit version 10-M: the caller shows the text instead. */
export function QrCode(props: { readonly text: string; readonly label: string; readonly size?: number }) {
  let qr;
  try {
    qr = encodeQr(props.text);
  } catch {
    return null;
  }
  const quiet = 4;
  const side = qr.size + quiet * 2;
  let d = '';
  qr.modules.forEach((row, y) => row.forEach((dark, x) => { if (dark) d += `M${x + quiet} ${y + quiet}h1v1h-1z`; }));
  return (
    <svg
      className="qr-code"
      role="img"
      aria-label={props.label}
      viewBox={`0 0 ${side} ${side}`}
      width={props.size ?? 220}
      height={props.size ?? 220}
      shapeRendering="crispEdges"
      data-version={qr.version}
    >
      <rect width={side} height={side} fill="#ffffff" />
      <path d={d} fill="#000000" />
    </svg>
  );
}
