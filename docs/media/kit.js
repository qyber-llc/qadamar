// Shared animation kit for the docs/media videos: palette, easing, building blocks, 3D camera, HUD and frame().
// A page defines SCENES, LOG, CAM, ORDER and DRAW, then calls setTimes() and frame(t) (see docs/media/build.mjs).
const brand = getComputedStyle(document.documentElement);
const token = (name) => brand.getPropertyValue('--gate-' + name).trim();
const C = { bg: token('bg'), text: token('text'), dim: token('muted'), faint: token('faint'),
  line: token('line'), line2: token('line-strong'), ok: token('allow'), no: token('deny'),
  amber: token('warning'), ice: token('info') };

const TR = 0.8;                                                      // seconds of fly-through between scenes

let TIMES = [], NOW = 0, UID = 0;
window.setTimes = (a) => { TIMES = a; };

const cl = (x) => Math.max(0, Math.min(1, x));
const eo = (x) => (x >= 1 ? 1 : 1 - Math.pow(2, -10 * x));            // ease-out expo
const eio = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
const ss = (x) => x * x * x * (x * (x * 6 - 15) + 10);               // smootherstep, for camera moves
const spring = (u) => (u <= 0 ? 0 : u >= 1 ? 1 : 1 - Math.exp(-6.5 * u) * Math.cos(10.5 * u));
const k = (p, a, b) => eio(cl((p - a) / (b - a)));
const ko = (p, a, b) => eo(cl((p - a) / (b - a)));
const L = (a, b, u) => a + (b - a) * u;
const hash = (n) => { const x = Math.sin(n * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); };
const uid = () => 'u' + UID++;
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;');
const tx = (x, y, size, s, o = {}) =>
  `<text x="${x}" y="${y}" font-size="${size}" fill="${o.fill || C.text}" font-weight="${o.w || 400}" text-anchor="${o.a || 'start'}" opacity="${o.op ?? 1}"${o.m ? ' class="m"' : ''}${o.ls ? ` letter-spacing="${o.ls}"` : ''}>${esc(s)}</text>`;
const type = (s, u) => s.slice(0, Math.round(s.length * cl(u)));      // typewriter reveal
const tw = (s, size, mono) => s.length * size * (mono ? 0.6 : 0.52);  // shortcut: approximate width, fine for labels
const pad = (n) => String(n).padStart(2, '0');
const GLYPHS = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789#%/<>*+';
function scramble(s, u) { return u <= 0 ? '' : s; }
const reveal = (u, dy = 18) => `opacity="${cl(u * 1.5)}" transform="translate(0 ${(1 - u) * dy})"`;
const popAt = (x, y, u) => `opacity="${cl(u * 3)}" transform="translate(${x} ${y}) scale(${spring(u)}) translate(${-x} ${-y})"`;
const STATUS = { PERMIT: C.ok, DENY: C.no, HIDDEN: C.dim, NOTICE: C.amber, REVIEW: C.amber, PROPOSE: C.ice, APPROVE: C.ok, VERIFY: C.ok, REFUSE: C.no };

// ---- building blocks ----
function panel(x, y, w, h, p, a, title, accent) {
  const u = ko(p, a, a + 0.1);
  if (u <= 0) return '';
  const id = uid(), sh = cl((p - a - 0.03) / 0.16), c = 16;
  const tick = (px, py, dx, dy) => `<path d="M${px} ${py + dy * c * u} V${py} H${px + dx * c * u}" fill="none" stroke="${accent || C.line2}" stroke-width="2"/>`;
  let s = `<g opacity="${cl(u * 1.4)}" transform="translate(0 ${(1 - u) * 28})">` +
    `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="24" fill="url(#glass)" stroke="url(#edge)" stroke-width="1.5" filter="url(#shadow)"/>` +
    `<path d="M${x + 14} ${y + 1.5} H${x + w - 14}" stroke="rgba(255,255,255,.14)"/>` +
    tick(x, y, 1, 1) + tick(x + w, y, -1, 1) + tick(x, y + h, 1, -1) + tick(x + w, y + h, -1, -1);
  if (title) s += tx(x + 26, y + 40, 15, scramble(title, k(p, a + 0.02, a + 0.1)), { m: 1, fill: C.dim, ls: 2.5 }) +
    `<path d="M${x + 26} ${y + 56} H${x + 26 + (w - 52) * u}" stroke="${C.line}"/>`;
  if (sh > 0 && sh < 1) s += `<clipPath id="${id}"><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10"/></clipPath>` +
    `<g clip-path="url(#${id})"><rect x="${L(x - 320, x + w + 200, sh)}" y="${y - 40}" width="220" height="${h + 80}" fill="url(#sheen)" transform="skewX(-18)" transform-origin="${x} ${y}"/></g>`;
  return s + `</g>`;
}
function pill(x, y, s, color, u = 1, size = 18) {
  if (u <= 0) return '';
  const w = tw(s, size, 1) + 28;
  return `<g ${popAt(x + w / 2, y - size * 0.1, u)}><rect x="${x}" y="${y - size}" width="${w}" height="${size * 1.75}" rx="${size * 0.35}" fill="${color}" fill-opacity=".12" stroke="${color}" stroke-opacity=".6"/>` +
    tx(x + 14, y + size * 0.33, size, s, { m: 1, fill: color, w: 600 }) + `</g>`;
}
function ring(x, y, u, col, r0 = 34, r1 = 110) {
  if (u <= 0 || u >= 1) return '';
  return `<circle cx="${x}" cy="${y}" r="${L(r0, r1, eo(u))}" fill="none" stroke="${col}" stroke-width="${3 * (1 - u) + 0.5}" opacity="${0.8 * (1 - u)}"/>`;
}
function verdict(x, y, ok, u, code) {
  if (u <= 0) return '';
  const col = ok ? C.ok : C.no;
  return ring(x, y, u * 1.4, col) + `<g ${popAt(x, y, u)}><g transform="translate(${x} ${y})"><circle r="34" fill="${col}" fill-opacity=".14" stroke="${col}" stroke-width="2.5" filter="url(#glow)"/>` +
    (ok ? `<path d="M-13 1 L-4 11 L14 -9" fill="none" stroke="${col}" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>`
        : `<path d="M-11 -11 L11 11 M11 -11 L-11 11" stroke="${col}" stroke-width="4.5" stroke-linecap="round"/>`) +
    (code ? tx(0, 64, 17, scramble(code, cl(u * 1.6)), { m: 1, a: 'middle', fill: col, w: 600 }) : '') + `</g></g>`;
}
function role(x, y, name, sub, u, col = C.ice) {
  if (u <= 0) return '';
  const w = Math.max(250, tw(name, 24) + 110, tw(sub, 16, 1) + 110);
  return `<g ${reveal(u, 14)}><g transform="translate(${x} ${y})"><rect x="0" y="-36" width="${w}" height="72" rx="12" fill="url(#glass)" stroke="${col}" stroke-opacity=".6" stroke-width="1.5" filter="url(#shadow)"/>` +
    `<g transform="translate(36 0)"><circle r="20" fill="${col}" fill-opacity=".08" stroke="${col}" stroke-width="2"/><circle cx="-5" r="6" fill="none" stroke="${col}" stroke-width="2.5"/><path d="M1 0 H12 M8 0 V5" stroke="${col}" stroke-width="2.5" stroke-linecap="round"/></g>` +
    tx(72, -4, 24, name, { w: 600 }) + tx(72, 22, 16, scramble(sub, cl(u * 1.3)), { m: 1, fill: C.dim }) + `</g></g>`;
}
function flow(x1, y1, x2, y2, u, col, dash) {
  if (u <= 0) return '';
  const len = Math.hypot(x2 - x1, y2 - y1);
  return `<path d="M${x1} ${y1} L${x2} ${y2}" stroke="${col}" stroke-width="2" stroke-dasharray="${dash ? '6 10' : len}" stroke-dashoffset="${dash ? -NOW * 40 : len * (1 - u)}" opacity="${dash ? u : 0.9}" fill="none"/>`;
}
function stream(x1, y1, x2, y2, col, u) {                               // energy travelling along a link
  if (u <= 0) return '';
  return `<path d="M${x1} ${y1} L${x2} ${y2}" stroke="${col}" stroke-width="3" stroke-dasharray="2 46" stroke-dashoffset="${-NOW * 90}" stroke-linecap="round" opacity="${0.7 * u}" fill="none" filter="url(#glow)"/>`;
}
function mover(pos, u, label, col) {                                     // glowing packet with a motion trail
  if (u <= 0 || u >= 1) return '';
  let s = '';
  for (let i = 6; i >= 1; i--) {
    const v = u - i * 0.016;
    if (v <= 0) continue;
    const [x, y] = pos(v);
    s += `<circle cx="${x}" cy="${y}" r="${8 - i}" fill="${col}" opacity="${0.42 - i * 0.06}"/>`;
  }
  const [x, y] = pos(u);
  s += `<circle cx="${x}" cy="${y}" r="8" fill="${col}" filter="url(#glow)"/><circle cx="${x}" cy="${y}" r="3.5" fill="#fff"/>`;
  if (label) {
    const w = tw(label, 14, 1) + 26, o = 1 - k(u, 0.82, 0.98);
    s += `<g opacity="${o}" transform="translate(${x} ${y - 32})"><rect x="${-w / 2}" y="-15" width="${w}" height="28" rx="14" fill="${C.bg}" fill-opacity=".9" stroke="${col}" stroke-opacity=".7"/>` +
      tx(0, 4, 14, label, { m: 1, a: 'middle', fill: col }) + `</g>`;
  }
  return s;
}
const hexPts = (x, y, r) => [...Array(6)].map((_, i) => `${x + Math.cos(Math.PI / 3 * i - Math.PI / 2) * r},${y + Math.sin(Math.PI / 3 * i - Math.PI / 2) * r}`).join(' ');
function hexNode(x, y, r, col, lit) {
  return `<polygon points="${hexPts(x, y, r)}" fill="${lit ? col : C.bg}" fill-opacity="${lit ? 0.12 : 1}" stroke="${col}" stroke-width="2.5"${lit ? ' filter="url(#glow)"' : ''}/>`;
}
const blocks = (x, y, col, op) => [0, 46, 112].map((dx, i) => `<rect x="${x + dx}" y="${y - 13}" width="${[38, 58, 30][i]}" height="16" rx="4" fill="${col}" opacity="${op}"/>`).join('');
const ICON = {
  government: (c) => `<path d="M-46 34 H46 M-40 34 V2 M-20 34 V2 M0 34 V2 M20 34 V2 M40 34 V2 M-48 2 H48 M-36 2 Q0 -48 36 2 M0 -36 V-52" fill="none" stroke="${c}" stroke-width="3" stroke-linecap="round"/>`,
  banking: (c) => `<circle r="40" fill="none" stroke="${c}" stroke-width="3"/><circle r="14" fill="none" stroke="${c}" stroke-width="3"/><path d="M0 -14 V-30 M0 14 V30 M-14 0 H-30 M14 0 H30" stroke="${c}" stroke-width="3" stroke-linecap="round"/>`,
  healthcare: (c) => `<rect x="-40" y="-40" width="80" height="80" rx="18" fill="none" stroke="${c}" stroke-width="3"/><path d="M0 -20 V20 M-20 0 H20" stroke="${c}" stroke-width="6" stroke-linecap="round"/>`,
  enterprise: (c) => `<path d="M-32 -42 H12 L34 -20 V42 H-32 Z M12 -42 V-20 H34" fill="none" stroke="${c}" stroke-width="3" stroke-linejoin="round"/><path d="M-18 -4 H20 M-18 10 H20 M-18 24 H4" stroke="${c}" stroke-width="3" stroke-linecap="round"/>`,
};
function engineCore(x, y, s, t, u, col = C.ok) {
  if (u <= 0) return '';
  return `<g opacity="${cl(u * 1.5)}" transform="translate(${x} ${y}) scale(${s * L(0.7, 1, spring(u))})"><circle r="170" fill="url(#core)"/>` +
    `<g transform="rotate(${t * 18})"><circle r="112" fill="none" stroke="${col}" stroke-opacity=".5" stroke-width="2" stroke-dasharray="3 14"/></g>` +
    `<g transform="rotate(${-t * 10})"><circle r="130" fill="none" stroke="${C.line2}" stroke-width="1" stroke-dasharray="60 24"/></g>` +
    `<g transform="rotate(${t * 60})"><path d="M0 -150 A150 150 0 0 1 106 -106" fill="none" stroke="${col}" stroke-width="2" opacity=".7" filter="url(#glow)"/></g>` +
    `<polygon points="${hexPts(0, 0, 70)}" fill="rgba(52,210,123,.07)" stroke="${col}" stroke-width="2.5" filter="url(#glow)"/>` +
    `<polygon points="${hexPts(0, 0, 54)}" fill="none" stroke="${col}" stroke-opacity=".35" stroke-width="1"/>` +
    tx(0, 8, 22, 'PDP', { m: 1, a: 'middle', w: 700, fill: col, ls: 3 }) + `</g>`;
}

// ---- world, camera and overlay ----
function background() {
  return `<rect width="1920" height="1080" fill="${C.bg}"/><ellipse cx="960" cy="520" rx="830" ry="480" fill="url(#atmoG)"/>`;
}
function camAt(id, p) {
  const ks = CAM[id] || [[0, 960, 540, 1]];
  if (p <= ks[0][0]) return ks[0].slice(1);
  for (let i = 0; i < ks.length - 1; i++) {
    const a = ks[i], b = ks[i + 1];
    if (p <= b[0]) { const u = ss(cl((p - a[0]) / (b[0] - a[0]))); return [L(a[1], b[1], u), L(a[2], b[2], u), L(a[3], b[3], u)]; }
  }
  return ks[ks.length - 1].slice(1);
}
function sceneLayer(sc, lt, mode, mu) {
  const p = cl(lt / sc.dur), [cx, cy, z] = camAt(sc.id, p);
  const opacity = mode === 'out' ? 1 - eio(mu) : mode === 'in' ? eo(mu) : 1;
  const scale = 1 + (z - 1) * .35;
  return `<g opacity="${opacity}" transform="translate(960 540) scale(${scale}) translate(${-960 - (cx - 960) * .15} ${-540 - (cy - 540) * .15})">${DRAW[sc.id](p, lt, NOW)}</g>`;
}
function hud(id, meta, lt, dur) {
  if (id === 'outro') return '';
  let s = tx(120, 100, 18, 'QADAMAR', { m: 1, fill: C.ok, w: 700, ls: 4 });
  const cur = ORDER.indexOf(id), prog = cl(lt / dur);
  ORDER.forEach((_, i) => {
    const x = 420 + i * 34;
    s += `<rect x="${x}" y="92" width="26" height="3" fill="${C.line2}"/>` + (i <= cur ? `<rect x="${x}" y="92" width="${26 * (i < cur ? 1 : prog)}" height="3" fill="${C.ok}"/>` : '');
  });
  if (meta.tag) s += tx(1800, 100, 18, scramble(meta.tag, cl(lt / 0.8)), { m: 1, a: 'end', fill: C.dim, ls: 4 });
  s += `<path d="M120 124 H1800" stroke="${C.line}"/>`;
  const u = eo(cl((lt - 0.2) / 0.8)), id2 = uid();
  s += tx(120, 905, 18, scramble(meta.label, cl((lt - 0.15) / 0.7)), { m: 1, fill: C.ok, ls: 3, w: 600 }) + `<rect x="120" y="922" width="${60 * u}" height="3" fill="${C.ok}"/>`;
  s += `<clipPath id="${id2}"><rect x="110" y="935" width="1180" height="66"/></clipPath><g clip-path="url(#${id2})"><text x="120" y="985" font-size="44" font-weight="500" fill="${C.text}">` +
    meta.title.split(' ').map((w, i) => { const v = eo(cl((lt - 0.35 - i * 0.06) / 0.7)); return `<tspan y="${985 + (1 - v) * 60}" opacity="${v}">${esc(w)} </tspan>`; }).join('') + `</text></g>`;
  return s;
}
function consoleLog(id, p) {
  if (!LOG[id]) return '';
  const lines = LOG[id].filter((l) => p >= l[0]);
  let s = `<g opacity="${ko(p, 0.05, 0.15)}"><rect x="1300" y="866" width="500" height="150" rx="18" fill="#ffffff" stroke="url(#edge)"/>` +
    tx(1320, 890, 13, 'DECISIONS', { m: 1, fill: C.faint, ls: 3 }) + `<circle cx="1782" cy="885" r="4" fill="${C.ok}" opacity="${0.5 + 0.5 * Math.sin(NOW * 5)}"/>`;
  lines.slice(-4).forEach((l, i, arr) => {
    const last = i === arr.length - 1, age = cl((p - l[0]) * 12), col = STATUS[l[1]], y = 918 + i * 26 + (last ? (1 - eo(age)) * 14 : 0);
    s += `<g opacity="${last ? cl(age * 2) : 0.55 + 0.45 * (i / arr.length)}">` + (last ? `<rect x="1306" y="${y - 15}" width="3" height="20" fill="${col}" opacity="${1 - age * 0.6}"/>` : '') +
      tx(1320, y, 14, l[1], { m: 1, fill: col, w: 700 }) + tx(1410, y, 14, type(l[2], age * 1.5), { m: 1, fill: C.text }) +
      tx(1785, y, 13, last ? scramble(l[3], age) : l[3], { m: 1, a: 'end', fill: C.dim }) + `</g>`;
  });
  return s + `</g>`;
}
function defs() {
  return `<defs><filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="0" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>` +
    `<filter id="shadow" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="10" stdDeviation="8" flood-color="#000" flood-opacity=".07"/></filter>` +
    `<filter id="grain" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="1" seed="${Math.floor(NOW * 30) % 60}" stitchTiles="stitch"/><feColorMatrix type="saturate" values="0"/></filter>` +
    `<linearGradient id="glass" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#fafafb"/></linearGradient>` +
    `<linearGradient id="edge" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#d2d2d7" stop-opacity=".8"/><stop offset=".5" stop-color="#d2d2d7" stop-opacity=".5"/><stop offset="1" stop-color="#d2d2d7" stop-opacity=".7"/></linearGradient>` +
    `<linearGradient id="sheen" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset=".5" stop-color="#fff" stop-opacity=".11"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient>` +
    `<linearGradient id="trailG" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="${C.ok}" stop-opacity="0"/><stop offset="1" stop-color="${C.ok}" stop-opacity=".18"/></linearGradient>` +
    `<linearGradient id="floorFade" gradientUnits="userSpaceOnUse" x1="0" y1="560" x2="0" y2="1080"><stop offset="0" stop-color="${C.ice}" stop-opacity="0"/><stop offset="1" stop-color="${C.ice}" stop-opacity=".1"/></linearGradient>` +
    `<radialGradient id="vignette" cx="50%" cy="45%" r="75%"><stop offset="55%" stop-color="${C.bg}" stop-opacity="0"/><stop offset="100%" stop-color="#000" stop-opacity=".8"/></radialGradient>` +
    `<radialGradient id="atmoG"><stop offset="0" stop-color="${C.ok}" stop-opacity=".035"/><stop offset="1" stop-color="${C.ok}" stop-opacity="0"/></radialGradient>` +
    `<radialGradient id="atmoB"><stop offset="0" stop-color="${C.ice}" stop-opacity=".06"/><stop offset="1" stop-color="${C.ice}" stop-opacity="0"/></radialGradient>` +
    `<radialGradient id="core"><stop offset="0%" stop-color="${C.ok}" stop-opacity=".24"/><stop offset="100%" stop-color="${C.ok}" stop-opacity="0"/></radialGradient>` +
    `<radialGradient id="coreRed"><stop offset="0%" stop-color="${C.no}" stop-opacity=".3"/><stop offset="100%" stop-color="${C.no}" stop-opacity="0"/></radialGradient></defs>`;
}

window.svgFrame = (t) => {
  NOW = t; UID = 0;
  const found = TIMES.findIndex((s) => t >= s.start && t < s.start + s.dur), i = found < 0 ? TIMES.length - 1 : found, sc = TIMES[i];
  const lt = t - sc.start, p = cl(lt / sc.dur);
  const layers = i > 0 && lt < TR ? sceneLayer(TIMES[i - 1], TIMES[i - 1].dur + lt, 'out', lt / TR) + sceneLayer(sc, lt, 'in', lt / TR) : sceneLayer(sc, lt, i === 0 && lt < TR ? 'in' : null, lt / TR);
  const hudOp = Math.min(cl(lt / .4), i === TIMES.length - 1 ? 1 : cl((sc.dur - lt) / .4));
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080"><style>text{font-family:Helvetica Neue,Arial,sans-serif}.m{font-family:Menlo,monospace}</style>${defs()}${background()}${layers}<g opacity="${hudOp}">${hud(sc.id, SCENES[sc.id], lt, sc.dur)}${consoleLog(sc.id, p)}</g></svg>`;
};
window.frame = t => { document.getElementById('root').innerHTML = window.svgFrame(t); };
