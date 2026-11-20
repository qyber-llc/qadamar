import { inflateSync } from 'node:zlib';

/** WCAG 2.2 contrast, computed here: sRGB relative luminance (§1.4.3 definitions) and (L1 + 0.05) / (L2 + 0.05). */
export type Rgb = readonly [number, number, number];
export type Rgba = readonly [number, number, number, number];

const linear = (c: number): number => {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
export const luminance = ([r, g, b]: Rgb): number => 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
export function contrastRatio(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}
/** A colour with alpha painted over an opaque one. */
export const over = ([r, g, b, a]: Rgba, [br, bg, bb]: Rgb): Rgb => [r * a + br * (1 - a), g * a + bg * (1 - a), b * a + bb * (1 - a)];

/** Large text (WCAG): at least 18 pt (24 px), or 14 pt (18.66 px) bold. */
export const isLarge = (px: number, weight: number): boolean => px >= 24 || (px >= 18.66 && weight >= 700);
export const required = (px: number, weight: number): number => (isLarge(px, weight) ? 3 : 4.5);

/** `rgb(…)` / `rgba(…)` / `color(srgb …)` from getComputedStyle. */
export function parseColor(css: string): Rgba {
  const srgb = /^color\(srgb ([\d.]+) ([\d.]+) ([\d.]+)(?: \/ ([\d.]+))?\)$/.exec(css);
  if (srgb) return [Number(srgb[1]) * 255, Number(srgb[2]) * 255, Number(srgb[3]) * 255, srgb[4] === undefined ? 1 : Number(srgb[4])];
  const m = /^rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?\)$/.exec(css);
  if (!m) throw new Error(`unsupported colour ${css}`);
  return [Number(m[1]), Number(m[2]), Number(m[3]), m[4] === undefined ? 1 : Number(m[4])];
}

export interface Image { readonly width: number; readonly height: number; readonly rgba: Uint8Array }

/** A PNG (8-bit greyscale, RGB or RGBA, not interlaced, as Chromium writes them) decoded to RGBA. */
export function decodePng(png: Buffer): Image {
  if (png.readUInt32BE(0) !== 0x89504e47) throw new Error('not a PNG');
  let at = 8, width = 0, height = 0, type = 0;
  const idat: Buffer[] = [];
  while (at < png.length) {
    const length = png.readUInt32BE(at);
    const kind = png.toString('latin1', at + 4, at + 8);
    const data = png.subarray(at + 8, at + 8 + length);
    if (kind === 'IHDR') {
      width = data.readUInt32BE(0); height = data.readUInt32BE(4); type = data[9]!;
      if (data[8] !== 8 || data[12] !== 0 || ![0, 2, 6].includes(type)) throw new Error('unsupported PNG format');
    } else if (kind === 'IDAT') idat.push(data);
    at += 12 + length;
  }
  const channels = type === 6 ? 4 : type === 2 ? 3 : 1;
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const pixels = new Uint8Array(stride * height);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)]!;
    for (let x = 0; x < stride; x++) {
      const v = raw[y * (stride + 1) + 1 + x]!;
      const a = x >= channels ? pixels[y * stride + x - channels]! : 0;
      const b = y > 0 ? pixels[(y - 1) * stride + x]! : 0;
      const c = x >= channels && y > 0 ? pixels[(y - 1) * stride + x - channels]! : 0;
      const p = a + b - c;
      const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
      const predictor = [0, a, b, (a + b) >> 1, pa <= pb && pa <= pc ? a : pb <= pc ? b : c][filter];
      if (predictor === undefined) throw new Error(`PNG filter ${filter}`);
      pixels[y * stride + x] = (v + predictor) & 0xff;
    }
  }
  const rgba = new Uint8Array(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    const s = i * channels;
    rgba.set(channels === 1 ? [pixels[s]!, pixels[s]!, pixels[s]!, 255] : [pixels[s]!, pixels[s + 1]!, pixels[s + 2]!, channels === 4 ? pixels[s + 3]! : 255], i * 4);
  }
  return { width, height, rgba };
}

/** The contrast of text in this colour over the background pixels of these boxes: a low percentile of the per-pixel
 *  ratios, so a photo or gradient behind the text counts by its darkest or lightest part, not its average. */
export function textContrast(image: Image, color: Rgba, boxes: readonly { x: number; y: number; w: number; h: number }[]): { ratio: number; background: Rgb } {
  const samples: { ratio: number; bg: Rgb }[] = [];
  for (const box of boxes) {
    const x0 = Math.max(0, Math.floor(box.x)), y0 = Math.max(0, Math.floor(box.y));
    const x1 = Math.min(image.width, Math.ceil(box.x + box.w)), y1 = Math.min(image.height, Math.ceil(box.y + box.h));
    const step = Math.max(1, Math.floor(Math.min(x1 - x0, y1 - y0) / 6));
    for (let y = y0; y < y1; y += step) for (let x = x0; x < x1; x += step) {
      const i = (y * image.width + x) * 4;
      const bg: Rgb = [image.rgba[i]!, image.rgba[i + 1]!, image.rgba[i + 2]!];
      samples.push({ ratio: contrastRatio(over(color, bg), bg), bg });
    }
  }
  if (samples.length === 0) return { ratio: Infinity, background: [0, 0, 0] };
  samples.sort((a, b) => a.ratio - b.ratio);
  const pick = samples[Math.floor(samples.length * 0.05)]!;
  return { ratio: pick.ratio, background: pick.bg };
}
