/** QR Code encoder (ISO/IEC 18004): byte mode, error correction level M, versions 1 to 10 (up to 213 bytes, enough
 *  for an otpauth URI). No dependency. Returns the module grid without quiet zone: true is a dark module. */

/** Per version (index 1..10), level M: [EC codewords per block, [block count, data codewords per block]...] (Table 9). */
export const BLOCKS_M: readonly (readonly [number, ...(readonly [number, number])[]])[] = [
  [0],
  [10, [1, 16]], [16, [1, 28]], [26, [1, 44]], [18, [2, 32]], [24, [2, 43]],
  [16, [4, 27]], [18, [4, 31]], [22, [2, 38], [2, 39]], [22, [3, 36], [2, 37]], [26, [4, 43], [1, 44]],
];
/** Alignment pattern centre coordinates (Annex E). */
export const ALIGN: readonly (readonly number[])[] = [
  [], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];
export const MAX_VERSION = 10;

// GF(256) with the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++, x = (x << 1) ^ (x & 0x80 ? 0x11d : 0)) { EXP[i] = x; LOG[x] = i; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
export const gfMul = (a: number, b: number): number => (a && b ? EXP[LOG[a]! + LOG[b]!]! : 0);
export const gfExp = (i: number): number => EXP[i % 255]!;

/** Reed-Solomon error correction codewords: remainder of data(x)·x^n by the generator ∏(x − α^i), i < n. */
export function rsEncode(data: readonly number[], n: number): number[] {
  let gen = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array<number>(gen.length + 1).fill(0);
    gen.forEach((c, j) => { next[j] = next[j]! ^ c; next[j + 1] = next[j + 1]! ^ gfMul(c, gfExp(i)); });
    gen = next;
  }
  const rem = new Array<number>(n).fill(0);
  for (const d of data) {
    const factor = d ^ rem.shift()!;
    rem.push(0);
    for (let j = 0; j < n; j++) rem[j] = rem[j]! ^ gfMul(gen[j + 1]!, factor);
  }
  return rem;
}

/** value followed by the BCH remainder of value·x^deg(poly) divided by poly. */
const bch = (value: number, poly: number): number => {
  const deg = 31 - Math.clz32(poly);
  let rem = value << deg;
  for (let d = 31 - Math.clz32(rem); rem !== 0 && d >= deg; d = 31 - Math.clz32(rem)) rem ^= poly << (d - deg);
  return (value << deg) | rem;
};
/** 15-bit format information: level M (00) and the mask, BCH(15,5) then XOR 101010000010010. */
export const formatBits = (mask: number): number => bch(mask, 0x537) ^ 0x5412;
/** 18-bit version information, BCH(18,6), versions 7 and up. */
export const versionBits = (version: number): number => bch(version, 0x1f25);

/** Data mask conditions (Table 10), x the column and y the row: the module is inverted where true. */
export const MASKS: readonly ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

export const dataCapacity = (v: number): number => {
  const [, ...groups] = BLOCKS_M[v]!;
  return groups.reduce((sum, [count, size]) => sum + count * size, 0);
};

/** Mode indicator, character count, bytes, terminator, padding (0xEC 0x11) up to the version's data codewords. */
function dataCodewords(bytes: Uint8Array, version: number): number[] {
  const bits: number[] = [];
  const put = (value: number, length: number) => { for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
  const capacity = dataCapacity(version) * 8;
  put(0b0100, 4);
  put(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, capacity - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  const out: number[] = [];
  for (let i = 0; i < bits.length; i += 8) out.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  for (let pad = 0xec; out.length < capacity / 8; pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}

/** Splits into blocks, adds each block's EC codewords and interleaves data then EC column by column. */
function interleave(data: readonly number[], version: number): number[] {
  const [ecLength, ...groups] = BLOCKS_M[version]!;
  const blocks: number[][] = [];
  let at = 0;
  for (const [count, size] of groups) for (let i = 0; i < count; i++) { blocks.push(data.slice(at, at + size)); at += size; }
  const ec = blocks.map((b) => rsEncode(b, ecLength));
  const out: number[] = [];
  const longest = Math.max(...blocks.map((b) => b.length));
  for (let i = 0; i < longest; i++) for (const b of blocks) if (i < b.length) out.push(b[i]!);
  for (let i = 0; i < ecLength; i++) for (const e of ec) out.push(e[i]!);
  return out;
}

export interface QrMatrix { readonly version: number; readonly size: number; readonly mask: number; readonly modules: readonly (readonly boolean[])[] }

/** Function patterns of a version (finders and separators, timing, alignment, version information, dark module), plus
 *  the reserved format areas. Everything reserved is skipped by the data placement and the mask. */
export function functionPatterns(version: number): { modules: boolean[][]; reserved: boolean[][] } {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const reserved = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const set = (x: number, y: number, dark: boolean) => { modules[y]![x] = dark; reserved[y]![x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]] as const) {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x < 0 || y < 0 || x >= size || y >= size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      set(x, y, d !== 2 && d !== 4);
    }
  }
  const align = ALIGN[version]!;
  for (const cy of align) for (const cx of align) {
    if ((cx === 6 && cy === 6) || (cx === 6 && cy === size - 7) || (cx === size - 7 && cy === 6)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  for (let i = 0; i < 9; i++) { reserved[8]![i] = true; reserved[i]![8] = true; }
  for (let i = 0; i < 8; i++) { reserved[8]![size - 1 - i] = true; reserved[size - 1 - i]![8] = true; }
  set(8, size - 8, true);
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(a, b, dark); set(b, a, dark);
    }
  }
  return { modules, reserved };
}

/** Both copies of the 15 format bits (bit 0 the least significant). */
function placeFormat(modules: boolean[][], mask: number): void {
  const size = modules.length;
  const bits = formatBits(mask);
  const bit = (i: number) => ((bits >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) modules[i]![8] = bit(i);
  modules[7]![8] = bit(6); modules[8]![8] = bit(7); modules[8]![7] = bit(8);
  for (let i = 9; i < 15; i++) modules[8]![14 - i] = bit(i);
  for (let i = 0; i < 8; i++) modules[8]![size - 1 - i] = bit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i]![8] = bit(i);
}

/** Codeword bits, most significant first, in the two-column zigzag from the bottom right, skipping column 6. */
function placeData(modules: boolean[][], reserved: readonly (readonly boolean[])[], codewords: readonly number[]): void {
  const size = modules.length;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let v = 0; v < size; v++) {
      const y = upward ? size - 1 - v : v;
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        if (reserved[y]![x]) continue;
        if (i < codewords.length * 8) modules[y]![x] = ((codewords[i >>> 3]! >>> (7 - (i & 7))) & 1) === 1;
        i++;
      }
    }
  }
}

/** Penalty rules N1 to N4 (weights 3, 3, 40, 10). */
function penalty(m: readonly (readonly boolean[])[]): number {
  const size = m.length;
  let score = 0;
  const line = (get: (i: number) => boolean) => {
    let run = 1;
    for (let i = 1; i <= size; i++) {
      if (i < size && get(i) === get(i - 1)) { run++; continue; }
      if (run >= 5) score += run - 2;
      run = 1;
    }
    const light = (from: number) => [0, 1, 2, 3].every((k) => from + k < 0 || from + k >= size || !get(from + k));
    for (let i = 0; i + 7 <= size; i++) {
      const finderLike = [true, false, true, true, true, false, true].every((d, k) => get(i + k) === d);
      if (finderLike && (light(i - 4) || light(i + 7))) score += 40;
    }
  };
  for (let y = 0; y < size; y++) line((x) => m[y]![x]!);
  for (let x = 0; x < size; x++) line((y) => m[y]![x]!);
  for (let y = 0; y + 1 < size; y++) for (let x = 0; x + 1 < size; x++) {
    const c = m[y]![x];
    if (c === m[y]![x + 1] && c === m[y + 1]![x] && c === m[y + 1]![x + 1]) score += 3;
  }
  const dark = m.reduce((n, row) => n + row.filter(Boolean).length, 0);
  return score + Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
}

/** Encodes text (UTF-8) in the smallest version that holds it, with the lowest-penalty mask; throws a RangeError
 *  beyond version 10. */
export function encodeQr(text: string): QrMatrix {
  const bytes = new TextEncoder().encode(text);
  let version = 1;
  while (version <= MAX_VERSION && 4 + (version < 10 ? 8 : 16) + bytes.length * 8 > dataCapacity(version) * 8) version++;
  if (version > MAX_VERSION) throw new RangeError(`QR: ${bytes.length} bytes exceed version ${MAX_VERSION}-M`);
  const codewords = interleave(dataCodewords(bytes, version), version);
  const { modules: base, reserved } = functionPatterns(version);
  let best: QrMatrix | null = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const modules = base.map((row) => [...row]);
    placeData(modules, reserved, codewords);
    const flip = MASKS[mask]!;
    for (let y = 0; y < modules.length; y++) for (let x = 0; x < modules.length; x++) {
      if (!reserved[y]![x] && flip(x, y)) modules[y]![x] = !modules[y]![x];
    }
    placeFormat(modules, mask);
    const score = penalty(modules);
    if (score < bestScore) { bestScore = score; best = { version, size: modules.length, mask, modules }; }
  }
  return best!;
}
