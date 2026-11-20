import test from 'node:test';
import assert from 'node:assert/strict';
import { BLOCKS_M, dataCapacity, encodeQr, formatBits, functionPatterns, gfExp, gfMul, rsEncode, versionBits } from '../src/utils/qr.ts';

// Vectors from ISO/IEC 18004:2015 itself, not from another library.
const bin = (s: string) => Number.parseInt(s.replace(/ /g, ''), 2);
/** Table 1: total codewords and data modules (excluding function patterns, format and version information). */
const TOTAL = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346];
const DATA_MODULES = [0, 208, 359, 567, 807, 1079, 1383, 1568, 1936, 2336, 2768];
/** Table 10, i the row and j the column. */
const MASK: readonly ((i: number, j: number) => boolean)[] = [
  (i, j) => (i + j) % 2 === 0, (i) => i % 2 === 0, (_i, j) => j % 3 === 0, (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0, (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0, (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
];

test('Reed-Solomon: the 1-M example of Annex I (16 data codewords give these 10 EC codewords)', () => {
  const data = ['00010000', '00100000', '00001100', '01010110', '01100001', '10000000', '11101100', '00010001',
    '11101100', '00010001', '11101100', '00010001', '11101100', '00010001', '11101100', '00010001'].map(bin);
  const ec = ['10100101', '00100100', '11010100', '11000001', '11101101', '00110110', '11000111', '10000111', '00101100', '01010101'].map(bin);
  assert.deepEqual(rsEncode(data, 10), ec);
});

test('format information: level M, mask 101 is 100000011001110 (Annex C); version 7 is 000111110010010100 (Annex D)', () => {
  assert.equal(formatBits(0b101), bin('100000011001110'));
  assert.equal(versionBits(7), bin('000111110010010100'));
  // every BCH(18,6) word leaves no remainder modulo the generator x^12+x^11+x^10+x^9+x^8+x^5+x^2+1
  for (let v = 7; v <= 10; v++) {
    let rem = versionBits(v);
    for (let d = 17; d >= 12; d--) if (rem & (1 << d)) rem ^= 0x1f25 << (d - 12);
    assert.equal(rem, 0, `version ${v}`);
    assert.equal(versionBits(v) >>> 12, v);
  }
});

test('Table 1 and Table 9 agree: codewords per version, data modules left by the function patterns', () => {
  for (let v = 1; v <= 10; v++) {
    const [ec, ...groups] = BLOCKS_M[v]!;
    const blocks = groups.reduce((n, [count]) => n + count, 0);
    assert.equal(dataCapacity(v) + blocks * ec, TOTAL[v], `version ${v} codewords`);
    const { reserved } = functionPatterns(v);
    const free = reserved.flat().filter((r) => !r).length;
    assert.equal(free, DATA_MODULES[v], `version ${v} data modules`);
    assert.equal(reserved.length, 17 + 4 * v);
  }
});

/** A reader written from the specification: finders, format information, mask, zigzag, blocks, syndromes, byte mode. */
function read(m: readonly (readonly boolean[])[]): string {
  const size = m.length;
  const version = (size - 17) / 4;
  for (const [ox, oy] of [[0, 0], [size - 7, 0], [0, size - 7]] as const) {
    for (let y = 0; y < 7; y++) for (let x = 0; x < 7; x++) {
      const d = Math.max(Math.abs(x - 3), Math.abs(y - 3));
      assert.equal(m[oy + y]![ox + x], d !== 2, `finder module ${ox + x},${oy + y}`);
    }
  }
  for (let i = 8; i < size - 8; i++) { assert.equal(m[6]![i], i % 2 === 0); assert.equal(m[i]![6], i % 2 === 0); }
  // Figure 25: copy 1 around the top-left finder, copy 2 split under the top-right and beside the bottom-left one
  const c1 = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
  const c2 = [...Array.from({ length: 8 }, (_, i) => [size - 1 - i, 8]), ...Array.from({ length: 7 }, (_, i) => [8, size - 7 + i])];
  const word = (cells: number[][]) => cells.reduce((w, [x, y], i) => w | (m[y!]![x!] ? 1 << i : 0), 0);
  const format = word(c1);
  assert.equal(word(c2), format, 'both format copies agree');
  assert.equal(m[size - 8]![8], true, 'dark module');
  const unmasked = format ^ bin('101010000010010');
  assert.equal(unmasked >>> 13, 0b00, 'level M');
  const mask = (unmasked >>> 10) & 7;
  const { reserved } = functionPatterns(version);
  // §7.7.3: two-module columns from the bottom right, up then down alternately, column 6 (timing) skipped
  const rights = [...Array.from({ length: (size - 7) / 2 }, (_, i) => size - 1 - 2 * i), 5, 3, 1];
  const bits: number[] = [];
  rights.forEach((right, pair) => {
    for (let k = 0; k < size; k++) {
      const y = pair % 2 === 0 ? size - 1 - k : k;
      for (const x of [right, right - 1]) if (!reserved[y]![x]) bits.push(Number(m[y]![x]) ^ Number(MASK[mask]!(y, x)));
    }
  });
  const codewords: number[] = [];
  for (let i = 0; i + 8 <= TOTAL[version]! * 8; i += 8) codewords.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  const [ec, ...groups] = BLOCKS_M[version]!;
  const sizes = groups.flatMap(([count, n]) => new Array<number>(count).fill(n));
  const blocks = sizes.map(() => [] as number[]);
  let at = 0;
  for (let i = 0; i < Math.max(...sizes); i++) sizes.forEach((n, b) => { if (i < n) blocks[b]!.push(codewords[at++]!); });
  for (let i = 0; i < ec; i++) blocks.forEach((b) => b.push(codewords[at++]!));
  const data: number[] = [];
  for (const [b, block] of blocks.entries()) {
    for (let i = 0; i < ec; i++) {
      const syndrome = block.reduce((s, c) => gfMul(s, gfExp(i)) ^ c, 0);
      assert.equal(syndrome, 0, `block ${b} syndrome ${i}`);
    }
    data.push(...block.slice(0, sizes[b]));
  }
  const stream = data.flatMap((c) => [7, 6, 5, 4, 3, 2, 1, 0].map((s) => (c >>> s) & 1));
  const take = (n: number) => stream.splice(0, n).reduce((a, b) => (a << 1) | b, 0);
  assert.equal(take(4), 0b0100, 'byte mode');
  const count = take(version < 10 ? 8 : 16);
  return new TextDecoder().decode(Uint8Array.from({ length: count }, () => take(8)));
}

test('encoded symbols read back through a reader written from the specification', () => {
  const samples = [
    'A',
    'otpauth://totp/Qadamar%3Aamira?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Qadamar&algorithm=SHA1&digits=6&period=30',
    'é'.repeat(30),
    'x'.repeat(213),
  ];
  const versions = new Set<number>();
  for (const text of samples) {
    const qr = encodeQr(text);
    versions.add(qr.version);
    assert.equal(read(qr.modules), text);
  }
  assert.equal(encodeQr('x'.repeat(14)).version, 1);
  assert.equal(encodeQr('x'.repeat(15)).version, 2);
  assert.equal(encodeQr('x'.repeat(213)).version, 10);
  assert.throws(() => encodeQr('x'.repeat(214)), RangeError);
  for (let n = 1; n <= 213; n += 7) assert.equal(read(encodeQr('q'.repeat(n)).modules), 'q'.repeat(n), `length ${n}`);
  assert.ok(versions.size >= 3);
});
