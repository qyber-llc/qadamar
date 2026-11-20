import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { contrastRatio, decodePng, isLarge, over, parseColor, textContrast } from '../e2e/contrast.ts';
import { launch, playwrightCorePaths } from '../e2e/harness.ts';

const near = (a: number, b: number, eps = 0.01) => assert.ok(Math.abs(a - b) < eps, `${a} ≈ ${b}`);

test('WCAG contrast: black on white 21:1, equal colours 1:1, #767676 on white just above 4.5:1, #777 just below', () => {
  near(contrastRatio([0, 0, 0], [255, 255, 255]), 21);
  near(contrastRatio([90, 90, 90], [90, 90, 90]), 1);
  assert.ok(contrastRatio([0x76, 0x76, 0x76], [255, 255, 255]) >= 4.5);
  assert.ok(contrastRatio([0x77, 0x77, 0x77], [255, 255, 255]) < 4.5);
  near(contrastRatio([255, 0, 0], [255, 255, 255]), 4, 0.01);
  assert.deepEqual(over([0, 0, 0, 0.5], [255, 255, 255]), [127.5, 127.5, 127.5]);
  assert.deepEqual(parseColor('rgba(10, 20, 30, 0.5)'), [10, 20, 30, 0.5]);
  assert.deepEqual(parseColor('rgb(1, 2, 3)'), [1, 2, 3, 1]);
  assert.equal(isLarge(24, 400), true);
  assert.equal(isLarge(19, 700), true);
  assert.equal(isLarge(19, 600), false);
});

test('PNG decoding handles all five filters, and text contrast reads the darkest part of a background', () => {
  const width = 4, height = 5;
  const rows: number[] = [];
  const pixel = (x: number, y: number) => [x * 40, y * 30, (x + y) * 20, 255];
  for (let y = 0; y < height; y++) {
    rows.push(y); // filter type = row index: None, Sub, Up, Average, Paeth
    const cur = Array.from({ length: width }, (_, x) => pixel(x, y)).flat();
    const prev = y > 0 ? Array.from({ length: width }, (_, x) => pixel(x, y - 1)).flat() : new Array<number>(width * 4).fill(0);
    cur.forEach((v, i) => {
      const a = i >= 4 ? cur[i - 4]! : 0, b = prev[i]!, c = i >= 4 ? prev[i - 4]! : 0;
      const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
      const pred = [0, a, b, (a + b) >> 1, pa <= pb && pa <= pc ? a : pb <= pc ? b : c][y]!;
      rows.push((v - pred) & 0xff);
    });
  }
  const chunk = (kind: string, data: Buffer) => {
    const head = Buffer.alloc(8); head.writeUInt32BE(data.length); head.write(kind, 4, 'latin1');
    return Buffer.concat([head, data, Buffer.alloc(4)]);
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 6;
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(Buffer.from(rows))), chunk('IEND', Buffer.alloc(0))]);
  const image = decodePng(png);
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
    assert.deepEqual([...image.rgba.subarray((y * width + x) * 4, (y * width + x) * 4 + 4)], pixel(x, y), `pixel ${x},${y}`);
  }
  const white = { width: 10, height: 1, rgba: new Uint8Array(40).fill(255) };
  white.rgba.set([0, 0, 0, 255], 0);
  const result = textContrast(white, [255, 255, 255, 1], [{ x: 0, y: 0, w: 10, h: 1 }]);
  near(result.ratio, 1); // white text over the white part: the black pixel does not rescue it
});

test('browser-test harness: PLAYWRIGHT_CORE_PATH wins, a missing browser skips, and fails under E2E_REQUIRED=1', async () => {
  assert.deepEqual(playwrightCorePaths({ PLAYWRIGHT_CORE_PATH: '/opt/pw', PLAYWRIGHT_CORE: '/old' }), ['/opt/pw']);
  assert.deepEqual(playwrightCorePaths({ PLAYWRIGHT_CORE: '/old' }), ['/old']);
  const missing = ['/nonexistent/playwright-core'];
  assert.match(String(await launch({}, missing)), /playwright-core not found at \/nonexistent/);
  assert.match(String(await launch({}, [])), /set PLAYWRIGHT_CORE_PATH/);
  await assert.rejects(launch({ E2E_REQUIRED: '1' }, missing), /E2E_REQUIRED is set and the browser tests cannot run/);
});
