import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const { CATALOGUES } = await vite.ssrLoadModule('/src/i18n/index.tsx');
const { api, ApiError } = await vite.ssrLoadModule('/src/api/client.ts');
const { errorText } = await vite.ssrLoadModule('/src/api/errorText.ts');

const root = resolve(import.meta.dirname, '../../..');
const files = (dir: string): string[] => readdirSync(dir, { withFileTypes: true })
  .flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith('.ts') ? [join(dir, e.name)] : []));

/** Every error code the console can receive: the server's HttpError codes and literal error envelopes, and the codes
 *  the console's own client makes up. */
function codes(): Set<string> {
  const found = new Set<string>();
  const scan = (file: string, pattern: RegExp) => { for (const m of readFileSync(file, 'utf8').matchAll(pattern)) found.add(m[1]!); };
  for (const file of files(resolve(root, 'packages/pdp-http/src'))) {
    scan(file, /new HttpError\(\s*\d+\s*,\s*'([a-z_]+)'/g);
    scan(file, /\berror:\s*'([a-z_]+)'/g);
  }
  scan(resolve(root, 'apps/admin/src/api/client.ts'), /new ApiError\([^,]+,\s*'([a-z_]+)'/g);
  return found;
}

test('every error code the server or the client can produce has a message in every console language', () => {
  const all = codes();
  for (const expected of ['bad_request', 'unauthenticated', 'forbidden', 'not_found', 'conflict', 'unprocessable', 'rate_limited', 'internal', 'stale', 'self_approval', 'session_changed', 'invalid_response']) {
    assert.ok(all.has(expected), `the scan finds ${expected}: the patterns still match the source`);
  }
  for (const lang of ['en', 'fr', 'ar'] as const) {
    const known: Record<string, string> = CATALOGUES[lang].errors.codes;
    const missing = [...all].filter((code) => !known[code]?.trim());
    assert.deepEqual(missing, [], `${lang}: codes without a message`);
  }
});

test('errorText: the translated code, the server text as a detail, a fallback for an unknown code', () => {
  const fr = CATALOGUES.fr;
  const stale = errorText(fr, new ApiError(409, 'stale', 'State changed since simulation'));
  assert.equal(stale.text, fr.errors.codes.stale);
  assert.equal(stale.detail, 'State changed since simulation');
  assert.deepEqual(errorText(fr, new ApiError(404, 'not_found', 'not_found')), { text: fr.errors.codes.not_found });
  assert.equal(errorText(fr, new ApiError(418, 'http_418', 'Request failed with status 418')).text, fr.errors.fallback(418));
  assert.equal(errorText(CATALOGUES.en, new ApiError(418, 'teapot', 'x')).text, CATALOGUES.en.errors.fallback(418));
  assert.equal(errorText(fr, new TypeError('Failed to fetch')).text, fr.errors.network);
  assert.equal(errorText(fr, new Error('Votre rôle ne permet pas.')).text, 'Votre rôle ne permet pas.');
});


test('a 204 response is invalid when the endpoint requires a response body', async (t) => {
  const fetchBefore = globalThis.fetch;
  t.after(() => { globalThis.fetch = fetchBefore; });
  globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
  await assert.rejects(api.getSession(), (err: unknown) => {
    if (!(err instanceof ApiError)) return false;
    assert.equal((err as { status: number }).status, 204);
    assert.equal((err as { code: string }).code, 'invalid_response');
    return true;
  });
});
