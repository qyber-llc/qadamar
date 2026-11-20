import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const { api, setCsrfToken } = await vite.ssrLoadModule('/src/api/client.ts');

test('console sign out clears CSRF and navigates to SAML logout only when returned by the server', async (t) => {
  const fetchBefore = globalThis.fetch;
  const windowBefore = Object.getOwnPropertyDescriptor(globalThis, 'window');
  t.after(() => {
    globalThis.fetch = fetchBefore;
    if (windowBefore) Object.defineProperty(globalThis, 'window', windowBefore); else Reflect.deleteProperty(globalThis, 'window');
  });
  const navigated: string[] = [];
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location: { origin: 'https://console.example', assign: (url: string) => navigated.push(url) } } });
  let withSlo = true;
  let expectedCsrf: string | undefined = 'test-csrf';
  globalThis.fetch = (async (url: string, options: RequestInit) => {
    assert.equal(url, '/admin/v1/session'); assert.equal(options.method, 'DELETE');
    assert.equal(options.credentials, 'same-origin');
    assert.equal((options.headers as Record<string, string>)['X-CSRF-Token'], expectedCsrf);
    return withSlo ? new Response(JSON.stringify({ logoutUrl: 'https://idp.example/logout?SAMLRequest=signed' }), { headers: { 'content-type': 'application/json' } }) : new Response(null, { status: 204 });
  }) as typeof fetch;
  setCsrfToken(expectedCsrf);
  await api.signOut();
  assert.deepEqual(navigated, ['https://idp.example/logout?SAMLRequest=signed']);
  withSlo = false; expectedCsrf = undefined;
  await api.signOut();
  assert.equal(navigated.length, 1);
});


test('console sign out accepts only HTTPS or same-origin logout URLs', async (t) => {
  const fetchBefore = globalThis.fetch;
  const windowBefore = Object.getOwnPropertyDescriptor(globalThis, 'window');
  t.after(() => {
    globalThis.fetch = fetchBefore;
    if (windowBefore) Object.defineProperty(globalThis, 'window', windowBefore); else Reflect.deleteProperty(globalThis, 'window');
  });
  const navigated: string[] = [];
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { location: { origin: 'https://console.example', assign: (url: string) => navigated.push(url) } } });
  let logoutUrl = '';
  globalThis.fetch = (async () => new Response(JSON.stringify({ logoutUrl }), { headers: { 'content-type': 'application/json' } })) as typeof fetch;
  for (const candidate of [
    'https://idp.example/logout',
    '/signed-out',
    'http://idp.example/logout',
    'javascript:alert(1)',
    'data:text/html,signed-out',
    'http://[',
  ]) {
    logoutUrl = candidate;
    await api.signOut();
  }
  assert.deepEqual(navigated, ['https://idp.example/logout', 'https://console.example/signed-out']);
});
