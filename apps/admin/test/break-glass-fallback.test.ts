// The console offers review and revoke to an access_admin only for the emergencies the server lists in
// fallbackReview (no security officer other than the opener and the subject exists), as break-glass.ts decides.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const { breakGlassCanManage } = await vite.ssrLoadModule('/src/screens/BreakGlassScreen.tsx');
const { en, fr, ar } = await vite.ssrLoadModule('/src/i18n/breakGlass.ts');

test('an access_admin manages only the emergencies listed for the fallback; a security officer manages all', () => {
  const list = { fallbackReview: ['e1'] };
  assert.equal(breakGlassCanManage(['access_admin'], list, 'e1'), true);
  assert.equal(breakGlassCanManage(['access_admin'], list, 'e2'), false);
  assert.equal(breakGlassCanManage(['access_admin'], {}, 'e1'), false, 'an older server sends no list');
  assert.equal(breakGlassCanManage(['security_officer'], {}, 'e2'), true);
  assert.equal(breakGlassCanManage(['auditor'], list, 'e1'), false);
});

test('the fallback is explained in every language', () => {
  for (const m of [en, fr, ar]) assert.ok(typeof m.fallbackReview === 'string' && m.fallbackReview.length > 20);
});
