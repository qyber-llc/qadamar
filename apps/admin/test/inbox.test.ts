// The Approvals inbox (docs/API.md §3.5.1): tabs, queue, keyboard map, list-mode selection and the approval modes card.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createElement as h, type FunctionComponent } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const noop = () => undefined;
globalThis.window = {
  matchMedia: () => ({ matches: true, addEventListener: noop, removeEventListener: noop }),
  localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
  location: { hash: '#/approvals', pathname: '/', search: '' }, history: { replaceState: noop },
} as unknown as Window & typeof globalThis;
globalThis.document = { documentElement: { dataset: {} } } as unknown as Document;
const i18n = await vite.ssrLoadModule('/src/i18n/index.tsx');
const inbox = await vite.ssrLoadModule('/src/utils/inbox.ts');
const { ApprovalQueue } = await vite.ssrLoadModule('/src/screens/ApprovalQueue.tsx');
const { ApprovalModesCard } = await vite.ssrLoadModule('/src/screens/ApprovalModesCard.tsx');
const render = (lang: string, node: unknown) => renderToStaticMarkup(h(i18n.I18nProvider, { lang }, node as never));

const impact = { evaluated: 1, gained: [], lost: [], obligationsLost: [], obligationsGained: [], policyVersionBefore: 'a', policyVersionAfter: 'a' };
const change = (id: string, extra: Record<string, unknown> = {}) => ({ id, kind: 'update_subject', status: 'pending', makerId: 'amira', reason: 'r', createdAt: '2026-11-08T10:00:00Z',
  broadens: false, stateDigest: 'd', impact, payload: { id: 'bob', set: { active: false } }, ...extra });
const emergency = (id: string, extra: Record<string, unknown> = {}) => ({ id, subjectId: 'bob', resourceId: 'CASE-15', reason: 'r', openedBy: 'amira',
  openedAt: '2026-11-08T10:00:00Z', expiresAt: '2026-11-08T11:00:00Z', status: 'active', ...extra });
const omar = { id: 'omar', name: 'omar', roles: ['approver'] };
const lina = { id: 'lina', name: 'lina', roles: ['security_officer'] };
const amira = { id: 'amira', name: 'amira', roles: ['access_admin'] };

test('tabs: "Awaiting you" lists what this user may decide and is not snoozed; Snoozed, Applied, Rejected and All', () => {
  const changes = [change('a'), change('own', { makerId: 'omar' }), change('done', { status: 'applied' }), change('no', { status: 'rejected' }), change('later')];
  const snoozed = new Set(['change:later']);
  const keys = (tab: string, user = omar, bg: unknown[] = []) => inbox.buildQueue(tab, changes, bg, snoozed, user).map((i: { key: string }) => i.key);
  assert.deepEqual(keys('awaiting'), ['change:a']);
  assert.deepEqual(keys('pending'), ['change:a', 'change:own']);
  assert.deepEqual(keys('snoozed'), ['change:later']);
  assert.deepEqual(keys('applied'), ['change:done']);
  assert.deepEqual(keys('rejected'), ['change:no']);
  assert.equal(keys('all').length, 5);
  assert.deepEqual(keys('awaiting', amira), [], 'an access admin decides no change');
  assert.deepEqual(keys('awaiting', lina, [emergency('e1')]), ['emergency:e1', 'change:a', 'change:own']);
});

test('break-glass rows: a security officer other than the opener and the subject, or the access_admin fallback', () => {
  const list = { active: [], reviewed: [], toReview: [emergency('e1'), emergency('e2', { openedBy: 'lina' }), emergency('e3', { subjectId: 'lina' })], fallbackReview: ['e3'] };
  assert.deepEqual(inbox.emergenciesAwaiting(list, lina).map((e: { id: string }) => e.id), ['e1', 'e3']);
  assert.deepEqual(inbox.emergenciesAwaiting(list, amira).map((e: { id: string }) => e.id), ['e3']);
  assert.deepEqual(inbox.emergenciesAwaiting(null, lina), []);
});

test('keyboard: J/K move, Shift extends and X selects only in list mode, S snooze, A decide, Enter open; never while typing', () => {
  const key = (k: string, extra: Record<string, unknown> = {}, list = true) =>
    inbox.inboxKey({ key: k, shiftKey: false, ctrlKey: false, metaKey: false, altKey: false, target: { tagName: 'BODY' }, ...extra }, list);
  assert.deepEqual(key('j'), { type: 'move', delta: 1, extend: false });
  assert.deepEqual(key('K', { shiftKey: true }), { type: 'move', delta: -1, extend: true });
  assert.deepEqual(key('J', { shiftKey: true }, false), { type: 'move', delta: 1, extend: false });
  assert.deepEqual(key('x'), { type: 'toggle' });
  assert.equal(key('x', {}, false), null);
  assert.deepEqual(key('s'), { type: 'snooze' });
  assert.deepEqual(key('a'), { type: 'primary' });
  assert.deepEqual(key('Enter'), { type: 'open' });
  assert.equal(key('Enter', { target: { tagName: 'BUTTON' } }), null, 'a focused button handles Enter itself');
  for (const target of [{ tagName: 'INPUT' }, { tagName: 'textarea' }, { tagName: 'SELECT' }, { tagName: 'DIV', isContentEditable: true }]) assert.equal(key('j', { target }), null);
  for (const mod of ['ctrlKey', 'metaKey', 'altKey']) assert.equal(key('a', { [mod]: true }), null);
  assert.equal(key('q'), null);
  assert.deepEqual(key('j', { target: { tagName: 'INPUT', type: 'checkbox' } }), { type: 'move', delta: 1, extend: false }, 'a checkbox is not a text field');
});

test('snooze dates follow the server day (UTC)', () => {
  assert.equal(inbox.dayAfter(Date.parse('2026-11-08T23:30:00Z'), 1), '2026-11-09');
  assert.equal(inbox.dayAfter(Date.parse('2026-11-08T10:00:00Z'), inbox.SNOOZE_MAX_DAYS), '2026-12-08');
});

for (const lang of ['en', 'fr', 'ar']) {
  test(`[${lang}] list mode: labelled checkboxes on decidable rows only, refusal reasons, snooze dates, break-glass rows link to their screen`, () => {
    const items = [
      { kind: 'emergency', key: 'emergency:e1', emergency: emergency('e1') },
      { kind: 'change', key: 'change:a', change: change('a') },
      { kind: 'change', key: 'change:own', change: change('own', { makerId: 'omar' }) },
    ];
    const html = render(lang, h(ApprovalQueue as FunctionComponent<Record<string, unknown>>, { items, user: omar, activeId: 'a', cursor: 'change:a', listMode: true, selected: new Set(['a']),
      failures: new Map([['a', 'State changed; submit a new proposal']]), snoozedUntil: new Map([['emergency:e1', '2026-11-10']]), busy: false,
      rowRef: noop, onOpen: noop, onCursor: noop, onToggle: noop, onSnooze: noop, onUnsnooze: noop }));
    assert.equal((html.match(/type="checkbox"/g) ?? []).length, 1, 'only the change this user may decide');
    assert.match(html, /type="checkbox"[^>]*aria-label="[^"]+"[^>]*checked=""|checked=""[^>]*aria-label="[^"]+"/);
    assert.match(html, /href="#\/break-glass"/);
    assert.ok(html.includes('State changed; submit a new proposal'));
    assert.ok(html.includes('2026-11-10'));
    const a = i18n.CATALOGUES[lang].approvals;
    assert.ok(html.includes(a.unsnooze));
    if (lang === 'ar') assert.ok(a.selectedCount(3, 50).includes('⁦50⁩') && !a.emergencyRow('bob', 'C').includes('→'));
  });
  test(`[${lang}] the approval modes card opens on a labelled region with a loading state`, () => {
    const html = render(lang, h(ApprovalModesCard as FunctionComponent<object>, {}));
    assert.match(html, /role="region" aria-labelledby="approval-modes-title"/);
    assert.ok(html.includes(i18n.CATALOGUES[lang].security.modes.title));
    assert.ok(html.includes(i18n.CATALOGUES[lang].security.modes.loading));
  });
}
