// Impact tooltips, version ranges, break-glass labels and change summaries come from the catalogues, with arrows that
// read in the console's direction (console review finding 12).
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
  location: { hash: '#/overview', pathname: '/', search: '' }, history: { replaceState: noop },
} as unknown as Window & typeof globalThis;
globalThis.document = { documentElement: { dataset: {} } } as unknown as Document;
const i18n = await vite.ssrLoadModule('/src/i18n/index.tsx');
const { ImpactTables } = await vite.ssrLoadModule('/src/components/ImpactTables.tsx');
const { summarizeChangePayload } = await vite.ssrLoadModule('/src/utils/expr.ts');
const render = (lang: string, node: unknown) => renderToStaticMarkup(h(i18n.I18nProvider, { lang }, node as never));

const impact = { evaluated: 4, gained: [], lost: [], obligationsLost: [], obligationsGained: [], policyVersionBefore: 'pv.aaaaaaaaaaaaaaaa', policyVersionAfter: 'pv.bbbbbbbbbbbbbbbb',
  analysis: { affectedCells: 3, reasons: ['certification records changed'] } };

test('the impact summary has no English tooltip in French or Arabic, and Arabic reads the version range right to left', () => {
  for (const lang of ['fr', 'ar']) {
    const html = render(lang, h(ImpactTables as FunctionComponent<{ impact: unknown }>, { impact }));
    assert.ok(!html.includes('affected cells'), `${lang}: no English tooltip`);
  }
  const ar = render('ar', h(ImpactTables as FunctionComponent<{ impact: unknown }>, { impact }));
  assert.ok(!ar.includes(' → '), 'no left-to-right arrow inside Arabic text');
  assert.ok(ar.includes('←'));
});

test('change summaries use catalogue words and arrows, and SCIM batches are summarised, not dumped as JSON', () => {
  const subject = { id: 'bob', set: { clearance: 3, roles: ['clerk'] } };
  render('fr', h('span', null));
  const fr = summarizeChangePayload('update_subject', subject);
  assert.ok(!fr.includes('->') && !fr.includes('clearance') && fr.includes('habilitation'), fr);
  render('ar', h('span', null));
  const ar = summarizeChangePayload('update_subject', subject);
  assert.ok(!ar.includes('->') && !ar.includes('→') && ar.includes('←'), ar);
  const scim = summarizeChangePayload('scim_subjects', { subjects: [{ id: 'a', type: 'user' }, { id: 'b', type: 'user' }] });
  assert.ok(!scim.startsWith('{'), scim);
  render('en', h('span', null));
  assert.match(summarizeChangePayload('scim_subjects', { subjects: [{ id: 'a' }, { id: 'b' }] }), /2/);
});
