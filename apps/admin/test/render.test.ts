import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createElement as h, type FunctionComponent } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const load = (path: string) => vite.ssrLoadModule(path);
const { ApiError } = await load('/src/api/client.ts');
const { FocusTrapModal } = await load('/src/components/FocusTrapModal.tsx');
const { ErrorAlert } = await load('/src/components/UiStates.tsx');
const { AccessMatrixScreen } = await load('/src/screens/AccessMatrixScreen.tsx');
const { AccessReviewsScreen } = await load('/src/screens/AccessReviewsScreen.tsx');
const { ApprovalsScreen } = await load('/src/screens/ApprovalsScreen.tsx');
const { AttributeModelScreen } = await load('/src/screens/AttributeModelScreen.tsx');
const { AuditExplorerScreen } = await load('/src/screens/AuditExplorerScreen.tsx');
const { BreakGlassScreen } = await load('/src/screens/BreakGlassScreen.tsx');
const { ComplianceScreen } = await load('/src/screens/ComplianceScreen.tsx');
const { ModelTablesPane } = await load('/src/screens/ModelTablesPane.tsx');
const { OverviewScreen } = await load('/src/screens/OverviewScreen.tsx');
const { PoliciesScreen } = await load('/src/screens/PoliciesScreen.tsx');
const { SignInScreen } = await load('/src/screens/SignInScreen.tsx');
const { SimulatorScreen } = await load('/src/screens/SimulatorScreen.tsx');
const { WhatCanResultsTable, WhoCanResultsTable } = await load('/src/screens/SimulatorQueryTables.tsx');

const noop = () => undefined;
const params = {};
const user = { id: 'amira', name: 'Amira', roles: ['access_admin'] } as const;

globalThis.window = {
  matchMedia: () => ({ matches: true, addEventListener: noop, removeEventListener: noop }),
  localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
  location: { hash: '#/overview', pathname: '/', search: '' },
  history: { replaceState: noop },
} as unknown as Window & typeof globalThis;
globalThis.document = { documentElement: { dataset: {} } } as unknown as Document;

const screens = [
  ['overview', OverviewScreen, { roles: user.roles, userName: user.name, onOverviewLoaded: noop }, 'Loading overview...'],
  ['model', AttributeModelScreen, { roles: user.roles, params, setParams: noop }, 'Loading attribute model...'],
  ['policies', PoliciesScreen, { roles: user.roles, params, setParams: noop }, 'Loading policies...'],
  ['matrix', AccessMatrixScreen, { params, setParams: noop, onExplain: noop }, 'Evaluating every pair...'],
  ['simulator', SimulatorScreen, { roles: user.roles, params, setParams: noop, onExplain: noop }, 'Loading simulator...'],
  ['approvals', ApprovalsScreen, { user, params, setParams: noop, onApprovalChanged: noop }, 'Loading approvals...'],
  ['breakglass', BreakGlassScreen, { user, onBreakGlassChanged: noop }, 'Loading break-glass grants...'],
  ['reviews', AccessReviewsScreen, { user, params, setParams: noop, onChangeCreated: noop }, 'Loading access reviews...'],
  ['audit', AuditExplorerScreen, { roles: user.roles, params, setParams: noop }, 'Loading audit log...'],
  ['compliance', ComplianceScreen, { params, setParams: noop }, 'Loading compliance frameworks...'],
] as const;

for (const [id, Screen, props, loading] of screens) {
  test(`${id} screen exposes its heading and live loading state`, () => {
    const html = renderToStaticMarkup(h(Screen as FunctionComponent<object>, props));
    assert.match(html, new RegExp(`<section[^>]*aria-labelledby="title-${id}"`));
    assert.match(html, new RegExp(`<h1[^>]*id="title-${id}"`));
    assert.match(html, /role="status" aria-live="polite"/);
    assert.ok(html.includes(loading));
  });
}

test('sign-in inputs have persistent labels, autocomplete and validation semantics', () => {
  const html = renderToStaticMarkup(h(SignInScreen, { embedded: true, onSignedIn: noop }));
  assert.match(html, /<label for="signin-username">Username<\/label>/);
  assert.match(html, /<label for="signin-password">Password<\/label>/);
  assert.match(html, /id="signin-username"[^>]*autoComplete="username"[^>]*required=""[^>]*aria-invalid="false"/);
  assert.match(html, /id="signin-password"[^>]*autoComplete="current-password"[^>]*required=""[^>]*aria-invalid="false"/);
  assert.doesNotMatch(html, /value="[^"]+"/);
});

test('screen error alerts assert the failure and identify retry controls', () => {
  const error = new ApiError(503, 'unavailable', 'Decision service unavailable', ['Try again shortly']);
  const html = renderToStaticMarkup(h(ErrorAlert, { error, contextTitle: 'Overview unavailable', onRetry: noop }));
  assert.match(html, /role="alert"/);
  assert.ok(html.includes('Overview unavailable:'));
  assert.ok(html.includes('Decision service unavailable'));
  assert.ok(html.includes('503'));
  assert.ok(html.includes('Try again shortly'));
  assert.match(html, /<button type="button"[^>]*>Retry<\/button>/);
});

test('simulator empty results use polite status notices', () => {
  const whatCan = renderToStaticMarkup(h(WhatCanResultsTable, {
    snapshot: { subjectId: 'amira', action: 'read', network: 'trusted', items: [] }, onExplain: noop,
  }));
  const whoCan = renderToStaticMarkup(h(WhoCanResultsTable, {
    snapshot: { resourceId: 'CASE-1', action: 'read', network: 'trusted', items: [] }, onExplain: noop,
  }));
  assert.match(whatCan, /role="status"/);
  assert.ok(whatCan.includes('No resources in scope to evaluate.'));
  assert.match(whoCan, /role="status"/);
  assert.ok(whoCan.includes('No subjects in scope to evaluate.'));
});

test('attribute table empty state retains labelled filters and a result count', () => {
  const html = renderToStaticMarkup(h(ModelTablesPane, {
    activeTab: 'subjects', roles: user.roles, schema: null, subjects: [], resources: [], tuples: [], params, setParams: noop,
  }));
  assert.match(html, /role="status"[^>]*>0 subjects shown/);
  assert.match(html, /<label for="model-search-input">Search<\/label>/);
  assert.match(html, /<label for="model-level-select">Level<\/label>/);
  assert.ok(html.includes('No subjects match the current filter.'));
});

test('open dialogs have an accessible name and modal semantics', () => {
  const html = renderToStaticMarkup(h(FocusTrapModal, {
    open: true, onClose: noop, titleId: 'test-dialog-title', title: 'Session expired', variant: 'modal',
  }, h('p', null, 'Sign in again')));
  assert.match(html, /role="dialog" aria-modal="true" aria-labelledby="test-dialog-title" tabindex="-1"/);
  assert.match(html, /<h2 id="test-dialog-title"[^>]*>Session expired<\/h2>/);
  assert.equal(renderToStaticMarkup(h(FocusTrapModal, {
    open: false, onClose: noop, titleId: 'test-dialog-title', title: 'Session expired',
  })), '');
});


test('approvals never substitute another change for a missing selected id', async () => {
  const { selectActiveChange } = await load('/src/screens/ApprovalsScreen.tsx');
  const changes = [{ id: 'first' }, { id: 'second' }];
  assert.equal(selectActiveChange(changes, ''), changes[0]);
  assert.equal(selectActiveChange(changes, 'second'), changes[1]);
  assert.equal(selectActiveChange(changes, 'missing'), null);
});

test('approvals ignore responses and completion from superseded loads', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../src/screens/ApprovalsScreen.tsx', import.meta.url), 'utf8');
  assert.match(source, /const gen = \+\+reqGenRef\.current;/);
  assert.match(source, /await Promise\.all\(\[\s+api\.getChanges\(\)[^;]+;\s+if \(reqGenRef\.current !== gen\) return;/);
  assert.match(source, /catch \(err\) \{\s+if \(reqGenRef\.current !== gen\) return;/);
  assert.match(source, /finally \{\s+if \(reqGenRef\.current === gen\) setLoading\(false\);/);
});

test('break-glass shows only mandatory restrictions and honours the bundle hour cap', async () => {
  const { mandatoryRestrictionRules, breakGlassHoursCap } = await load('/src/screens/BreakGlassScreen.tsx');
  assert.deepEqual(mandatoryRestrictionRules(undefined), []);
  assert.deepEqual(mandatoryRestrictionRules(['RBAC.NOT_ELIGIBLE', 'ABAC.DENY']), []);
  assert.deepEqual(
    mandatoryRestrictionRules(['BLP.NO_READ_UP', 'MAC.COMPARTMENT', 'NET.UNTRUSTED', 'BIBA.NO_READ_DOWN', 'ABAC.DENY']),
    ['BLP.NO_READ_UP', 'MAC.COMPARTMENT', 'NET.UNTRUSTED', 'BIBA.NO_READ_DOWN'],
  );
  assert.equal(breakGlassHoursCap(undefined), 4);
  assert.equal(breakGlassHoursCap(2), 2);
  assert.equal(breakGlassHoursCap(8), 4);
});

test('candidate changes clear submission state and current submissions cannot be repeated', async () => {
  const { readFileSync } = await import('node:fs');
  const read = (path: string) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8');
  assert.match(
    read('utils/useChangePreview.ts'),
    /setPreview\(\(prev\)[^;]+;\s+setError\(null\);\s+setSubmittedChange\(null\);/,
  );
  for (const path of ['screens/SimulatorImpactPane.tsx', 'screens/PolicyEditorPane.tsx']) {
    assert.match(read(path), /const canSubmit =[^;]+&& !submittedChange;/);
  }
});

test('a modal without a close callback exposes no dismissal control', () => {
  const html = renderToStaticMarkup(h(FocusTrapModal, {
    open: true, onClose: undefined as never, titleId: 'reauth-title', title: 'Session expired', variant: 'modal',
  }, h('p', null, 'Sign in again')));
  assert.match(html, /role="dialog" aria-modal="true"/);
  assert.doesNotMatch(html, /<button[^>]*>Close \(Esc\)<\/button>/);
});
