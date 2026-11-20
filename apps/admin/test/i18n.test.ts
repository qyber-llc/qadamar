import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createElement as h, type FunctionComponent, type ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const load = (path: string) => vite.ssrLoadModule(path);

const store = new Map<string, string>();
const noop = () => undefined;
globalThis.window = {
  matchMedia: () => ({ matches: true, addEventListener: noop, removeEventListener: noop }),
  localStorage: { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v); }, removeItem: noop },
  location: { hash: '#/overview', pathname: '/', search: '' },
  history: { replaceState: noop },
} as unknown as Window & typeof globalThis;
globalThis.document = { documentElement: { dataset: {} } } as unknown as Document;

const i18n = await load('/src/i18n/index.tsx');
const { ApiError } = await load('/src/api/client.ts');
const { LevelBadge, ErrorAlert } = await load('/src/components/UiStates.tsx');
const { SecretPanel } = await load('/src/components/SecretPanel.tsx');
const { PepCredentialsCard, SigningKeysCard, ScimCard } = await load('/src/screens/CredentialsCards.tsx');
const { CredentialsScreen } = await load('/src/screens/CredentialsScreen.tsx');
const { TwoStepScreen } = await load('/src/screens/TwoStepScreen.tsx');
const { QrCode } = await load('/src/components/QrCode.tsx');
const permissions = await load('/src/utils/permissions.ts');

type Lang = 'en' | 'fr' | 'ar';
const LANGS: readonly Lang[] = ['en', 'fr', 'ar'];
// The catalogue is data: read it loosely here, its exact type is checked by tsc.
type Tree = { readonly [key: string]: Tree | string | ((...args: unknown[]) => string) };
const cat = (lang: Lang) => i18n.CATALOGUES[lang] as Tree;
const sec = (lang: Lang) => cat(lang).security as Tree;
const part = (lang: Lang, ...path: string[]) => path.reduce((node: Tree, key) => node[key] as Tree, sec(lang));
const str = (lang: Lang, ...path: string[]) => {
  const parent = part(lang, ...path.slice(0, -1));
  return parent[path.at(-1)!] as string;
};
const fn = (lang: Lang, ...path: string[]) => {
  const parent = part(lang, ...path.slice(0, -1));
  return parent[path.at(-1)!] as (...args: unknown[]) => string;
};
const render = (lang: Lang, node: ReactNode) => renderToStaticMarkup(h(i18n.I18nProvider, { lang }, node));
/** Static markup escapes quotes and apostrophes; compare the catalogue text the same way. */
const esc = (text: string) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

function walk(node: unknown, path: string, out: Map<string, string>): void {
  if (typeof node === 'string') { out.set(path, 'string'); return; }
  if (typeof node === 'function') { out.set(path, `function/${node.length}`); return; }
  for (const [key, child] of Object.entries(node as object)) walk(child, path ? `${path}.${key}` : key, out);
}

test('all catalogues have exactly the same keys, kinds and arities; no translated text is empty', () => {
  const en = new Map<string, string>();
  walk(cat('en'), '', en);
  for (const lang of ['fr', 'ar'] as const) {
    const translated = new Map<string, string>();
    walk(cat(lang), '', translated);
    assert.deepEqual([...translated.keys()].sort(), [...en.keys()].sort(), `${lang}: exact keys`);
    for (const [key, kind] of en) assert.equal(translated.get(key), kind, `${lang}: ${key} kind or arity`);
  }
  assert.ok(en.size > 500, `the catalogue covers every screen (${en.size} keys)`);
  const sample = (f: (...args: unknown[]) => string) => f(...Array.from({ length: f.length }, () => 2));
  for (const lang of LANGS) {
    const values = new Map<string, string>();
    const leaves = (node: unknown, path: string): void => {
      if (typeof node === 'string') values.set(path, node);
      else if (typeof node === 'function') values.set(path, sample(node as (...args: unknown[]) => string));
      else for (const [k, v] of Object.entries(node as object)) leaves(v, `${path}.${k}`);
    };
    leaves(cat(lang), lang);
    for (const [key, value] of values) assert.ok(value.trim().length > 0, `${key} is empty`);
  }
});

test('levels and roles follow the console language', () => {
  assert.match(render('en', h(LevelBadge, { level: 1 })), />L1 Internal</);
  assert.match(render('fr', h(LevelBadge, { level: 1 })), />L1 Interne</);
  render('fr', null);
  assert.equal(permissions.ROLE_LABELS.access_admin, 'Administrateur des accès');
  render('en', null);
  assert.equal(permissions.ROLE_LABELS.access_admin, 'Access Administrator');
});

test('the language is kept per user, falls back to the last choice, and survives blocked storage', () => {
  store.clear();
  i18n.writeLang('amira', 'ar');
  assert.equal(i18n.readLang('amira'), 'ar');
  i18n.writeLang('amira', 'fr');
  assert.equal(i18n.readLang('amira'), 'fr');
  assert.equal(i18n.readLang(), 'fr', 'last choice on this browser');
  store.set('qadamar-lang:lina', 'en');
  assert.equal(i18n.readLang('lina'), 'en', 'a person’s own choice wins');
  const saved = window.localStorage;
  (globalThis.window as unknown as { localStorage: unknown }).localStorage = {
    getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); },
  };
  assert.doesNotThrow(() => i18n.writeLang('amira', 'en'));
  assert.ok(i18n.LANGS.includes(i18n.readLang('amira')));
  (globalThis.window as unknown as { localStorage: unknown }).localStorage = saved;
});

test('only access admins and security officers reach the credentials screen; actions follow the server roles', () => {
  const roles = ['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner', 'auditor'];
  const reach = roles.filter((r) => permissions.canAccessRoute([r], 'credentials'));
  assert.deepEqual(reach, ['access_admin', 'security_officer']);
  assert.deepEqual(roles.filter((r) => permissions.canManagePepCredentials([r])), ['security_officer']);
  assert.deepEqual(roles.filter((r) => permissions.canRotateScimCredential([r])), ['access_admin']);
});

const credentials = [
  { id: 'c1', name: 'records-api', created: '2026-11-01T08:00:00Z', lastUsed: '2026-11-09T10:00:00Z', rotated: '2026-11-05T08:00:00Z', previousValidUntil: '2026-11-05T08:05:00Z' },
  { id: 'c2', name: 'bootstrap', created: '2026-10-01T08:00:00Z', revoked: '2026-11-02T08:00:00Z' },
];
const keys = [
  { kid: 'kid-new', created: '2026-11-09T08:00:00Z', active: true },
  { kid: 'kid-old', created: '2026-10-01T08:00:00Z', active: false, verifyUntil: '2026-11-09T08:05:00Z' },
];

for (const lang of LANGS) {
  test(`[${lang}] two-step sign-in opens on a labelled section with a polite loading state; every role reaches it`, () => {
    const t = cat(lang).twoStep as Tree;
    const html = render(lang, h(TwoStepScreen, {}));
    assert.match(html, /<section[^>]*aria-labelledby="title-two-step"/);
    assert.ok(html.includes(`id="title-two-step">${esc(t.title as string)}</h1>`));
    assert.match(html, /role="status" aria-live="polite"/);
    assert.ok(html.includes(esc(t.loading as string)));
    for (const role of ['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner', 'auditor']) {
      assert.ok(permissions.canAccessRoute([role], 'two-step'), role);
    }
  });

  test(`[${lang}] the QR code is a labelled image, dark modules on white with a quiet zone`, () => {
    const html = render(lang, h(QrCode, { text: 'A', label: 'QR' }));
    assert.match(html, /<svg[^>]*role="img"[^>]*aria-label="QR"[^>]*viewBox="0 0 29 29"/);
    assert.match(html, /<rect width="29" height="29" fill="#ffffff"><\/rect><path d="M4 4h1v1h-1z/);
    assert.equal(render(lang, h(QrCode, { text: 'x'.repeat(300), label: 'QR' })), '', 'too long for version 10: nothing drawn, the text stays');
  });

  test(`[${lang}] the credentials screen opens on a labelled section with a polite loading state`, () => {
    const html = render(lang, h(CredentialsScreen, { roles: ['security_officer'] }));
    assert.match(html, /<section[^>]*aria-labelledby="title-credentials"/);
    assert.ok(html.includes(`id="title-credentials">${esc(str(lang, 'title'))}</h1>`));
    assert.match(html, /role="status" aria-live="polite"/);
    assert.ok(html.includes(esc(str(lang, 'loading'))));
  });

  test(`[${lang}] PEP credentials: a security officer gets labelled rotate, revoke and create controls`, () => {
    const html = render(lang, h(PepCredentialsCard, { loaded: { value: credentials }, canManage: true, busy: false, onRetry: noop, onCreate: async () => true, onRotate: noop, onRevoke: noop }));
    assert.match(html, /role="region" aria-labelledby="pep-title"/);
    assert.ok(html.includes(`aria-label="${esc(str(lang, 'pep', 'tableLabel'))}"`));
    for (const col of ['name', 'created', 'lastUsed', 'rotated', 'status', 'actions']) assert.ok(html.includes(`<th scope="col">${esc(str(lang, 'pep', col))}</th>`), col);
    assert.ok(html.includes(`aria-label="${esc(fn(lang, 'pep', 'rotateLabel')('records-api'))}"`));
    assert.ok(html.includes(`aria-label="${esc(fn(lang, 'pep', 'revokeLabel')('records-api'))}"`));
    assert.ok(!html.includes(esc(fn(lang, 'pep', 'revokeLabel')('bootstrap'))), 'a revoked credential has no actions');
    assert.ok(html.includes(esc(fn(lang, 'pep', 'count')(1))));
    assert.match(html, /<label for="pep-name-input">/);
    assert.match(html, /id="pep-name-input"[^>]*maxLength="80"[^>]*required=""/);
    assert.ok(!html.includes(esc(str(lang, 'pep', 'readOnly'))));
  });

  test(`[${lang}] PEP credentials: an access admin reads the list without any action`, () => {
    const html = render(lang, h(PepCredentialsCard, { loaded: { value: credentials }, canManage: false, busy: false, onRetry: noop, onCreate: async () => true, onRotate: noop, onRevoke: noop }));
    assert.ok(!html.includes(`>${esc(str(lang, 'pep', 'actions'))}</th>`));
    assert.ok(!html.includes(esc(fn(lang, 'pep', 'rotateLabel')('records-api'))));
    assert.ok(!html.includes('pep-name-input'));
    assert.ok(html.includes(esc(str(lang, 'pep', 'readOnly'))));
    const empty = render(lang, h(PepCredentialsCard, { loaded: { value: [] }, canManage: false, busy: false, onRetry: noop, onCreate: async () => true, onRotate: noop, onRevoke: noop }));
    assert.match(empty, /role="status"/);
    assert.ok(empty.includes(esc(str(lang, 'pep', 'empty'))));
  });

  test(`[${lang}] a 403 reads as "not for your role", other errors as an alert with retry`, () => {
    const denied = render(lang, h(SigningKeysCard, { loaded: { error: new ApiError(403, 'forbidden', 'forbidden') }, canManage: false, busy: false, onRetry: noop, onRotate: noop }));
    assert.match(denied, /role="status"/);
    assert.ok(denied.includes(esc(str(lang, 'notForRole'))));
    assert.doesNotMatch(denied, /role="alert"/);
    const failed = render(lang, h(SigningKeysCard, { loaded: { error: new ApiError(500, 'internal', 'boom') }, canManage: true, busy: false, onRetry: noop, onRotate: noop }));
    assert.match(failed, /role="alert"/);
    assert.ok(failed.includes(`>${esc((cat(lang).common as Tree).retry as string)}</button>`));
  });

  test(`[${lang}] signing keys show the signing key and the verify-only one; rotation for security officers`, () => {
    const manage = render(lang, h(SigningKeysCard, { loaded: { value: keys }, canManage: true, busy: false, onRetry: noop, onRotate: noop }));
    assert.match(manage, /role="region" aria-labelledby="keys-title"/);
    assert.ok(manage.includes(`aria-label="${esc(str(lang, 'keys', 'tableLabel'))}"`));
    assert.ok(manage.includes(esc(str(lang, 'keys', 'signing'))));
    assert.ok(manage.includes('kid-old') && manage.includes(esc(fn(lang, 'keys', 'verifyUntil')('').trim())));
    assert.ok(manage.includes(`>${esc(str(lang, 'keys', 'rotate'))}</button>`));
    const read = render(lang, h(SigningKeysCard, { loaded: { value: keys }, canManage: false, busy: false, onRetry: noop, onRotate: noop }));
    assert.ok(!read.includes(`>${esc(str(lang, 'keys', 'rotate'))}</button>`));
    assert.ok(read.includes(esc(str(lang, 'keys', 'readOnly'))));
  });

  test(`[${lang}] SCIM: holder, last rotation and the two-person rule; rotation for access admins only`, () => {
    const info = { source: 'console', rotatedBy: 'amira' };
    const admin = render(lang, h(ScimCard, { loaded: { value: info }, canRotate: true, busy: false, onRetry: noop, onRotate: noop }));
    assert.match(admin, /role="region" aria-labelledby="scim-title"/);
    assert.ok(admin.includes(esc(str(lang, 'scim', 'holder'))) && admin.includes('amira'));
    assert.ok(admin.includes(esc(str(lang, 'scim', 'notRecorded'))));
    assert.ok(admin.includes(esc(str(lang, 'scim', 'twoPerson'))));
    assert.ok(admin.includes(`>${esc(str(lang, 'scim', 'rotate'))}</button>`));
    const officer = render(lang, h(ScimCard, { loaded: { value: info }, canRotate: false, busy: false, onRetry: noop, onRotate: noop }));
    assert.ok(!officer.includes(`>${esc(str(lang, 'scim', 'rotate'))}</button>`));
    assert.ok(officer.includes(esc(str(lang, 'scim', 'readOnly'))));
    const env = render(lang, h(ScimCard, { loaded: { value: { source: 'env' } }, canRotate: true, busy: false, onRetry: noop, onRotate: noop }));
    assert.ok(env.includes(esc(str(lang, 'scim', 'env'))));
    assert.ok(!env.includes(`>${esc(str(lang, 'scim', 'rotate'))}</button>`), 'an env token cannot be rotated here');
  });

  test(`[${lang}] the one-time secret is a labelled region with a read-only field and a status line`, () => {
    const html = render(lang, h(SecretPanel, { name: 'records-api', secret: 'pep.c1.s3cr3t', onDone: noop }));
    assert.match(html, /role="region" aria-labelledby="secret-panel-title"/);
    assert.match(html, /<h2[^>]*id="secret-panel-title" tabindex="-1"/);
    assert.ok(html.includes(esc(fn(lang, 'secret', 'heading')('records-api'))));
    assert.ok(html.includes(`<label for="secret-panel-value">${esc(str(lang, 'secret', 'label'))}</label>`));
    assert.match(html, /id="secret-panel-value"[^>]*readOnly=""[^>]*value="pep.c1.s3cr3t"/);
    assert.ok(html.includes(esc(str(lang, 'secret', 'warning'))));
    assert.match(html, /role="status" aria-live="polite"/);
  });
}

test('every screen renders its heading and loading state in French, without the English text', async () => {
  const user = { id: 'amira', name: 'Amira', roles: ['security_officer'] } as const;
  const params = {};
  const screens: readonly [string, string, string, object][] = [
    ['overview', '/src/screens/OverviewScreen.tsx', 'OverviewScreen', { roles: user.roles, userName: user.name, onOverviewLoaded: noop }],
    ['model', '/src/screens/AttributeModelScreen.tsx', 'AttributeModelScreen', { roles: user.roles, params, setParams: noop }],
    ['policies', '/src/screens/PoliciesScreen.tsx', 'PoliciesScreen', { roles: user.roles, params, setParams: noop }],
    ['matrix', '/src/screens/AccessMatrixScreen.tsx', 'AccessMatrixScreen', { params, setParams: noop, onExplain: noop }],
    ['simulator', '/src/screens/SimulatorScreen.tsx', 'SimulatorScreen', { roles: user.roles, params, setParams: noop, onExplain: noop }],
    ['approvals', '/src/screens/ApprovalsScreen.tsx', 'ApprovalsScreen', { user, params, setParams: noop, onApprovalChanged: noop }],
    ['breakGlass', '/src/screens/BreakGlassScreen.tsx', 'BreakGlassScreen', { user, onBreakGlassChanged: noop }],
    ['reviews', '/src/screens/AccessReviewsScreen.tsx', 'AccessReviewsScreen', { user, params, setParams: noop, onChangeCreated: noop }],
    ['audit', '/src/screens/AuditExplorerScreen.tsx', 'AuditExplorerScreen', { roles: user.roles, params, setParams: noop }],
    ['compliance', '/src/screens/ComplianceScreen.tsx', 'ComplianceScreen', { params, setParams: noop }],
    ['security', '/src/screens/CredentialsScreen.tsx', 'CredentialsScreen', { roles: user.roles }],
  ];
  for (const [area, path, name, props] of screens) {
    const Screen = (await load(path))[name] as FunctionComponent<object>;
    const fr = cat('fr')[area] as Tree;
    const en = cat('en')[area] as Tree;
    const html = render('fr', h(Screen, props));
    assert.ok(html.includes(esc(fr.loading as string)), `${area}: French loading label`);
    assert.ok(!html.includes(esc(en.loading as string)), `${area}: no English loading label`);
    assert.match(html, /<h1[^>]*id="title-/, `${area}: heading`);
    // the overview's heading is a greeting; every other screen's h1 is its title
    if (area !== 'overview' && typeof fr.title === 'string' && fr.title !== en.title) assert.ok(html.includes(esc(fr.title)), `${area}: French heading`);
  }
});

test('the audit type filter offers security events in both languages', async () => {
  const { AuditExplorerScreen } = await load('/src/screens/AuditExplorerScreen.tsx');
  const en = render('en', h(AuditExplorerScreen, { roles: ['auditor'], params: {}, setParams: noop }));
  const fr = render('fr', h(AuditExplorerScreen, { roles: ['auditor'], params: {}, setParams: noop }));
  assert.match(en, /<option value="security">security<\/option>/);
  assert.match(fr, /<option value="security">sécurité<\/option>/);
  assert.match(fr, /<label for="audit-type-select">Type<\/label>/);
});

test('the one-time code field on sign-in and the certification change summary follow the console language', async () => {
  const { SignInScreen } = await load('/src/screens/SignInScreen.tsx');
  const { summarizeChangePayload } = await load('/src/utils/expr.ts');
  const signIn = (lang: Lang) => cat(lang).signIn as Tree;
  for (const lang of LANGS) {
    const html = render(lang, h(SignInScreen, { onSignedIn: noop }));
    assert.ok(html.includes(esc(signIn(lang).code as string)), `${lang}: code label`);
    assert.ok(html.includes(esc(signIn(lang).codeHint as string)), `${lang}: code hint`);
  }
  const fr = render('fr', h(SignInScreen, { onSignedIn: noop }));
  assert.ok(!fr.includes(esc(signIn('en').code as string)) && !fr.includes(esc(signIn('en').codeHint as string)), 'no English code text in French');
  render('fr', h('span', null));
  assert.equal(summarizeChangePayload('certify_tp', { resourceType: 'payment', action: 'approve' }),
    'Certification de approve sur payment comme procédure de transformation (Clark-Wilson)');
  render('en', h('span', null));
  assert.match(summarizeChangePayload('certify_tp', { resourceType: 'payment', action: 'approve' }), /^Certify approve on payment/);
});

test('sign-in offers one link per identity provider the server configures (OIDC, SAML), labelled in the console language', async () => {
  const { IdpSignInLinks } = await load('/src/screens/SignInScreen.tsx');
  for (const lang of LANGS) {
    const signIn = cat(lang).signIn as Tree;
    const both = render(lang, h(IdpSignInLinks, { methods: { password: false, sso: true, saml: true } }));
    assert.ok(both.includes(`href="/admin/v1/oidc/login"`) && both.includes(esc(signIn.sso as string)), `${lang}: OIDC link`);
    assert.ok(both.includes(`href="/admin/v1/saml/login"`) && both.includes(esc(signIn.saml as string)), `${lang}: SAML link`);
    const samlOnly = render(lang, h(IdpSignInLinks, { methods: { password: true, sso: false, saml: true } }));
    assert.ok(samlOnly.includes('/admin/v1/saml/login') && !samlOnly.includes('/admin/v1/oidc/login'), `${lang}: SAML only`);
    assert.equal(render(lang, h(IdpSignInLinks, { methods: { password: true, sso: false, saml: false } })), '', `${lang}: none`);
  }
  render('en', h('span', null));
});

test('the evidence pack card offers each framework, the pseudonym option and the disclaimer in both languages', async () => {
  const { EvidencePackCard } = await load('/src/screens/EvidencePackCard.tsx');
  const { validateEvidencePack } = await load('/src/api/validators.ts');
  const frameworks = [{ id: 'iso27001', name: 'ISO/IEC 27001:2022 Annex A' }, { id: 'soc2', name: 'AICPA TSC' }];
  for (const lang of LANGS) {
    const c = cat(lang).compliance as Tree;
    const html = render(lang, h(EvidencePackCard, { frameworks }));
    assert.match(html, /role="region" aria-labelledby="evidence-pack-title"/);
    assert.ok(html.includes(`<label for="evidence-framework-select">${esc(c.evidenceFramework as string)}</label>`));
    assert.match(html, /<option value="iso27001" selected="">ISO\/IEC 27001:2022 Annex A<\/option><option value="soc2">AICPA TSC<\/option>/);
    assert.match(html, /id="evidence-pseudonymise" type="checkbox"/);
    assert.ok(html.includes(esc(c.evidenceDisclaimer as string)));
    assert.ok(html.includes(`>${esc(c.evidenceExport as string)}</button>`));
  }
  const good = { pack: {}, signature: 'h..s', manifest: { framework: 'soc2', generatedAt: '2026-11-10T00:00:00Z', packSha256: 'a', sections: { audit: 'b' } } };
  assert.deepEqual(validateEvidencePack(good), good);
  for (const bad of [{ ...good, signature: 1 }, { ...good, manifest: { ...good.manifest, sections: { audit: 1 } } }, { ...good, manifest: null }]) {
    assert.throws(() => validateEvidencePack(bad), /evidence pack/);
  }
});

test('KIMI-02: the impact view shows obligations lost on still-allowed requests, in both languages', async () => {
  const { ImpactTables } = await load('/src/components/ImpactTables.tsx');
  const row = { subject: 'bob', resource: 'CASE-14', action: 'read', rules: ['ABAC.CONTENT_MASK'],
    obligations: { redact: [], maskClasses: ['finance.amount'], notify: [], fieldAllowlist: { before: ['id'], after: null }, decisionToken: true } };
  const impact = { evaluated: 10, gained: [], lost: [], obligationsLost: [row], obligationsGained: [], policyVersionBefore: '', policyVersionAfter: '' };
  for (const lang of LANGS) {
    const html = render(lang, h(ImpactTables as FunctionComponent<{ impact: unknown }>, { impact }));
    const imp = (cat(lang).explain as Tree).impact as Tree;
    const f = (k: string) => imp[k] as (...args: unknown[]) => string;
    for (const text of [imp.obligationsLost as string, imp.obligationsLostHint as string, f('masked')('finance.amount'),
      f('allowlist')('id', imp.allFields as string), imp.decisionToken as string, f('obligationsLostCount')(1), 'ABAC.CONTENT_MASK']) {
      assert.ok(html.includes(esc(text)), `${lang}: ${text}`);
    }
  }
  const quiet = render('en', h(ImpactTables as FunctionComponent<{ impact: unknown }>, { impact: { ...impact, obligationsLost: undefined } }));
  assert.ok(!quiet.includes(esc(((cat('en').explain as Tree).impact as Tree).obligationsLost as string)), 'an older server without obligation rows renders as before');
});

test('0.4.1 integrity fields: certification state, stale procedures, invalidated certifications and reservations, in both languages', async () => {
  const { CertificationsCard, ReservationsCard, InvalidatedCertifications, IntegrityPanel } = await load('/src/screens/IntegrityCards.tsx');
  const { validateCertifications, validateReservations, validateChangeRecord } = await load('/src/api/validators.ts');
  const record = { resourceType: 'payment', action: 'approve', certifiedBy: 'sam', approvedBy: 'ada', certifiedAt: '2026-11-01T08:00:00Z',
    policyVersion: 'abcdef0123456789', changeId: 'chg-1', reason: 'certified after review', fingerprint: 'f', current: false };
  const certs = { items: [record, { ...record, action: 'release', changeId: 'chg-2', current: true }],
    missing: [{ resourceType: 'payment', action: 'approve' }, { resourceType: 'payment', action: 'refund' }], stale: [{ resourceType: 'payment', action: 'approve' }] };
  const reservation = { reservation: 'res-1', subject: { type: 'user', id: 'bob' }, resource: { type: 'payment', id: 'PAY-7' }, action: 'approve',
    reservedAt: '2026-11-09T10:00:00Z', pep: 'cred-9', onBehalfOf: [{ type: 'user', id: 'carol' }] };
  const invalidated = [{ resourceType: 'payment', action: 'approve', changeId: 'chg-1' }];
  for (const lang of LANGS) {
    const c = cat(lang).integrity as Tree;
    const f = (k: string) => c[k] as (...args: unknown[]) => string;
    const cards = render(lang, h(CertificationsCard, { data: certs }));
    assert.match(cards, /role="region" aria-labelledby="certifications-title"/);
    assert.match(cards, /<th scope="col">/);
    for (const text of [c.certTitle as string, f('staleTitle')(1), f('uncertifiedTitle')(1), f('procedure')('refund', 'payment'), c.current as string, c.stale as string, 'chg-2']) {
      assert.ok(cards.includes(esc(text)), `${lang}: ${text}`);
    }
    assert.match(cards, new RegExp(`class="badge badge-warn">${esc(c.stale as string)}<`), 'a stale record is labelled in text, not only by colour');
    const res = render(lang, h(ReservationsCard, { items: [reservation] }));
    for (const text of [c.resTitle as string, c.resIntro as string, f('resCount')(1), 'user:bob', 'payment:PAY-7', 'cred-9', 'user:carol']) assert.ok(res.includes(esc(text)), `${lang}: ${text}`);
    assert.ok(render(lang, h(ReservationsCard, { items: [] })).includes(esc(c.resEmpty as string)));
    const inv = render(lang, h(InvalidatedCertifications, { items: invalidated }));
    for (const text of [f('invalidatesTitle')(1), f('certifiedBy')('chg-1'), c.invalidatesDetail as string]) assert.ok(inv.includes(esc(text)), `${lang}: ${text}`);
    assert.equal(render(lang, h(InvalidatedCertifications, { items: undefined })), '', 'a change without the field (older server, other kinds) renders nothing');
  }
  // what each role loads follows the server's role checks
  const roles = ['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner', 'auditor'];
  assert.deepEqual(roles.filter((r) => permissions.canViewCertifications([r])), ['access_admin', 'policy_author', 'approver', 'security_officer', 'auditor']);
  assert.deepEqual(roles.filter((r) => permissions.canViewReservations([r])), ['access_admin', 'security_officer', 'auditor']);
  assert.equal(render('en', h(IntegrityPanel, { roles: ['resource_owner'] })), '');
  assert.match(render('en', h(IntegrityPanel, { roles: ['auditor'] })), /role="status" aria-live="polite"/);
  assert.deepEqual(validateCertifications(certs), certs);
  assert.deepEqual(validateReservations({ items: [reservation] }), { items: [reservation] });
  for (const bad of [{ ...certs, stale: undefined }, { ...certs, items: [{ ...record, current: 'yes' }] }]) assert.throws(() => validateCertifications(bad), /certifications/);
  assert.throws(() => validateReservations({ items: [{ ...reservation, subject: 'bob' }] }), /reservations/);
  const change = { id: 'chg-3', kind: 'publish_policy', status: 'pending', impact: { evaluated: 0, gained: [], lost: [] }, invalidatesCertifications: invalidated };
  assert.deepEqual(validateChangeRecord(change).invalidatesCertifications, invalidated);
});

test('resource inventory and PEP resource types: labelled type picker, paged tables, retired ids outside owner scope, proposals linked to approvals, both languages', async () => {
  const { ResourceInventoryPane, PendingRegistrations } = await load('/src/screens/ResourceInventoryPane.tsx');
  const { validateInventoryPage, validateRetiredPage, validatePepCredentials } = await load('/src/api/validators.ts');
  const schema = { resourceTypes: { case: {}, payment: {} }, compartments: [], subjectRelations: {} };
  const change = { id: 'chg-7', kind: 'register_resources', status: 'pending', impact: {}, reason: 'owner changed', createdAt: '2026-11-10T09:00:00Z',
    makerId: 'pep:ab', pepCredential: { id: 'cred-1' }, payload: { resources: [{ type: 'case', id: 'CASE-9' }, { type: 'payment', id: 'PAY-1' }], retire: [{ type: 'case', id: 'CASE-3' }] } };
  for (const lang of LANGS) {
    const m = (cat(lang).model as Tree).inventory as Tree;
    const t = (key: string) => esc(m[key] as string);
    const f = (key: string) => m[key] as (...args: unknown[]) => string;
    const pane = render(lang, h(ResourceInventoryPane, { schema, roles: ['auditor'], params: { rtype: 'payment' }, setParams: noop }));
    assert.ok(pane.includes(`<label for="inventory-type-select">${t('type')}</label>`));
    assert.match(pane, /<option value="case">case<\/option><option value="payment" selected="">payment<\/option>/);
    for (const id of ['inventory-registered-title', 'inventory-pending-title', 'inventory-retired-title']) assert.match(pane, new RegExp(`role="region" aria-labelledby="${id}"`));
    assert.ok(pane.includes(esc(f('tableLabel')('payment'))) && pane.includes(t('loading')) && pane.includes(t('intro')));
    assert.ok(!pane.includes(t('retiredOwner')), 'an auditor reads retired ids');
    const owner = render(lang, h(ResourceInventoryPane, { schema, roles: ['resource_owner'], params: {}, setParams: noop }));
    assert.ok(owner.includes(t('retiredOwner')) && owner.includes(esc(f('tableLabel')('case'))), 'the first type by default; no retired ids for an owner');
    const pending = render(lang, h(PendingRegistrations, { type: 'case', changes: [change, { ...change, id: 'chg-8', kind: 'add_tuple' }], error: null, onRetry: noop }));
    assert.ok(pending.includes(`aria-label="${esc(f('pendingTable')('case'))}"`));
    assert.ok(pending.includes('CASE-9') && pending.includes('CASE-3') && !pending.includes('PAY-1') && pending.includes('cred-1') && !pending.includes('chg-8'));
    assert.ok(pending.includes(`href="#/approvals?status=pending&amp;id=chg-7" aria-label="${esc(f('reviewLabel')('chg-7'))}"`));
    assert.ok(render(lang, h(PendingRegistrations, { type: 'folder', changes: [change], error: null, onRetry: noop })).includes(t('pendingEmpty')));
    const p = (cat(lang).security as Tree).pep as Tree;
    const card = render(lang, h(PepCredentialsCard, { loaded: { value: [{ ...credentials[0], resourceTypes: ['case'] }, credentials[1]] }, canManage: true, busy: false,
      onRetry: noop, onCreate: async () => true, onRotate: noop, onRevoke: noop, resourceTypes: ['case', 'payment'] }));
    assert.ok(card.includes(`<th scope="col">${esc(p.resourceTypes as string)}</th>`));
    assert.ok(card.includes(`<fieldset class="form-group" aria-describedby="pep-types-hint"><legend>${esc(p.resourceTypesLegend as string)}</legend>`));
    assert.match(card, /<input type="checkbox" name="pep-resource-types" value="payment"\/>/);
    assert.ok(card.includes(`id="pep-types-hint">${esc(p.resourceTypesHint as string)}</p>`) && card.includes(esc(p.noResourceTypes as string)));
    const noSchema = render(lang, h(PepCredentialsCard, { loaded: { value: credentials }, canManage: true, busy: false, onRetry: noop, onCreate: async () => true, onRotate: noop, onRevoke: noop }));
    assert.ok(!noSchema.includes('pep-resource-types'), 'without the schema no type is offered');
  }
  const roles = ['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner', 'auditor'];
  assert.deepEqual(roles.filter((r) => !permissions.canViewRetiredResources([r])), ['resource_owner']);
  assert.ok(permissions.canViewRetiredResources(['resource_owner', 'auditor']));
  const page = { type: 'case', total: 1, next: null, items: [{ id: 'CASE-1', title: 'x', level: 1, compartments: [], integrity: 'system', owner: null, contentClasses: [], version: 2, parent: { type: 'folder', id: 'F' } }] };
  assert.deepEqual(validateInventoryPage(page), page);
  for (const bad of [{ ...page, next: 1 }, { ...page, items: [{ ...page.items[0], version: '2' }] }, { ...page, items: [{ ...page.items[0], parent: 'F' }] }]) assert.throws(() => validateInventoryPage(bad), /resource inventory/);
  const retired = { type: 'case', total: 1, next: 'CASE-1', items: [{ id: 'CASE-1', version: 1, retiredAt: '2026-11-10T09:00:00Z', registeredAgain: false }] };
  assert.deepEqual(validateRetiredPage(retired), retired);
  assert.throws(() => validateRetiredPage({ ...retired, items: [{ ...retired.items[0], registeredAgain: 'no' }] }), /retired resources/);
  assert.throws(() => validatePepCredentials({ items: [{ ...credentials[0], resourceTypes: 'case' }] }), /PEP credentials/);
});


test('context-class impact previews show gains, losses and truncation in all languages', async () => {
  const { ImpactTables } = await load('/src/components/ImpactTables.tsx');
  const row = { subject: 'bob', resource: 'CASE-14', action: 'read', rules: ['CBAC.COUNTRY'] };
  const impact = {
    evaluated: 20, gained: [], lost: [], obligationsLost: [], obligationsGained: [], policyVersionBefore: '', policyVersionAfter: '',
    contextAnalysis: {
      cap: 1, evaluatedClasses: 2, truncated: true,
      classes: [{ context: { network: 'trusted', now: '2026-11-08T10:00:00Z', country: 'FR', sessionExpired: false },
        evaluated: 10, gained: [row], lost: [{ ...row, action: 'export' }], obligationsLost: [], obligationsGained: [] }],
    },
  };
  for (const lang of LANGS) {
    const html = render(lang, h(ImpactTables as FunctionComponent<{ impact: unknown }>, { impact }));
    const context = ((cat(lang).explain as Tree).impact as Tree).context as Tree;
    for (const text of [context.title as string, (context.summary as (...args: unknown[]) => string)(2, 1),
      (context.truncated as (...args: unknown[]) => string)(1), (context.session as (...args: unknown[]) => string)(false),
      (context.direction as (...args: unknown[]) => string)(true), (context.direction as (...args: unknown[]) => string)(false), 'FR', 'CASE-14']) {
      assert.ok(html.includes(esc(text)), `${lang}: ${text}`);
    }
  }
});

test('Arabic messages isolate numeric values and identifiers without changing their contents', () => {
  const ar = i18n.CATALOGUES.ar;
  assert.match(render('ar', h(ErrorAlert, { error: new ApiError(500, 'internal', 'failure') })), /margin-inline-end:8px/);
  assert.equal(ar.shell.records(12345), '\u206612,345\u2069 سجلاً');
  assert.ok(ar.approvals.updateSubject('user-42').includes('\u2066user-42\u2069'));
  assert.ok(ar.common.changes.publishPolicy('bundle', 1, 2, 3, 4, 'enforce').includes('\u2066enforce\u2069'));
});

test('a fresh browser opens in English before any stored language choice', () => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  store.clear();
  try {
    for (const [language, expected] of [['ar-AE', 'en'], ['ar', 'en'], ['fr-CA', 'en'], ['en-GB', 'en'], ['de-DE', 'en']]) {
      Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { language } });
      assert.equal(i18n.readLang(), expected);
    }
  } finally {
    if (saved) Object.defineProperty(globalThis, 'navigator', saved);
    else Reflect.deleteProperty(globalThis, 'navigator');
  }
});
