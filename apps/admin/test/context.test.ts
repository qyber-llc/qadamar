import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const { en, fr } = await vite.ssrLoadModule('/src/i18n/policies.ts');
const explain = await vite.ssrLoadModule('/src/i18n/explain.ts');
const { validateCandidateBundle, extractTenantSections } = await vite.ssrLoadModule('/src/utils/bundleValidator.ts');

const base = {
  name: 'test', schema: { resourceTypes: { case: { actions: { read: { kind: 'read' } } } }, compartments: [] },
  rbac: { roles: {} }, mandatory: { trustedRoles: [], untrustedNetworkMaxLevel: 0, compartmentsRequireTrustedNetwork: true, bibaNoReadDownActions: [] },
  needToKnow: { mode: 'off', protect: {}, breakGlassMaxHours: 4, breakGlassNotify: [] },
  abac: [], abacContent: [], sod: [], clarkWilson: { tokenTtlSeconds: 15 },
};

test('CBAC means context in English and French; content rules are ABAC on content attributes', () => {
  assert.equal(en.stage.contentTitle, 'ABAC on content attributes (mask, redact, deny)');
  assert.equal(en.stage.contextTitle, 'CBAC (context-based, Zero Trust)');
  assert.equal(fr.stage.contentTitle, 'ABAC sur attributs de contenu (masquage, caviardage, refus)');
  assert.equal(fr.stage.contextTitle, 'CBAC (contexte, Zero Trust)');
  assert.equal(explain.en.stages.cbac, 'CBAC (context-based, Zero Trust)');
  assert.equal(explain.fr.stages.cbac, 'CBAC (contexte, Zero Trust)');
  assert.ok(!Object.hasOwn(explain.en.stages, 'context'), 'no separate context stage');
});

test('candidate editor reads a legacy cbac section as abacContent with a warning, and refuses both', () => {
  const rule = { id: 'mask', description: 'mask', contentClass: 'pii', effect: 'mask' };
  const { abacContent: ignored, ...legacyBase } = base;
  const legacy = validateCandidateBundle({ ...legacyBase, cbac: [rule] });
  assert.equal(legacy.ok, true);
  assert.deepEqual(legacy.bundle.abacContent, [rule]);
  assert.ok(!Object.hasOwn(legacy.bundle, 'cbac'));
  assert.match(legacy.warnings[0], /^DEPRECATED_CBAC_FIELD/);
  assert.deepEqual(validateCandidateBundle(base).warnings, []);
  const both = validateCandidateBundle({ ...base, cbac: [rule] });
  assert.equal(both.ok, false);
  assert.ok(both.errors.includes('cbac and abacContent cannot both be present'));
  const named = validateCandidateBundle({ ...legacyBase, cbac: [{ ...rule, effect: 'redact' }] });
  assert.ok(!named.ok && named.errors.some((e: string) => e.startsWith('cbac mask:')));
  // a published legacy bundle opens in the editor under the new name
  assert.deepEqual(extractTenantSections({ ...legacyBase, cbac: [rule] } as never).abacContent, [rule]);
});

test('candidate editor accepts a context rule, preserves it, and rejects a missing signal requirement', () => {
  const rule = { id: 'zero-trust', resourceTypes: ['case'], actionKinds: ['read'], minResourceLevel: 1,
    countries: ['AE'], ipRanges: ['10.0.0.0/8', '2001:db8::/32'], device: { managed: true, compliant: true },
    timeWindows: [{ days: [1, 7], from: '22:00', to: '02:00', timeZone: 'Asia/Dubai' }],
    mfaMaxAgeSeconds: 300, authMaxAgeSeconds: 3600, authMethodsAny: ['webauthn'], maxRiskScore: 50 };
  const valid = validateCandidateBundle({ ...base, context: [rule] });
  assert.equal(valid.ok, true, valid.ok ? '' : valid.errors.join('; '));
  assert.deepEqual(extractTenantSections({ ...base, context: [rule] } as never).context, [rule]);
  assert.equal(validateCandidateBundle({ ...base, context: [{ id: 'empty', actions: ['read'] }] }).ok, false);
  assert.equal(validateCandidateBundle({ ...base, context: [{ ...rule, timeZone: 'invalid' }] }).ok, false, 'unknown rule keys are refused');
  assert.equal(validateCandidateBundle({ ...base, context: [{ ...rule, timeWindows: [{ days: [8], from: '09:00', to: '10:00', timeZone: 'Asia/Dubai' }] }] }).ok, false);
  assert.deepEqual(extractTenantSections(base as never).context, []);
});

test('candidate editor refuses an ABAC rule id with the reserved CONTENT_ prefix', () => {
  const rule = { id: 'CONTENT_DENY', description: 'clash', effect: 'forbid', when: { op: 'true' } };
  const refused = validateCandidateBundle({ ...base, abac: [rule] });
  assert.ok(!refused.ok && refused.errors.some((e: string) => /CONTENT_ is reserved/.test(e)));
  assert.equal(validateCandidateBundle({ ...base, abac: [{ ...rule, id: 'NO_CONTENT_DENY' }] }).ok, true);
});


test('candidate editor validates the Biba no-read-down scope', () => {
  for (const bibaNoReadDownScope of ['actions', 'reads', 'all']) {
    const result = validateCandidateBundle({ ...base, mandatory: { ...base.mandatory, bibaNoReadDownScope } });
    assert.equal(result.ok, true, result.ok ? '' : result.errors.join('; '));
  }
  const result = validateCandidateBundle({ ...base, mandatory: { ...base.mandatory, bibaNoReadDownScope: 'sometimes' } });
  assert.ok(!result.ok && result.errors.includes(en.validation.bibaScope));
  assert.equal(fr.validation.bibaScope.length > 0, true);
});
