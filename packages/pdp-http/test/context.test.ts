import assert from 'node:assert/strict';
import test from 'node:test';
import { context } from '../src/runtime.ts';
import { pdp } from '../src/pdp.ts';
import { decideChange, impact, propose } from '../src/admin/changes.ts';
import { HttpError } from '../src/http.ts';
import { contextChecks, inTimeWindow, validIp, type ContextRule } from '../../core/src/index.ts';
import { impactContexts } from '../src/admin/context-impact.ts';
import { evaluation, fixture, FIXED } from './helpers.ts';

const signals = { ip: '10.0.0.1', country: 'AE', device: { managed: true, compliant: true },
  authTime: '2026-11-08T09:59:00Z', mfaTime: '2026-11-08T09:59:30Z', authMethods: ['pwd', 'webauthn'], riskScore: 0 };

test('PDP context parsing preserves valid Zero Trust signals and rejects malformed values with 400', () => {
  const parsed = context(signals, FIXED);
  assert.deepEqual(parsed, { network: 'untrusted', now: FIXED, ...signals });
  const invalid: unknown[] = [
    { ip: '999.1.1.1' }, { ip: '10.0.0.1/8' }, { country: 'ae' }, { country: 'ZZ' },
    { device: { managed: true } }, { device: { managed: true, compliant: true, spoofed: true } },
    { authTime: 'now' }, { mfaTime: '2026-11-08 09:00:00Z' }, { authMethods: Array(17).fill('pwd') },
    { riskScore: -1 }, { riskScore: 100.5 }, { riskScore: 101 },
  ];
  for (const value of invalid) {
    assert.throws(() => context(value, FIXED), (error) => error instanceof HttpError && error.status === 400, JSON.stringify(value));
  }
});

test('HTTP point, search, filter and list assertion decisions agree as the request context changes', (t) => {
  const { rt } = fixture(t);
  const rule: ContextRule = { id: 'low-risk', resourceTypes: ['case'], actionKinds: ['read'], minResourceLevel: 1, maxRiskScore: 50 };
  rt.store.state = { ...rt.store.state, bundle: { ...rt.store.state.bundle, context: [rule] } };
  const request = { ...evaluation(), context: signals };
  const low = pdp(rt, '/access/v1/evaluation', request) as { decision: boolean };
  const high = pdp(rt, '/access/v1/evaluation', { ...request, context: { ...signals, riskScore: 51 } }) as { decision: boolean; context: { rules: string[] } };
  assert.equal(low.decision, true);
  assert.equal(high.decision, false);
  assert.ok(high.context.rules.includes('CBAC.RISK'));
  const search = { ...request, resource: { type: 'case' } };
  const allowed = pdp(rt, '/access/v1/search/resource', search) as { results: unknown[] };
  const denied = pdp(rt, '/access/v1/search/resource', { ...search, context: { ...signals, riskScore: 100 } }) as { results: unknown[] };
  assert.ok(allowed.results.length > 0);
  assert.deepEqual(denied.results.map((item) => (item as { id: string }).id), ['CASE-18'], 'L0 is outside the minimum-L1 selector');
  const filtered = pdp(rt, '/x/v1/filter', { ...search, columns: {
    'resource.id': 'id', 'resource.level': { column: 'level', type: 'number' },
    'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.integrity': 'integrity',
    'resource.owner': 'owner', 'resource.contentClasses': { column: 'content_classes', kind: 'text[]' }, 'resource.attrs.status': 'status',
  } }) as { residual: { op: string } };
  assert.equal(filtered.residual.op, 'and');
  const asserted = pdp(rt, '/x/v1/assertions/list', { ...search, request: {
    audience: 'http://backend', method: 'GET', path: '/cases', bodySha256: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  } }) as { decision: boolean };
  assert.equal(asserted.decision, true);
});

test('policy impact preview includes context rule gains and losses', (t) => {
  const { rt } = fixture(t);
  const state = rt.store.state;
  const rule: ContextRule = { id: 'country', resourceTypes: ['case'], actions: ['read'], countries: ['FR'] };
  const restricted = impact(rt, { ...state, bundle: { ...state.bundle, context: [rule] } });
  assert.ok(restricted.lost.length > 0);
  assert.ok(restricted.analysis?.reasons.includes('context rule country changed'));
  rt.store.state = { ...state, bundle: { ...state.bundle, context: [rule] } };
  const loosened = impact(rt, { ...state, bundle: state.bundle });
  assert.ok(loosened.gained.length > 0);
});


test('impact detects a gain confined to one newly allowed country and approval rechecks that analysis', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const current: ContextRule = { id: 'country', resourceTypes: ['case'], actions: ['read'], countries: ['AE'] };
  rt.store.state = { ...rt.store.state, bundle: { ...before, context: [current] } };
  const bundle = { ...before, context: [{ ...current, countries: ['AE', 'FR'] }] };
  const delta = impact(rt, { ...rt.store.state, bundle });
  assert.ok(delta.gained.length > 0, 'the unchanged AE baseline must not hide the FR gain');
  const fr = delta.contextAnalysis?.classes.find((item) => item.context.country === 'FR');
  assert.ok(fr && fr.gained.length > 0);
  assert.ok(fr?.gained.every((row) => row.rules.includes('CBAC.COUNTRY')));

  const proposed = propose(rt, { id: 'amira', name: 'Amira', roles: ['access_admin'] },
    { kind: 'publish_policy', payload: { bundle }, reason: 'country preview test' });
  assert.equal(proposed.broadens, true);
  const approved = decideChange(rt, { id: 'lina', name: 'Lina', roles: ['security_officer'] }, proposed.id, true, { reason: 'verified FR class' });
  assert.equal(approved.status, 'applied');
  assert.deepEqual(approved.impact, proposed.impact);
});

test('impact detects a loss confined to one removed CIDR', (t) => {
  const { rt } = fixture(t);
  const state = rt.store.state;
  const current: ContextRule = { id: 'networks', resourceTypes: ['case'], actions: ['read'], ipRanges: ['10.0.0.0/8', '192.0.2.0/24'] };
  const next = { ...state.bundle, context: [{ ...current, ipRanges: ['10.0.0.0/8'] }] };
  rt.store.state = { ...state, bundle: { ...state.bundle, context: [current] } };
  const delta = impact(rt, { ...state, bundle: next });
  assert.ok(delta.lost.length > 0, 'the unchanged 10/8 baseline must not hide the 192.0.2.0/24 loss');
  const removed = delta.contextAnalysis?.classes.find((item) => item.context.ip === '192.0.2.0');
  assert.ok(removed && removed.lost.length > 0);
  assert.ok(removed?.lost.every((row) => row.rules.includes('CBAC.IP_RANGE')));
});

test('context representatives cover every rule signal and its boundaries', (t) => {
  const { rt } = fixture(t);
  const bundle = rt.store.state.bundle;
  const rule: ContextRule = {
    id: 'all-signals', resourceTypes: ['case'], actions: ['read'], countries: ['AE', 'FR'], ipRanges: ['10.0.0.0/8'],
    timeWindows: [{ days: [1, 2, 3, 4, 5, 6, 7], from: '09:00', to: '17:00', timeZone: 'Asia/Dubai' }],
    device: { managed: true, compliant: true }, mfaMaxAgeSeconds: 60, authMaxAgeSeconds: 3600,
    authMethodsAny: ['otp', 'webauthn'], maxRiskScore: 50,
  };
  const partition = impactContexts({ ...bundle, context: [rule] }, bundle, rt.now(), 1000);
  const contexts = partition.contexts;
  for (const country of ['AE', 'FR', undefined]) assert.ok(contexts.some((context) => context.country === country), `country ${country}`);
  for (const ip of ['10.0.0.0', '192.0.2.1', undefined]) assert.ok(contexts.some((context) => context.ip === ip), `IP ${ip}`);
  assert.ok(new Set(contexts.map((context) => context.now)).size >= 7, 'both time-window edges, just before and just after');
  assert.ok(contexts.some((context) => inTimeWindow(context.now, rule.timeWindows![0]!)));
  assert.ok(contexts.some((context) => !inTimeWindow(context.now, rule.timeWindows![0]!)));
  for (const managed of [true, false]) for (const compliant of [true, false]) {
    assert.ok(contexts.some((context) => context.device?.managed === managed && context.device.compliant === compliant));
  }
  assert.ok(contexts.some((context) => context.device === undefined));
  const ages = (key: 'mfaTime' | 'authTime'): Set<number | undefined> => new Set(contexts.map((context) =>
    context[key] === undefined ? undefined : Math.round((Date.parse(context.now) - Date.parse(context[key]!)) / 1000)));
  for (const age of [-1, 59, 60, 61, undefined]) assert.ok(ages('mfaTime').has(age), `MFA age ${age}`);
  for (const age of [-1, 3599, 3600, 3601, undefined]) assert.ok(ages('authTime').has(age), `auth age ${age}`);
  for (const riskScore of [49, 50, 51, undefined]) assert.ok(contexts.some((context) => context.riskScore === riskScore), `risk ${riskScore}`);
  for (const methods of [['otp'], ['webauthn'], ['no-matching-method'], [], undefined]) {
    assert.ok(contexts.some((context) => JSON.stringify(context.authMethods) === JSON.stringify(methods)), `methods ${methods}`);
  }
  for (const sessionExpired of [false, true]) assert.ok(contexts.some((context) => context.sessionExpired === sessionExpired));
  const failed = contexts.some((context) => contextChecks(rule, context).every((check) => check.ok));
  assert.equal(failed, true, 'at least one representative satisfies the complete rule');
});

test('context partitioning is capped, reports truncation and is deterministic', (t) => {
  const { rt } = fixture(t);
  const bundle = rt.store.state.bundle;
  const rule: ContextRule = { id: 'many', resourceTypes: ['case'], actions: ['read'], countries: ['AE', 'FR', 'US', 'GB', 'DE', 'JP'],
    ipRanges: ['10.0.0.0/8', '192.0.2.0/24', '2001:db8::/32'], maxRiskScore: 50 };
  const first = impactContexts({ ...bundle, context: [rule] }, bundle, rt.now(), 7);
  const second = impactContexts({ ...bundle, context: [rule] }, bundle, rt.now(), 7);
  assert.deepEqual(first, second);
  assert.equal(first.contexts.length, 7);
  assert.equal(first.truncated, true);
  assert.equal(first.partitioned, true);

  const state = { ...rt.store.state, bundle: { ...bundle, context: [rule] } };
  const one = impact(rt, state, Number.MAX_SAFE_INTEGER, 1);
  const again = impact(rt, state, Number.MAX_SAFE_INTEGER, 1);
  assert.deepEqual(one, again);
  assert.equal(one.contextAnalysis?.evaluatedClasses, 2);
  assert.equal(one.contextAnalysis?.cap, 1);
  assert.equal(one.contextAnalysis?.truncated, true);
});


test('overnight time-window representatives include the end edge on the following local day', (t) => {
  const { rt } = fixture(t);
  const bundle = rt.store.state.bundle;
  const window = { days: [1], from: '22:00', to: '02:00', timeZone: 'Asia/Dubai' };
  const rule: ContextRule = { id: 'overnight', resourceTypes: ['case'], actions: ['read'], timeWindows: [window] };
  const contexts = impactContexts({ ...bundle, context: [rule] }, bundle, rt.now()).contexts;
  const local = (iso: string) => new Intl.DateTimeFormat('en-US', { timeZone: window.timeZone, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .format(Date.parse(iso));
  assert.ok(contexts.some((context) => inTimeWindow(context.now, window) && local(context.now).startsWith('Tue')),
    'Tuesday after midnight belongs to Monday’s overnight window');
  assert.ok(contexts.some((context) => local(context.now).startsWith('Tue') && !inTimeWindow(context.now, window)),
    'the Tuesday end-exclusive edge is represented too');
});


test('midnight edges normalize across days and time variants preserve authentication freshness', (t) => {
  const { rt } = fixture(t);
  const bundle = rt.store.state.bundle;
  const rule: ContextRule = { id: 'midnight', resourceTypes: ['case'], actions: ['read'],
    timeWindows: [{ days: [1], from: '00:00', to: '23:59', timeZone: 'Asia/Dubai' }], mfaMaxAgeSeconds: 60 };
  const partition = impactContexts({ ...bundle, context: [rule] }, bundle, rt.now(), 8);
  const times = [...new Set(partition.contexts.map((context) => context.now))];
  assert.equal(times.length, 7, 'start/end edges and one minute on either side, including midnight');
  assert.equal(partition.truncated, true);
  for (const now of times) {
    const context = partition.contexts.find((item) => item.now === now);
    assert.equal(context?.mfaTime, now, 'the one-clock variant does not accidentally become MFA-stale');
  }
});


test('ABAC country equality literals produce the France-only gain without truncating the analysis', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const bundle = { ...before, abac: [...before.abac, {
    id: 'france-read', description: 'Read only in France', effect: 'permit' as const, resourceTypes: ['case'], actions: ['read'],
    when: { op: 'eq' as const, left: { path: 'context.country' }, right: { value: 'FR' } },
  }] };
  const delta = impact(rt, { ...rt.store.state, bundle });
  assert.ok(delta.gained.some((row) => row.subject === 'omar' && row.resource === 'CASE-18' && row.action === 'read'),
    'omar gains read on CASE-18 only in France');
  assert.ok(delta.contextAnalysis?.classes.some((item) => item.context.country === 'FR'
    && item.gained.some((row) => row.subject === 'omar' && row.resource === 'CASE-18')));
  assert.equal(delta.contextAnalysis?.truncated, false);
  assert.equal(delta.contextAnalysis?.incomplete, false);
});

test('ABAC in-lists and numeric and instant boundaries contribute representatives', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const bundle = { ...before, abac: [...before.abac, {
    id: 'boundaries', description: 'Exercise expression boundaries', effect: 'forbid' as const, actions: ['read'],
    when: { op: 'and' as const, args: [
      { op: 'in' as const, left: { path: 'context.country' }, right: { value: ['FR', 'DE'] } },
      { op: 'ge' as const, left: { path: 'context.riskScore' }, right: { value: 50 } },
      { op: 'le' as const, left: { path: 'context.mfaTime' }, right: { value: '2026-11-08T09:00:00Z' } },
      { op: 'ge' as const, left: { path: 'context.now' }, right: { value: '2026-11-08T10:00:00Z' } },
    ] },
  }], abacContent: [...(before.abacContent ?? []), {
    id: 'swiss-content', description: 'Content rule boundary', contentClass: 'pii.iban', effect: 'mask' as const,
    unless: { op: 'eq' as const, left: { path: 'context.country' }, right: { value: 'CH' } },
  }] };
  const contexts = impactContexts(before, bundle, rt.now(), 1000).contexts;
  for (const country of ['FR', 'DE', 'CH']) assert.ok(contexts.some((context) => context.country === country), country);
  for (const riskScore of [49, 50, 51]) assert.ok(contexts.some((context) => context.riskScore === riskScore), `risk ${riskScore}`);
  const mfaAges = new Set(contexts.map((context) => Math.round((Date.parse(context.now) - Date.parse(context.mfaTime!)) / 1000)));
  for (const age of [3599, 3600, 3601]) assert.ok(mfaAges.has(age), `MFA age ${age}`);
  for (const delta of [-1000, 0, 1000]) {
    const expected = Date.parse(rt.now()) + delta;
    assert.ok(contexts.some((context) => Date.parse(context.now) === expected), `now ${delta}`);
  }
});

test('unsupported ABAC context comparisons mark the analysis incomplete and require security-officer approval', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const bundle = { ...before, abac: [...before.abac, {
    id: 'country-from-subject', description: 'Country matched to subject attribute', effect: 'permit' as const, resourceTypes: ['case'], actions: ['read'],
    when: { op: 'eq' as const, left: { path: 'context.country' }, right: { path: 'subject.attrs.country' } },
  }] };
  const proposed = propose(rt, { id: 'amira', name: 'Amira', roles: ['access_admin'] },
    { kind: 'publish_policy', payload: { bundle }, reason: 'unsupported expression test' });
  assert.equal(proposed.impact.contextAnalysis?.incomplete, true);
  assert.equal(proposed.impact.contextAnalysis?.truncated, false);
  assert.ok((proposed.impact.contextAnalysis?.unsupported?.length ?? 0) > 0);
  assert.throws(() => decideChange(rt, { id: 'omar', name: 'Omar', roles: ['approver'] }, proposed.id, true, { reason: 'ordinary review' }),
    (error) => error instanceof HttpError && error.status === 403);
  assert.equal(decideChange(rt, { id: 'lina', name: 'Lina', roles: ['security_officer'] }, proposed.id, true, { reason: 'strict review' }).status, 'applied');
});

test('CIDR interval classes expose gains at new IPv4 and IPv6 boundaries', (t) => {
  const { rt } = fixture(t);
  const state = rt.store.state;
  for (const testCase of [
    { before: '10.0.0.0/9', after: '10.0.0.0/8', representative: '10.128.0.0' },
    { before: '2001:db8::/33', after: '2001:db8::/32', representative: '2001:db8:8000::' },
  ]) {
    const current: ContextRule = { id: 'cidr', resourceTypes: ['case'], actions: ['read'], ipRanges: [testCase.before] };
    rt.store.state = { ...state, bundle: { ...state.bundle, context: [current] } };
    const bundle = { ...state.bundle, context: [{ ...current, ipRanges: [testCase.after] }] };
    const delta = impact(rt, { ...state, bundle });
    assert.ok(delta.gained.some((row) => row.subject === 'bob' && row.resource === 'CASE-18' && row.action === 'read'), testCase.before);
    assert.ok(delta.contextAnalysis?.classes.some((item) => item.context.ip === testCase.representative
      && item.gained.some((row) => row.subject === 'bob' && row.resource === 'CASE-18')), testCase.representative);
  }
});


test('full-range CIDRs never produce an address outside the IP family', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  for (const cidr of ['0.0.0.0/0', '::/0']) {
    const bundle = { ...before, context: [{ id: 'all-addresses', resourceTypes: ['case'], actions: ['read'], ipRanges: [cidr] }] };
    const partition = impactContexts(before, bundle, rt.now(), 100);
    for (const context of partition.contexts) assert.ok(context.ip === undefined || validIp(context.ip), `${cidr}: ${context.ip}`);
    assert.equal(partition.incomplete, false);
  }
});
