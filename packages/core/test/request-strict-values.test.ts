// Request values the engine could read two ways are refused (ENGINE.MALFORMED_REQUEST), as in the Lean model:
// a context.now without an explicit zone (read in the host's time zone), and a number beyond 2^53 (two different JSON
// integers rounding to the same double compare equal).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { buildFilter, evaluate, FALSE, indexTuples, requestErrors, type Context, type PolicyBundle, type Resource, type Subject, type Tuple } from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const toy: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const S = (id: string): Subject => world.subjects.find((s) => s.id === id) as Subject;
const R = (id: string): Resource => world.resources.find((r) => r.id === id) as Resource;

// lina holds no role: CASE-18 is readable only through a viewer assignment that ends at 10:30Z
const lina: Subject = { ...S('lina'), roleAssignments: [{ role: 'viewer', notAfter: '2026-11-08T10:30:00Z' }] };
const readAt = (now: string) => evaluate(toy, { subject: lina, action: 'read', resource: R('CASE-18'), context: { network: 'trusted', now } }, graph);

test('a zone-less context.now is refused, so the decision does not depend on the host time zone', () => {
  const saved = process.env.TZ;
  try {
    const rules = ['UTC', 'Asia/Dubai', 'America/Los_Angeles'].map((tz) => { process.env.TZ = tz; return readAt('2026-11-08T10:00:00').rules; });
    for (const r of rules) assert.deepEqual(r, ['ENGINE.MALFORMED_REQUEST']);
  } finally {
    if (saved === undefined) delete process.env.TZ; else process.env.TZ = saved;
  }
});

test('context.now must be a full ISO-8601 instant with Z or an offset', () => {
  for (const now of ['2026-11-08T10:00:00', '2026-11-08T24:00:00Z', 'Nov 8, 2026', '2026-11-08', '2026-11-08T10:00Z',
    '2026-02-29T10:00:00Z', '2026-11-08T10:00:00+24:00', '2026-11-08T10:00:00.1234567891Z', '+002026-11-08T10:00:00Z']) {
    assert.ok(requestErrors({ subject: lina, action: 'read', resource: R('CASE-18'), context: { network: 'trusted', now } }).some((e) => e.startsWith('context.now')), now);
  }
  assert.deepEqual(readAt('2026-11-08T10:00:00Z').rules, ['RBAC.viewer']);
  assert.deepEqual(readAt('2026-11-08T14:00:00.5+04:00').rules, ['RBAC.viewer']);
  assert.deepEqual(readAt('2026-11-08T10:31:00Z').rules, ['RBAC.NOT_ELIGIBLE']);
});

const sameTenant: PolicyBundle = {
  ...toy,
  abac: [...toy.abac, { id: 'same-tenant', description: 'Same tenant may read', effect: 'permit', resourceTypes: ['case'], actions: ['read'],
    when: { op: 'eq', left: { path: 'resource.attrs.tenant' }, right: { path: 'subject.attrs.tenant' } } }],
};
// JSON.parse is the real path: the source literal 9007199254740993 would already be rounded
const tenantOf = (subjectTenant: string): Subject => ({ ...S('lina'), attrs: JSON.parse(`{"tenant": ${subjectTenant}}`) });
const tenantRead = (subjectTenant: string, resourceTenant: string, context: Context = { network: 'trusted', now: world.now }) =>
  evaluate(sameTenant, { subject: tenantOf(subjectTenant), action: 'read',
    resource: { ...R('CASE-18'), attrs: { ...R('CASE-18').attrs, tenant: JSON.parse(resourceTenant) } }, context }, graph);

test('an integer beyond 2^53 is refused instead of comparing equal to its rounded neighbour', () => {
  assert.deepEqual(tenantRead('9007199254740993', '9007199254740992').rules, ['ENGINE.MALFORMED_REQUEST']);
  assert.deepEqual(tenantRead('-9007199254740992', '-9007199254740992').rules, ['ENGINE.MALFORMED_REQUEST']);
  assert.deepEqual(tenantRead('1e21', '1e21').rules, ['ENGINE.MALFORMED_REQUEST']);
  // the largest safe integer still compares exactly
  assert.deepEqual(tenantRead('9007199254740991', '9007199254740991').rules, ['ABAC.same-tenant']);
  assert.notDeepEqual(tenantRead('9007199254740991', '9007199254740990').rules, ['ABAC.same-tenant']);
  // anywhere the conditions can read: context.input, nested arrays
  const ctx = (input: Record<string, unknown>): Context => ({ network: 'trusted', now: world.now, input: input as Context['input'] });
  assert.deepEqual(tenantRead('1', '1', ctx({ list: [1, [2, 2 ** 60]] })).rules, ['ENGINE.MALFORMED_REQUEST']);
  assert.deepEqual(tenantRead('1', '1', ctx({ ok: 1.5, big: 2 ** 53 - 1 })).rules, ['ABAC.same-tenant']);
});

test('the walk over request values survives cycles and deep nesting', () => {
  const input: Record<string, unknown> = { n: 1 };
  input.self = input;
  let deep: unknown = 2 ** 60;
  for (let i = 0; i < 100_000; i += 1) deep = [deep];
  const req = (extra: Record<string, unknown>) => ({ subject: lina, action: 'read', resource: R('CASE-18'), context: { network: 'trusted' as const, now: world.now, input: extra as Context['input'] } });
  assert.deepEqual(requestErrors(req(input)), []);
  assert.ok(requestErrors(req({ deep })).length > 0);
});

test('the residual filter refuses the same values (FALSE, no rows)', () => {
  const filter = (subject: Subject, now: string) => buildFilter(toy, subject, 'case', 'read', { network: 'trusted', now }, graph);
  assert.notDeepEqual(filter(lina, '2026-11-08T10:00:00Z'), FALSE);
  assert.deepEqual(filter(lina, '2026-11-08T10:00:00'), FALSE);
  assert.deepEqual(filter({ ...lina, attrs: { tenant: 2 ** 53 } }, '2026-11-08T10:00:00Z'), FALSE);
});
