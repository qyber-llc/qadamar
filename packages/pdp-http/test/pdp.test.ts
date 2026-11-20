import test from 'node:test';
import assert from 'node:assert/strict';
import { pdp } from '../src/pdp.ts';
import { HttpError, object, string } from '../src/http.ts';
import { context, decide, ref } from '../src/runtime.ts';
import type { Runtime } from '../src/runtime.ts';
import type { State } from '../src/store.ts';
import { applyResourcesInPlace } from '../src/resource-registry.ts';
import { fixture, evaluation, required } from './helpers.ts';
import type { Decision } from '../../core/src/index.ts';

interface Evaluation { decision: boolean; context: { rules: string[]; policy_version: string; obligations: object; would_deny: string[]; decision_token?: string } }
interface SearchResult { results: { type: string; id: string }[]; page: { next_token: string } }
const conflict = (err: unknown): boolean => err instanceof HttpError && err.status === 409;

function referenceSearch(rt: Runtime, path: string, b: Record<string, unknown>): SearchResult {
  const state = rt.store.state; const ctx = context(b.context, rt.now());
  const action = string(object(b.action).name);
  const resourceSearch = path === '/access/v1/search/resource';
  if (!resourceSearch && path !== '/access/v1/search/subject') throw new HttpError(404, 'not_found');
  const target = ref(resourceSearch ? b.subject : b.resource);
  const type = string(object(resourceSearch ? b.resource : b.subject).type);
  const page = b.page === undefined ? {} : object(b.page);
  const limit = page.limit ?? 100;
  if (!Number.isInteger(limit) || Number(limit) < 1 || Number(limit) > 1000) throw new HttpError(400, 'bad_request');
  const numericLimit = Number(limit);
  const token = page.token === undefined ? '' : (page.token === '' ? '' : string(page.token));
  const decoded = token ? Buffer.from(token, 'base64url').toString() : 'c0';
  if (token && (!/^c\d+$/.test(decoded) || Buffer.from(decoded).toString('base64url') !== token)) throw new HttpError(400, 'bad_request');
  const offset = Number(decoded.slice(1));
  if (!Number.isSafeInteger(offset) || offset < 0) throw new HttpError(400, 'bad_request');
  const candidates = resourceSearch ? state.resources : state.subjects;
  const results: SearchResult['results'] = [];
  let nextToken = '';
  for (let i = offset; i < candidates.length; i++) {
    const candidate = candidates[i];
    if (candidate === undefined || candidate.type !== type) continue;
    const allowed = decide(rt, resourceSearch ? target : candidate, resourceSearch ? candidate : target,
      action, ctx, 'pep', state, results.length < numericLimit).decision;
    if (!allowed) continue;
    if (results.length === numericLimit) {
      nextToken = Buffer.from(`c${i}`).toString('base64url');
      break;
    }
    results.push({ type: candidate.type, id: candidate.id });
  }
  return { results, page: { next_token: nextToken } };
}
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 0x100000000; };
}
function syntheticState(state: State, resourceSearch: boolean, allowed: readonly boolean[]): State {
  const allocation = required(state.tuples.find((tuple) => tuple.object.id === 'CASE-14' && tuple.subject.id === 'bob' && tuple.relation === 'allocated'));
  if (resourceSearch) {
    const permit = required(state.resources.find((r) => r.id === 'CASE-14'));
    const deny = required(state.resources.find((r) => r.id === 'CASE-7'));
    const resources = allowed.map((ok, i) => ({ ...(ok ? permit : deny), id: `RESOURCE-${i}` }));
    const grants = allowed.flatMap((ok, i) => ok ? [{ ...allocation, id: `resource-grant-${i}`, object: { type: 'case', id: `RESOURCE-${i}` } }] : []);
    return { ...state, resources, tuples: [...state.tuples, ...grants] };
  }
  const permit = required(state.subjects.find((s) => s.id === 'bob'));
  const deny = required(state.subjects.find((s) => s.id === 'frank'));
  const subjects = allowed.map((ok, i) => ({ ...(ok ? permit : deny), id: `SUBJECT-${i}` }));
  const grants = allowed.flatMap((ok, i) => ok ? [{ ...allocation, id: `subject-grant-${i}`, subject: { type: 'user', id: `SUBJECT-${i}` } }] : []);
  return { ...state, subjects, tuples: [...state.tuples, ...grants] };
}

test('search pages match the current implementation on randomized corpora', (t) => {
  const actual = fixture(t); const reference = fixture(t);
  const base = actual.rt.store.state; const rng = prng(0x51a7c4);
  for (const path of ['/access/v1/search/resource', '/access/v1/search/subject']) {
    const request = path.endsWith('/resource')
      ? { ...evaluation(), resource: { type: 'case' } }
      : { ...evaluation(), subject: { type: 'user' } };
    for (let run = 0; run < 8; run++) {
      const allowed = Array.from({ length: 80 + Math.floor(rng() * 80) }, () => rng() < 0.55);
      const state = syntheticState(base, path.endsWith('/resource'), allowed);
      actual.rt.store.state = state; reference.rt.store.state = state;
      const limit = 1 + Math.floor(rng() * 20);
      let token = ''; let referenceToken = ''; let number = 0;
      do {
        const body = { ...request, page: { limit, ...(token ? { token } : {}) } };
        const referenceBody = { ...request, page: { limit, ...(referenceToken ? { token: referenceToken } : {}) } };
        const expected = referenceSearch(reference.rt, path, referenceBody);
        const page = pdp(actual.rt, path, body) as SearchResult;
        assert.deepEqual(page, expected, `${path}, run ${run}, page ${number}`);
        token = page.page.next_token; referenceToken = expected.page.next_token; number++;
        assert.ok(number <= allowed.length + 1, 'pagination must terminate');
      } while (token);
    }
  }
});

test('one search page audits decisions made, not candidates excluded by the residual', (t) => {
  const { rt } = fixture(t); const reference = fixture(t);
  const allowed = Array.from({ length: 400 }, (_, i) => i >= 40 && (i - 40) % 5 === 0);
  rt.store.state = syntheticState(rt.store.state, true, allowed); reference.rt.store.state = rt.store.state;
  const limit = 7; const request = { ...evaluation(), resource: { type: 'case' }, page: { limit } };
  const first = pdp(rt, '/access/v1/search/resource', request) as SearchResult;
  const original = referenceSearch(reference.rt, '/access/v1/search/resource', request);
  let scanned = 0; let found = 0; let answered = 0;
  for (const ok of allowed) {
    scanned++; if (ok) found++;
    if (found === limit && answered === 0) answered = scanned;
    if (found === limit + 1) break;
  }
  assert.deepEqual(first, original);
  assert.equal(first.page.next_token, Buffer.from(`c${scanned - 1}`).toString('base64url'));
  assert.equal(reference.rt.decisions, answered);
  // The allowed lookahead is decided but not audited; residual-excluded candidates are neither decided nor audited.
  assert.equal(rt.decisions, limit);
  assert.ok(rt.decisions < reference.rt.decisions);
  assert.equal(rt.audit.records().filter((r) => r.type === 'decision').length, rt.decisions);
});

test('one sparse page makes a constant number of decisions across 10,000 inaccessible resources', (t) => {
  const { rt } = fixture(t);
  const allowed = Array.from({ length: 10008 }, (_, i) => i >= 10000);
  rt.store.state = syntheticState(rt.store.state, true, allowed);
  const limit = 7;
  const page = pdp(rt, '/access/v1/search/resource', {
    ...evaluation(), resource: { type: 'case' }, page: { limit },
  }) as SearchResult;
  assert.equal(page.results.length, limit);
  assert.ok(page.page.next_token);
  assert.ok(rt.decisions <= limit + 1);
  assert.equal(rt.decisions, limit);
  assert.equal(rt.audit.records().filter((r) => r.type === 'decision').length, limit);
});

test('resource search matches the reference for every toy action, network and subject with recorded history', (t) => {
  const actual = fixture(t); const reference = fixture(t);
  const created = pdp(actual.rt, '/access/v1/evaluation', evaluation('grace', 'PAY-3', 'create', 'trusted')) as Evaluation;
  assert.equal(created.decision, true);
  pdp(actual.rt, '/x/v1/tokens/consume', {
    token: created.context.decision_token, action: 'create', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4,
  });
  reference.rt.store.performed = [...actual.rt.store.performed];
  assert.equal(actual.rt.store.performed.length, 1);

  for (const action of ['create', 'approve', 'release']) {
    const request = {
      subject: { type: 'user', id: 'grace' }, action: { name: action }, resource: { type: 'payment' },
      context: { network: 'trusted', makerId: 'grace' }, page: { limit: 10 },
    };
    const actualBefore = actual.rt.decisions; const referenceBefore = reference.rt.decisions;
    const page = pdp(actual.rt, '/access/v1/search/resource', request);
    const expected = referenceSearch(reference.rt, '/access/v1/search/resource', request);
    assert.deepEqual(page, expected);
    const actualAudited = actual.rt.decisions - actualBefore, referenceAudited = reference.rt.decisions - referenceBefore;
    assert.equal(referenceAudited, 1);
    assert.ok(actualAudited <= referenceAudited, `${action} decides only residual survivors`);
  }

  let checked = 0;
  for (const network of ['trusted', 'untrusted'] as const) {
    for (const who of actual.rt.store.state.subjects) {
      for (const [type, definition] of Object.entries(actual.rt.store.state.bundle.schema.resourceTypes)) {
        for (const action of Object.keys(definition.actions)) {
          const request = {
            subject: { type: who.type, id: who.id }, action: { name: action }, resource: { type },
            context: { network, makerId: 'grace' },
          };
          const limit = 1 + checked % 3;
          let token = ''; let referenceToken = ''; let pages = 0;
          do {
            const page = pdp(actual.rt, '/access/v1/search/resource', {
              ...request, page: { limit, ...(token ? { token } : {}) },
            });
            const expected = referenceSearch(reference.rt, '/access/v1/search/resource', {
              ...request, page: { limit, ...(referenceToken ? { token: referenceToken } : {}) },
            });
            assert.deepEqual(page, expected, `${who.id} ${type} ${action} ${network}, page ${pages}`);
            token = (page as SearchResult).page.next_token; referenceToken = expected.page.next_token; pages++;
            assert.ok(pages <= 10, 'pagination must terminate');
          } while (token);
          checked++;
        }
      }
    }
  }
  assert.equal(checked, 264); // 12 subjects (lina and omar included) x 11 actions x 2 networks
});

test('malformed search tokens make no decisions and replay in another query is harmless', (t) => {
  const actual = fixture(t); const reference = fixture(t);
  const state = syntheticState(actual.rt.store.state, true, Array.from({ length: 80 }, (_, i) => i % 3 !== 0));
  actual.rt.store.state = state; reference.rt.store.state = state;
  const request = { ...evaluation(), resource: { type: 'case' }, page: { limit: 3 } };
  const first = pdp(actual.rt, '/access/v1/search/resource', request) as SearchResult;
  const before = actual.rt.decisions;
  for (const token of ['!!!', 'IA', 'MA=', 'Mw', 'LTE', 'MS4w', 'OTk5OTk5OTk5OTk5OTk5OTk5OTk5', 'Yy0x']) { // Mw: a pre-versioning token
    assert.throws(() => pdp(actual.rt, '/access/v1/search/resource', { ...request, page: { token } }), (e) => e instanceof HttpError && e.status === 400);
  }
  assert.equal(actual.rt.decisions, before);
  const otherQuery = { ...request, context: { network: 'trusted' }, page: { limit: 3, token: first.page.next_token } };
  const replayed = pdp(actual.rt, '/access/v1/search/resource', otherQuery) as SearchResult;
  const expected = referenceSearch(reference.rt, '/access/v1/search/resource', otherQuery);
  assert.deepEqual(replayed, expected);
  assert.deepEqual(pdp(actual.rt, '/access/v1/search/resource', { ...request, resource: { type: 'payment' }, page: { token: first.page.next_token } }), { results: [], page: { next_token: '' } });
});

test('AuthZEN response, identity resolved from store, defaults fail closed, delegation', (t) => {
  const { rt } = fixture(t);
  const call = (body: Record<string, unknown>): Evaluation => pdp(rt, '/access/v1/evaluation', body) as Evaluation;
  const d = call(evaluation());
  assert.equal(d.decision, true); assert.match(d.context.policy_version, /^pv\./);
  assert.deepEqual(Object.keys(d).sort(), ['context', 'decision']);
  assert.deepEqual(Object.keys(d.context).sort(), ['obligations', 'policy_version', 'reasons', 'rules', 'would_deny']);
  const forged = evaluation('bob', 'CASE-7');
  forged.subject = { type: 'user', id: 'bob', clearance: 3, roles: ['security_officer'], compartments: ['ORCHID'] };
  assert.equal(call(forged).decision, false);
  assert.equal(call(evaluation('unknown')).decision, false);
  assert.equal(call(evaluation('alice', 'CASE-7')).decision, false);
  assert.equal(call(evaluation('alice', 'CASE-7', 'read', 'trusted')).decision, true);
  assert.equal(call(evaluation('assistant-1')).decision, true);
  rt.store.state = { ...rt.store.state, subjects: rt.store.state.subjects.map((s) => s.id === 'bob' ? { ...s, active: false } : s) };
  assert.equal(call(evaluation('assistant-1')).decision, false);
  assert.equal(rt.audit.records().length, 7);
});
test('hidden-means-absent responses match missing resources; admin has full explain', (t) => {
  const { rt } = fixture(t);
  for (const b of [evaluation('bob', 'CASE-7'), evaluation('bob', 'unknown'), evaluation('bob', 'CASE-15'), evaluation('alice', 'CASE-7')]) {
    assert.throws(() => pdp(rt, '/x/v1/explain', b), (e) => e instanceof HttpError && e.status === 404 && e.code === 'not_found');
  }
  const d = pdp(rt, '/x/v1/explain', evaluation()) as Decision;
  assert.equal(d.decision, true); assert.ok(d.trace.length);
});
test('batch defaults and all three evaluation semantics', (t) => {
  const { rt } = fixture(t);
  const common = evaluation();
  const evaluations = [evaluation('bob', 'CASE-7'), {}, evaluation('alice', 'CASE-7', 'read', 'trusted')];
  for (const [semantic, count] of [['execute_all', 3], ['deny_on_first_deny', 1], ['permit_on_first_permit', 2]] as const) {
    const result = pdp(rt, '/access/v1/evaluations', { ...common, evaluations, options: { evaluations_semantic: semantic } }) as { evaluations: Evaluation[] };
    assert.equal(result.evaluations.length, count);
  }
  assert.throws(() => pdp(rt, '/access/v1/evaluations', { evaluations: [], options: { evaluations_semantic: 'anything' } }), HttpError);
});
test('search resources, subjects and actions exposes only allowed identifiers and paginates', (t) => {
  const { rt } = fixture(t);
  const b = { ...evaluation(), resource: { type: 'case' }, page: { limit: 1 } };
  const first = pdp(rt, '/access/v1/search/resource', b) as { results: { type: string; id: string }[]; page: { next_token: string } };
  assert.equal(first.results.length, 1); assert.ok(first.page.next_token);
  const second = pdp(rt, '/access/v1/search/resource', { ...b, page: { limit: 1, token: first.page.next_token } }) as typeof first;
  assert.notDeepEqual(first.results, second.results);
  assert.ok(!JSON.stringify([first, second]).includes('CASE-7'));
  const who = pdp(rt, '/access/v1/search/subject', { ...evaluation(), subject: { type: 'user' } }) as { results: { id: string }[] };
  assert.ok(who.results.some((s) => s.id === 'bob'));
  assert.ok(!who.results.some((s) => s.id === 'frank'));
  const actions = pdp(rt, '/access/v1/search/action', evaluation()) as { results: { name: string }[] };
  assert.ok(actions.results.some((a) => a.name === 'read'));
});
test('filter compiles residuals; missing mapping and unsupported dialect are rejected', (t) => {
  const { rt } = fixture(t);
  const columns = { 'resource.level': { column: 'level', type: 'number' }, 'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.id': 'id' };
  const b = { ...evaluation(), resource: { type: 'case' }, columns };
  const filter = pdp(rt, '/x/v1/filter', b) as { sql: { text: string; params: unknown[] } };
  assert.doesNotMatch(filter.sql.text, /coalesce/); assert.ok(filter.sql.params.length);
  assert.throws(() => pdp(rt, '/x/v1/filter', { ...b, columns: {} }), (e) => e instanceof HttpError && e.status === 400);
  assert.throws(() => pdp(rt, '/x/v1/filter', { ...b, dialect: 'mysql' }), HttpError);
});
test('decision JWS verifies, is bound, single-use, survives restart, and rejects tampering', (t) => {
  const { rt } = fixture(t);
  rt.sodHistory = 'caller';
  const d = pdp(rt, '/access/v1/evaluation', { ...evaluation('henry', 'PAY-3', 'approve'), context: { makerId: 'grace', network: 'trusted' } }) as Evaluation;
  assert.equal(d.decision, true);
  const token = d.context.decision_token;
  assert.ok(token);
  const header = JSON.parse(Buffer.from(required(token.split('.')[0]), 'base64url').toString());
  assert.equal(header.alg, 'EdDSA');
  const consume = { token, action: { name: 'approve' }, resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 };
  assert.throws(() => pdp(rt, '/x/v1/tokens/consume', { ...consume, resourceVersion: 5 }), conflict);
  const parts = token.split('.'); parts[1] = Buffer.from('{"sub":"user:grace"}').toString('base64url');
  assert.throws(() => pdp(rt, '/x/v1/tokens/consume', { ...consume, token: parts.join('.') }), conflict);
  assert.equal((pdp(rt, '/x/v1/tokens/consume', consume) as { ok: boolean }).ok, true);
  assert.throws(() => pdp(rt, '/x/v1/tokens/consume', consume), conflict);
});
test('token expiry and re-decision against revoked identities', (t) => {
  const { rt, setClock } = fixture(t);
  const make = (): string => (pdp(rt, '/access/v1/evaluation', evaluation('henry', 'PAY-3', 'release')) as Evaluation).context.decision_token as string;
  const consume = (token: string): unknown => pdp(rt, '/x/v1/tokens/consume', { token, action: 'release', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 });
  const expired = make(); setClock('2026-11-08T10:00:16Z'); assert.throws(() => consume(expired), conflict);
  const revoked = make();
  rt.store.state = { ...rt.store.state, subjects: rt.store.state.subjects.map((s) => s.id === 'henry' ? { ...s, active: false } : s) };
  assert.throws(() => consume(revoked), conflict);
});

test('seeded random policy worlds (CBAC context rules and grant windows included) match point-wise resource, subject and action searches with stable pages', (t) => {
  const actual = fixture(t), reference = fixture(t);
  const base = actual.rt.store.state, rng = prng(0x8a11ce);
  const pick = <T>(values: readonly T[]): T => values[Math.floor(rng() * values.length)]!;
  const many = <T>(values: readonly T[]): T[] => values.filter(() => rng() < 0.5);
  const roles = Object.keys(base.bundle.rbac.roles), integrities = ['derived', 'extracted', 'system', 'verified'] as const;
  // grant windows around the fixture clock (2026-11-08T10:00:00Z): expired, not yet, live, open-ended
  const windows = [{ notAfter: '2026-11-08T09:00:00Z' }, { notBefore: '2026-11-08T11:00:00Z' },
    { notBefore: '2026-11-08T09:00:00Z', notAfter: '2026-11-08T10:30:00Z' }, { notBefore: '2026-11-08T10:00:00Z' }, {}];
  const requirements = [{ network: 'trusted' as const }, { countries: ['AE'] }, { ipRanges: ['10.0.0.0/8'] }, { device: { managed: true } },
    { mfaMaxAgeSeconds: 600 }, { authMethodsAny: ['otp'] }, { maxRiskScore: 40 },
    { timeWindows: [{ days: [7], from: '13:00', to: '15:00', timeZone: 'Asia/Dubai' }] }];
  for (let run = 0; run < 24; run++) {
    const subjects = base.subjects.map((s) => ({ ...s, active: rng() > 0.12, roles: many(roles),
      clearance: Math.floor(rng() * 4) as 0 | 1 | 2 | 3, compartments: many(['ORCHID', 'FALCON']), integrity: pick(integrities),
      ...(rng() < 0.5 ? { roleAssignments: many(roles).map((role) => ({ role, ...pick(windows) })) } : {}) }));
    const resources = base.resources.map((r) => ({ ...r, level: Math.floor(rng() * 4) as 0 | 1 | 2 | 3,
      compartments: many(['ORCHID', 'FALCON']), integrity: pick(integrities), owner: pick(subjects).id,
      contentClasses: many(['finance.amount', 'pii.iban']),
      attrs: { ...r.attrs, status: pick(['open', 'closed', 'pending']), priority: Math.floor(rng() * 5), flagged: rng() < 0.25 } }));
    const tuples: Array<State['tuples'][number]> = base.tuples.flatMap((tuple) => {
      if (rng() < 0.2) return [];
      const mode = Math.floor(rng() * 8);
      const window = mode === 1 ? { validTo: '2026-11-08T09:00:00Z' }
        : mode === 2 ? { validFrom: '2026-11-08T08:00:00Z', validTo: '2026-11-08T10:00:00Z', breakGlass: true }
          : mode === 3 ? { validFrom: '2026-11-08T08:00:00Z', validTo: '2026-11-08T11:00:00Z', breakGlass: true }
            : mode === 4 ? { validFrom: '2026-11-08T04:00:00Z', validTo: '2026-11-08T12:00:00Z', breakGlass: true }
              : mode >= 5 ? pick(windows) : {};
      return [{ ...tuple, validFrom: undefined, validTo: undefined, notBefore: undefined, notAfter: undefined, breakGlass: undefined, ...window }];
    });
    for (let i = 0; i < 20; i++) {
      const resource = pick(resources.filter((r) => r.type === 'case')), subject = pick(subjects);
      tuples.push({ id: `random-${run}-${i}`, object: { type: resource.type, id: resource.id }, relation: pick(['allocated', 'granted', 'delegate']),
        subject: { type: subject.type, id: subject.id }, ...(rng() < 0.25 ? { validFrom: '2026-11-08T08:00:00Z', validTo: '2026-11-08T11:00:00Z', breakGlass: true } : pick(windows)) });
    }
    const bundle = { ...base.bundle, abac: [...base.bundle.abac,
      { id: 'random-priority-read', description: 'random indexed attribute permit', effect: 'permit' as const, resourceTypes: ['case'], actions: ['read'],
        when: { op: 'lt' as const, left: { path: 'resource.attrs.priority' }, right: { value: 2 } } },
      { id: 'random-flagged-deny', description: 'random indexed attribute forbid', effect: 'forbid' as const, resourceTypes: ['case'], actions: ['read', 'update'],
        when: { op: 'eq' as const, left: { path: 'resource.attrs.flagged' }, right: { value: true } } },
    ], context: Array.from({ length: Math.floor(rng() * 4) }, (_, i) => ({ id: `random-context-${i}`,
      ...pick([{ actions: ['read'] }, { actions: ['update'] }, { actionKinds: ['read' as const, 'write' as const] }, { resourceTypes: ['case'] }]),
      ...(rng() < 0.3 ? { minResourceLevel: Math.floor(rng() * 4) as 0 | 1 | 2 | 3 } : {}),
      ...(rng() < 0.3 ? { contentClasses: ['finance.amount'] } : {}),
      ...pick(requirements) })) };
    actual.rt.store.state = { ...base, bundle, subjects, resources, tuples };
    reference.rt.store.state = actual.rt.store.state;
    const performed = Array.from({ length: 2 }, (_, i) => ({ subject: { type: 'user', id: pick(['grace', 'henry']) },
      resource: { type: 'payment', id: 'PAY-3' }, action: 'create', at: `2026-11-08T09:0${i}:00Z`,
      ...(rng() < 0.5 ? { id: `random-performed-${run}-${i}`, outcome: pick(['completed', 'failed'] as const) } : {}) }));
    actual.rt.store.performed = performed; reference.rt.store.performed = performed;

    const who = pick(subjects), resource = pick(resources.filter((r) => r.type === 'case'));
    const common = { context: { network: pick(['trusted', 'untrusted']), sessionLevel: Math.floor(rng() * 4),
      ...(rng() < 0.6 ? { country: pick(['AE', 'FR']) } : {}), ...(rng() < 0.6 ? { ip: pick(['10.1.2.3', '192.0.2.7']) } : {}),
      ...(rng() < 0.6 ? { device: { managed: rng() < 0.5, compliant: rng() < 0.5 } } : {}),
      ...(rng() < 0.6 ? { mfaTime: pick(['2026-11-08T09:55:00Z', '2026-11-08T08:00:00Z']) } : {}),
      ...(rng() < 0.6 ? { authMethods: many(['pwd', 'otp']) } : {}), ...(rng() < 0.6 ? { riskScore: Math.floor(rng() * 101) } : {}),
      ...(rng() < 0.1 ? { sessionExpired: true } : {}) } };
    const requests: Array<[string, Record<string, unknown>]> = [
      ['/access/v1/search/resource', { subject: { type: who.type, id: who.id }, action: { name: 'read' }, resource: { type: 'case' }, ...common }],
      ['/access/v1/search/resource', { subject: { type: who.type, id: who.id }, action: { name: 'update' }, resource: { type: 'case' }, ...common }],
      ['/access/v1/search/resource', { subject: { type: 'user', id: pick(['grace', 'henry']) }, action: { name: pick(['approve', 'release']) },
        resource: { type: 'payment' }, context: { network: 'trusted', makerId: 'grace' } }],
      ['/access/v1/search/subject', { subject: { type: 'user' }, action: { name: 'read' }, resource: { type: 'case', id: resource.id }, ...common }],
    ];
    for (const [path, request] of requests) {
      const limit = 1 + Math.floor(rng() * 5);
      let token = '', referenceToken = '', pages = 0;
      do {
        const expected = referenceSearch(reference.rt, path, { ...request, page: { limit, ...(referenceToken ? { token: referenceToken } : {}) } });
        const page = pdp(actual.rt, path, { ...request, page: { limit, ...(token ? { token } : {}) } }) as SearchResult;
        assert.deepEqual(page, expected, `run=${run} path=${path} page=${pages} request=${JSON.stringify(request)}`);
        token = page.page.next_token; referenceToken = expected.page.next_token; pages++;
        assert.ok(pages <= resources.length + subjects.length + 1);
      } while (token);
    }

    const actionRequest = { subject: { type: who.type, id: who.id }, resource: { type: resource.type, id: resource.id }, ...common };
    const expectedActions = Object.keys(bundle.schema.resourceTypes.case?.actions ?? {}).filter((action) =>
      decide(reference.rt, { type: who.type, id: who.id }, { type: resource.type, id: resource.id }, action,
        context(actionRequest.context, reference.rt.now())).decision).map((name) => ({ name }));
    assert.deepEqual(pdp(actual.rt, '/access/v1/search/action', actionRequest), { results: expectedActions });
  }
});

test('resource candidates follow in-place record patches without changing their array identity', (t) => {
  const { rt } = fixture(t);
  const request = { ...evaluation('bob', 'CASE-14', 'update', 'trusted'), resource: { type: 'case' } };
  const before = pdp(rt, '/access/v1/search/resource', request) as SearchResult;
  assert.ok(before.results.some((r) => r.id === 'CASE-14'));
  const stored = required(rt.store.state.resources.find((r) => r.id === 'CASE-14'));
  const resources = rt.store.state.resources;
  rt.store.state = applyResourcesInPlace(rt.store.state, [{ ...stored, attrs: { ...stored.attrs, status: 'closed' }, version: (stored.version ?? 0) + 1 }]);
  assert.equal(rt.store.state.resources, resources);
  const closed = pdp(rt, '/access/v1/search/resource', request) as SearchResult;
  assert.ok(!closed.results.some((r) => r.id === 'CASE-14'));
  const changed = required(rt.store.state.resources.find((r) => r.id === 'CASE-14'));
  rt.store.state = applyResourcesInPlace(rt.store.state, [{ ...changed, attrs: { ...changed.attrs, status: 'open' }, version: (changed.version ?? 0) + 1 }]);
  const reopened = pdp(rt, '/access/v1/search/resource', request) as SearchResult;
  assert.ok(reopened.results.some((r) => r.id === 'CASE-14'));
});

test('resource candidates match point decisions after committed relabels and deletes', (t) => {
  const actual = fixture(t), reference = fixture(t);
  const request = { ...evaluation('bob', 'CASE-14', 'update', 'trusted'), resource: { type: 'case' } };
  const stored = required(actual.rt.store.state.resources.find((r) => r.id === 'CASE-14'));
  actual.rt.store.state = applyResourcesInPlace(actual.rt.store.state, [{ ...stored, attrs: { ...stored.attrs, status: 'closed' }, version: (stored.version ?? 0) + 1 }]);
  actual.rt.store.save();
  pdp(actual.rt, '/access/v1/search/resource', request);
  const closed = required(actual.rt.store.state.resources.find((r) => r.id === 'CASE-14'));
  actual.rt.store.state = applyResourcesInPlace(actual.rt.store.state, [{ ...closed, attrs: { ...closed.attrs, status: 'open' }, version: (closed.version ?? 0) + 1 }]);
  actual.rt.store.save();
  reference.rt.store.state = actual.rt.store.state;
  assert.deepEqual(pdp(actual.rt, '/access/v1/search/resource', request), referenceSearch(reference.rt, '/access/v1/search/resource', request));

  const reopened = required(actual.rt.store.state.resources.find((r) => r.id === 'CASE-14'));
  actual.rt.store.state = applyResourcesInPlace(actual.rt.store.state, [], [reopened]);
  actual.rt.store.save();
  reference.rt.store.state = actual.rt.store.state;
  assert.deepEqual(pdp(actual.rt, '/access/v1/search/resource', request), referenceSearch(reference.rt, '/access/v1/search/resource', request));
});

test('a committed resource insertion advances search and matches point decisions', (t) => {
  const actual = fixture(t), reference = fixture(t);
  const request = { ...evaluation(), resource: { type: 'case' } };
  pdp(actual.rt, '/access/v1/search/resource', request);
  const stored = required(actual.rt.store.state.resources.find((r) => r.id === 'CASE-14'));
  const added = applyResourcesInPlace(actual.rt.store.state, [{ ...stored, id: 'CASE-NEW' }]);
  actual.rt.store.state = { ...added, tuples: [...added.tuples, { id: 'grant-CASE-NEW', object: { type: 'case', id: 'CASE-NEW' }, relation: 'allocated', subject: { type: 'user', id: 'bob' } }] };
  actual.rt.store.save();
  reference.rt.store.state = actual.rt.store.state;
  const page = pdp(actual.rt, '/access/v1/search/resource', request) as SearchResult;
  assert.deepEqual(page, referenceSearch(reference.rt, '/access/v1/search/resource', request));
  assert.ok(page.results.some((r) => r.id === 'CASE-NEW'));
});
