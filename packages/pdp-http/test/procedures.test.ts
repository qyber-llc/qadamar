// Clark-Wilson C5 (input validation of certified commands, at decision and on the post-state at consumption), E3 (a
// certified command is decided only for a subject population the calling PEP credential is bound to) and E4 at run
// time (a certifier never runs what it certified), through the PDP's own entry points.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFilter, FALSE, indexTuples, mandatoryWeakenings, validateBundle } from '../../core/src/index.ts';
import type { InputValidatorDef, PolicyBundle } from '../../core/src/index.ts';
import { pdp } from '../src/pdp.ts';
import { HttpError } from '../src/http.ts';
import { admin } from '../src/admin/index.ts';
import { subject, withCertified } from '../src/runtime.ts';
import { fixture, FIXED, req, required, user } from './helpers.ts';
import type { Fixture } from './helpers.ts';

const NOTE: InputValidatorDef = { id: 'approval-note', description: 'An approval carries its status and a bounded note', resourceTypes: ['payment'],
  actions: ['approve'], fields: { status: { type: 'string', required: true, enum: ['approved'] }, note: { type: 'string', maxLength: 20 }, amount: { type: 'integer', min: 1, max: 5000 } } };
interface Evaluation { decision: boolean; context: { rules: string[]; decision_token?: string; obligations: { decisionToken?: { postState?: true } } } }
const conflict = (e: unknown): boolean => e instanceof Error && 'status' in e && e.status === 409;

function configure(f: Fixture, clarkWilson: Partial<PolicyBundle['clarkWilson']>): PolicyBundle {
  const s = f.rt.store.state;
  const bundle = { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, ...clarkWilson } };
  f.rt.store.state = { ...s, bundle };
  return bundle;
}
const approve = (f: Fixture, pepTypes: readonly string[], input?: Record<string, unknown>): Evaluation => {
  f.rt.sodHistory = 'caller';
  return pdp(f.rt, '/access/v1/evaluation', {
    subject: { type: 'user', id: 'henry' }, action: { name: 'approve' }, resource: { type: 'payment', id: 'PAY-3' },
    context: { network: 'trusted', makerId: 'grace', ...(input ? { input } : {}) } }, pepTypes) as Evaluation;
};
const consume = (f: Fixture, token: string, pepTypes: readonly string[], attrs?: Record<string, unknown>) => pdp(f.rt, '/x/v1/tokens/consume',
  { token, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4, ...(attrs ? { attrs } : {}) }, pepTypes);

test('C5: a certified command with input validators is decided on its input and consumed only with a valid post-state', (t) => {
  const f = fixture(t);
  configure(f, { inputValidators: [NOTE] });
  assert.deepEqual(approve(f, []).context.rules, ['CW.INPUT_REQUIRED']);
  for (const bad of [{ status: 'rejected' }, { status: 'approved', note: 'x'.repeat(21) }, { status: 'approved', amount: 1.5 }, { status: 'approved', amount: 9000 },
    { status: 'approved', extra: true }, { note: 'no status' }, { status: 7 }]) {
    assert.deepEqual(approve(f, [], bad).context.rules, ['CW.INPUT.approval-note'], JSON.stringify(bad));
  }
  const allowed = approve(f, [], { status: 'approved', note: 'ok', amount: 1200 });
  assert.equal(allowed.decision, true);
  assert.equal(allowed.context.obligations.decisionToken?.postState, true, 'the PEP is told to send the post-state');
  const token = required(allowed.context.decision_token);
  assert.throws(() => consume(f, token, []), conflict, 'no post-state: refused');
  assert.throws(() => consume(f, token, [], { status: 'approved', extra: 'smuggled' }), (e: unknown) => e instanceof HttpError && e.status === 400,
    'a post-state key the procedure does not declare: refused before the token is touched');
  assert.throws(() => consume(f, token, [], { status: 'rejected' }), conflict, 'a post-state other than validated: refused');
  const row = required(f.rt.audit.records().at(-1));
  assert.equal(row.effect, 'deny');
  assert.ok(row.rules?.includes('CW.INPUT.approval-note'), 'the refusal is audited with the failed validator');
  assert.equal(f.rt.store.performed.length, 0);
  assert.equal((consume(f, token, [], { status: 'approved' }) as { ok: boolean }).ok, true, 'the token stays usable with a valid post-state');
  // the list filter agrees: without input no item, with a valid one the usual residual
  const s = f.rt.store.state; const who = required(subject(s, 'henry', 'user'));
  const ctx = { network: 'trusted' as const, now: FIXED, pepSubjectTypes: [] };
  assert.deepEqual(buildFilter(s.bundle, who, 'payment', 'approve', withCertified(s, ctx), indexTuples(s.tuples)), FALSE);
  assert.notDeepEqual(buildFilter(s.bundle, who, 'payment', 'approve', withCertified(s, { ...ctx, input: { status: 'approved' } }), indexTuples(s.tuples)), FALSE);
});

test('C5 and E3 declarations are validated, and dropping them is a mandatory weakening', (t) => {
  const f = fixture(t);
  const base = f.rt.store.state.bundle;
  const errors = (cw: Record<string, unknown>): string[] => {
    const r = validateBundle({ ...base, clarkWilson: { ...base.clarkWilson, ...cw } });
    return r.ok ? [] : r.errors;
  };
  assert.deepEqual(errors({ inputValidators: [NOTE], requirePepBinding: ['payment'] }), []);
  assert.ok(errors({ inputValidators: [{ ...NOTE, actions: ['edit'] }] }).some((e) => e.includes('certified commands')), 'edit is not certified');
  assert.ok(errors({ inputValidators: [{ ...NOTE, fields: {} }] }).some((e) => e.includes('at least one field')));
  assert.ok(errors({ inputValidators: [{ ...NOTE, fields: { a: { type: 'date' } } }] }).some((e) => e.includes('needs a type')));
  assert.ok(errors({ inputValidators: [{ ...NOTE, fields: { a: { type: 'string', pattern: '.*' } } }] }).some((e) => e.includes('needs a type')), 'no regular expressions');
  assert.ok(errors({ inputValidators: [{ ...NOTE, fields: { a: { type: 'number', min: 'x', maxLength: -1, enum: [], required: 'y' } } }] }).length >= 4);
  assert.ok(errors({ inputValidators: [NOTE, NOTE] }).some((e) => e.includes('duplicate')));
  assert.ok(errors({ inputValidators: {} }).length > 0);
  assert.ok(errors({ inputValidators: [1] }).length > 0);
  assert.ok(errors({ requirePepBinding: ['case'] }).some((e) => e.includes('requirePepBinding')), 'case is not constrained');
  const strict = { ...base, clarkWilson: { ...base.clarkWilson, inputValidators: [NOTE], requirePepBinding: ['payment'] } };
  assert.deepEqual(mandatoryWeakenings(strict, base), ['payment procedures no longer require a PEP bound to the subject\'s population', 'input validation approval-note removed or changed']);
  assert.deepEqual(mandatoryWeakenings(base, strict), []);
});

test('E3: certified commands are decided only through a PEP credential bound to the subject population', (t) => {
  const f = fixture(t);
  configure(f, { requirePepBinding: ['payment'] });
  assert.deepEqual(approve(f, []).context.rules, ['CW.SUBJECT_NOT_AUTHENTICATED'], 'the unbound bootstrap credential');
  assert.deepEqual(approve(f, ['service']).context.rules, ['CW.SUBJECT_NOT_AUTHENTICATED'], 'bound to another population');
  const created = admin(f.rt, user('lina'), 'POST', new URL('http://x/admin/v1/pep-credentials'), { name: 'payments-gateway', subjectTypes: ['user', 'user'] }, f.auth).value as
    { credential: { subjectTypes: string[] }; secret: string };
  assert.deepEqual(created.credential.subjectTypes, ['user']);
  const caller = f.auth.pepCaller(req({ authorization: `Bearer ${created.secret}` }));
  assert.deepEqual(caller.subjectTypes, ['user']);
  assert.deepEqual(f.auth.pepCaller(req({ authorization: `Bearer ${f.pepApiKey}` })).subjectTypes, []);
  for (const bad of [[], 'user', [''], Array.from({ length: 17 }, (_, i) => `t${i}`)]) {
    assert.throws(() => f.auth.createPepCredential(`bad-${JSON.stringify(bad)}`, 'lina', bad), (e: unknown) => e instanceof Error && 'status' in e && e.status === 400);
  }
  const allowed = approve(f, caller.subjectTypes);
  assert.equal(allowed.decision, true);
  // a decision token taken by a bound PEP cannot be spent by an unbound one: consumption re-decides for the consumer
  const token = required(allowed.context.decision_token);
  assert.throws(() => consume(f, token, []), conflict);
  assert.equal((consume(f, token, ['user']) as { ok: boolean }).ok, true);
  // reads and uncertified actions are not affected
  const read = pdp(f.rt, '/access/v1/evaluation', { subject: { type: 'user', id: 'henry' }, action: { name: 'read' }, resource: { type: 'payment', id: 'PAY-3' },
    context: { network: 'trusted' } }, []) as Evaluation;
  assert.equal(read.decision, true);
  // console views answer for a PEP bound to the subject's population
  const who = admin(f.rt, user('amira'), 'POST', new URL('http://x/admin/v1/simulate/who-can'),
    { resourceId: 'PAY-3', action: 'approve', network: 'trusted', makerId: 'grace' }, f.auth).value as { items: { subject: { id: string }; decision: boolean; rules: string[] }[] };
  const henry = required(who.items.find((x) => x.subject.id === 'henry'));
  assert.ok(!henry.rules.includes('CW.SUBJECT_NOT_AUTHENTICATED'), JSON.stringify(henry.rules));
});

test('E4: a certifier (or its checker) is denied the procedure it certified, whatever role it is granted later', (t) => {
  const f = fixture(t);
  const s = f.rt.store.state;
  f.rt.store.state = { ...s, certifications: [{ resourceType: 'payment', action: 'approve', certifiedBy: 'lina', approvedBy: 'henry',
    certifiedAt: FIXED, policyVersion: 'pv', changeId: 'c-1', reason: 'test' }] };
  assert.deepEqual(approve(f, []).context.rules, ['CW.CERTIFIER_EXECUTES'], 'henry approved the certification');
  const state = f.rt.store.state; const who = required(subject(state, 'henry', 'user'));
  assert.deepEqual(buildFilter(state.bundle, who, 'payment', 'approve', withCertified(state, { network: 'trusted', now: FIXED }), indexTuples(state.tuples)), FALSE);
  const release = pdp(f.rt, '/access/v1/evaluation', { subject: { type: 'user', id: 'henry' }, action: { name: 'release' }, resource: { type: 'payment', id: 'PAY-3' },
    context: { network: 'trusted' } }, []) as Evaluation;
  assert.ok(!release.context.rules.includes('CW.CERTIFIER_EXECUTES'), 'only the certified procedure is barred');
});
