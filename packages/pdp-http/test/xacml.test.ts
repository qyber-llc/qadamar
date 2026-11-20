import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { createHandler } from '../src/router.ts';
import { ADVICE, ATTRIBUTE, CATEGORY, OBLIGATION, STATUS, XACML_MAX_REQUESTS, unexpressible } from '../src/xacml.ts';
import { evaluation as authzen } from '../src/pdp.ts';
import { evaluation, fixture, type Fixture } from './helpers.ts';

type Handler = ReturnType<typeof createHandler>;
type Obj = Record<string, unknown>;
interface Result { Decision: string; Status: { StatusCode: { Value: string }; StatusMessage?: string; StatusDetail?: { MissingAttributeDetail: Obj[] } };
  Obligations?: { Id: string; AttributeAssignment: { AttributeId: string; Value: string }[] }[]; AssociatedAdvice?: { Id: string; AttributeAssignment: { AttributeId: string; Value: string }[] }[];
  PolicyIdentifierList?: { PolicyIdReference: { Id: string }[] } }
interface Response { status: number; type: string; text: string; results: Result[]; data: Obj }
const XACML_TYPE = 'application/xacml+json';
async function send(handler: Handler, path: string, payload: unknown, headers: Record<string, string>, method = 'POST'): Promise<Response> {
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const req = new IncomingMessage(socket); req.url = path; req.method = method;
  req.headers = { 'content-type': XACML_TYPE, ...headers };
  let text = '';
  const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = handler(req, res);
  req.push(typeof payload === 'string' ? payload : JSON.stringify(payload)); req.push(null);
  await pending;
  const data = JSON.parse(text || '{}') as Obj;
  return { status: res.statusCode, type: String(res.getHeader('content-type')), text, data, results: (data.Response ?? []) as Result[] };
}
const route = (f: Fixture, rateLimit?: number): Handler => createHandler(f.rt, f.auth, rateLimit ? { rateLimit, pepRateLimit: rateLimit } : {}, () => 'http://localhost:8787');
const pep = (f: Fixture): Record<string, string> => ({ authorization: `Bearer ${f.pepApiKey}` });
const attr = (AttributeId: string, Value: unknown, DataType?: string): Obj => ({ AttributeId, Value, ...(DataType ? { DataType } : {}) });
function request(subject: string, resource: string, type: string, action: string, environment: Obj[] = [], subjectType?: string): Obj {
  return { Request: {
    AccessSubject: { Attribute: [attr(ATTRIBUTE.subjectId, subject), ...(subjectType ? [attr(ATTRIBUTE.subjectType, subjectType)] : [])] },
    Resource: { Attribute: [attr(ATTRIBUTE.resourceId, resource), attr(ATTRIBUTE.resourceType, type)] },
    Action: { Attribute: attr(ATTRIBUTE.actionId, action) },
    ...(environment.length ? { Environment: { Attribute: environment } } : {}),
  } };
}
const ok = (r: Result): void => assert.equal(r.Status.StatusCode.Value, STATUS.ok);
const obligation = (r: Result, id: string): string[] | undefined => r.Obligations?.find((o) => o.Id === id)?.AttributeAssignment.map((a) => a.Value);
const advice = (r: Result, id: string): { AttributeId: string; Value: string }[] => r.AssociatedAdvice?.find((a) => a.Id === id)?.AttributeAssignment ?? [];
const decisions = (f: Fixture): Obj[] => f.rt.audit.records().filter((r) => r.type === 'decision').map(({ seq: _s, hash: _h, prevHash: _p, ...rest }) => rest);

test('XACML endpoint authenticates the PEP like /access routes and refuses other methods and media types', async (t) => {
  const f = fixture(t); const h = route(f);
  const body = request('bob', 'CASE-14', 'case', 'read');
  assert.equal((await send(h, '/xacml/v3/authorize', body, {})).status, 401);
  assert.equal((await send(h, '/xacml/v3/authorize', body, { authorization: 'Bearer wrong' })).status, 401);
  assert.equal((await send(h, '/xacml/v3/authorize', body, { ...pep(f), 'content-type': 'text/plain' })).status, 415);
  assert.equal((await send(h, '/xacml/v3/authorize', '', pep(f), 'GET')).status, 404);
  assert.equal(decisions(f).length, 0, 'nothing decided without an authenticated PEP');
  const accepted = await send(h, '/xacml/v3/authorize', body, { ...pep(f), 'content-type': 'application/json' });
  assert.equal(accepted.status, 200); assert.match(accepted.type, /^application\/xacml\+json/);
});

test('category mapping: subject, resource, action and environment reach the same decision and audit row as AuthZEN', async (t) => {
  const f = fixture(t); const h = route(f);
  const trusted = [attr(ATTRIBUTE.network, 'trusted')];
  // network: alice reads CASE-7 only from a trusted network, and not at session level 1
  assert.equal((await send(h, '/xacml/v3/authorize', request('alice', 'CASE-7', 'case', 'read'), pep(f))).results[0]?.Decision, 'Deny');
  const permit = (await send(h, '/xacml/v3/authorize', request('alice', 'CASE-7', 'case', 'read', trusted), pep(f))).results[0]!;
  assert.equal(permit.Decision, 'Permit'); ok(permit);
  const level = await send(h, '/xacml/v3/authorize', request('alice', 'CASE-7', 'case', 'read', [...trusted, attr(ATTRIBUTE.sessionLevel, 1, 'integer')]), pep(f));
  assert.equal(level.results[0]?.Decision, 'Deny');
  assert.ok(advice(level.results[0]!, ADVICE.basis).some((a) => a.Value === 'BLP.NO_READ_UP'));
  // subject type: the agent is found only under its own type
  assert.equal((await send(h, '/xacml/v3/authorize', request('assistant-1', 'CASE-14', 'case', 'read', trusted, 'agent'), pep(f))).results[0]?.Decision, 'Permit');
  assert.equal((await send(h, '/xacml/v3/authorize', request('assistant-1', 'CASE-14', 'case', 'read', trusted), pep(f))).results[0]?.Decision, 'Deny');
  // the Category array form with full category URNs, and anyURI identifiers
  const longForm = { Request: { Category: [
    { CategoryId: CATEGORY.subject, Attribute: [attr(ATTRIBUTE.subjectId, 'bob', 'http://www.w3.org/2001/XMLSchema#string')] },
    { CategoryId: CATEGORY.resource, Attribute: [attr(ATTRIBUTE.resourceId, 'CASE-14', 'anyURI'), attr(ATTRIBUTE.resourceType, 'case')] },
    { CategoryId: 'action', Attribute: [attr(ATTRIBUTE.actionId, 'read')] },
    { CategoryId: CATEGORY.environment, Attribute: [attr(ATTRIBUTE.network, 'trusted'), attr('urn:oasis:names:tc:xacml:1.0:environment:current-dateTime', '2030-01-01T00:00:00Z', 'dateTime')] },
    { CategoryId: 'urn:example:custom', Attribute: [attr('urn:example:role', 'admin')] },
  ] } };
  assert.equal((await send(h, '/xacml/v3/authorize', longForm, pep(f))).results[0]?.Decision, 'Permit');
  // explicit compatibility mode: prior actions and maker id match the equivalent AuthZEN context and audit row
  f.rt.sodHistory = 'caller';
  const env = [attr(ATTRIBUTE.makerId, 'grace'), attr(ATTRIBUTE.priorAction, ['create'])];
  const viaXacml = await send(h, '/xacml/v3/authorize', request('henry', 'PAY-3', 'payment', 'approve', env), pep(f));
  const before = decisions(f).length;
  const authzen = await sendAuthzen(h, f, { ...evaluation('henry', 'PAY-3', 'approve'), context: { makerId: 'grace', priorActions: ['create'] } });
  assert.equal(viaXacml.results[0]?.Decision, 'Deny'); assert.equal(authzen.decision, false);
  assert.ok(advice(viaXacml.results[0]!, ADVICE.basis).some((a) => a.Value === 'SOD.create-vs-approve'), 'prior-action reached the SoD check');
  const rows = decisions(f);
  assert.equal(rows.length, before + 1);
  assert.deepEqual(rows.at(-2), rows.at(-1), 'XACML and AuthZEN append the same decision record');
});
test('SOD_HISTORY=server and resource ownership hold for XACML as for /access: caller maker, history and owner claims are ignored', async (t) => {
  const f = fixture(t); const h = route(f);
  f.rt.sodHistory = 'caller';
  const claim = [attr(ATTRIBUTE.makerId, 'grace')];
  const approve = async (environment: Obj[]): Promise<Result> => (await send(h, '/xacml/v3/authorize', request('henry', 'PAY-3', 'payment', 'approve', environment), pep(f))).results[0]!;
  assert.equal((await approve(claim)).Decision, 'Permit', 'SOD_HISTORY=caller: the claimed maker is believed');
  f.rt.sodHistory = 'server';
  const refused = await approve([...claim, attr(ATTRIBUTE.priorAction, ['create'])]);
  assert.equal(refused.Decision, 'Deny');
  const basis = advice(refused, ADVICE.basis).map((a) => a.Value);
  assert.ok(basis.includes('SOD.MAKER_UNKNOWN'), basis.join(', '));
  assert.ok(!basis.includes('SOD.create-vs-approve'), 'the claimed prior action is ignored too');
  assert.equal((await sendAuthzen(h, f, { ...evaluation('henry', 'PAY-3', 'approve'), context: { makerId: 'grace' } })).decision, false, 'same answer as /access');
  // the owner is the stored one: an owner attribute in the request is not an input
  const owned = request('bob', 'CASE-14', 'case', 'read', [attr(ATTRIBUTE.network, 'trusted')]);
  const claimed = structuredClone(owned) as { Request: { Resource: { Attribute: Obj[] } } };
  claimed.Request.Resource.Attribute.push(attr('urn:qadamar:1.0:resource:owner', 'bob'));
  assert.equal((await send(h, '/xacml/v3/authorize', claimed, pep(f))).results[0]?.Decision, (await send(h, '/xacml/v3/authorize', owned, pep(f))).results[0]?.Decision);
});
async function sendAuthzen(h: Handler, f: Fixture, b: Obj): Promise<{ decision: boolean }> {
  return (await send(h, '/access/v1/evaluation', b, { ...pep(f), 'content-type': 'application/json' })).data as { decision: boolean };
}

test('decision values: Permit with obligations and advice, Deny, fail-closed Deny, NotApplicable, Indeterminate', async (t) => {
  const f = fixture(t); const h = route(f);
  const trusted = [attr(ATTRIBUTE.network, 'trusted')];
  const permit = (await send(h, '/xacml/v3/authorize', request('bob', 'CASE-14', 'case', 'read', trusted), pep(f))).results[0]!;
  assert.equal(permit.Decision, 'Permit');
  assert.deepEqual(obligation(permit, OBLIGATION.redact), ['informant_name']);
  assert.deepEqual(obligation(permit, OBLIGATION.mask), ['finance.amount']);
  assert.equal(permit.Obligations?.find((o) => o.Id === OBLIGATION.mask)?.AttributeAssignment[0]?.AttributeId, `${OBLIGATION.mask}:content-class`);
  assert.ok(advice(permit, ADVICE.basis).some((a) => a.AttributeId === `${ADVICE.basis}:policy-version` && a.Value.startsWith('pv.')));
  const notify = (await send(h, '/xacml/v3/authorize', request('dan', 'CASE-12', 'case', 'read', trusted), pep(f))).results[0]!;
  assert.deepEqual(obligation(notify, OBLIGATION.notify), ['security-officer']);
  const certified = (await send(h, '/xacml/v3/authorize', request('alice', 'CASE-7', 'case', 'close', trusted), pep(f))).results[0]!;
  assert.match(obligation(certified, OBLIGATION.decisionToken)?.[0] ?? '', /^[\w-]+\.[\w-]+\.[\w-]+$/, 'certified command carries its single-use JWS');

  const deny = (await send(h, '/xacml/v3/authorize', request('bob', 'CASE-7', 'case', 'read', trusted), pep(f))).results[0]!;
  assert.equal(deny.Decision, 'Deny'); ok(deny); assert.equal(deny.Obligations, undefined, 'a Deny releases nothing');
  const unknown = (await send(h, '/xacml/v3/authorize', request('nobody', 'CASE-7', 'case', 'read'), pep(f))).results[0]!;
  assert.equal(unknown.Decision, 'Deny'); assert.ok(advice(unknown, ADVICE.basis).some((a) => a.Value === 'CORE.UNKNOWN_ID'));
  const notApplicable = (await send(h, '/xacml/v3/authorize', request('bob', 'CASE-14', 'case', 'teleport', trusted), pep(f))).results[0]!;
  assert.equal(notApplicable.Decision, 'NotApplicable'); ok(notApplicable);

  const missing = (await send(h, '/xacml/v3/authorize', { Request: { AccessSubject: { Attribute: [attr(ATTRIBUTE.subjectId, 'bob')] }, Resource: { Attribute: [attr(ATTRIBUTE.resourceId, 'CASE-14')] } } }, pep(f))).results[0]!;
  assert.equal(missing.Decision, 'Indeterminate'); assert.equal(missing.Status.StatusCode.Value, STATUS.missing);
  assert.deepEqual(missing.Status.StatusDetail?.MissingAttributeDetail.map((m) => m.AttributeId), [ATTRIBUTE.resourceType, ATTRIBUTE.actionId]);
  const audited = decisions(f);
  assert.equal(audited.length, 7, 'one audit row per Permit, Deny, NotApplicable and Indeterminate');
  const { ts: _ts, ...last } = audited.at(-1)!;
  assert.deepEqual(last, { type: 'decision', actor: 'pep', action: 'xacml', effect: 'deny', rules: ['XACML.INDETERMINATE'],
    details: { status: 'missing', reason: 'Required attributes are missing', missing: [ATTRIBUTE.resourceType, ATTRIBUTE.actionId] } });
});

test('malformed input is Indeterminate with a syntax-error or processing-error status and decides nothing', async (t) => {
  const f = fixture(t); const h = route(f);
  const base = request('bob', 'CASE-14', 'case', 'read') as { Request: Obj };
  const cases: Array<[unknown, string]> = [
    ['{not json', STATUS.syntax], [[1, 2], STATUS.syntax], [{}, STATUS.syntax], [{ Request: [] }, STATUS.syntax],
    [{ Request: { ...base.Request, Environment: { Attribute: [attr(ATTRIBUTE.sessionLevel, '2')] } } }, STATUS.syntax],
    [{ Request: { ...base.Request, Environment: { Attribute: [attr(ATTRIBUTE.sessionLevel, 7)] } } }, STATUS.syntax],
    [{ Request: { ...base.Request, Environment: { Attribute: [attr(ATTRIBUTE.network, 'somewhere')] } } }, STATUS.syntax],
    [{ Request: { ...base.Request, AccessSubject: { Attribute: [attr(ATTRIBUTE.subjectId, ['bob', 'alice'])] } } }, STATUS.syntax],
    [{ Request: { ...base.Request, AccessSubject: [base.Request.AccessSubject, base.Request.AccessSubject] } }, STATUS.syntax],
    [{ Request: { ...base.Request, Resource: { Attribute: [{ AttributeId: ATTRIBUTE.resourceId }] } } }, STATUS.syntax],
    [{ Request: { ...base.Request, Action: { Attribute: [attr(ATTRIBUTE.actionId, 3)] } } }, STATUS.syntax],
    [{ Request: { ...base.Request, Category: [{ Attribute: [] }] } }, STATUS.syntax],
    [{ Request: { ...base.Request, ReturnPolicyIdList: 'yes' } }, STATUS.syntax],
    [{ Request: { ...base.Request, CombinedDecision: true } }, STATUS.processing],
  ];
  for (const [payload, status] of cases) {
    const answer = await send(h, '/xacml/v3/authorize', payload, pep(f));
    assert.equal(answer.status, 200);
    assert.equal(answer.results.length, 1);
    assert.equal(answer.results[0]?.Decision, 'Indeterminate', JSON.stringify(payload));
    assert.equal(answer.results[0]?.Status.StatusCode.Value, status, JSON.stringify(payload));
  }
  const rows = decisions(f);
  assert.equal(rows.length, cases.length, 'every Indeterminate is audited as a deny');
  assert.ok(rows.every((r) => r.effect === 'deny' && JSON.stringify(r.rules) === '["XACML.INDETERMINATE"]' && typeof (r.details as Obj).reason === 'string'));
  assert.equal((rows.at(-1)?.details as Obj).status, 'processing');
});

test('a Permit with an obligation the mapping cannot express is recorded as a deny without a decision token', (t) => {
  const f = fixture(t);
  f.rt.sodHistory = 'caller';
  const known = { redact: [], maskClasses: [], notify: [], decisionToken: { ttlSeconds: 15, resourceVersion: 4 } };
  assert.equal(unexpressible({ obligations: known }), undefined);
  assert.equal(unexpressible({ obligations: { ...known, watermark: ['viewer'] } as never })?.rule, 'XACML.OBLIGATION_UNEXPRESSIBLE');
  // the veto turns the engine's permit (a certified approve, which would carry a token) into an audited deny
  const vetoed = authzen(f.rt, { subject: { type: 'user', id: 'henry' }, action: { name: 'approve' }, resource: { type: 'payment', id: 'PAY-3' },
    context: { network: 'trusted', makerId: 'grace' } }, (d) => unexpressible({ obligations: { ...d.obligations, watermark: ['viewer'] } as never })) as
    { decision: boolean; context: { rules: string[]; decision_token?: string } };
  assert.equal(vetoed.decision, false);
  assert.deepEqual(vetoed.context.rules, ['XACML.OBLIGATION_UNEXPRESSIBLE']);
  assert.equal(vetoed.context.decision_token, undefined, 'no token is issued');
  const row = decisions(f).at(-1);
  assert.equal(row?.effect, 'deny');
  assert.deepEqual(row?.rules, ['XACML.OBLIGATION_UNEXPRESSIBLE']);
});

test('MultiRequests: one result per reference, shared categories, per-request errors, limits and rate cost', async (t) => {
  const f = fixture(t); const h = route(f);
  const multi = { Request: {
    ReturnPolicyIdList: true,
    AccessSubject: [{ Id: 'bob', Attribute: [attr(ATTRIBUTE.subjectId, 'bob')] }, { Id: 'alice', Attribute: [attr(ATTRIBUTE.subjectId, 'alice')] }],
    Resource: [{ Id: 'c14', Attribute: [attr(ATTRIBUTE.resourceId, 'CASE-14'), attr(ATTRIBUTE.resourceType, 'case')] },
      { Id: 'c7', Attribute: [attr(ATTRIBUTE.resourceId, 'CASE-7'), attr(ATTRIBUTE.resourceType, 'case')] }],
    Action: { Id: 'read', Attribute: [attr(ATTRIBUTE.actionId, 'read')] },
    Environment: { Attribute: [attr(ATTRIBUTE.network, 'trusted')] },
    MultiRequests: { RequestReference: [{ ReferenceId: ['bob', 'c14', 'read'] }, { ReferenceId: ['bob', 'c7', 'read'] },
      { ReferenceId: ['alice', 'c7', 'read'] }, { ReferenceId: ['alice', 'nowhere', 'read'] }, { ReferenceId: ['bob', 'alice', 'c7', 'read'] }] },
  } };
  const answer = await send(h, '/xacml/v3/authorize', multi, pep(f));
  assert.deepEqual(answer.results.map((r) => r.Decision), ['Permit', 'Deny', 'Permit', 'Indeterminate', 'Indeterminate']);
  assert.deepEqual(answer.results[2]?.PolicyIdentifierList?.PolicyIdReference.map((p) => p.Id), ['RBAC.viewer', 'NTK.knows']);
  assert.equal(answer.results[3]?.Status.StatusCode.Value, STATUS.syntax);
  assert.equal(decisions(f).length, 5, 'each individual request is audited once, Indeterminate ones as denials');

  const tooMany = { Request: { ...multi.Request, MultiRequests: { RequestReference: Array.from({ length: XACML_MAX_REQUESTS + 1 }, () => ({ ReferenceId: ['bob', 'c14', 'read'] })) } } };
  const refused = await send(route(f, 5000), '/xacml/v3/authorize', tooMany, pep(f));
  assert.deepEqual(refused.results.map((r) => r.Decision), ['Indeterminate']);
  const duplicate = { Request: { ...multi.Request, Action: [{ Id: 'bob', Attribute: [attr(ATTRIBUTE.actionId, 'read')] }] } };
  assert.equal((await send(h, '/xacml/v3/authorize', duplicate, pep(f))).results[0]?.Status.StatusCode.Value, STATUS.syntax);
  assert.equal(decisions(f).length, 7);

  // one rate-limit token per individual request, as for /access/v1/evaluations
  const limited = route(f, 4);
  const throttled = await send(limited, '/xacml/v3/authorize', multi, pep(f));
  assert.equal(throttled.status, 429); assert.ok(throttled.type.startsWith('application/json'));
  assert.equal(decisions(f).length, 7);
});
