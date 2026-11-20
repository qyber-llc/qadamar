import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical, contentRules, obligationLoss, policyVersion, procedureFingerprint } from '../../core/src/index.ts';
import type { AbacContentRule, Context, Decision, Impact, PolicyBundle, Subject } from '../../core/src/index.ts';
import { candidate, decideChange, impact, propose } from '../src/admin/changes.ts';
import { HttpError } from '../src/http.ts';
import { decide } from '../src/runtime.ts';
import type { Runtime } from '../src/runtime.ts';
import { pdp } from '../src/pdp.ts';
import { Store, type Backing, type Disk, type State } from '../src/store.ts';
import { applyResourcesInPlace } from '../src/resource-registry.ts';
import { withRecordDeltas } from '../src/record-deltas.ts';
import { mkdtempSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { evaluation, fixture, required, users, WHY } from './helpers.ts';

type ChangeKind = 'add_tuple' | 'remove_tuple' | 'update_subject' | 'update_resource' | 'publish_policy' | 'scim_subjects' | 'register_resources' | 'certify_tp';

const kinds: readonly ChangeKind[] = ['add_tuple', 'remove_tuple', 'update_subject', 'update_resource', 'publish_policy', 'scim_subjects', 'register_resources', 'certify_tp'];
const grantPayload = (): Record<string, unknown> => ({
  object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id: 'bob' }, validTo: '2026-12-08T10:00:00Z',
});

const cellKey = (subject: Subject, resource: State['resources'][number], action: string): string =>
  JSON.stringify([subject.type, subject.id, resource.type, resource.id, action]);

type ReferenceCell = { allowed: boolean; rules: readonly string[]; pv: string; obligations: Decision['obligations']; trace: Decision['trace'] };
function referenceWorld(rt: Runtime, state: State, context: Context): Map<string, ReferenceCell> {
  const out = new Map<string, ReferenceCell>();
  for (const subject of state.subjects) for (const resource of state.resources) {
    for (const action of Object.keys(state.bundle.schema.resourceTypes[resource.type]?.actions ?? {})) {
      const result = decide(rt, subject, resource, action, context, 'impact-reference', state, false);
      out.set(cellKey(subject, resource, action), { allowed: result.decision, rules: result.rules, pv: result.policyVersion, obligations: result.obligations, trace: result.trace });
    }
  }
  return out;
}

function referenceVariant(rt: Runtime, before: State, after: State, context: Context): Impact {
  const b = referenceWorld(rt, before, context);
  const a = referenceWorld(rt, after, context);
  const gained: Impact['gained'][number][] = [];
  const lost: Impact['lost'][number][] = [];
  const obligationsLost: Impact['obligationsLost'][number][] = [];
  const obligationsGained: Impact['obligationsGained'][number][] = [];
  const keys = new Set([...b.keys(), ...a.keys()]);
  for (const key of keys) {
    const was = b.get(key); const now = a.get(key);
    const [subjectType, subject, resourceType, resource, action] = JSON.parse(key) as string[];
    const base = { subjectType, subject, resourceType, resource, action } as Omit<Impact['gained'][number], 'rules'>;
    if (now?.allowed && !was?.allowed) gained.push({ ...base, rules: was?.rules ?? ['ABSENT'] });
    if (was?.allowed && !now?.allowed) lost.push({ ...base, rules: now?.rules ?? ['ABSENT'] });
    if (was?.allowed && now?.allowed) {
      const less = obligationLoss(was, now); const more = obligationLoss(now, was);
      if (less) obligationsLost.push({ ...base, ...less });
      if (more) obligationsGained.push({ ...base, ...more });
    }
  }
  const order = (x: Impact['gained'][number], y: Impact['gained'][number]) => `${x.subject}${x.resource}${x.action}`.localeCompare(`${y.subject}${y.resource}${y.action}`);
  return { evaluated: keys.size, gained: gained.sort(order), lost: lost.sort(order),
    obligationsLost: obligationsLost.sort(order), obligationsGained: obligationsGained.sort(order),
    policyVersionBefore: [...b.values()][0]?.pv ?? '', policyVersionAfter: [...a.values()][0]?.pv ?? '' };
}

function referenceImpact(rt: Runtime, after: State): Impact {
  const before = rt.store.state;
  const variants: Impact[] = [];
  const ids = [...new Set([...before.subjects.map((s) => s.id), ...after.subjects.map((s) => s.id)])];
  let independent = 'impact-independent-maker';
  while (ids.includes(independent)) independent += '-';
  for (const network of ['trusted', 'untrusted'] as const) for (const makerId of [undefined, independent, ...ids]) {
    variants.push(referenceVariant(rt, before, after, { network, now: rt.now(), ...(makerId === undefined ? {} : { makerId }) }));
  }
  const first = variants[0]!;
  const unique = <T>(rows: readonly T[]): T[] => [...new Map(rows.map((r) => [canonical(r), r])).values()];
  return { ...first, evaluated: variants.reduce((n, x) => n + x.evaluated, 0), gained: unique(variants.flatMap((x) => x.gained)), lost: unique(variants.flatMap((x) => x.lost)),
    obligationsLost: unique(variants.flatMap((x) => x.obligationsLost)), obligationsGained: unique(variants.flatMap((x) => x.obligationsGained)) };
}

function assertMatchesReference(rt: Runtime, after: State, label: string): void {
  const auditRows = rt.audit.records().length; const decisions = rt.decisions;
  const expected = referenceImpact(rt, after);
  const actual = impact(rt, after, Number.MAX_SAFE_INTEGER);
  const withoutCount = ({ evaluated: _evaluated, analysis: _analysis, ...delta }: Impact) => delta;
  assert.deepEqual(withoutCount(actual), withoutCount(expected), label);
  assert.ok(actual.evaluated < expected.evaluated,
    `${label}: optimized evaluated count ${actual.evaluated} must be below reference count ${expected.evaluated}`);
  assert.equal(rt.audit.records().length, auditRows, `${label}: comparison writes no audit rows`);
  assert.equal(rt.decisions, decisions, `${label}: comparison writes no decision rows`);
}

function seeded(seed: number): () => number {
  return () => {
    seed = (seed + 0x6D2B79F5) | 0;
    let value = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function randomCandidate(rt: Runtime, kind: ChangeKind, random: () => number, covered = new Set<string>(), variant = 0) {
  const before = rt.store.state;
  const integer = (limit: number): number => Math.floor(random() * limit);
  const pick = <T>(values: readonly T[]): T => required(values[integer(values.length)]);
  const compartments = (): string[] => before.bundle.schema.compartments.filter(() => random() < 0.5);

  if (kind === 'add_tuple') {
    const resource = pick(before.resources.filter((r) => r.type === 'case'));
    const person = pick(before.subjects.filter((s) => s.type === 'user'));
    const folder = required(before.resources.find((r) => r.type === 'folder'));
    const agent = required(before.subjects.find((s) => s.type === 'agent'));
    const shapes = ['allocated', 'granted', 'userset', 'parent', 'manager', 'delegate', 'team-member', 'folder-member'] as const;
    const shape = shapes[variant % shapes.length]!;
    covered.add(`add:${shape}`);
    const payload: Record<string, unknown> = { validTo: '2026-12-08T10:00:00Z' };
    if (shape === 'userset') Object.assign(payload, { object: { type: 'case', id: resource.id }, relation: 'member', subject: { type: 'team', id: 'orchid' }, subjectRelation: 'member' });
    else if (shape === 'parent') Object.assign(payload, { object: { type: 'case', id: resource.id }, relation: 'parent', subject: { type: folder.type, id: folder.id } });
    else if (shape === 'manager') Object.assign(payload, { object: { type: 'user', id: person.id }, relation: 'manager', subject: { type: 'user', id: pick(before.subjects.filter((s) => s.type === 'user')).id } });
    else if (shape === 'delegate') Object.assign(payload, { object: { type: 'case', id: resource.id }, relation: 'delegate', subject: { type: agent.type, id: agent.id } });
    else if (shape === 'team-member') Object.assign(payload, { object: { type: 'team', id: 'orchid' }, relation: 'member', subject: { type: person.type, id: person.id } });
    else if (shape === 'folder-member') Object.assign(payload, { object: { type: folder.type, id: folder.id }, relation: 'member', subject: { type: person.type, id: person.id } });
    else Object.assign(payload, { object: { type: 'case', id: resource.id }, relation: shape, subject: { type: person.type, id: person.id } });
    return candidate(rt, users.amira, kind, payload);
  }
  if (kind === 'remove_tuple') {
    const tuples = before.tuples.filter((t) => !t.breakGlass);
    const tuple = required(tuples[variant % tuples.length]);
    covered.add(`remove:${tuple.relation}${tuple.subjectRelation ? '-userset' : ''}`);
    return candidate(rt, users.amira, kind, { tupleId: tuple.id });
  }
  if (kind === 'update_subject') {
    const subject = pick(before.subjects);
    const patches: Record<string, unknown>[] = [
      { active: !subject.active }, { clearance: integer(4) }, { compartments: compartments() }, { roles: [pick(Object.keys(before.bundle.rbac.roles))] },
    ];
    const names = ['active', 'clearance', 'compartments', 'roles'];
    covered.add(`subject:${names[variant % names.length]}`);
    return candidate(rt, users.amira, kind, { id: subject.id, set: patches[variant % patches.length] });
  }
  if (kind === 'update_resource') {
    const resource = pick(before.resources);
    const patches: Record<string, unknown>[] = [
      { integrity: pick(['derived', 'extracted', 'system', 'verified'] as const) }, { compartments: compartments() },
    ];
    const names = ['integrity', 'compartments'];
    const isParent = before.resources.some((r) => r.parent?.type === resource.type && r.parent.id === resource.id);
    if (!resource.parent && !isParent) { patches.push({ level: integer(4) }); names.push('level'); }
    covered.add(`resource:${names[variant % names.length]}`);
    return candidate(rt, users.amira, kind, { id: resource.id, set: patches[variant % patches.length] });
  }
  if (kind === 'scim_subjects') {
    const old = pick(before.subjects.filter((s) => s.type === 'user'));
    const names = ['active', 'roles', 'name', 'scimUserName', 'scimExternalId', 'scimDisplayName', 'new-subject'];
    const shape = names[variant % names.length]!; covered.add(`scim:${shape}`);
    let next: Subject;
    if (shape === 'new-subject') next = { ...old, id: `scim-fuzz-${variant}`, active: true, roles: [], clearance: 0, compartments: [], attrs: { name: `SCIM ${variant}` } };
    else if (shape === 'active') next = { ...old, active: !old.active };
    else if (shape === 'roles') next = { ...old, roles: [pick(Object.keys(before.bundle.rbac.roles))] };
    else next = { ...old, attrs: { ...old.attrs, [shape]: `SCIM ${integer(1_000_000)}` } };
    return candidate(rt, { id: 'scim', name: 'scim', roles: ['scim_provisioner'] }, kind, { subjects: [next] });
  }
  if (kind === 'register_resources') {
    const registrar = { id: 'registrar', name: 'registrar', roles: ['resource_registrar'] };
    const shapes = ['compartments', 'integrity', 'owner', 'content', 'attrs', 'new', 'retire', 'level'];
    const shape = shapes[variant % shapes.length]!; covered.add(`registration:${shape}`);
    const old = pick(before.resources.filter((r) => r.type === 'case' && (shape !== 'retire' || !before.resources.some((child) => child.parent?.id === r.id && child.parent.type === r.type))));
    if (shape === 'new') {
      const next = { ...old, id: `CASE-FUZZ-${variant}`, level: 1 as const, compartments: [], contentClasses: [], version: 1, attrs: { ...old.attrs, status: 'open' } };
      return candidate(rt, registrar, kind, { resources: [next], basis: ['new'] });
    }
    if (shape === 'retire') return candidate(rt, registrar, kind, { resources: [], basis: [], retire: [{ type: old.type, id: old.id }], retireBasis: [`live:${old.version ?? 0}`] });
    let next = { ...old, version: (old.version ?? 0) + 1 };
    if (shape === 'compartments') next = { ...next, compartments: compartments() };
    else if (shape === 'integrity') next = { ...next, integrity: pick(['derived', 'extracted', 'system', 'verified'] as const) };
    else if (shape === 'owner') next = { ...next, owner: pick(before.subjects).id };
    else if (shape === 'content') next = { ...next, contentClasses: pick([[], ['finance.amount'], ['pii.iban']]) };
    else if (shape === 'attrs') next = { ...next, attrs: { ...old.attrs, status: old.attrs?.status === 'closed' ? 'open' : 'closed' } };
    else if (shape === 'level') {
      const parentLevel = old.parent ? before.resources.find((r) => r.id === old.parent?.id && r.type === old.parent?.type)?.level ?? 0 : 0;
      const childLevels = before.resources.filter((r) => r.parent?.id === old.id && r.parent.type === old.type).map((r) => r.level);
      const high = childLevels.length ? Math.min(...childLevels) : 3;
      next = { ...next, level: (parentLevel === high ? parentLevel : parentLevel + 1 + integer(high - parentLevel)) as Subject['clearance'] };
    }
    return candidate(rt, registrar, kind, { resources: [next], basis: [`live:${old.version ?? 0}`] });
  }
  if (kind === 'certify_tp') {
    const action = ['create', 'approve', 'release'][variant % 3]!; covered.add(`certify:${action}`);
    const record = { resourceType: 'payment', action, certifiedBy: 'lina', approvedBy: 'omar', certifiedAt: rt.now(),
      policyVersion: policyVersion(before.bundle), changeId: `fuzz-certification-${variant}`, reason: WHY,
      fingerprint: procedureFingerprint(before.bundle, 'payment', action) };
    return { state: { ...before, certifications: [...(before.certifications ?? []), record] }, payload: { resourceType: 'payment', action } };
  }

  let bundle = before.bundle;
  const choice = variant % 16;
  const labels = ['name', 'abac', 'needToKnow', 'abac-content', 'mandatory', 'token-obligation', 'sod', 'rbac', 'action', 'relations',
    'requireCertification', 'requirePepBinding', 'ivp', 'inputValidator', 'obligations', 'abac-content-actions'];
  covered.add(`policy:${labels[choice]}`);
  switch (choice) {
    case 0: bundle = { ...bundle, name: `seeded-policy-${integer(1_000_000)}` }; break;
    case 1: bundle = { ...bundle, abac: bundle.abac.filter((r) => r.id !== pick(bundle.abac).id) }; break;
    case 2: bundle = { ...bundle, needToKnow: { ...bundle.needToKnow, mode: bundle.needToKnow.mode === 'off' ? 'enforce' : 'off' } }; break;
    case 3: bundle = { ...bundle, abacContent: contentRules(bundle).filter((r) => r.id !== pick(contentRules(bundle)).id) }; break;
    case 4: bundle = { ...bundle, mandatory: { ...bundle.mandatory, untrustedNetworkMaxLevel: bundle.mandatory.untrustedNetworkMaxLevel === 2 ? 1 : 2 } }; break;
    case 5: bundle = { ...bundle, clarkWilson: { ...bundle.clarkWilson, tokenTtlSeconds: bundle.clarkWilson.tokenTtlSeconds + 1 } }; break;
    case 6: bundle = { ...bundle, sod: bundle.sod.filter((r) => r.id !== pick(bundle.sod).id) }; break;
    case 7: {
      const viewer = required(bundle.rbac.roles.viewer);
      bundle = { ...bundle, rbac: { ...bundle.rbac, roles: { ...bundle.rbac.roles, viewer: { ...viewer, grants: viewer.grants.filter((g) => g.resourceType !== 'folder') } } } };
      break;
    }
    case 8: {
      const approve = required(bundle.schema.resourceTypes.payment?.actions.approve);
      bundle = { ...bundle, schema: { ...bundle.schema, resourceTypes: { ...bundle.schema.resourceTypes, payment: { ...bundle.schema.resourceTypes.payment,
        actions: { ...bundle.schema.resourceTypes.payment?.actions, approve: { ...approve, requiresSecondPerson: !approve.requiresSecondPerson } } } } } };
      break;
    }
    case 9: {
      const direct = required(bundle.schema.resourceTypes.case?.relations?.direct_knows);
      bundle = { ...bundle, schema: { ...bundle.schema, resourceTypes: { ...bundle.schema.resourceTypes, case: { ...required(bundle.schema.resourceTypes.case),
        relations: { ...bundle.schema.resourceTypes.case?.relations, direct_knows: { union: direct.union.filter((r) => !('computed' in r && r.computed === 'allocated')) } } } } } };
      break;
    }
    case 10: bundle = { ...bundle, clarkWilson: { ...bundle.clarkWilson, requireCertification: bundle.clarkWilson.requireCertification?.length ? [] : ['payment'] } }; break;
    case 11: bundle = { ...bundle, clarkWilson: { ...bundle.clarkWilson, requirePepBinding: bundle.clarkWilson.requirePepBinding?.length ? [] : ['payment'] } }; break;
    case 12: bundle = { ...bundle, clarkWilson: { ...bundle.clarkWilson, ivps: [...(bundle.clarkWilson.ivps ?? []), {
      id: 'fuzz-ivp', description: 'fuzz integrity', resourceTypes: ['payment'],
      check: { op: 'eq' as const, left: { path: 'resource.integrity' }, right: { value: 'verified' } },
    }] } }; break;
    case 13: bundle = { ...bundle, clarkWilson: { ...bundle.clarkWilson, inputValidators: [...(bundle.clarkWilson.inputValidators ?? []), {
      id: 'fuzz-input', description: 'fuzz input', resourceTypes: ['payment'], actions: ['create'], fields: { reason: { type: 'string' as const, required: true } },
    }] } }; break;
    case 14: {
      const obligations = pick([{ redact: ['informant_name'] }, { notify: ['dpo'] }, { fieldAllowlist: ['id', 'title'] }]);
      bundle = { ...bundle, abac: [...bundle.abac, { id: 'fuzz-obligation', description: 'fuzz obligation', effect: 'obligation' as const,
        resourceTypes: ['case'], actions: ['read'], when: { op: 'true' as const }, obligations }] };
      break;
    }
    default: bundle = { ...bundle, abacContent: contentRules(bundle).map((rule) => rule.id === 'finance-mask' ? { ...rule, actions: ['read'] } : rule) };
  }
  return candidate(rt, users.amira, kind, { bundle });
}

interface Evaluation { decision: boolean; context: { rules: string[]; decision_token?: string } }

function preparePayment(rt: Runtime, id: string, delegate = false): void {
  const payment = required(rt.store.state.resources.find((r) => r.id === 'PAY-3'));
  const alice = required(rt.store.state.subjects.find((s) => s.id === 'alice'));
  const roles = ['finance_clerk', 'finance_approver'];
  const subjects = rt.store.state.subjects.map((s) => s.id === 'alice' ? { ...s, clearance: 1 as const, roles } : s);
  if (delegate) subjects.push({ ...alice, type: 'agent', id: 'alice-delegate', clearance: 1, roles, attrs: { delegatedBy: 'alice' } });
  rt.store.state = { ...rt.store.state, subjects, resources: [...rt.store.state.resources, { ...payment, id, owner: 'alice' }] };
}

function consumeCreate(rt: Runtime, subject: { type: string; id: string }, resource: string): void {
  const created = pdp(rt, '/access/v1/evaluation', { ...evaluation(subject.id, resource, 'create'), subject }) as Evaluation;
  assert.equal(created.decision, true);
  const payment = required(rt.store.state.resources.find((r) => r.id === resource));
  assert.equal((pdp(rt, '/x/v1/tokens/consume', {
    token: required(created.context.decision_token), action: 'create', resource: { type: payment.type, id: resource }, resourceVersion: payment.version,
  }) as { ok: boolean }).ok, true);
}

function withoutCreateVsRelease(rt: Runtime): PolicyBundle {
  return { ...rt.store.state.bundle, sod: rt.store.state.bundle.sod.filter((rule) => rule.id !== 'create-vs-release') };
}

function release(rt: Runtime, subject: { type: string; id: string }, resource: string, state = rt.store.state) {
  return decide(rt, subject, { type: 'payment', id: resource }, 'release', { network: 'trusted', now: rt.now() }, 'impact-test', state, false);
}

test('impact includes consumed create history and approval rechecks the same authoritative preview', (t) => {
  const { rt } = fixture(t);
  preparePayment(rt, 'PAY-IMPACT');
  consumeCreate(rt, { type: 'user', id: 'alice' }, 'PAY-IMPACT');
  const before = release(rt, { type: 'user', id: 'alice' }, 'PAY-IMPACT');
  assert.equal(before.decision, false);
  assert.ok(before.rules.includes('SOD.create-vs-release'));

  const change = propose(rt, users.amira, { kind: 'publish_policy', payload: { bundle: withoutCreateVsRelease(rt) }, reason: WHY });
  const gained = change.impact.gained.find((row) => row.subjectType === 'user' && row.subject === 'alice'
    && row.resourceType === 'payment' && row.resource === 'PAY-IMPACT' && row.action === 'release');
  assert.ok(gained, 'alice gains release on the payment she created');
  assert.ok(gained.rules.includes('SOD.create-vs-release'));

  const approved = decideChange(rt, users.lina, change.id, true, { reason: WHY });
  assert.equal(approved.status, 'applied');
  assert.deepEqual(approved.impact, change.impact);
  assert.equal(release(rt, { type: 'user', id: 'alice' }, 'PAY-IMPACT').decision, true);
});

test('impact includes actions recorded for a delegate and the person acted for', (t) => {
  const { rt } = fixture(t);
  preparePayment(rt, 'PAY-DELEGATE', true);
  const alice = { type: 'user', id: 'alice' };
  const delegate = { type: 'agent', id: 'alice-delegate' };
  consumeCreate(rt, delegate, 'PAY-DELEGATE');
  assert.deepEqual(rt.store.performed[0]?.onBehalfOf, [alice]);
  assert.equal(release(rt, alice, 'PAY-DELEGATE').decision, false);
  assert.equal(release(rt, delegate, 'PAY-DELEGATE').decision, false);

  const after = candidate(rt, users.amira, 'publish_policy', { bundle: withoutCreateVsRelease(rt) }).state;
  const delta = impact(rt, after);
  for (const subject of [alice, delegate]) {
    assert.ok(delta.gained.some((row) => row.subjectType === subject.type && row.subject === subject.id
      && row.resourceType === 'payment' && row.resource === 'PAY-DELEGATE' && row.action === 'release'));
    assert.equal(release(rt, subject, 'PAY-DELEGATE', after).decision, true);
  }
  assertMatchesReference(rt, after, 'delegate history');
});

test('optimized impact exactly matches the full-grid reference on toy-domain changes', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state;
  const published = { ...before.bundle, abac: before.bundle.abac.filter((r) => r.id !== 'no-export-untrusted') };
  const changes: Array<{ kind: ChangeKind; payload: Record<string, unknown> }> = [
    { kind: 'add_tuple', payload: grantPayload() },
    { kind: 'remove_tuple', payload: { tupleId: 'seed-4' } },
    { kind: 'update_subject', payload: { id: 'bob', set: { roles: ['finance_approver'] } } },
    { kind: 'update_resource', payload: { id: 'CASE-11', set: { level: 2 } } },
    { kind: 'publish_policy', payload: { bundle: published } },
  ];
  for (const { kind, payload } of changes) {
    const after = candidate(rt, users.amira, kind, payload).state;
    assertMatchesReference(rt, after, `toy-domain ${kind}`);
  }
});

test('maker- and history-dependent policy expressions retain every contextual variant', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state;
  const bundle = { ...before.bundle, abac: [...before.bundle.abac, {
    id: 'maker-dependent-read', description: 'The named maker cannot read', effect: 'forbid' as const, actions: ['read'],
    when: { op: 'eq' as const, left: { path: 'context.makerId' }, right: { value: 'bob' } },
  }, {
    id: 'history-dependent-read', description: 'Prior create history cannot read', effect: 'forbid' as const, actions: ['read'],
    when: { op: 'contains' as const, left: { path: 'context.priorActions' }, right: { value: 'create' } },
  }] };
  const after = candidate(rt, users.amira, 'publish_policy', { bundle }).state;
  assertMatchesReference(rt, after, 'maker-dependent ABAC');
  assert.ok(impact(rt, after).lost.some((row) => row.subject === 'bob' && row.action === 'read'));
});

function impactFuzzRuns(): number {
  const raw = process.env.IMPACT_FUZZ_RUNS;
  if (raw === undefined) return 240;
  const runs = Number(raw);
  assert.ok(Number.isSafeInteger(runs) && runs >= 1 && runs <= 100_000, 'IMPACT_FUZZ_RUNS must be an integer in 1..100000');
  return runs;
}

test('optimized impact exactly matches the full-grid reference on seeded random changes', (t) => {
  const { rt } = fixture(t);
  const random = seeded(0xA1E21A); const covered = new Set<string>(); const runs = impactFuzzRuns();
  for (let index = 0; index < runs; index++) {
    const kind = kinds[index % kinds.length]!;
    const after = randomCandidate(rt, kind, random, covered, Math.floor(index / kinds.length)).state;
    assertMatchesReference(rt, after, `seeded case ${index} (${kind})`);
  }
  const expected = [
    ...['allocated', 'granted', 'userset', 'parent', 'manager', 'delegate', 'team-member', 'folder-member'].map((shape) => `add:${shape}`),
    ...['member-userset', 'parent', 'manager', 'delegate', 'allocated', 'granted', 'member'].map((shape) => `remove:${shape}`),
    ...['active', 'clearance', 'compartments', 'roles'].map((shape) => `subject:${shape}`),
    'resource:integrity', 'resource:compartments',
    ...['active', 'roles', 'name', 'scimUserName', 'scimExternalId', 'scimDisplayName', 'new-subject'].map((shape) => `scim:${shape}`),
    ...['compartments', 'integrity', 'owner', 'content', 'attrs', 'new', 'retire', 'level'].map((shape) => `registration:${shape}`),
    ...['create', 'approve', 'release'].map((shape) => `certify:${shape}`),
    ...['name', 'abac', 'needToKnow', 'abac-content', 'mandatory', 'token-obligation', 'sod', 'rbac', 'action', 'relations',
      'requireCertification', 'requirePepBinding', 'ivp', 'inputValidator', 'obligations', 'abac-content-actions'].map((shape) => `policy:${shape}`),
  ];
  if (runs >= 240) for (const shape of expected) assert.ok(covered.has(shape), `seeded generator did not cover ${shape}`);
});

test('impact and propose reject work above the configured evaluation limit', { concurrency: false }, (t) => {
  const { rt } = fixture(t);
  const after = candidate(rt, users.amira, 'add_tuple', grantPayload()).state;
  const splitChange = (error: unknown): boolean => {
    assert.ok(error instanceof HttpError);
    assert.equal(error.status, 422);
    assert.match(error.message, /split/i);
    assert.match(error.message, /change/i);
    return true;
  };

  const exact = impact(rt, after);
  assert.equal(exact.evaluated, 30);
  assert.deepEqual(exact.analysis, { affectedCells: 15, reasons: ['relation tuples changed'] });
  assert.equal(impact(rt, after, exact.evaluated).evaluated, exact.evaluated);
  assert.throws(() => impact(rt, after, exact.evaluated - 1), splitChange);
  assert.throws(() => impact(rt, after, 1), splitChange);

  const previous = process.env.IMPACT_MAX_EVALUATIONS;
  t.after(() => {
    if (previous === undefined) delete process.env.IMPACT_MAX_EVALUATIONS;
    else process.env.IMPACT_MAX_EVALUATIONS = previous;
  });
  process.env.IMPACT_MAX_EVALUATIONS = '1';
  assert.throws(() => impact(rt, after), splitChange);
  const pending = rt.store.changes.length;
  assert.throws(() => propose(rt, users.amira, { kind: 'add_tuple', reason: WHY, payload: grantPayload() }), splitChange);
  assert.equal(rt.store.changes.length, pending);
});

// ---------- KIMI-02 (pentest 2026-11-10): obligations are part of the impact ----------

const bobReadsCase14 = (row: Impact['obligationsLost'][number]): boolean =>
  row.subjectType === 'user' && row.subject === 'bob' && row.resourceType === 'case' && row.resource === 'CASE-14' && row.action === 'read';

test('KIMI-02: removing the finance mask from a still-allowed read broadens, and the preview says what is lost', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const bundle = { ...before, abacContent: contentRules(before).map((r) => r.id === 'finance-mask' ? { ...r, unless: { op: 'true' } } as AbacContentRule : r) };
  const change = propose(rt, users.amira, { kind: 'publish_policy', payload: { bundle }, reason: WHY });
  assert.equal(change.broadens, true);
  assert.deepEqual(change.impact.gained, []);
  const row = change.impact.obligationsLost.find(bobReadsCase14);
  assert.ok(row, 'bob keeps reading CASE-14 without the mask');
  assert.deepEqual(row.obligations.maskClasses, ['finance.amount']);
  assert.deepEqual(row.rules, ['ABAC.CONTENT_MASK']);
  assert.deepEqual(change.impact.obligationsGained, []);
  assert.ok(change.weakensMandatory?.includes('ABAC content rule finance-mask removed or weakened'));
  assert.throws(() => decideChange(rt, users.omar, change.id, true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.status === 403);
  assertMatchesReference(rt, candidate(rt, users.amira, 'publish_policy', { bundle }).state, 'finance mask removed');
});

test('KIMI-02: each obligation type lost on an allowed cell broadens; gaining it narrows', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const extra = (obligations: Record<string, unknown>) => ({ ...before, abac: [...before.abac, {
    id: 'kimi-02', description: 'test obligation', effect: 'obligation' as const, resourceTypes: ['case'], actions: ['read'], when: { op: 'true' as const }, obligations,
  }] });
  const kinds: Array<[string, Record<string, unknown>, (o: Impact['obligationsLost'][number]['obligations']) => boolean]> = [
    ['redact', { redact: ['informant_name', 'witness_name'] }, (o) => o.redact.includes('witness_name')],
    ['notify', { notify: ['dpo'] }, (o) => o.notify.includes('dpo')],
    ['fieldAllowlist', { fieldAllowlist: ['id', 'title'] }, (o) => o.fieldAllowlist?.after === null && o.fieldAllowlist.before?.join() === 'id,title'],
  ];
  for (const [label, obligations, check] of kinds) {
    const strict = extra(obligations);
    const narrowing = impact(rt, candidate(rt, users.amira, 'publish_policy', { bundle: strict }).state);
    assert.ok(narrowing.obligationsGained.some((row) => bobReadsCase14(row) && check(row.obligations)), `${label}: gained`);
    assert.deepEqual(narrowing.obligationsLost, [], `${label}: nothing lost`);
    assert.equal(narrowing.gained.length + narrowing.obligationsLost.length > 0, false, `${label}: does not broaden`);
    rt.store.state = { ...rt.store.state, bundle: strict };
    const loosening = impact(rt, candidate(rt, users.amira, 'publish_policy', { bundle: before }).state);
    assert.ok(loosening.obligationsLost.some((row) => bobReadsCase14(row) && check(row.obligations) && row.rules.includes('ABAC.kimi-02')), `${label}: lost`);
    rt.store.state = { ...rt.store.state, bundle: before };
  }
  // the decision token: a longer lifetime is a weaker token requirement on every certified command still allowed
  const longer = { ...before, clarkWilson: { ...before.clarkWilson, tokenTtlSeconds: before.clarkWilson.tokenTtlSeconds + 60 } };
  const delta = impact(rt, candidate(rt, users.amira, 'publish_policy', { bundle: longer }).state);
  assert.ok(delta.obligationsLost.length > 0 && delta.obligationsLost.every((row) => row.obligations.decisionToken === true));
  assert.equal(delta.obligationsLost.length + delta.gained.length > 0, true);
});


test('a no-op and a policy rename evaluate no cells but retain policy versions and explain why', (t) => {
  const { rt } = fixture(t);
  const unchanged = impact(rt, rt.store.state);
  assert.equal(unchanged.evaluated, 0);
  assert.deepEqual(unchanged.analysis, { affectedCells: 0, reasons: ['no decision or obligation inputs changed'] });
  assertMatchesReference(rt, rt.store.state, 'same state');

  const renamed = { ...rt.store.state.bundle, name: 'only-the-policy-name-changed' };
  const after = candidate(rt, users.amira, 'publish_policy', { bundle: renamed }).state;
  const delta = impact(rt, after);
  assert.equal(delta.evaluated, 0);
  assert.equal(delta.analysis?.affectedCells, 0);
  assert.notEqual(delta.policyVersionBefore, delta.policyVersionAfter);
  assertMatchesReference(rt, after, 'policy rename');
});

test('every direct, userset, parent, computed and reporting tuple removal matches the full grid', (t) => {
  const { rt } = fixture(t);
  for (const tuple of rt.store.state.tuples.filter((item) => !item.breakGlass)) {
    const after = candidate(rt, users.amira, 'remove_tuple', { tupleId: tuple.id }).state;
    assertMatchesReference(rt, after, `remove ${tuple.id} (${tuple.object.type}:${tuple.object.id}#${tuple.relation})`);
  }

  const replaced: State = { ...rt.store.state, tuples: rt.store.state.tuples.map((tuple) => tuple.id === 'seed-4'
    ? { ...tuple, subject: { type: 'user', id: 'alice' } } : tuple) };
  const delta = impact(rt, replaced, Number.MAX_SAFE_INTEGER);
  assert.ok(delta.lost.some((row) => row.subject === 'bob'), 'the old tuple content contributes its revocation');
  assert.ok(delta.gained.some((row) => row.subject === 'alice'), 'the new tuple content contributes its grant');
  assertMatchesReference(rt, replaced, 'same tuple id with different before and after content');
});

test('certification changes select only their procedure and match certification-aware decisions', (t) => {
  const { rt } = fixture(t);
  rt.sodHistory = 'caller';
  const state = rt.store.state;
  const bundle = { ...state.bundle, clarkWilson: { ...state.bundle.clarkWilson, requireCertification: ['payment'] } };
  rt.store.state = { ...state, bundle };
  const before = rt.store.state;
  const after: State = { ...before, certifications: [{
    resourceType: 'payment', action: 'approve', certifiedBy: 'lina', approvedBy: 'omar', certifiedAt: rt.now(),
    policyVersion: policyVersion(bundle), changeId: 'impact-certification', reason: WHY,
    fingerprint: procedureFingerprint(bundle, 'payment', 'approve'),
  }] };
  const delta = impact(rt, after, Number.MAX_SAFE_INTEGER);
  assert.ok(delta.analysis?.affectedCells);
  assert.ok(delta.analysis!.affectedCells <= before.subjects.length * before.resources.filter((r) => r.type === 'payment').length);
  assert.deepEqual([...new Set(delta.gained.map((row) => row.action)), ...new Set(delta.lost.map((row) => row.action))].sort(), ['approve']);
  assertMatchesReference(rt, after, 'new certification');

  rt.store.state = after;
  const roleChange = { ...bundle, rbac: { ...bundle.rbac, roles: { ...bundle.rbac.roles, unused_approver: {
    grants: [{ resourceType: 'payment', actions: ['approve'] }],
  } } } };
  const stale = candidate(rt, users.amira, 'publish_policy', { bundle: roleChange }).state;
  assert.ok(impact(rt, stale, Number.MAX_SAFE_INTEGER).lost.some((row) => row.action === 'approve' && row.rules.includes('CW.CERTIFICATION_STALE')));
  assertMatchesReference(rt, stale, 'RBAC edit stales a certification without changing a subject grant');
});

test('optimized impact exactly matches full grids across randomized worlds and all proposal generators', (t) => {
  const { rt } = fixture(t);
  const original = rt.store.state;
  const random = seeded(0x1A9AC7);
  for (let index = 0; index < 24; index++) {
    const subjects = original.subjects.map((subject) => ({
      ...subject,
      active: random() < 0.12 ? !subject.active : subject.active,
      roles: random() < 0.3 ? [Object.keys(original.bundle.rbac.roles)[Math.floor(random() * Object.keys(original.bundle.rbac.roles).length)]!] : subject.roles,
    }));
    const resources = original.resources.map((resource) => ({
      ...resource,
      contentClasses: random() < 0.25 ? [random() < 0.5 ? 'finance.amount' : 'pii.iban'] : resource.contentClasses,
      attrs: { ...resource.attrs, status: random() < 0.25 ? 'closed' : 'open' },
    }));
    rt.store.state = { ...original, subjects, resources };
    const kind = kinds[index % kinds.length]!;
    const after = randomCandidate(rt, kind, random, new Set<string>(), Math.floor(index / kinds.length)).state;
    assertMatchesReference(rt, after, `randomized world ${index} (${kind})`);
  }
});


test('rule additions select their declared scope and content-rule wildcard edits remain exact', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const extra = { ...before, abac: [...before.abac, {
    id: 'scoped-addition', description: 'test scoped addition', effect: 'obligation' as const,
    resourceTypes: ['case'], actions: ['read'], when: { op: 'true' as const }, obligations: { notify: ['dpo'] },
  }] };
  const added = candidate(rt, users.amira, 'publish_policy', { bundle: extra }).state;
  const addition = impact(rt, added, Number.MAX_SAFE_INTEGER);
  assert.equal(addition.analysis?.affectedCells,
    rt.store.state.subjects.length * rt.store.state.resources.filter((resource) => resource.type === 'case').length);
  assertMatchesReference(rt, added, 'scoped ABAC addition');

  const narrowed = { ...before, abacContent: contentRules(before).map((rule) => rule.id === 'finance-mask' ? { ...rule, actions: ['read'] } : rule) };
  const after = candidate(rt, users.amira, 'publish_policy', { bundle: narrowed }).state;
  const delta = impact(rt, after, Number.MAX_SAFE_INTEGER);
  const matching = rt.store.state.resources.filter((resource) => resource.contentClasses?.includes('finance.amount'));
  const actionCount = Object.keys(before.schema.resourceTypes.case?.actions ?? {}).length;
  assert.equal(delta.analysis?.affectedCells, rt.store.state.subjects.length * matching.length * actionCount);
  assertMatchesReference(rt, after, 'ABAC content rule wildcard to explicit action');
});

test('impact stays exact on a per-record store whose arrays and indexes were patched in place', (t) => {
  const { rt } = fixture(t);
  const dir = mkdtempSync('/tmp/pdp-test-records-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  // the PostgreSQL backing's shape (records: true): committed states patch the live arrays rather than replacing them
  let disk: Disk | undefined;
  const backing: Backing<Disk> = { records: true, load: () => disk && structuredClone(disk), save: (value) => { disk = structuredClone(value); } };
  rt.store = new Store(dir, resolve('examples/toy-domain'), rt.now(), backing);
  const arrays = [rt.store.state.subjects, rt.store.state.resources, rt.store.state.tuples];
  rt.store.state = applyResourcesInPlace(rt.store.state, [{ type: 'case', id: 'INPLACE-1', level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: ['finance.amount'], version: 1 }]);
  const grant = { id: 'inplace-grant', object: { type: 'case', id: 'INPLACE-1' }, relation: 'allocated', subject: { type: 'user', id: 'bob' } };
  rt.store.state = withRecordDeltas({ ...rt.store.state, tuples: [...rt.store.state.tuples, grant] }, [{ kind: 'tuple', op: 'put', type: '', id: grant.id, value: grant }]);
  const subjects = rt.store.state.subjects.map((s) => s.id === 'carol' ? { ...s, active: !s.active } : s);
  const carol = subjects.find((s) => s.id === 'carol')!;
  rt.store.state = withRecordDeltas({ ...rt.store.state, subjects }, [{ kind: 'subject', op: 'put', type: carol.type, id: carol.id, value: carol }]);
  rt.store.save();
  assert.ok(arrays.every((list, i) => list === [rt.store.state.subjects, rt.store.state.resources, rt.store.state.tuples][i]), 'the live arrays were patched, not replaced');
  assert.equal(rt.store.state.subjects.find((s) => s.id === 'carol')!.active, carol.active);
  assert.ok(rt.store.digest().startsWith('v2.'));
  const random = seeded(0x1B9ACE);
  for (let index = 0; index < kinds.length * 4; index++) {
    const kind = kinds[index % kinds.length]!;
    assertMatchesReference(rt, randomCandidate(rt, kind, random, new Set<string>(), Math.floor(index / kinds.length)).state, `in-place case ${index} (${kind})`);
  }
});
