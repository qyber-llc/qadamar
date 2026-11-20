import assert from 'node:assert/strict';
import { randomInt } from 'node:crypto';
import { test } from 'node:test';
import {
  actionDef, buildFilter, evalExpr, evaluate, indexTuples, principals, requestErrors,
  type PolicyBundle, type Request, type Subject, type Tuple,
} from '../src/index.ts';
import { MANDATORY_RULES, UNTRUSTED_ROLES, bundle, envInteger, graph, malformed, pick, prng, randomContextRules, randomRequest, world } from './fuzz-gen.ts';

const grantAll = (req: Request): Tuple[] => principals(req.subject).map((subject) => ({
  object: { type: req.resource.type, id: req.resource.id },
  relation: 'granted',
  subject: { type: subject.type, id: subject.id },
}));

function withOrdinaryRoles(subject: Subject): Subject {
  return {
    ...subject,
    roles: [...new Set([...subject.roles, ...UNTRUSTED_ROLES])],
    ...(subject.delegator ? { delegator: withOrdinaryRoles(subject.delegator) } : {}),
  };
}

const isMandatory = (rule: string): boolean => MANDATORY_RULES.has(rule.replace(/^DELEGATION\./, ''));

function checkMandatoryDeny(req: Request, active: PolicyBundle): void {
  const baseline = evaluate(active, req, graph).rules.filter(isMandatory);
  const grants = grantAll(req);
  const withRelations = evaluate(active, req, indexTuples([...world.tuples, ...grants]));
  const withRoles = evaluate(
    active,
    { ...req, subject: withOrdinaryRoles(req.subject) },
    indexTuples([...world.tuples, ...grants]),
  );
  assert.deepEqual(withRelations.rules.filter(isMandatory), baseline);
  assert.deepEqual(withRoles.rules.filter(isMandatory), baseline);
  if (baseline.length > 0) {
    assert.equal(withRelations.decision, false);
    assert.equal(withRoles.decision, false);
  }
}

function hasPointOnlyHistory(req: Request): boolean {
  if (actionDef(bundle, req.resource.type, req.action)?.requiresSecondPerson) {
    const maker = req.context.makerId;
    if (maker === undefined || principals(req.subject).some((subject) => subject.id === maker)) return true;
  }
  const prior = req.context.priorActions ?? [];
  return bundle.sod.some((rule) => rule.conflicting.includes(req.action) &&
    prior.some((action) => action !== req.action && rule.conflicting.includes(action)));
}

function checkFilter(req: Request, active: PolicyBundle): void {
  const def = actionDef(active, req.resource.type, req.action);
  if (!def) return;
  const residual = buildFilter(active, req.subject, req.resource.type, req.action, req.context, graph);
  const resources = [
    ...world.resources.filter((resource) => resource.type === req.resource.type),
    req.resource,
  ];
  for (const resource of resources) {
    const point = evaluate(active, { ...req, resource }, graph).decision;
    const kept = evalExpr(residual, {
      subject: req.subject,
      resource,
      action: { name: req.action, kind: def.kind },
      context: req.context,
    });
    assert.equal(kept, point, `filter mismatch for ${resource.type}:${resource.id}`);
  }
}


const seed = envInteger('FUZZ_SEED', randomInt(0x100000000), 0xffffffff);
const runs = envInteger('FUZZ_RUNS', 200, 1_000_000);
const printable = (value: unknown): string => JSON.stringify(value) ?? String(value);

test('seeded differential invariants over random toy-domain requests', () => {
  const rng = prng(seed);
  let current: unknown;
  let run = -1;
  try {
    for (run = 0; run < runs; run++) {
      const req = randomRequest(rng);
      const active = { ...bundle, context: randomContextRules(rng) };
      current = { req, contextRules: active.context };
      const first = evaluate(active, req, graph);
      assert.deepEqual(evaluate(active, req, graph), first);

      if (requestErrors(req).length === 0) {
        checkMandatoryDeny(req, active);
        if (!hasPointOnlyHistory(req)) checkFilter(req, active);
      }

      current = pick(rng, malformed)(rng);
      const denied = evaluate(bundle, current as Request, graph);
      assert.equal(denied.decision, false);
      assert.deepEqual(denied.rules, ['ENGINE.MALFORMED_REQUEST']);
    }
  } catch (error) {
    console.error(`Fuzz failure: FUZZ_SEED=${seed} FUZZ_RUNS=${runs}, run=${run}, input=${printable(current)}`);
    throw error;
  }
});
