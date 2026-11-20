import test from 'node:test';
import assert from 'node:assert/strict';
import { principals } from '../../core/src/index.ts';
import type { Context, Subject } from '../../core/src/index.ts';
import { withPerformed } from '../src/runtime.ts';
import type { Runtime } from '../src/runtime.ts';
import type { Performed } from '../src/store.ts';

const baseContext: Context = { now: '2026-11-10T00:00:00Z', network: 'trusted' };

function subject(type: string, id: string, delegator?: Subject): Subject {
  return { type, id, active: true, roles: [], clearance: 3, compartments: [], integrity: 'verified',
    ...(delegator === undefined ? {} : { delegator }) };
}

function ref(value: { type: string; id: string }): { type: string; id: string } {
  return { type: value.type, id: value.id };
}

function runtime(performed: Performed[]): Runtime {
  return { store: { performed } } as Runtime;
}

function scanReference(performed: readonly Performed[], who: Subject, r: { id: string; type: string }, ctx: Context): Context {
  const onResource = performed.filter((p) => p.resource.type === r.type && p.resource.id === r.id);
  const chain = principals(who);
  const people = (p: Performed): Array<{ type: string; id: string }> => [p.subject, ...(p.onBehalfOf ?? [])];
  const mine = (p: Performed): boolean => people(p).some((x) => chain.some((s) => s.type === x.type && s.id === x.id));
  const actions = onResource.filter(mine).map((p) => p.action);
  const first = onResource[0];
  const makers = first ? people(first) : [];
  const maker = first === undefined ? undefined
    : makers.some((x) => x.id === ctx.makerId) ? ctx.makerId
    : chain.find((s) => makers.some((x) => x.type === s.type && x.id === s.id))?.id ?? first.subject.id;
  return { ...ctx, priorActions: [...new Set([...(ctx.priorActions ?? []), ...actions])], ...(maker === undefined ? {} : { serverMakerId: maker }) };
}

const alice = subject('user', 'alice');
const bob = subject('user', 'bob');
const carol = subject('user', 'carol');
const serviceAlice = subject('service', 'alice');
const agent = subject('agent', 'agent-1', alice);
const deepAgent = subject('agent', 'agent-2', subject('agent', 'agent-3', bob));
const outsider = subject('user', 'outsider');
const subjects = [alice, bob, carol, serviceAlice, agent, deepAgent, outsider];
const resources = [
  { type: 'case', id: 'shared' },
  { type: 'payment', id: 'shared' },
  { type: 'case', id: 'other' },
  { type: 'case', id: 'empty' },
];
const performers = [alice, bob, carol, serviceAlice, agent, outsider];
const delegations: Array<Array<{ type: string; id: string }>> = [
  [], [ref(alice)], [ref(bob), ref(alice)], [ref(carol)], [ref(agent)], [ref(serviceAlice)],
];
const actions = ['create', 'approve', 'create', 'read', 'release', 'approve'];
const historyResources = resources.slice(0, 3);
const generated = Array.from({ length: 48 }, (_, i): Performed => {
  const onBehalfOf = delegations[(i * 5 + Math.floor(i / 3)) % delegations.length]!;
  return {
    subject: ref(performers[(i * 5 + 1) % performers.length]!),
    resource: ref(historyResources[i % historyResources.length]!),
    action: actions[(i * 5) % actions.length]!,
    at: `2026-11-10T00:${String(i).padStart(2, '0')}:00Z`,
    ...(onBehalfOf.length === 0 ? {} : { onBehalfOf }),
  };
});
const contexts: Context[] = [
  baseContext,
  { ...baseContext, makerId: 'alice', priorActions: ['create', 'client-only', 'create'] },
  { ...baseContext, network: 'untrusted', makerId: 'bob', priorActions: ['approve', 'create'] },
  { ...baseContext, makerId: 'unknown', priorActions: [], serverMakerId: 'existing' },
];

test('indexed history matches an independent scan across histories, resources, subjects and contexts', () => {
  const histories: Performed[][] = [[], generated, generated.slice(0, 17), generated.slice().reverse()];
  for (let h = 0; h < 12; h++) {
    histories.push(Array.from({ length: 4 + h * 4 }, (_, i) => generated[(i * 11 + h * 7) % generated.length]!));
  }
  const rt = runtime([]);
  let comparisons = 0;
  for (const [historyIndex, history] of histories.entries()) {
    rt.store.performed = history;
    for (const resource of resources) for (const who of subjects) for (const [contextIndex, ctx] of contexts.entries()) {
      const expected = scanReference(history, who, resource, ctx);
      assert.deepEqual(withPerformed(rt, who, resource, ctx), expected,
        `history ${historyIndex}, ${resource.type}/${resource.id}, ${who.type}/${who.id}, context ${contextIndex}`);
      comparisons++;
    }
  }
  assert.equal(comparisons, 1792);
});

test('maker selection, onBehalfOf matching and prior-action order and dedupe are unchanged', () => {
  const resource = resources[0]!;
  const history: Performed[] = [
    { subject: ref(carol), resource, action: 'read', at: '1', onBehalfOf: [ref(alice), ref(bob)] },
    { subject: ref(bob), resource, action: 'approve', at: '2', onBehalfOf: [ref(alice)] },
    { subject: ref(carol), resource, action: 'read', at: '3' },
    { subject: ref(alice), resource: resources[1]!, action: 'delete', at: '4' },
  ];
  const rt = runtime(history);
  assert.deepEqual(withPerformed(rt, agent, resource, {
    ...baseContext, makerId: 'bob', priorActions: ['read', 'client-only', 'read'],
  }), {
    ...baseContext, makerId: 'bob', priorActions: ['read', 'client-only', 'approve'], serverMakerId: 'bob',
  });
  assert.deepEqual(withPerformed(rt, agent, resource, baseContext), {
    ...baseContext, priorActions: ['read', 'approve'], serverMakerId: 'alice',
  });
  assert.deepEqual(withPerformed(rt, outsider, resource, { ...baseContext, priorActions: ['client-only'] }), {
    ...baseContext, priorActions: ['client-only'], serverMakerId: 'carol',
  });
});

test('cached lookups read no history entries and replacement arrays are reindexed', () => {
  const rt = runtime([]);
  let entryReads = 0;
  const observed = (entries: Performed[]): Performed[] => new Proxy(entries, {
    get(target, property, receiver) {
      if (typeof property === 'string' && /^(0|[1-9]\d*)$/.test(property)) entryReads++;
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
  rt.store.performed = observed(generated);
  assert.deepEqual(withPerformed(rt, agent, resources[0]!, baseContext),
    scanReference(generated, agent, resources[0]!, baseContext));
  assert.ok(entryReads >= generated.length);

  entryReads = 0;
  for (let repeat = 0; repeat < 3; repeat++) for (const resource of resources) for (const who of subjects) {
    assert.deepEqual(withPerformed(rt, who, resource, contexts[1]!),
      scanReference(generated, who, resource, contexts[1]!));
  }
  assert.equal(entryReads, 0, 'cached lookups must not scan related or unrelated history');

  const added: Performed = {
    subject: ref(carol), resource: resources[3]!, action: 'approve', at: '49', onBehalfOf: [ref(alice)],
  };
  const replacedHistory = [...generated, added];
  rt.store.performed = observed(replacedHistory);
  assert.deepEqual(withPerformed(rt, agent, resources[3]!, baseContext), {
    ...baseContext, priorActions: ['approve'], serverMakerId: 'alice',
  });
  assert.ok(entryReads >= replacedHistory.length);

  entryReads = 0;
  assert.deepEqual(withPerformed(rt, agent, resources[3]!, baseContext),
    scanReference(replacedHistory, agent, resources[3]!, baseContext));
  assert.equal(entryReads, 0);
});
