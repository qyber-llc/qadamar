import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import type { TestContext } from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Store, fileBacking } from '../src/store.ts';
import { Audit } from '../src/audit.ts';
import { Auth } from '../src/auth.ts';
import { Tokens } from '../src/tokens.ts';
import type { Runtime } from '../src/runtime.ts';
import type { User } from '../src/auth.ts';
import { applyResourcesInPlace, retiredId } from '../src/resource-registry.ts';
import { findRef } from '../src/decision-index.ts';

export const FIXED = '2026-11-08T10:00:00Z';
export const WHY = 'Investigation requires this reviewed access change';
export const users = {
  amira: { id: 'amira', name: 'amira', roles: ['access_admin', 'policy_author'] },
  omar: { id: 'omar', name: 'omar', roles: ['approver'] }, lina: { id: 'lina', name: 'lina', roles: ['security_officer'] },
  ruth: { id: 'ruth', name: 'ruth', roles: ['resource_owner'] }, sam: { id: 'sam', name: 'sam', roles: ['auditor'] },
} satisfies Record<string, User>;
export const DEMO_OWNERS: ReadonlyMap<string, readonly string[]> = new Map([['ruth', ['carol']]]);
/** Replaces crypto.scrypt for one test (auth.ts's named import follows via syncBuiltinESMExports): records each call's
 *  cost and answers 32 zero bytes once `gate` resolves. scryptSync (seeding, wrapping) stays real. */
export function mockScrypt(t: TestContext, gate: Promise<void> = Promise.resolve()): string[] {
  const calls: string[] = [];
  const fake = (_secret: unknown, _salt: unknown, length: number, o: { N: number; r: number; p: number }, done: (err: Error | null, key: Buffer) => void): void => {
    calls.push(`N=${o.N} r=${o.r} p=${o.p}`);
    void gate.then(() => done(null, Buffer.alloc(length)));
  };
  t.mock.method(crypto, 'scrypt', fake as unknown as typeof crypto.scrypt);
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return calls;
}
export function required<T>(value: T | undefined | null): T {
  assert.ok(value !== undefined && value !== null, 'Expected a fixture value');
  return value;
}
export function user(id: string): User {
  assert.ok(Object.hasOwn(users, id), `Unknown fixture user: ${id}`);
  return required((users as Record<string, User>)[id]);
}
export interface Fixture { rt: Runtime & { audit: Audit }; auth: Auth; dir: string; passwords: Record<string, string>; pepApiKey: string; setClock: (value: string) => void }
export function fixture(t: TestContext): Fixture {
  const dir = mkdtempSync('/tmp/pdp-test-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let clock = FIXED; const now = (): string => clock;
  const store = new Store(dir, resolve('examples/toy-domain'), now());
  const audit = new Audit(resolve(dir, 'audit.jsonl'), now);
  const auth = new Auth(dir, audit, now, () => Date.parse(clock)); /* tests move time with setClock */ const tokens = new Tokens(dir, now);
  const credentials = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string>; pepApiKey: string };
  // the demo world's resources belong to "carol"; the console account "ruth" answers for them (RESOURCE_OWNERS)
  return { rt: { store, audit, tokens, now, started: Date.parse(clock), decisions: 0, resourceOwners: DEMO_OWNERS, approvalPrefs: fileBacking(resolve(dir, 'approval-prefs.json')) }, auth, dir, ...credentials, setClock: (value: string): void => { clock = value; } };
}
export function req(headers: Record<string, string> = {}): IncomingMessage { return { headers } as unknown as IncomingMessage; }
export const evaluation = (id = 'bob', resource = 'CASE-14', action = 'read', network?: string): Record<string, unknown> => ({
  subject: { type: id === 'assistant-1' ? 'agent' : 'user', id }, action: { name: action },
  resource: { type: resource.startsWith('PAY') ? 'payment' : 'case', id: resource }, ...(network ? { context: { network } } : {}),
});

/** Changes that leave the add_tuple grant's own impact alone, so only the v2 digest can refuse its approval. */
export const digestMutations: ReadonlyArray<readonly [string, (rt: { store: Store; now: () => string }) => void]> = [
  ['tuple', (rt) => { rt.store.state = { ...rt.store.state, tuples: [...rt.store.state.tuples, { id: 'digest-tuple', object: { type: 'case', id: 'CASE-14' }, relation: 'allocated', subject: { type: 'user', id: 'carol' } }] }; }],
  ['subject', (rt) => { rt.store.state = { ...rt.store.state, subjects: rt.store.state.subjects.map((s) => s.id === 'carol' ? { ...s, attrs: { ...s.attrs, digest: 1 } } : s) }; }],
  ['resource registered in place', (rt) => { rt.store.state = applyResourcesInPlace(rt.store.state, [{ type: 'case', id: 'DIGEST-1', level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], version: 1 }]); }],
  ['resource retired in place', (rt) => {
    const live = findRef(rt.store.state.resources, 'DIGEST-1', 'case')!;
    rt.store.state = applyResourcesInPlace(rt.store.state, [], [live]); rt.store.retired.append(retiredId(live, rt.now()));
  }],
  ['policy', (rt) => { rt.store.state = { ...rt.store.state, bundle: { ...rt.store.state.bundle, name: `${rt.store.state.bundle.name} (digest)` } }; }],
  ['certification', (rt) => { rt.store.state = { ...rt.store.state, certifications: [...rt.store.state.certifications ?? [], { resourceType: 'case', action: 'read',
    certifiedBy: 'amira', approvedBy: 'omar', certifiedAt: rt.now(), policyVersion: 'x', changeId: 'digest', reason: WHY }] }; }],
];
