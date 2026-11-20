import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Auth } from '../src/auth.ts';
import { Audit } from '../src/audit.ts';
import { FileSubjectIdentities } from '../src/audit-subjects.ts';
import { audit as auditRoute } from '../src/admin/audit.ts';
import { pullAudit } from '../src/siem.ts';
import { approveErasure, eraseSubject } from '../src/admin/privacy.ts';
import { dueGrants } from '../src/admin/reviews.ts';
import { propose } from '../src/admin/changes.ts';
import { HttpError } from '../src/http.ts';
import { fixture, users } from './helpers.ts';

const code = (expected: string) => (error: unknown): boolean => error instanceof HttpError && error.code === expected;

test('new audit rows and SIEM omit every person id; admin display resolves only while the mapping exists', async (t) => {
  const f = fixture(t);
  const audit = new Audit(resolve(f.dir, 'pseudonymous-audit.jsonl'), f.rt.now, { subjects: new FileSubjectIdentities(resolve(f.dir, 'audit-subjects.json')) });
  f.rt.audit = audit;
  audit.append({ type: 'change', actor: 'amira', action: 'approve', subject: 'bob', details: { makerId: 'amira', checkerId: 'omar', openedBy: 'lina', approvedBy: 'omar', subjectIds: ['bob', 'dan'] } });
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'bob', effect: 'allow' });
  audit.append({ type: 'change', actor: 'scim', action: 'scim.group.patch', details: { subjectIds: ['dan'] } });
  const text = JSON.stringify(audit.records());
  for (const id of ['amira', 'omar', 'lina', 'bob', 'dan']) assert.ok(!text.includes(id), `${id} is absent from chained rows`);
  assert.deepEqual(audit.records().map((row) => row.actor).slice(1), ['pep', 'scim'], 'technical actors stay readable');

  const exported = await pullAudit(audit, users.sam, new URL('https://pdp.example/admin/v1/audit/export'));
  for (const id of ['amira', 'omar', 'lina', 'bob', 'dan']) assert.ok(!exported.body.includes(id), `${id} is absent from SIEM`);
  const before = await auditRoute(f.rt, users.sam, new URL('https://pdp.example/admin/v1/audit')) as { items: Array<{ actor: string; details?: Record<string, unknown> }> };
  assert.equal(before.items[0]?.actor, 'amira', 'admin display resolves the actor while its mapping exists');
  assert.equal(before.items[0]?.details?.makerId, 'amira');
  assert.equal(before.items[0]?.details?.checkerId, 'omar');

  await audit.eraseSubject('amira', 'omar');
  const after = await auditRoute(f.rt, users.sam, new URL('https://pdp.example/admin/v1/audit')) as { items: Array<{ actor: string; details?: Record<string, unknown> }> };
  assert.match(after.items[0]?.actor ?? '', /^ps\./, 'erasure makes the display pseudonymous again');
  assert.match(String(after.items[0]?.details?.makerId), /^ps\./);
  assert.ok(!JSON.stringify(audit.records()).includes('amira'));
  assert.ok(!(await pullAudit(audit, users.sam, new URL('https://pdp.example/admin/v1/audit/export'))).body.includes('amira'));
  assert.equal(audit.verify().verified, true);
});


test('erasure requires a second security officer and records a pseudonymous review reference', async (t) => {
  const f = fixture(t);
  const audit = new Audit(resolve(f.dir, 'pseudonymous-audit.jsonl'), f.rt.now, { subjects: new FileSubjectIdentities(resolve(f.dir, 'audit-subjects.json')) });
  f.rt.audit = audit;
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'erase-me', effect: 'allow' });
  const target = audit.records()[0]!.subject!;
  const proposal = await eraseSubject(f.rt, users.lina, 'erase-me') as { id: string; status: string };
  assert.equal(proposal.status, 'pending');
  await assert.rejects(approveErasure(f.rt, users.lina, proposal.id, true, { reason: 'self approval must fail' }), code('self_approval'));
  await assert.rejects(approveErasure(f.rt, users.omar, proposal.id, true, { reason: 'role check must fail' }), code('forbidden'));
  const other = { id: 'second-officer', name: 'Second officer', roles: ['security_officer'] };
  const approved = await approveErasure(f.rt, other, proposal.id, true, { reason: 'independent privacy review' });
  assert.equal(approved.status, 'applied');
  assert.deepEqual(approved.erasure, { pseudonym: target, erased: true, changeId: proposal.id });
  const row = audit.records().find((item) => item.action === 'subject_erased')!;
  assert.equal(row.details?.changeId, proposal.id);
  assert.match(String(row.details?.approvedBy), /^ps\./);
  assert.ok(!JSON.stringify(row).includes('erase-me'));
  assert.ok(!JSON.stringify(row).includes('second-officer'));
  assert.equal(audit.subjectPseudonym('erase-me'), undefined);
  assert.deepEqual(f.rt.store.changes.find((item) => item.id === proposal.id)?.payload, { pseudonym: target }, 'the applied proposal keeps no raw id');
  assert.equal(audit.verify().verified, true);
});

test('a failed erasure restores its change to pending', async (t) => {
  const f = fixture(t);
  const audit = new Audit(resolve(f.dir, 'pseudonymous-audit.jsonl'), f.rt.now, { subjects: new FileSubjectIdentities(resolve(f.dir, 'audit-subjects.json')) });
  f.rt.audit = audit;
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'erase-me', effect: 'allow' });
  const proposal = await eraseSubject(f.rt, users.lina, 'erase-me') as { id: string };
  audit.eraseSubject = async () => { throw new Error('erasure failed'); };
  const other = { id: 'second-officer', name: 'Second officer', roles: ['security_officer'] };
  await assert.rejects(approveErasure(f.rt, other, proposal.id, true, { reason: 'independent privacy review' }), /erasure failed/);
  assert.equal(f.rt.store.changes.find((item) => item.id === proposal.id)?.status, 'pending');
});

test('self-erasure, open break-glass and pending reviews block the proposal', async (t) => {
  const f = fixture(t);
  const audit = new Audit(resolve(f.dir, 'pseudonymous-audit.jsonl'), f.rt.now, { subjects: new FileSubjectIdentities(resolve(f.dir, 'audit-subjects.json')) });
  f.rt.audit = audit;
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'lina', effect: 'allow' });
  await assert.rejects(eraseSubject(f.rt, users.lina, 'lina'), code('self_erasure'));
  const direct = propose(f.rt, users.lina, { kind: 'erase_subject', payload: { id: 'lina' }, reason: 'self erasure through the generic change route' });
  await assert.rejects(approveErasure(f.rt, { id: 'second-officer', name: 'Second officer', roles: ['security_officer'] }, direct.id, true, { reason: 'must fail' }), code('self_erasure'));
  assert.ok(audit.subjectPseudonym('lina'), 'the mapping survives');

  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'erase-me', effect: 'allow' });
  f.rt.store.emergencies = [{ id: 'e-1', subjectId: 'erase-me', resourceId: 'CASE-12', reason: 'open incident', openedBy: 'amira', openedAt: f.rt.now(), expiresAt: '2027-01-01T00:00:00Z', status: 'active', tupleId: 't-1' }];
  await assert.rejects(eraseSubject(f.rt, users.lina, 'erase-me'), code('open_break_glass'));
  f.rt.store.emergencies = [];

  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'bob', effect: 'allow' });
  f.rt.store.state = { ...f.rt.store.state, tuples: [...f.rt.store.state.tuples, { id: 'review-bob', object: { type: 'case', id: 'CASE-14' }, relation: 'granted',
    subject: { type: 'user', id: 'bob' }, validFrom: f.rt.now(), validTo: '2026-11-15T10:00:00Z' }] };
  assert.ok(dueGrants(f.rt, (tuple) => tuple.subject.id === 'bob').length > 0, 'the demo has a pending review for bob');
  await assert.rejects(eraseSubject(f.rt, users.lina, 'bob'), code('pending_reviews'));
});

test('a username spray mints no subject mapping: unknown ids are keyed hashes, a known account keeps its pseudonym', async (t) => {
  const f = fixture(t);
  const mapping = resolve(f.dir, 'spray-subjects.json');
  const audit = new Audit(resolve(f.dir, 'spray-audit.jsonl'), f.rt.now, { subjects: new FileSubjectIdentities(mapping) });
  const seal = Buffer.alloc(32, 7).toString('base64url');
  mkdirSync(resolve(f.dir, 'spray-auth'));
  const auth = new Auth(resolve(f.dir, 'spray-auth'), audit, f.rt.now, () => Date.parse(f.rt.now()), { signingKeySeal: seal });
  const sprayed = Array.from({ length: 40 }, (_, i) => `sprayed-${i}@example.test`);
  for (const [i, name] of [...sprayed, sprayed[0]!].entries()) {
    await assert.rejects(auth.login(name, 'wrong password', `198.51.100.${i}`), code('unauthenticated'));
  }
  assert.ok(!existsSync(mapping) || JSON.parse(readFileSync(mapping, 'utf8')).length === 0, 'no mapping row for any sprayed username');
  const actors = audit.records().map((row) => row.actor);
  assert.equal(actors.length, sprayed.length + 1);
  for (const actor of actors) assert.match(actor, /^unknown:[0-9a-f]{32}$/);
  assert.equal(new Set(actors).size, sprayed.length, 'one id hashes the same way twice, distinct ids differ');
  assert.ok(!JSON.stringify(audit.records()).includes('sprayed-'), 'no raw username in the chain');
  // the same key on a restart (derived from SIGNING_KEY_SEAL), and an id that already has a mapping keeps it
  const again = new Auth(resolve(f.dir, 'spray-auth'), audit, f.rt.now, () => Date.parse(f.rt.now()), { signingKeySeal: seal });
  assert.equal(again.failedLoginActor(sprayed[0]!), actors[0]);
  audit.append({ type: 'change', actor: 'amira', action: 'approve' });
  assert.equal(again.failedLoginActor('amira'), 'amira', 'a mapped person is pseudonymised the normal way');
  assert.equal(JSON.parse(readFileSync(mapping, 'utf8')).length, 1);
});
