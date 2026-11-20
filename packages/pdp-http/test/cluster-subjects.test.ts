// Cluster subject mappings (storage review 1): a pseudonym another node stored first is adopted, never a node exit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { PgLedger } from '../src/postgres.ts';
import { Store } from '../src/store.ts';
import { FIXED } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

const decisionOn = (subject: string) => ({ type: 'decision' as const, actor: 'pep', action: 'read', subject, resource: 'DOC-1', effect: 'deny' as const, rules: ['CORE.UNKNOWN_ID'], policyVersion: 'v' });

test('a subject mapping a follower stored first is adopted by the leader, which stays up; the chains verify', { skip, timeout: 60_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'gate_subjects');
  const dir = mkdtempSync('/tmp/pdp-pg-subjects-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const failures: Error[] = [];
  const options = { cluster: true, pseudonymiseSubjects: true, maxStalenessMs: 500 } as const;
  const leader = await PgLedger.open(url, (err) => failures.push(err), { ...options, node: 'a' });
  t.after(() => leader.close());
  new Store(dir, resolve(import.meta.dirname, '../../../examples/toy-domain'), FIXED, leader.backing('state'));
  await leader.commit();
  await sql(`INSERT INTO gate_doc (name, body) VALUES ('credentials', '{}')`);
  const follower = await PgLedger.open(url, (err) => failures.push(err), { ...options, node: 'b' });
  t.after(() => follower.close());
  assert.ok(leader.leader && !follower.leader);

  follower.auditLog(() => FIXED).append(decisionOn('nobody-x'));
  await follower.commit();
  const stored = follower.subjectPseudonym('nobody-x');
  assert.ok(stored);

  const audit = leader.auditLog(() => FIXED);
  audit.append(decisionOn('nobody-x'));
  audit.append(decisionOn('nobody-x'));
  await leader.commit();
  assert.deepEqual(failures.map((e) => e.message), [], 'the leader is not latched');
  assert.equal(leader.subjectPseudonym('nobody-x'), stored, 'the leader adopted the stored pseudonym');
  const subjects = (await sql(`SELECT record::jsonb->>'subject' AS s FROM gate_audit WHERE node = 'a' AND record::jsonb->>'type' = 'decision'`)).rows.map((r) => r.s as string);
  assert.deepEqual(subjects, [stored, stored], 'its rows carry the shared pseudonym');
  assert.equal((await sql('SELECT count(*)::int AS n FROM gate_subject_identity')).rows[0]!.n, 1);

  audit.append(decisionOn('nobody-x'));
  await leader.commit(); // still deciding
  assert.ok(await leader.recheck(), 'every chain verifies');
  assert.equal(audit.verify().verified, true);
});
