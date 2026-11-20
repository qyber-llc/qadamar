// Storage review 2: a subject id that is not a world subject and was not used for SUBJECT_IDLE_DAYS loses its mapping
// (crypto-shredding: its old rows stay and verify, but no longer resolve). A world subject's mapping is never purged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { Audit } from '../src/audit.ts';
import { FileSubjectIdentities, SUBJECT_IDLE_DAYS } from '../src/audit-subjects.ts';
import { subjectReport } from '../src/admin/privacy.ts';
import { PgLedger } from '../src/postgres.ts';
import { Store } from '../src/store.ts';
import { FIXED, fixture, users } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

const DAY = 86_400_000;
const clock = (): { now: () => string; days: (n: number) => void } => {
  let at = Date.parse('2026-01-01T00:00:00.000Z');
  return { now: () => new Date(at).toISOString(), days: (n) => { at += n * DAY; } };
};
const decisionOn = (subject: string) => ({ type: 'decision' as const, actor: 'pep', action: 'read', subject, resource: 'DOC-1', effect: 'deny' as const, rules: ['CORE.UNKNOWN_ID'], policyVersion: 'v' });

test('file mode: an unknown id unused for 90 days loses its mapping; world subjects and recent ids keep theirs', async (t) => {
  assert.equal(SUBJECT_IDLE_DAYS, 90);
  const f = fixture(t);
  const c = clock();
  const world = f.rt.store.state.subjects[0]!.id;
  const mapping = resolve(f.dir, 'purge-subjects.json');
  const audit = new Audit(resolve(f.dir, 'purge-audit.jsonl'), c.now, { subjects: new FileSubjectIdentities(mapping, c.now) });
  f.rt.audit = audit;
  for (const id of [world, 'ghost-old', 'ghost-twice']) audit.append(decisionOn(id));
  const old = audit.subjectPseudonym('ghost-old');
  c.days(89);
  assert.equal(await audit.purgeSubjects([world]), 0, 'nothing is idle for 90 days yet');
  audit.append(decisionOn('ghost-twice')); // used again: its idle time restarts
  c.days(3); // ghost-old: 92 days idle
  audit.append(decisionOn('ghost-recent'));
  assert.equal(await audit.purgeSubjects([world]), 1);
  assert.equal(audit.subjectPseudonym('ghost-old'), undefined, 'the idle unknown id is shredded');
  assert.equal(audit.displayIdentity(old!), undefined);
  assert.ok(audit.subjectPseudonym(world), 'a world subject keeps its mapping however long it is idle');
  assert.ok(audit.subjectPseudonym('ghost-twice'));
  const stored = JSON.parse(readFileSync(mapping, 'utf8')) as Array<{ id: string }>;
  assert.deepEqual(stored.map((row) => row.id).sort(), [world, 'ghost-recent', 'ghost-twice'].sort(), 'the purge is durable');

  const purged = audit.records().filter((row) => row.action === 'subject_mappings_purged');
  assert.equal(purged.length, 1, 'one maintenance row, and none for an empty purge');
  assert.equal(purged[0]!.actor, 'system');
  assert.deepEqual(purged[0]!.details, { count: 1 });
  assert.ok(!JSON.stringify(purged[0]).includes('ghost'), 'no id in the maintenance row');
  assert.equal(purged[0]!.subject, undefined);

  // the subject access report and erasure still work for a recent unknown id
  const report = await subjectReport(f.rt, users.lina, 'ghost-recent') as { audit: { rows: unknown[] } };
  assert.equal(report.audit.rows.length, 1);
  assert.equal((await audit.eraseSubject('ghost-recent', 'lina')).erased, true);

  // the same id back after its purge: a new mapping, never the old one
  audit.append(decisionOn('ghost-old'));
  assert.ok(audit.subjectPseudonym('ghost-old'));
  assert.notEqual(audit.subjectPseudonym('ghost-old'), old);

  // an id that becomes a world subject is never purged, and its mapping survives later world changes
  c.days(SUBJECT_IDLE_DAYS + 2);
  // only ghost-old (back 92 days ago); lina, the officer, acted: never purged although she is not a world subject
  assert.equal(await audit.purgeSubjects([world, 'ghost-twice']), 1);
  assert.ok(audit.subjectPseudonym('lina'));
  assert.ok(audit.subjectPseudonym('ghost-twice'));
  c.days(SUBJECT_IDLE_DAYS + 2);
  assert.equal(await audit.purgeSubjects([world]), 0, 'a former world subject stays pinned');
  assert.ok(audit.subjectPseudonym('ghost-twice'));
  assert.equal(audit.verify().verified, true, 'the chain verifies after purges');
  // a restart reads the same mapping
  const again = new Audit(resolve(f.dir, 'purge-audit.jsonl'), c.now, { subjects: new FileSubjectIdentities(mapping, c.now) });
  assert.equal(again.verify().verified, true);
  assert.ok(again.subjectPseudonym('ghost-twice'));
  assert.equal(again.subjectPseudonym('ghost-old'), undefined);
});

test('PostgreSQL: the leader purges idle unknown-id mappings, followers drop them at reload, the chains verify', { skip, timeout: 60_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'gate_purge');
  const dir = mkdtempSync('/tmp/pdp-pg-purge-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const c = clock();
  const failures: Error[] = [];
  const options = { cluster: true, pseudonymiseSubjects: true, maxStalenessMs: 500, now: c.now } as const;
  const leader = await PgLedger.open(url, (err) => failures.push(err), { ...options, node: 'a' });
  t.after(() => leader.close());
  const store = new Store(dir, resolve(import.meta.dirname, '../../../examples/toy-domain'), FIXED, leader.backing('state'));
  await leader.commit();
  const world = store.state.subjects[0]!.id;
  await leader.ensureSubjects([world]);
  await sql(`INSERT INTO gate_doc (name, body) VALUES ('credentials', '{}')`);
  const follower = await PgLedger.open(url, (err) => failures.push(err), { ...options, node: 'b' });
  t.after(() => follower.close());
  assert.ok(leader.leader && !follower.leader);

  const audit = leader.auditLog(c.now);
  for (const id of [world, 'ghost-old', 'ghost-busy']) audit.append(decisionOn(id));
  await leader.commit();
  const old = leader.subjectPseudonym('ghost-old')!;
  assert.ok(old);
  assert.equal(await follower.purgeSubjects([world]), 0, 'a follower never purges');
  c.days(89);
  assert.equal(await leader.purgeSubjects([world]), 0);
  // ghost-busy is used on the follower only: its touch reaches the shared table
  follower.auditLog(c.now).append(decisionOn('ghost-busy'));
  await follower.commit();
  c.days(3);
  await follower.sync();
  assert.ok(follower.subjectPseudonym('ghost-old'), 'the follower holds the mapping before the purge');
  assert.equal(await leader.purgeSubjects([world]), 1);
  const ids = (await sql('SELECT id FROM gate_subject_identity ORDER BY id')).rows.map((r) => JSON.parse(r.id as string) as string);
  assert.deepEqual(ids.sort(), [world, 'ghost-busy'].sort());
  assert.equal(leader.subjectPseudonym('ghost-old'), undefined);
  await follower.sync();
  assert.equal(follower.subjectPseudonym('ghost-old'), undefined, 'the follower dropped it at reload');
  assert.ok(follower.subjectPseudonym('ghost-busy'));

  const purged = (await sql(`SELECT record FROM gate_audit WHERE record::jsonb->>'action' = 'subject_mappings_purged'`)).rows.map((r) => JSON.parse(r.record as string));
  assert.equal(purged.length, 1);
  assert.equal(purged[0].actor, 'system');
  assert.deepEqual(purged[0].details, { count: 1 });
  assert.ok(!JSON.stringify(purged[0]).includes('ghost'));

  // erasure still works for a recent unknown id, and a purged id comes back under a new mapping
  assert.equal((await audit.eraseSubject('ghost-busy', 'lina')).erased, true);
  audit.append(decisionOn('ghost-old'));
  await leader.commit();
  assert.ok(leader.subjectPseudonym('ghost-old'));
  assert.notEqual(leader.subjectPseudonym('ghost-old'), old);

  // a world subject idle for years keeps its mapping
  c.days(3 * 365);
  assert.equal(await leader.purgeSubjects([world]), 1, 'ghost-old again; never the world subject nor lina, who acted');
  assert.ok(leader.subjectPseudonym('lina'));
  assert.ok(leader.subjectPseudonym(world));
  assert.deepEqual(failures.map((e) => e.message), []);
  assert.ok(await leader.recheck(), 'every chain verifies after the purge');
});

test('PostgreSQL: an earlier schema gains the last-used column; its existing mappings are kept (never purged)', { skip, timeout: 60_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'gate_purge_migrate');
  const c = clock();
  let ledger = await PgLedger.open(url, () => undefined, { pseudonymiseSubjects: true, now: c.now });
  ledger.auditLog(c.now).append(decisionOn('legacy-ghost'));
  await ledger.commit();
  await ledger.close();
  // back to the 0.11.0 shape: no last-used column, no marker
  await sql('DROP INDEX gate_subject_identity_used; ALTER TABLE gate_subject_identity DROP COLUMN used_at');
  ledger = await PgLedger.open(url, () => undefined, { pseudonymiseSubjects: true, now: c.now });
  t.after(() => ledger.close());
  assert.equal((await sql(`SELECT count(*)::int AS n FROM pg_indexes WHERE indexname = 'gate_subject_identity_used'`)).rows[0]!.n, 1);
  c.days(10 * 365);
  assert.equal(await ledger.purgeSubjects([]), 0, 'a mapping from before the upgrade has no last use: kept');
  assert.ok(ledger.subjectPseudonym('legacy-ghost'));
});

// Integrator rule: only an id used solely as a PEP decision subject is purgeable; any actor or person-detail use protects it
const adminRows = (id: string) => [
  { type: 'change' as const, actor: id, action: 'approve', details: { makerId: 'maker-y' } },
  { type: 'security' as const, actor: 'system', action: 'break_glass_review', details: { openedBy: 'opener-z' } },
];

test('file mode: an id used as an actor or a person detail keeps its mapping when idle; a PEP-only id is purged', async (t) => {
  const f = fixture(t);
  const c = clock();
  const mapping = resolve(f.dir, 'actor-subjects.json');
  const audit = new Audit(resolve(f.dir, 'actor-audit.jsonl'), c.now, { subjects: new FileSubjectIdentities(mapping, c.now) });
  audit.append(decisionOn('ghost-pep'));
  audit.append(decisionOn('later-admin')); // first a decision subject, later an actor
  for (const row of adminRows('officer-x')) audit.append(row);
  audit.append({ type: 'change', actor: 'later-admin', action: 'propose' });
  c.days(92);
  assert.equal(await audit.purgeSubjects([]), 1, 'only the PEP-only id goes');
  assert.equal(audit.subjectPseudonym('ghost-pep'), undefined);
  for (const id of ['officer-x', 'maker-y', 'opener-z', 'later-admin']) assert.ok(audit.subjectPseudonym(id), `${id} is protected`);
  const row = audit.records().find((r) => r.action === 'approve')!;
  assert.equal(audit.displayIdentity(row.actor), 'officer-x', 'the admin row still resolves');
  assert.equal(audit.displayIdentity(String(row.details?.makerId)), 'maker-y');
  // a restart keeps the protection
  const again = new Audit(resolve(f.dir, 'actor-audit.jsonl'), c.now, { subjects: new FileSubjectIdentities(mapping, c.now) });
  c.days(365);
  assert.equal(await again.purgeSubjects([]), 0);
  assert.equal(again.displayIdentity(row.actor), 'officer-x');
});

test('PostgreSQL: an id used as an actor (on any node) or a person detail keeps its mapping when idle; a PEP-only id is purged', { skip, timeout: 60_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'gate_purge_actor');
  const dir = mkdtempSync('/tmp/pdp-pg-purge-actor-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const c = clock();
  const options = { cluster: true, pseudonymiseSubjects: true, maxStalenessMs: 500, now: c.now } as const;
  const leader = await PgLedger.open(url, () => undefined, { ...options, node: 'a' });
  t.after(() => leader.close());
  new Store(dir, resolve(import.meta.dirname, '../../../examples/toy-domain'), FIXED, leader.backing('state'));
  await leader.commit();
  await sql(`INSERT INTO gate_doc (name, body) VALUES ('credentials', '{}')`);
  const follower = await PgLedger.open(url, () => undefined, { ...options, node: 'b' });
  t.after(() => follower.close());
  const audit = leader.auditLog(c.now);
  audit.append(decisionOn('ghost-pep'));
  audit.append(decisionOn('later-admin'));
  for (const row of adminRows('officer-x')) audit.append(row);
  await leader.commit();
  follower.auditLog(c.now).append({ type: 'change', actor: 'later-admin', action: 'propose' }); // an actor on the follower
  await follower.commit();
  c.days(92);
  assert.equal(await leader.purgeSubjects([]), 1);
  const left = (await sql('SELECT id, used_at FROM gate_subject_identity ORDER BY id')).rows.map((r) => [JSON.parse(r.id as string), r.used_at]);
  assert.deepEqual(left, [['later-admin', null], ['maker-y', null], ['officer-x', null], ['opener-z', null]], 'actors and person details are pinned');
  const approve = JSON.parse((await sql(`SELECT record FROM gate_audit WHERE record::jsonb->>'action' = 'approve'`)).rows[0]!.record as string);
  assert.equal(leader.displayIdentity(approve.actor), 'officer-x', 'the admin row still resolves');
  assert.ok(await leader.recheck());
});
