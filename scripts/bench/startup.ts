// Start-up (takeover) cost against audit length, PostgreSQL mode: a start that verifies every row before serving (no
// checkpoint: what GATE_PROFILE=production did up to 0.4.2) against a start from the authenticated checkpoint (every
// profile since), and the full background verification that the checkpointed start launches.
// Usage: TEST_DATABASE_URL=... node scripts/bench/startup.ts --rows 1000000 --tail 1000 --repeats 3
import { randomBytes } from 'node:crypto';
import { PgLedger } from '../../packages/pdp-http/src/postgres.ts';
import { CHECKPOINT_KEY_LABEL, derivedKey } from '../../packages/pdp-http/src/tokens.ts';
import { adminClient, commandLine, databaseUrl, intOption, options, resetDatabase } from './common.ts';

const args = options();
const rows = intOption(args, 'rows', 1_000_000);
const tail = intOption(args, 'tail', 1000, 0);
const repeats = intOption(args, 'repeats', 3);
const url = databaseUrl();
const FIXED = '2026-11-10T10:00:00.000Z';
const ledgerOptions = { now: () => FIXED, checkpointKey: derivedKey(randomBytes(32).toString('base64url'), CHECKPOINT_KEY_LABEL) };
const fatal = (err: Error): void => { throw err; };
const round = (ms: number): number => Math.round(ms);

async function append(ledger: PgLedger, n: number): Promise<void> {
  const audit = ledger.auditLog(() => FIXED);
  for (let i = 1; i <= n; i++) {
    audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: `user-${i % 1000}`, resource: `case-${i % 10_000}`,
      effect: i % 3 ? 'allow' : 'deny', rules: [i % 3 ? 'allocated-read' : 'default-deny'] });
    if (i % 5000 === 0) await ledger.commit();
  }
  await ledger.commit();
}
async function timedOpen(): Promise<{ ledger: PgLedger; ms: number }> {
  const started = performance.now();
  const ledger = await PgLedger.open(url, fatal, ledgerOptions);
  return { ledger, ms: performance.now() - started };
}

await resetDatabase();
const seeding = performance.now();
let ledger = await PgLedger.open(url, fatal, ledgerOptions);
await append(ledger, rows);
if (!await ledger.recheck()) throw new Error('seeded chain does not verify');
await append(ledger, tail); // written after the checkpoint: what a takeover must still read
await ledger.close();
const seedMs = performance.now() - seeding;

const sql = adminClient();
await sql.connect();
const checkpoint = (await sql.query(`SELECT body FROM gate_doc WHERE name = 'audit_checkpoint'`)).rows[0]!.body as string;
const runs: Array<Record<string, number | string>> = [];
for (let r = 1; r <= repeats; r++) {
  await sql.query(`UPDATE gate_doc SET body = 'null' WHERE name = 'audit_checkpoint'`);
  let o = await timedOpen();
  runs.push({ repetition: r, mode: 'full chain at start', startMs: round(o.ms), rowsRead: o.ledger.startup.rowsRead });
  await o.ledger.close();
  await sql.query(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [checkpoint]);
  o = await timedOpen();
  const verifying = performance.now();
  if (!await o.ledger.recheck()) throw new Error('background verification failed');
  runs.push({ repetition: r, mode: 'from checkpoint', startMs: round(o.ms), rowsRead: o.ledger.startup.rowsRead,
    backgroundFullVerifyMs: round(performance.now() - verifying) });
  await o.ledger.close();
}
await sql.end();
console.log(JSON.stringify({ command: commandLine(), rows: rows + tail, tail, seedMs: round(seedMs), node: process.version, runs }, null, 2));
