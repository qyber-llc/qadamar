// The key each replica of a GATE_REPLICA_KEYS group holds: HKDF of the group's master for that replica id
// (packages/pdp-http/src/replica-protocol.ts replicaKeyOf). The master is read from stdin, never from the command line:
//   node scripts/ops/replica-key.ts gate-replica-0 gate-replica-1 < master.key > replica-keys.env
//   kubectl create secret generic gate-replica-keys --from-env-file=replica-keys.env
// Prints one `id=key` line per id (base64url). Only the database nodes hold the master; each replica pod gets its line.
import { readFileSync } from 'node:fs';
import { replicaKeyOf } from '../../packages/pdp-http/src/replica-protocol.ts';
import { decodeSeal } from '../../packages/pdp-http/src/tokens.ts';

const ids = process.argv.slice(2);
if (!ids.length) throw new Error('Usage: node scripts/ops/replica-key.ts <replica id>... < master key (32 bytes, base64url or hex)');
const master = decodeSeal(readFileSync(0, 'utf8').trim(), 'the group master key')!;
for (const id of ids) console.log(`${id}=${replicaKeyOf(master, id).toString('base64url')}`);
