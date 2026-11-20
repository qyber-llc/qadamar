// One PDP node in its own process for load.ts --nodes: cluster mode on DATABASE_URL (passed in the environment, never
// on the command line), or, with GATE_REPLICA_OF, a stateless replica of that node; prints "READY <url>" once it serves.
import { createServer } from '../../packages/pdp-http/src/server.ts';
import { parseReplicaKeys } from '../../packages/pdp-http/src/replica-protocol.ts';

const env = process.env;
const server = createServer({
  port: 0, dataDir: env.DATA_DIR, worldDir: env.WORLD_DIR, clock: 'fixed:2026-11-08T10:00:00Z', rateLimit: 1_000_000_000, pepRateLimit: 1_000_000_000,
  nodeId: env.GATE_NODE_ID,
  ...(env.GATE_REPLICA_OF ? { replicaOf: env.GATE_REPLICA_OF, replicaKey: env.GATE_REPLICA_KEY }
    : { databaseUrl: env.DATABASE_URL, signingKeySeal: env.SIGNING_KEY_SEAL, cluster: true, replicaKeys: parseReplicaKeys(env.GATE_REPLICA_KEYS) }),
  onFatal: (err) => { console.error(`Storage failure, stopping: ${err.message}`); process.exit(1); },
});
await server.listen();
process.stdout.write(`READY ${server.url}\n`);
process.once('SIGTERM', () => { void server.close().then(() => process.exit(0)); });
