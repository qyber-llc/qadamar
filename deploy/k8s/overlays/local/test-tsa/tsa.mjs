// TEST ONLY (deploy/k8s/overlays/local). An RFC 3161 time-stamp authority for the production-profile smoke test, after
// packages/pdp-http/test/tsa.ts: `openssl ts -reply` with a throwaway signer certificate issued by the tenant's test CA
// (scripts/managed/local-test-pki.sh). Runs on the gate-ops image: node:22-bookworm-slim has no openssl command, the
// Debian PostgreSQL image it is built from does.
import { createServer } from 'node:https';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = mkdtempSync('/tmp/tsa-');
writeFileSync(join(dir, 'serial'), '01\n');
writeFileSync(join(dir, 'tsa.cnf'), `[ tsa ]\ndefault_tsa = tsa_config\n[ tsa_config ]\nserial = ${join(dir, 'serial')}\ncrypto_device = builtin\n` +
  'signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n');
let replies = 0;
function reply(query) {
  writeFileSync(join(dir, 'q.tsq'), query);
  const out = spawnSync('openssl', ['ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-inkey', '/etc/test-tsa/tsa.key',
    '-signer', '/etc/test-tsa/tsa.crt', '-out', 'r.tsr'], { cwd: dir, encoding: 'utf8', timeout: 10_000 });
  if (out.status !== 0) throw new Error(`openssl ts -reply failed: ${out.stderr}`);
  return readFileSync(join(dir, 'r.tsr'));
}
const server = createServer({ cert: readFileSync('/etc/test-services/tls.crt'), key: readFileSync('/etc/test-services/tls.key') }, (req, res) => {
  if (req.method !== 'POST' || req.url !== '/tsa' || req.headers['content-type'] !== 'application/timestamp-query') { res.writeHead(404); res.end(); return; }
  const parts = []; let size = 0;
  req.on('data', (chunk) => { size += chunk.length; if (size > 65_536) req.destroy(); else parts.push(chunk); });
  req.on('end', () => {
    try {
      const body = reply(Buffer.concat(parts));
      res.writeHead(200, { 'content-type': 'application/timestamp-reply' }); res.end(body);
      console.log(`time-stamp reply ${++replies}`);
    } catch (err) { console.error(err.message); res.writeHead(500); res.end(); }
  });
});
server.listen(8443, () => console.log('TEST-ONLY time-stamp authority listening on 8443 (POST /tsa)'));
process.once('SIGTERM', () => server.close(() => process.exit(0)));
