// Local RFC 3161 authority for tests: OpenSSL signs with a throwaway CA, nothing leaves the machine.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';

export const openssl = process.env.OPENSSL ?? 'openssl';
export const hasOpensslTs = spawnSync(openssl, ['ts', '-help'], { encoding: 'utf8' }).status === 0;
function run(args: string[], cwd: string): string {
  const out = spawnSync(openssl, args, { cwd, encoding: 'utf8' });
  if (out.status !== 0) throw new Error(`openssl ${args[0]} failed: ${out.stderr}`);
  return out.stdout;
}
export interface Tsa { url: string; dir: string; requests: number; verify: (tokenBase64: string, hashHex: string) => string; reply: (query: Buffer) => Buffer }
export async function startTsa(t: { after: (fn: () => unknown) => void }): Promise<Tsa> {
  const dir = mkdtempSync('/tmp/pdp-tsa-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  run(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=Test TSA Root', '-days', '2',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign'], dir);
  run(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'tsa.key', '-out', 'tsa.csr', '-subj', '/CN=Test TSA'], dir);
  writeFileSync(join(dir, 'ext.cnf'), 'extendedKeyUsage=critical,timeStamping\nkeyUsage=critical,digitalSignature\n');
  run(['x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tsa.crt', '-days', '2', '-extfile', 'ext.cnf'], dir);
  writeFileSync(join(dir, 'serial'), '01\n');
  writeFileSync(join(dir, 'tsa.cnf'), `[ tsa ]\ndefault_tsa = tsa_config\n[ tsa_config ]\nserial = ${join(dir, 'serial')}\ncrypto_device = builtin\n` +
    'signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n');
  const reply = (query: Buffer): Buffer => {
    writeFileSync(join(dir, 'q.tsq'), query);
    run(['ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-inkey', 'tsa.key', '-signer', 'tsa.crt', '-out', 'r.tsr'], dir);
    return readFileSync(join(dir, 'r.tsr'));
  };
  const tsa: Tsa = {
    url: '', dir, requests: 0, reply,
    verify: (token, hash) => {
      writeFileSync(join(dir, 'token.der'), Buffer.from(token, 'base64'));
      return run(['ts', '-verify', '-digest', hash, '-in', 'token.der', '-token_in', '-CAfile', 'ca.crt'], dir);
    },
  };
  const server = createServer((req, res) => {
    const parts: Buffer[] = [];
    req.on('data', (c: Buffer) => parts.push(c));
    req.on('end', () => {
      tsa.requests++;
      try { res.setHeader('content-type', 'application/timestamp-reply'); res.end(reply(Buffer.concat(parts))); }
      catch { res.statusCode = 500; res.end(); }
    });
  });
  await new Promise<void>((accept) => server.listen(0, '127.0.0.1', accept));
  t.after(() => new Promise<void>((accept) => server.close(() => accept())));
  const address = server.address();
  tsa.url = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}/tsa`;
  return tsa;
}
