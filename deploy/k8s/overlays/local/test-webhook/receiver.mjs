// TEST ONLY (deploy/k8s/overlays/local). Receiver of Qadamar's signed break-glass notices (docs/API.md §3.6.1): checks the
// HMAC-SHA256 over "<timestamp>.<body>" with BREAK_GLASS_WEBHOOK_SECRET, refuses stale timestamps and replays, and logs
// one line per notice (smoke.sh reads the log). Never logs the secret or the signature.
import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { createHmac, timingSafeEqual } from 'node:crypto';

const secret = process.env.BREAK_GLASS_WEBHOOK_SECRET;
if (!secret) throw new Error('BREAK_GLASS_WEBHOOK_SECRET is required');
const seen = new Set();
function check(req, body) {
  const timestamp = String(req.headers['x-gate-timestamp'] ?? ''), signature = String(req.headers['x-gate-signature'] ?? '');
  if (!/^\d+$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return 'stale or missing timestamp';
  const expected = Buffer.from(`sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`, 'utf8').digest('hex')}`);
  const given = Buffer.from(signature);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return 'bad signature';
  return '';
}
const server = createServer({ cert: readFileSync('/etc/test-services/tls.crt'), key: readFileSync('/etc/test-services/tls.key') }, (req, res) => {
  if (req.method !== 'POST' || req.url !== '/notices') { res.writeHead(404); res.end(); return; }
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => { body += chunk; if (body.length > 65_536) req.destroy(); });
  req.on('end', () => {
    const problem = check(req, body);
    if (problem) { console.log(`rejected notice: ${problem}`); res.writeHead(401); res.end(); return; }
    let notice;
    try { notice = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
    const duplicate = seen.has(notice.id); seen.add(notice.id);
    console.log(`verified notice ${notice.event} emergency=${notice.emergencyId} subject=${notice.subjectId} resource=${notice.resourceId} actor=${notice.actorId}${duplicate ? ' (retry)' : ''}`);
    res.writeHead(204); res.end();
  });
});
server.listen(8443, () => console.log('TEST-ONLY break-glass notice receiver listening on 8443 (POST /notices)'));
process.once('SIGTERM', () => server.close(() => process.exit(0)));
