// RFC 3161 timestamping of the audit chain head: only a SHA-256 hash leaves the server.
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Anchor } from './audit.ts';

interface Der { tag: number; start: number; body: Buffer; end: number }
const SHA256 = Buffer.from('608648016503040201', 'hex'); // 2.16.840.1.101.3.4.2.1
const TST_INFO = Buffer.from('2a864886f70d0109100104', 'hex'); // 1.2.840.113549.1.9.16.1.4
const MAX_REPLY = 64 * 1024;

function tlv(tag: number, body: Buffer): Buffer {
  const size: number[] = [];
  for (let n = body.length; n > 0; n = Math.floor(n / 256)) size.unshift(n % 256);
  const length = body.length < 0x80 ? [body.length] : [0x80 | size.length, ...size];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}
function read(buf: Buffer, at: number): Der {
  const tag = buf[at]; let size = buf[at + 1]; let p = at + 2;
  if (tag === undefined || size === undefined) throw new Error('Truncated timestamp reply');
  if (size & 0x80) {
    const count = size & 0x7f;
    if (count < 1 || count > 3) throw new Error('Unsupported DER length');
    size = 0;
    for (let i = 0; i < count; i++) { const byte = buf[p + i]; if (byte === undefined) throw new Error('Truncated timestamp reply'); size = size * 256 + byte; }
    if (size < 0x80 || (count > 1 && buf[p] === 0)) throw new Error('Non-minimal DER length');
    p += count;
  }
  if (p + size > buf.length) throw new Error('Truncated timestamp reply');
  return { tag, start: at, body: buf.subarray(p, p + size), end: p + size };
}
function items(body: Buffer): Der[] {
  const out: Der[] = [];
  for (let at = 0; at < body.length;) { const d = read(body, at); out.push(d); at = d.end; }
  return out;
}
function expect(d: Der | undefined, tag: number): Der {
  if (!d || d.tag !== tag) throw new Error('Unexpected timestamp reply structure');
  return d;
}

/** TimeStampReq for a SHA-256 hash, with a nonce and the TSA certificate requested. */
export function timestampQuery(hashHex: string, nonce: Buffer): Buffer {
  const algorithm = tlv(0x30, Buffer.concat([tlv(0x06, SHA256), Buffer.from([0x05, 0x00])]));
  const imprint = tlv(0x30, Buffer.concat([algorithm, tlv(0x04, Buffer.from(hashHex, 'hex'))]));
  return tlv(0x30, Buffer.concat([tlv(0x02, Buffer.from([1])), imprint, tlv(0x02, nonce), Buffer.from([0x01, 0x01, 0xff])]));
}
/** Checks the reply is granted and is for this hash and nonce; returns the token (TimeStampToken DER) and its time.
 *  The TSA signature itself is checked offline with `openssl ts -verify` (docs/API.md). */
export function readTimestampReply(der: Buffer, hashHex: string, nonce: Buffer): { genTime: string; token: Buffer } {
  const reply = expect(read(der, 0), 0x30);
  if (reply.end !== der.length) throw new Error('Trailing bytes after the timestamp reply');
  const [status, token] = items(reply.body);
  const code = expect(items(expect(status, 0x30).body)[0], 0x02).body;
  if (code.length !== 1 || (code[0] !== 0 && code[0] !== 1)) throw new Error('Timestamp refused by the authority');
  const content = items(expect(token, 0x30).body);
  const signed = items(expect(items(expect(content[1], 0xa0).body)[0], 0x30).body);
  const encap = items(expect(signed[2], 0x30).body);
  if (!expect(encap[0], 0x06).body.equals(TST_INFO)) throw new Error('Not a timestamp token');
  const octets = expect(items(expect(encap[1], 0xa0).body)[0], 0x04);
  const info = items(expect(read(octets.body, 0), 0x30).body);
  const imprint = items(expect(info[2], 0x30).body);
  if (!expect(items(expect(imprint[0], 0x30).body)[0], 0x06).body.equals(SHA256)) throw new Error('Timestamp uses another hash algorithm');
  if (!expect(imprint[1], 0x04).body.equals(Buffer.from(hashHex, 'hex'))) throw new Error('Timestamp is for another hash');
  if (!info.slice(5).some((d) => d.tag === 0x02 && d.body.equals(nonce))) throw new Error('Timestamp nonce mismatch');
  const time = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(expect(info[4], 0x18).body.toString('latin1'));
  if (!time) throw new Error('Unreadable timestamp time');
  const genTime = new Date(`${time[1]}-${time[2]}-${time[3]}T${time[4]}:${time[5]}:${time[6]}${time[7] ?? ''}Z`).toISOString();
  return { genTime, token: Buffer.from(reply.body.subarray(token!.start, token!.end)) }; // offsets are within the reply body
}
/** Sends the head hash to the authority and returns the anchor to keep. */
export async function requestAnchor(tsa: string, head: { seq: number; hash: string }, caFile?: string): Promise<Anchor> {
  const nonce = randomBytes(8);
  nonce[0] = (nonce[0]! % 0x7f) + 1; // positive, minimal DER INTEGER
  const res = await fetch(tsa, {
    method: 'POST', body: new Uint8Array(timestampQuery(head.hash, nonce)), redirect: 'error', signal: AbortSignal.timeout(15_000),
    headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' },
  });
  if (!res.ok) throw new Error(`Timestamp authority answered ${res.status}`);
  const parts: Buffer[] = []; let size = 0;
  for await (const chunk of res.body ?? []) {
    size += chunk.length;
    if (size > MAX_REPLY) { await res.body?.cancel(); throw new Error('Timestamp reply too large'); }
    parts.push(Buffer.from(chunk));
  }
  const { genTime, token } = readTimestampReply(Buffer.concat(parts), head.hash, nonce);
  if (Math.abs(Date.parse(genTime) - Date.now()) > 10 * 60_000) throw new Error('Timestamp time is more than 10 minutes off');
  if (caFile) verifyToken(token, head.hash, caFile);
  return { seq: head.seq, hash: head.hash, tsa, genTime, token: token.toString('base64') };
}
/** The authority's signature and certificate chain, checked by OpenSSL against the authority's CA (TSA_CA_FILE). */
export function verifyToken(token: Buffer, hashHex: string, caFile: string, openssl = process.env.OPENSSL ?? 'openssl'): void {
  // a file, not /dev/stdin: Node gives a child's stdin as a socket, which OpenSSL cannot fopen on Linux (ENXIO)
  const dir = mkdtempSync(join(tmpdir(), 'gate-tst-'));
  try {
    const file = join(dir, 'token.der');
    writeFileSync(file, token, { mode: 0o600 });
    const out = spawnSync(openssl, ['ts', '-verify', '-digest', hashHex, '-in', file, '-token_in', '-CAfile', caFile], { encoding: 'utf8', timeout: 10_000 });
    if (out.status !== 0 || !/Verification: OK/.test(out.stdout)) throw new Error('Timestamp signature does not verify against TSA_CA_FILE');
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export const loadAnchorFile = (file: string): Anchor[] =>
  existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line) as Anchor) : [];
export const appendAnchorFile = (file: string, a: Anchor): void => appendFileSync(file, JSON.stringify(a) + '\n', { mode: 0o600 });
