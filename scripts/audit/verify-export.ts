// Offline check of a tenant's audit evidence, run by the customer's auditor on its own machine (docs/MANAGED-OFFER.md
// §13). Inputs, all downloaded beforehand: the rows (GET /admin/v1/audit/export, every page, NOT pseudonymised), the
// signed manifest (GET /admin/v1/audit/verification), the JWKS of the day (GET /.well-known/jwks.json) and, optionally,
// the anchors with their tokens (GET /admin/v1/audit/anchors) and the TSA's CA certificate.
//
//   node scripts/audit/verify-export.ts --rows audit.ndjson --manifest verification.json --jwks jwks.json \
//     [--anchors anchors.json --tsa-ca tsa-ca.pem] [--pin pinned-jwks.json [--keyring keyring.json]]
//
// Checks: the manifest signature; every chain recomputed row by row from its genesis or its sealed segment head up to
// its signed head, only chains the manifest's heads name, and no row after a head (export with `until=` the heads: such
// a row is not covered by the signature, so it fails the check); the manifest's heads present in the rows; every anchor consistent with the rows
// (and, with --anchors, its token the one the manifest hashed; with --tsa-ca, `openssl ts -verify` of each token); with
// --pin, the signing key held out of band. Prints a JSON report; exit 1 on any problem, 3 when the evidence is only
// self-consistent (no token verified with --tsa-ca and no pinned signing key).
import { createPublicKey, verify, type JsonWebKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { canonical } from '../../packages/core/src/index.ts';
import { LEGACY_NODE, sha256, verifyChain, type AuditRecord, type Head } from '../../packages/pdp-http/src/audit.ts';
import { TrustedKeys } from '../../packages/pdp-http/src/replica-protocol.ts';
import type { SigningKeyDisk } from '../../packages/pdp-http/src/tokens.ts';
import type { AuditSegment } from '../../packages/pdp-http/src/audit-integrity.ts';

type Segment = Omit<AuditSegment, 'mac'>;
interface ManifestAnchor { seq: number; hash: string; genTime: string; tokenSha256: string; heads?: Record<string, Head> }
export interface Manifest { format: string; heads: Record<string, Head>; segments: Segment[]; anchors: ManifestAnchor[] }
export interface Evidence { rows: AuditRecord[]; manifest: Manifest; signature: string; jwks: { keys: JsonWebKey[] };
  anchors?: { items: Array<{ seq: number; hash: string; token: string }> };
  /** Signing keys the auditor holds out of band (a JWKS kept from onboarding), and the public keyring whose
   *  introductions lead from one of them to the signer. */
  pins?: { keys: JsonWebKey[] }; keyring?: SigningKeyDisk }
/** `ok`: consistent; `pinned`: signed by a key held out of band. Neither alone says the evidence is anchored (verdict). */
export interface Report { ok: boolean; pinned: boolean; problems: string[]; chains: Record<string, number>; anchorsChecked: number; tokens: Array<{ seq: number; hash: string; token: string }> }

/** A detached JWS (header..signature) over canonical(payload), EdDSA, key chosen by kid from the JWKS. */
export function signatureValid(payload: unknown, jws: string, jwks: { keys: JsonWebKey[] }): boolean {
  try {
    const [header, empty, signature] = jws.split('.');
    const { alg, kid } = JSON.parse(Buffer.from(header!, 'base64url').toString()) as { alg?: string; kid?: string };
    const jwk = jwks.keys.find((k) => (k as { kid?: string }).kid === kid);
    if (alg !== 'EdDSA' || empty !== '' || !jwk) return false;
    const content = `${header}.${Buffer.from(canonical(payload)).toString('base64url')}`;
    return verify(null, Buffer.from(content), createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(signature!, 'base64url'));
  } catch { return false; }
}

export function verifyEvidence(e: Evidence): Report {
  const problems: string[] = [];
  if (e.manifest.format !== 'gate-audit-verification/1') problems.push(`unknown manifest format ${e.manifest.format}`);
  const keys = withKeyring(e.jwks, e.keyring);
  const signed = signatureValid(e.manifest, e.signature, keys);
  if (!signed) problems.push('manifest signature does not verify against the JWKS');
  if (e.rows.some((r) => (r as { pseudonymised?: boolean }).pseudonymised)) problems.push('pseudonymised rows no longer hash to their hash: export without pseudonymise=1');
  const segments = e.manifest.segments as AuditSegment[];
  const sealed = (node: string): number => segments.filter((s) => s.node === node).at(-1)?.lastSeq ?? 0;
  // per chain, in seq order: each row recomputes and links to the previous one, from genesis or the sealed head
  const byChain = new Map<string, AuditRecord[]>();
  for (const row of e.rows) {
    const node = row.node ?? LEGACY_NODE;
    const rows = byChain.get(node) ?? [];
    rows.push(row); byChain.set(node, rows);
  }
  const hashes = new Map<string, string>();
  const chains: Record<string, number> = {};
  for (const [node, rows] of byChain) {
    // a chain the signed manifest does not name proves nothing: a forged, self-consistent chain would otherwise pass
    if (!Object.hasOwn(e.manifest.heads, node)) { problems.push(`chain ${node} is not among the manifest's heads`); continue; }
    // only rows up to the signed head are certified: rows after it could be invented and rehashed by anyone
    const head = e.manifest.heads[node]!.seq;
    const all = [...rows].sort((a, b) => a.seq - b.seq);
    const sorted = all.filter((row) => row.seq <= head);
    if (all.length > sorted.length) problems.push(`chain ${node}: ${all.length - sorted.length} row(s) after the signed head ${head} (unauthenticated tail: export with until=<the manifest's heads>)`);
    const result = verifyChain(sorted, [], segments, node);
    chains[node] = sorted.length;
    if (!result.verified) problems.push(`chain ${node} breaks at seq ${result.brokenAt}`);
    for (const row of sorted) hashes.set(`${node}:${row.seq}`, row.hash);
  }
  // a head is matched by its row; a row removed by sealed retention only by the segment head it was, if it was one
  // (older anchors are covered by the seal, docs/API.md §3.9.4)
  const holds = (node: string, head: Head): boolean => {
    if (head.seq === 0) return true;
    if (head.seq > sealed(node)) return hashes.get(`${node}:${head.seq}`) === head.hash;
    const segment = segments.find((s) => s.node === node && s.head.seq === head.seq);
    return segment ? segment.head.hash === head.hash : true;
  };
  for (const [node, head] of Object.entries(e.manifest.heads)) if (!holds(node, head)) problems.push(`head ${node}:${head.seq} is not in the exported rows`);
  for (const anchor of e.manifest.anchors) {
    const heads = anchor.heads ?? { [LEGACY_NODE]: { seq: anchor.seq, hash: anchor.hash } };
    if (anchor.heads && sha256(canonical(anchor.heads)) !== anchor.hash) problems.push(`anchor ${anchor.seq}: heads do not hash to the timestamped value`);
    for (const [node, head] of Object.entries(heads)) if (!holds(node, head)) problems.push(`anchor ${anchor.seq}: head ${node}:${head.seq} differs from the rows`);
  }
  const tokens: Report['tokens'] = [];
  if (e.anchors) {
    for (const anchor of e.manifest.anchors) {
      const item = e.anchors.items.find((a) => a.seq === anchor.seq && a.hash === anchor.hash);
      if (!item || sha256(item.token) !== anchor.tokenSha256) problems.push(`anchor ${anchor.seq}: token missing or not the one the manifest signed`);
      else tokens.push(item);
    }
  }
  const pinned = signed && e.pins !== undefined && pinnedSigner(e.signature, keys, e.pins.keys, e.keyring);
  return { ok: problems.length === 0, pinned, problems, chains, anchorsChecked: e.manifest.anchors.length, tokens };
}

/** The JWKS of the day plus the keyring's retained public keys it no longer lists: a key leaves the JWKS once its
 *  verification windows close (tokens.ts jwks), but a manifest it signed before a rotation still names it. Same trust
 *  as the JWKS (both come from the server); only a pin or a TSA token anchors the verdict. */
function withKeyring(jwks: { keys: JsonWebKey[] }, keyring?: SigningKeyDisk): { keys: JsonWebKey[] } {
  const listed = new Set(jwks.keys.map((k) => (k as { kid?: string }).kid));
  const retained = (keyring?.keys ?? []).flatMap((k) => {
    if (listed.has(k.kid)) return [];
    try { return [{ ...createPublicKey(k.publicKey).export({ format: 'jwk' }), kid: k.kid } as JsonWebKey]; } catch { return []; }
  });
  return { keys: [...jwks.keys, ...retained] };
}

/** True when the manifest's signer is held out of band: its `x` is pinned, or a pinned key introduced it at a rotation
 *  listed in `keyring` (the keyring's public half, replica-protocol.ts TrustedKeys; a retired parent introduces nothing). */
function pinnedSigner(jws: string, jwks: { keys: JsonWebKey[] }, pins: JsonWebKey[], keyring?: SigningKeyDisk): boolean {
  try {
    const { kid } = JSON.parse(Buffer.from(jws.split('.')[0]!, 'base64url').toString()) as { kid?: string };
    const x = (jwks.keys.find((k) => (k as { kid?: string }).kid === kid))?.x;
    const trusted = new TrustedKeys(pins.flatMap((k) => (typeof k.x === 'string' ? [k.x] : [])));
    return kid !== undefined && x !== undefined && (trusted.x.has(x) || trusted.learn(keyring).get(kid) === x);
  } catch { return false; }
}

/** The verdict printed: `ok` only when the evidence is consistent AND tied to something the serving tenant cannot forge,
 *  TSA tokens accepted by the authority's CA or a signing key held out of band. The rows, manifest and JWKS all come
 *  from the same server, so otherwise they prove self-consistency only. */
export function verdict(report: Report, tokensVerified: number): { ok: boolean; result: string; anchoredBy: string[] } {
  const anchoredBy = [...(tokensVerified > 0 ? ['tsa'] : []), ...(report.pinned ? ['pinned signing key'] : [])];
  const result = report.problems.length ? 'failed' : anchoredBy.length ? 'ok' : 'self-consistent only (not anchored)';
  return { ok: result === 'ok', result, anchoredBy };
}

/** openssl ts -verify of each token against the TSA's CA: the authority vouches for the hash and its time. */
function verifyTokens(tokens: Report['tokens'], caFile: string): string[] {
  const dir = mkdtempSync(join(tmpdir(), 'gate-tokens-'));
  try {
    return tokens.flatMap(({ seq, hash, token }) => {
      const file = join(dir, `${seq}.tsr`);
      writeFileSync(file, Buffer.from(token, 'base64'));
      try { execFileSync('openssl', ['ts', '-verify', '-digest', hash, '-in', file, '-token_in', '-CAfile', caFile], { stdio: 'pipe' }); return []; }
      catch { return [`anchor ${seq}: openssl ts -verify refused the token`]; }
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: { rows: { type: 'string' }, manifest: { type: 'string' }, jwks: { type: 'string' }, anchors: { type: 'string' }, 'tsa-ca': { type: 'string' },
    pin: { type: 'string' }, keyring: { type: 'string' } } });
  if (!values.rows || !values.manifest || !values.jwks || (values.keyring && !values.pin)) {
    console.error('Usage: node scripts/audit/verify-export.ts --rows <ndjson> --manifest <json> --jwks <json> [--anchors <json> [--tsa-ca <pem>]] [--pin <jwks> [--keyring <json>]]');
    process.exit(2);
  }
  const json = (file: string): any => JSON.parse(readFileSync(file, 'utf8'));
  const signed = json(values.manifest) as { manifest: Manifest; signature: string };
  const rows = readFileSync(values.rows, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line) as AuditRecord);
  const report = verifyEvidence({ rows, manifest: signed.manifest, signature: signed.signature, jwks: json(values.jwks), ...(values.anchors ? { anchors: json(values.anchors) } : {}),
    ...(values.pin ? { pins: json(values.pin) } : {}), ...(values.keyring ? { keyring: json(values.keyring) } : {}) });
  if (values['tsa-ca']) report.problems.push(...verifyTokens(report.tokens, values['tsa-ca']));
  const tokensChecked = values['tsa-ca'] ? report.tokens.length : 0;
  const { ok, result, anchoredBy } = verdict(report, tokensChecked);
  console.log(JSON.stringify({ ok, result, anchoredBy, problems: report.problems, chains: report.chains, anchorsChecked: report.anchorsChecked, tokensChecked }, null, 2));
  process.exit(ok ? 0 : result === 'failed' ? 1 : 3);
}
