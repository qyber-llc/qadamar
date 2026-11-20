// The signed verification material a tenant's security officer or auditor takes away with the audit rows
// (GET /admin/v1/audit/export), so the chain, the sealed segments and the RFC 3161 anchors can be checked offline,
// without trusting this server: scripts/audit/verify-export.ts (docs/MANAGED-OFFER.md §13).
import { readFileSync } from 'node:fs';
import { canonical } from '../../../core/src/index.ts';
import type { Runtime } from '../runtime.ts';
import { allowed, type User } from '../auth.ts';
import { LEGACY_NODE, sha256, type Head } from '../audit.ts';
import { HttpError } from '../http.ts';

export const VERIFICATION_FORMAT = 'gate-audit-verification/1';
const VERSION = (JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string }).version;

/** GET /admin/v1/audit/verification → { manifest, signature }: a detached EdDSA JWS over canonical(manifest). */
export async function auditVerification(rt: Runtime, user: User, url: URL): Promise<{ manifest: Record<string, unknown>; signature: string }> {
  allowed(user, ['security_officer', 'auditor']);
  if ([...url.searchParams.keys()].length) throw new HttpError(400, 'bad_request');
  const checked = rt.audit.recheck ? await rt.audit.recheck() : undefined;
  const verification = rt.audit.verify();
  // the heads just verified (several chains: one per node); a failed recheck leaves the current head
  const point: Head & { heads?: Record<string, Head> } = checked || rt.audit.tip();
  const heads: Record<string, Head> = point.heads ?? { [LEGACY_NODE]: { seq: point.seq, hash: point.hash } };
  const manifest = {
    format: VERIFICATION_FORMAT, product: { name: 'Qadamar', version: VERSION }, generatedAt: rt.now(), generatedBy: user.id,
    verification, heads,
    // the seal's HMAC needs the deployment seal key, which a customer never holds: the head it commits to is what counts
    segments: (rt.audit.segments ?? []).map(({ mac: _mac, anchor: _anchor, ...segment }) => segment),
    anchors: rt.audit.anchors.map((a) => ({ seq: a.seq, hash: a.hash, tsa: a.tsa, genTime: a.genTime, tokenSha256: sha256(a.token), ...(a.heads ? { heads: a.heads } : {}) })),
    tsa: rt.anchoring?.url ? new URL(rt.anchoring.url).origin : null,
    verify: 'Detached EdDSA JWS over canonical(manifest), keys at /.well-known/jwks.json; rows from /admin/v1/audit/export (not pseudonymised); tokens from /admin/v1/audit/anchors.',
  };
  const signature = rt.tokens.detached(manifest);
  rt.audit.append({ type: 'security', actor: user.id, action: 'audit_verification_export',
    details: { manifestSha256: sha256(canonical(manifest)), chains: Object.keys(heads).length, anchors: manifest.anchors.length } });
  return { manifest, signature };
}
