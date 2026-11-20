import { legacyPolicyVersion, policyVersion } from '../../core/src/index.ts';
import type { PolicyBundle } from '../../core/src/index.ts';
import type { PolicySignature, Store } from './store.ts';
import type { Tokens } from './tokens.ts';
import type { AuditLog } from './audit.ts';

/** Signs canonical(bundle) with the active decision-token key: a detached JWS a PEP checks against the JWKS. */
export function signPolicy(tokens: Tokens, bundle: PolicyBundle): PolicySignature {
  const jws = tokens.detached(bundle);
  const header = JSON.parse(Buffer.from(jws.slice(0, jws.indexOf('.')), 'base64url').toString()) as { kid: string };
  return { alg: 'EdDSA', kid: header.kid, jws };
}
/** Re-signs the bundle in force (latest publication) with the active key, e.g. after a key rotation. */
export function resignLatest(store: Store, tokens: Tokens): void {
  const latest = store.history.at(-1);
  if (!latest) throw new Error('No policy publication to sign');
  store.history = [...store.history.slice(0, -1), { ...latest, signature: signPolicy(tokens, store.state.bundle) }];
  store.save();
}
/** Startup: the stored bundle must be the latest publication and carry a signature of this keyring. A store created
 *  now is signed at once only when the audit chain is empty too (a genuinely new deployment): a state that vanished
 *  under an existing audit trail is not new. Otherwise `adopt` (POLICY_SIGNATURE_ADOPT) signs it, audited. */
export function checkPolicySignature(store: Store, tokens: Tokens, audit: AuditLog, adopt = false): void {
  const bundle = store.state.bundle; const latest = store.history.at(-1);
  if (!latest || ![policyVersion(bundle), legacyPolicyVersion(bundle)].includes(latest.version)) {
    throw new Error('Stored policy bundle does not match its latest publication');
  }
  if (latest.signature && tokens.verifyDetached(bundle, latest.signature.jws)) return;
  const fresh = store.fresh && audit.tip().seq === 0;
  if (!fresh && !adopt) {
    throw new Error(store.fresh
      ? 'The policy store is new but the audit trail is not; check it, then start once with POLICY_SIGNATURE_ADOPT=1 to sign it'
      : latest.signature
        ? 'Stored policy bundle signature does not verify against the signing keyring'
        : 'Stored policy bundle is unsigned; check it, then start once with POLICY_SIGNATURE_ADOPT=1 to sign it');
  }
  resignLatest(store, tokens);
  if (!fresh) {
    audit.append({ type: 'security', actor: 'system', action: 'policy_signature_adopt', policyVersion: policyVersion(bundle),
      details: { kid: store.history.at(-1)?.signature?.kid, previousKid: latest.signature?.kid ?? null, freshStore: store.fresh } });
  }
}
