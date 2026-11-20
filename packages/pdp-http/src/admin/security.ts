import type { Runtime } from '../runtime.ts';
import type { Auth, User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { HttpError } from '../http.ts';
import { resignLatest } from '../policy-signature.ts';
import { knownType } from '../resource-registry.ts';

interface AdminResult { value: unknown; status: number }
export function securityAdmin(rt: Runtime, auth: Auth | undefined, user: User, method: string, path: string, b: Record<string, unknown>): AdminResult | undefined {
  if (path === '/blp-sessions/revocations' && method === 'GET') {
    allowed(user, ['access_admin', 'security_officer']);
    return { value: { items: rt.pepSessions?.revocations() ?? [] }, status: 200 };
  }
  if (path === '/blp-sessions/revoke' && method === 'POST') {
    allowed(user, ['security_officer']);
    if (!rt.pepSessions) throw new HttpError(503, 'unavailable', 'Session service unavailable');
    return { value: rt.pepSessions.revoke(b, user.id), status: 200 };
  }
  if (path === '/pep-credentials' || path.startsWith('/pep-credentials/')) {
    if (!auth) throw new HttpError(500, 'internal');
    if (method === 'GET' && path === '/pep-credentials') {
      allowed(user, ['access_admin', 'security_officer']);
      return { value: { items: auth.pepCredentials() }, status: 200 };
    }
    allowed(user, ['security_officer']);
    if (method === 'POST' && path === '/pep-credentials') {
      // a binding to a type the policy does not declare could never be used: refused rather than kept for later
      if (Array.isArray(b.resourceTypes) && b.resourceTypes.some((t) => typeof t !== 'string' || !knownType(rt.store.state.bundle, t))) {
        throw new HttpError(400, 'bad_request', 'resourceTypes must name resource types of the policy');
      }
      return { value: auth.createPepCredential(b.name, user.id, b.subjectTypes, b.allowSubjectSearch, b.resourceTypes, b.contextScopes), status: 201 };
    }
    const action = /^\/pep-credentials\/([^/]+)\/(rotate|revoke)$/.exec(path);
    if (method === 'POST' && action) {
      const id = action[1]!;
      return action[2] === 'rotate'
        ? { value: auth.rotatePepCredential(id, user.id), status: 200 }
        : { value: auth.revokePepCredential(id, user.id), status: 200 };
    }
  }
  if (path === '/signing-keys' && method === 'GET') {
    allowed(user, ['access_admin', 'security_officer']);
    return { value: { items: rt.tokens.signingKeys() }, status: 200 };
  }
  if (path === '/signing-keys/rotate' && method === 'POST') {
    allowed(user, ['security_officer']);
    // audited before the keyring changes, with the new kid: a refused append leaves the current key in force
    const rotated = rt.tokens.rotate((next) => { rt.audit.append({ type: 'security', actor: user.id, action: 'signing_key_rotate', details: next }); });
    resignLatest(rt.store, rt.tokens); // the previous key leaves the keyring after its grace period: re-sign the bundle in force
    return { value: rotated, status: 201 };
  }
  return undefined;
}
