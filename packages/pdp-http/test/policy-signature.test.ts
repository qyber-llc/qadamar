// Published policy bundles are signed with the decision-token keyring; startup refuses a bundle that does not verify.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonical, legacyPolicyVersion, policyVersion } from '../../core/src/index.ts';
import type { PolicyBundle } from '../../core/src/index.ts';
import { admin } from '../src/admin/index.ts';
import { Audit } from '../src/audit.ts';
import { checkPolicySignature } from '../src/policy-signature.ts';
import { Store } from '../src/store.ts';
import type { Change, PolicySignature } from '../src/store.ts';
import { Tokens } from '../src/tokens.ts';
import { createServer } from '../src/server.ts';
import { FIXED, WHY, user } from './helpers.ts';

const WORLD = resolve('examples/toy-domain');
function boot(dir: string, adopt = false, now = (): string => FIXED): { store: Store; tokens: Tokens; audit: Audit } {
  const store = new Store(dir, WORLD, now()); const audit = new Audit(resolve(dir, 'audit.jsonl'), now);
  const tokens = new Tokens(dir, now);
  checkPolicySignature(store, tokens, audit, adopt);
  return { store, tokens, audit };
}
function temp(t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync('/tmp/pdp-sig-'); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir;
}
/** What a PEP or auditor does: JWKS key by kid, Ed25519 over "<header>.<base64url(canonical bundle)>". */
function verifyWithJwks(jwks: { keys: Array<Record<string, unknown>> }, bundle: PolicyBundle, signature: PolicySignature): boolean {
  const [header, , sig] = signature.jws.split('.');
  const parsed = JSON.parse(Buffer.from(header!, 'base64url').toString()) as { alg: string; kid: string };
  const jwk = jwks.keys.find((k) => k.kid === parsed.kid);
  if (!jwk || parsed.alg !== 'EdDSA' || parsed.kid !== signature.kid) return false;
  const { kid: ignoredKid, use: ignoredUse, alg: ignoredAlg, ...key } = jwk;
  const signingInput = `${header}.${Buffer.from(canonical(bundle)).toString('base64url')}`;
  return verify(null, Buffer.from(signingInput), createPublicKey({ key: key as never, format: 'jwk' }), Buffer.from(sig!, 'base64url'));
}
const stateFile = (dir: string): string => resolve(dir, 'state.json');
const edit = (dir: string, change: (disk: { state: { bundle: PolicyBundle }; history: Array<{ version: string; signature?: PolicySignature }> }) => void): void => {
  const disk = JSON.parse(readFileSync(stateFile(dir), 'utf8')) as Parameters<typeof change>[0];
  change(disk); writeFileSync(stateFile(dir), JSON.stringify(disk));
};

test('policy versions are SHA-256 over the canonical bundle; legacy FNV ids stay computable', () => {
  const bundle = JSON.parse(readFileSync(resolve(WORLD, 'bundle.json'), 'utf8')) as PolicyBundle;
  assert.match(policyVersion(bundle), /^pv\.[0-9a-f]{64}$/);
  assert.match(legacyPolicyVersion(bundle), /^pv\.[0-9a-f]{16}$/);
});

test('a new store is signed at boot, verifies with the public JWKS alone, and restarts cleanly', (t) => {
  const dir = temp(t);
  const { store, tokens } = boot(dir);
  const latest = store.history.at(-1)!;
  assert.equal(latest.version, policyVersion(store.state.bundle));
  assert.ok(latest.signature && verifyWithJwks(tokens.jwks(), store.state.bundle, latest.signature));
  assert.equal(verifyWithJwks(tokens.jwks(), { ...store.state.bundle, name: 'forged' }, latest.signature), false);
  assert.doesNotThrow(() => boot(dir));
});

test('startup refuses a stored bundle that was changed, even with a recomputed version', (t) => {
  const dir = temp(t);
  boot(dir);
  edit(dir, (disk) => { disk.state.bundle = { ...disk.state.bundle, name: 'tampered' }; });
  assert.throws(() => boot(dir), /does not match its latest publication/);
  edit(dir, (disk) => { disk.history.at(-1)!.version = policyVersion(disk.state.bundle); });
  assert.throws(() => boot(dir), /signature does not verify/);
  assert.throws(() => createServer({ port: 0, dataDir: dir, clock: `fixed:${FIXED}` }), /signature does not verify/);
  // adopting is an explicit, audited operator act
  const adopted = boot(dir, true);
  assert.ok(adopted.audit.records().some((r) => r.type === 'security' && r.action === 'policy_signature_adopt'));
  assert.doesNotThrow(() => boot(dir));
});

test('a legacy unsigned store (FNV version id) is refused until adopted, then verifies', (t) => {
  const dir = temp(t);
  boot(dir);
  edit(dir, (disk) => { const latest = disk.history.at(-1)!; delete latest.signature; latest.version = legacyPolicyVersion(disk.state.bundle); });
  assert.throws(() => boot(dir), /unsigned; check it, then start once with POLICY_SIGNATURE_ADOPT=1/);
  const { store } = boot(dir, true);
  assert.equal(store.history.at(-1)!.version, legacyPolicyVersion(store.state.bundle), 'the historical id is kept');
  assert.doesNotThrow(() => boot(dir));
});

test('a two-person publication stores its signature; GET /policy returns bundle, signature and kid; rotation re-signs', (t) => {
  const dir = temp(t);
  let clock = FIXED;
  const { store, tokens, audit } = boot(dir, false, () => clock);
  const rt = { store, tokens, audit, now: () => clock, started: Date.parse(FIXED), decisions: 0 };
  const call = (id: string, path: string, method = 'GET', b: Record<string, unknown> = {}): unknown =>
    admin(rt, user(id), method, new URL(`http://localhost/admin/v1${path}`), b).value;
  const next = { ...store.state.bundle, name: 'Toy domain, second edition' };
  const proposed = call('amira', '/changes', 'POST', { kind: 'publish_policy', payload: { bundle: next }, reason: WHY }) as Change;
  call('omar', `/changes/${proposed.id}/approve`, 'POST', { reason: WHY });
  const published = store.history.at(-1)!;
  assert.equal(published.version, policyVersion(next)); assert.equal(published.publishedBy, 'amira');
  type PolicyView = { current: { version: string; bundle: PolicyBundle; signature: PolicySignature | null } };
  const view = call('sam', '/policy') as PolicyView;
  assert.equal(view.current.version, published.version);
  assert.ok(view.current.signature && view.current.signature.kid === tokens.signingKeys().find((k) => k.active)!.kid);
  assert.ok(verifyWithJwks(tokens.jwks(), view.current.bundle, view.current.signature));
  // rotation: the bundle in force is re-signed with the new key, so it still verifies once the old key is gone
  const rotated = call('lina', '/signing-keys/rotate', 'POST') as { current: { kid: string } };
  assert.equal(store.history.at(-1)!.signature!.kid, rotated.current.kid);
  clock = '2026-11-08T11:00:00Z';
  assert.ok(!tokens.jwks().keys.some((k) => k.kid === published.signature!.kid), 'the old key has left the JWKS');
  assert.ok(verifyWithJwks(tokens.jwks(), next, (call('sam', '/policy') as PolicyView).current.signature!));
  assert.doesNotThrow(() => boot(dir, false, () => clock));
});

test('a new policy store under an existing audit trail is not signed silently: refused until adopted, and the adoption is audited', (t) => {
  const used = temp(t);
  boot(used).audit.append({ type: 'security', actor: 'system', action: 'probe' });
  // the state is gone but the trail remains: a store created now would sign whatever bundle the world directory holds
  const dir = temp(t);
  writeFileSync(resolve(dir, 'audit.jsonl'), readFileSync(resolve(used, 'audit.jsonl')));
  assert.throws(() => boot(dir), /policy store is new but the audit trail is not/);
  assert.throws(() => boot(dir), /POLICY_SIGNATURE_ADOPT/, 'a second start is still refused');
  const adopted = boot(dir, true);
  const row = adopted.audit.records().at(-1)!;
  assert.equal(row.action, 'policy_signature_adopt');
  assert.doesNotThrow(() => boot(dir));
  // an empty trail is a genuinely new deployment: signed at once, nothing to adopt
  const blank = temp(t);
  assert.equal(boot(blank).audit.records().length, 0);
});
