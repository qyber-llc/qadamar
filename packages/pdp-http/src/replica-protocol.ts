// Stateless decision replicas (docs/API.md §3.9.5): what a database node and a replica share. A replica authenticates
// every request with an HMAC hop header (forward.ts format) under a key derived from its own replica key; a database
// node signs every answer to a replica with its decision-token keyring (Ed25519, detached JWS over the body's SHA-256),
// which the replica verifies against keys it trusts (a pin, or the JWKS over verified TLS, then key introductions).
import { createHash, createPublicKey, hkdfSync, verify, type KeyObject } from 'node:crypto';
import { canonical } from '../../core/src/index.ts';
import { NODE_ID } from './postgres-chains.ts';
import { LEGACY_NODE, type AuditRecord, type Head } from './audit.ts';
import { decodeSeal, keyIntroduction, type SigningKeyDisk, type Tokens } from './tokens.ts';
import type { RecordDelta } from './record-deltas.ts';
import type { RecordSnapshot } from './postgres-records.ts';
import type { SessionRevocation } from './pep-sessions.ts';

export const REPLICA_HOP_HEADER = 'x-gate-replica-hop';
export const REPLICA_SIGNATURE_HEADER = 'x-gate-replica-signature';
export const REPLICA_TYP = 'gate-replica/v1';
export const REPLICA_PATHS = '/x/v1/replica/';
const HOP_LABEL = 'qadamar/replica-hop/hmac-sha256/v1';
export const REPLICA_CHECKPOINT_LABEL = 'qadamar/replica-audit-checkpoint/hmac-sha256/v1';
export const REPLICA_TRUST_LABEL = 'qadamar/replica-trust/hmac-sha256/v1';
/** Longest a database node holds a state request open for a change before it answers "nothing new". */
export const MAX_WAIT_MS = 25_000;

export interface Generation { version: number; records: number }
/** What a replica decides on: the state document without workflow data, PEP credentials only, public keys and revocations. */
export interface ReplicaDocs { state: unknown; credentials: unknown; signing_keys: SigningKeyDisk; blp_revocations: SessionRevocation[] }
export interface SubjectsUpdate { epoch: string; n: number; full?: Record<string, string>; changes?: Array<readonly [string, string | null]> }
/** The signed body of GET /x/v1/replica/state. `records` (every record row) or `deltas` (changes since `after`). */
export interface StateMessage {
  typ: typeof REPLICA_TYP; kind: 'state'; aud: string; nonce: string; at: Generation;
  docs?: ReplicaDocs; docsHash: string; deltas?: RecordDelta[]; records?: RecordSnapshot; subjects: SubjectsUpdate;
  config: { blpSessionRequired: boolean };
}
/** The signed body of POST /x/v1/replica/audit. */
export interface AuditMessage { typ: typeof REPLICA_TYP; kind: 'audit'; aud: string; nonce: string; head: Head; refused?: string }
/** Every answer names its signing key (public entry): a key rotated an instant ago is learned from its introduction. */
export type Signer = SigningKeyDisk['keys'][number];
export interface AuditBatch { base: Head; rows: AuditRecord[] }

export const derive = (key: Buffer, label: string): Buffer => Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), label, 32));
export const hopKeyOf = (key: Buffer): Buffer => derive(key, HOP_LABEL);
export const digest = (body: Buffer | string): string => createHash('sha256').update(body).digest('base64url');

/** A replica id: a chain id (NODE_ID) other than the legacy chain "0". */
export function replicaId(value: string | undefined, name = 'GATE_NODE_ID'): string {
  if (value === undefined || !NODE_ID.test(value) || value === LEGACY_NODE) throw new Error(`${name} must name the replica (1..64 of [A-Za-z0-9_.-], first a letter or digit, not "0")`);
  return value;
}
/** GATE_REPLICA_KEYS on a database node: `id=key,id=key`, each key 32 bytes as base64url or hex. An id ending in `*`
 *  is a group whose key is a master: each replica id with that prefix holds only its own key, derived from the master
 *  for that id (replicaKeyOf), so one replica's key never authenticates a sibling. */
export function parseReplicaKeys(raw: string | undefined): Map<string, Buffer> | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  const keys = new Map<string, Buffer>();
  for (const entry of raw.split(',').map((e) => e.trim()).filter(Boolean)) {
    const at = entry.indexOf('=');
    const name = at > 0 ? entry.slice(0, at) : undefined;
    const id = name?.endsWith('*') ? `${replicaId(`${name.slice(0, -1)}0`, 'GATE_REPLICA_KEYS ids').slice(0, -1)}*` : replicaId(name, 'GATE_REPLICA_KEYS ids');
    if (keys.has(id)) throw new Error(`GATE_REPLICA_KEYS names ${id} twice`);
    keys.set(id, decodeSeal(entry.slice(at + 1), 'GATE_REPLICA_KEYS keys')!);
  }
  return keys;
}

/** The GATE_REPLICA_KEYS entry that holds `id`'s key: its own, else the first group whose prefix it has. */
export function replicaKeyEntry(keys: ReadonlyMap<string, Buffer>, id: string): string | undefined {
  if (id === LEGACY_NODE || !NODE_ID.test(id)) return undefined;
  return keys.has(id) ? id : [...keys.keys()].find((name) => name.endsWith('*') && id.startsWith(name.slice(0, -1)));
}

const REPLICA_KEY_LABEL = 'qadamar/replica-key/v1/';
/** The key replica `id` holds when its database nodes list it under a group master: HKDF(master, label + id). */
export const replicaKeyOf = (master: Buffer, id: string): Buffer => derive(master, `${REPLICA_KEY_LABEL}${replicaId(id, 'replica id')}`);
/** The key that authenticates replica `id` (hops, audit row MACs): its own entry, else derived from its group's master. */
export function replicaKeyFor(keys: ReadonlyMap<string, Buffer>, id: string): Buffer | undefined {
  const entry = replicaKeyEntry(keys, id);
  if (entry === undefined) return undefined;
  return entry === id ? keys.get(id) : replicaKeyOf(keys.get(entry)!, id);
}

/** A database node's signature on an answer to a replica: the active key signs {typ, sha256 of the body}. */
export const signBody = (tokens: Tokens, body: string): string => tokens.detached({ typ: REPLICA_TYP, sha256: digest(body) });

/** An Ed25519 public key as its JWK `x` (the form of pins and of the trusted set). */
export const keyX = (publicKey: string | KeyObject): string => {
  const jwk = (typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey).export({ format: 'jwk' });
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') throw new Error('Not an Ed25519 key');
  return jwk.x;
};
const fromX = (x: string): KeyObject => createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
function verifyDetached(x: string, pack: unknown, jws: string): boolean {
  try {
    const [header, empty, signature, extra] = jws.split('.');
    if (!header || empty !== '' || !signature || extra !== undefined) return false;
    return verify(null, Buffer.from(`${header}.${Buffer.from(canonical(pack)).toString('base64url')}`), fromX(x), Buffer.from(signature, 'base64url'));
  } catch { return false; }
}
const kidOf = (jws: string): string | undefined => {
  try {
    const header = JSON.parse(Buffer.from(jws.slice(0, jws.indexOf('.')), 'base64url').toString()) as { alg?: unknown; kid?: unknown };
    return header.alg === 'EdDSA' && typeof header.kid === 'string' ? header.kid : undefined;
  } catch { return undefined; }
};

/** The keys a replica trusts, as JWK `x` values. A key of a keyring becomes trusted when its own `x` already is (a pin,
 *  the bootstrap JWKS) or when a trusted key introduced it at a rotation (tokens.ts keyIntroduction); nothing in an
 *  unverified message can make a key trusted any other way. */
export class TrustedKeys {
  readonly x: Set<string>;
  constructor(x: Iterable<string>) { this.x = new Set(x); }
  /** Trusts every key of `keyring` reachable by introductions from a trusted one; returns kid -> x of the trusted ones. */
  learn(keyring: SigningKeyDisk | undefined, now = Date.now()): Map<string, string> {
    const keys = (keyring?.keys ?? []).map((k) => ({ ...k, x: keyX(k.publicKey) }));
    let grew = true;
    while (grew) {
      grew = false;
      for (const k of keys) {
        if (this.x.has(k.x) || !k.introducedBy) continue;
        const parent = keys.find((p) => p.kid === k.introducedBy!.kid);
        // a key past its verification window introduces nothing (it may have leaked after it was retired)
        if (parent && this.x.has(parent.x) && !(parent.verifyUntil && Date.parse(parent.verifyUntil) <= now) && verifyDetached(parent.x, keyIntroduction(k.kid, k.publicKey), k.introducedBy.jws)) { this.x.add(k.x); grew = true; }
      }
    }
    return new Map(keys.filter((k) => this.x.has(k.x)).map((k) => [k.kid, k.x]));
  }
  /** After a verified keyring is applied: keys it no longer lists (rotated out and pruned) stop being trusted. */
  keep(keyring: SigningKeyDisk, now = Date.now()): void {
    const listed = new Set(this.learn(keyring, now).values());
    for (const x of [...this.x]) if (!listed.has(x)) this.x.delete(x);
  }
  /** True when `jws` signs this exact body with a trusted key of `keyring` that is not past its verification window. */
  verifies(body: Buffer, jws: string | undefined, keyring: SigningKeyDisk | undefined, now = Date.now()): boolean {
    if (!jws) return false;
    const kid = kidOf(jws);
    const key = keyring?.keys.find((k) => k.kid === kid);
    const x = kid === undefined ? undefined : this.learn(keyring, now).get(kid);
    if (!key || !x || (key.verifyUntil && Date.parse(key.verifyUntil) <= now)) return false;
    return verifyDetached(x, { typ: REPLICA_TYP, sha256: digest(body) }, jws);
  }
}
