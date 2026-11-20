// SIGNING_KEY_SEAL rotation (docs/handbook/operations/rotate-credentials.md): the node starts with the new key as
// SIGNING_KEY_SEAL and the old one as SIGNING_KEY_SEAL_PREVIOUS; at start everything sealed at rest is re-sealed under the
// new key, in the transaction of the start's first commit, with one audit row. Nothing is ever sealed with the previous key.
import type { Backing } from './store.ts';
import type { Credentials } from './auth.ts';
import { seal, unseal, type SigningKeyDisk } from './tokens.ts';

export interface Resealed { signingKeys: number; totpSecrets: number }
const SEALED = /^v[12]\./;

/** Checks that every sealed value at rest (signing keyring, TOTP secrets) opens under `current` or `previous`, and
 *  re-seals under `current` those only `previous` opens. When a value opens under neither it throws having saved
 *  nothing: sealed material is never discarded or overwritten. Returns how many values were re-sealed. */
export function resealAtRest(keyring: Backing<SigningKeyDisk>, credentials: Backing<Credentials>, current: Buffer, previous?: Buffer): Resealed {
  const counts: Resealed = { signingKeys: 0, totpSecrets: 0 };
  const unopened: string[] = [];
  const reseal = (value: string, aad: string, what: string, counter: keyof Resealed): string => {
    try { unseal(value, current, aad); return value; } catch { /* not sealed under the current key */ }
    if (previous) {
      try { const plain = unseal(value, previous, aad); counts[counter]++; return seal(plain, current, aad); } catch { /* under neither */ }
    }
    unopened.push(what);
    return value;
  };
  const disk = keyring.load();
  const keys = disk?.keys.map((key) => key.privateKey && SEALED.test(key.privateKey)
    ? { ...key, privateKey: reseal(key.privateKey, key.kid, `signing key ${key.kid}`, 'signingKeys') } : key);
  const stored = credentials.load();
  const users = stored?.users.map((user) => user.totp
    ? { ...user, totp: { ...user.totp, secret: reseal(user.totp.secret, `totp:${user.id}`, `TOTP secret of ${user.id}`, 'totpSecrets') } } : user);
  if (unopened.length) {
    const keysTried = previous ? 'SIGNING_KEY_SEAL or SIGNING_KEY_SEAL_PREVIOUS' : 'SIGNING_KEY_SEAL';
    throw new Error(`${unopened.length} sealed value(s) at rest do not open under ${keysTried} (${unopened.slice(0, 5).join(', ')}${unopened.length > 5 ? ', ...' : ''}). `
      + 'Nothing was changed. Start with the key that sealed them as SIGNING_KEY_SEAL, or as SIGNING_KEY_SEAL_PREVIOUS to rotate (docs/handbook/operations/rotate-credentials.md).');
  }
  if (disk && keys && counts.signingKeys) keyring.save({ ...disk, keys });
  if (stored && users && counts.totpSecrets) credentials.save({ ...stored, users });
  return counts;
}

/** A rotation in progress: some sealed value at rest opens only under `previous` (nothing is saved). False when every
 *  value opens under `current`, and when some opens under neither (the start then refuses in resealAtRest). */
export function sealedUnderPrevious(keyring: unknown, credentials: unknown, current: Buffer, previous: Buffer): boolean {
  const view = <T>(value: unknown): Backing<T> => ({ load: () => value as T | undefined, save: () => undefined });
  try {
    const counts = resealAtRest(view<SigningKeyDisk>(keyring), view<Credentials>(credentials), current, previous);
    return counts.signingKeys + counts.totpSecrets > 0;
  } catch { return false; }
}
