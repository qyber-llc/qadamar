// RFC 6238 TOTP for local console accounts: HMAC-SHA-1, 6 digits, 30 s steps, one step of drift either way.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_MS = 30_000;
const ISSUER = 'Qadamar';

/** RFC 4648 base32 without padding, as authenticator apps expect it. */
export function base32(bytes: Buffer): string {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = ((value << 8) | byte) & 0xffff; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits > 0 ? out + ALPHABET[(value << (5 - bits)) & 31] : out;
}
export function fromBase32(text: string): Buffer {
  const bytes: number[] = [];
  let bits = 0, value = 0;
  for (const char of text) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error('Invalid base32');
    value = ((value << 5) | index) & 0xffff; bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(bytes);
}
/** RFC 4226 HOTP truncated to 6 digits. */
export function hotp(key: Buffer, counter: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', key).update(message).digest();
  const offset = mac[mac.length - 1]! & 0xf;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}
/** The time step a 6-digit code matches at `ms` (wall clock), within ±1 step; undefined when it matches none. */
export function totpStep(key: Buffer, code: unknown, ms: number): number | undefined {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return undefined;
  const current = Math.floor(ms / STEP_MS);
  let found: number | undefined;
  // every candidate is compared, so the time taken does not tell which step matched
  for (const step of [current - 1, current, current + 1]) {
    if (timingSafeEqual(Buffer.from(hotp(key, step)), Buffer.from(code)) && found === undefined) found = step;
  }
  return found;
}
export const newTotpSecret = (): string => base32(randomBytes(20));
export const otpauthUri = (account: string, secret: string): string =>
  `otpauth://totp/${encodeURIComponent(`${ISSUER}:${account}`)}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=6&period=30`;
/** 80 random bits, shown as xxxx-xxxx-xxxx-xxxx; only its SHA-256 is stored (high entropy: no slow hash needed). */
export const newRecoveryCode = (): string => base32(randomBytes(10)).toLowerCase().match(/.{4}/g)!.join('-');
export const recoveryDigest = (code: string): string => createHash('sha256').update(code.replace(/[\s-]/g, '').toUpperCase()).digest('hex');
