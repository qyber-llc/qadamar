// Encrypts or decrypts a backup archive with AES-256-GCM, streaming. Usage:
//   BACKUP_ENCRYPTION_KEY=<64 hex | 43 base64url> node scripts/ops/archive-crypt.ts encrypt|decrypt <in> <out>
// Format: "GATEBK" | version 1 | 12-byte random nonce (this header is the GCM additional data) | ciphertext | 16-byte tag.
// <out> is created exclusively with mode 600 and removed on any failure, so a decrypted file that survives is authentic.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { closeSync, createReadStream, createWriteStream, fstatSync, lstatSync, openSync, readSync, rmSync } from 'node:fs';
import { pipeline } from 'node:stream/promises';

const MAGIC = Buffer.from('GATEBK');
const VERSION = 1;
const NONCE = 12;
const TAG = 16;
const HEADER = MAGIC.length + 1 + NONCE;

class Refusal extends Error {}

/** Same rule as decodeSeal (packages/pdp-http/src/tokens.ts): 64 hexadecimal characters or canonical unpadded base64url of 32 bytes. */
function decodeKey(value = ''): Buffer {
  if (/^[a-f0-9]{64}$/i.test(value)) return Buffer.from(value, 'hex');
  const key = Buffer.from(value, 'base64url');
  if (key.length !== 32 || key.toString('base64url') !== value) {
    throw new Refusal('BACKUP_ENCRYPTION_KEY must be 32 bytes as 64 hexadecimal characters or unpadded base64url');
  }
  return key;
}

async function encrypt(key: Buffer, input: string, out: number): Promise<void> {
  const nonce = randomBytes(NONCE);
  const header = Buffer.concat([MAGIC, Buffer.from([VERSION]), nonce]);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(header);
  await pipeline(createReadStream(input), async function* (source: AsyncIterable<Buffer>) {
    yield header;
    for await (const chunk of source) yield cipher.update(chunk);
    yield cipher.final();
    yield cipher.getAuthTag();
  }, createWriteStream('', { fd: out }));
}

async function decrypt(key: Buffer, input: string, out: number): Promise<void> {
  const fd = openSync(input, 'r');
  const header = Buffer.alloc(HEADER);
  const tag = Buffer.alloc(TAG);
  const size = fstatSync(fd).size;
  if (size < HEADER + TAG || readSync(fd, header, 0, HEADER, 0) !== HEADER || readSync(fd, tag, 0, TAG, size - TAG) !== TAG) {
    closeSync(fd);
    throw new Refusal('the archive is truncated');
  }
  if (!header.subarray(0, MAGIC.length).equals(MAGIC) || header[MAGIC.length] !== VERSION) {
    closeSync(fd);
    throw new Refusal('not a Qadamar backup archive of version 1');
  }
  const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(MAGIC.length + 1), { authTagLength: 16 });
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  await pipeline(async function* () {
    // an empty plaintext has no byte range to stream (createReadStream rejects end < start)
    if (size === HEADER + TAG) closeSync(fd);
    else for await (const chunk of createReadStream('', { fd, start: HEADER, end: size - TAG - 1 })) yield decipher.update(chunk);
    try {
      yield decipher.final();
    } catch {
      throw new Refusal('authentication failed: wrong key, or a damaged or tampered archive');
    }
  }, createWriteStream('', { fd: out }));
}

async function main(argv: string[]): Promise<void> {
  const [mode, input, output] = argv;
  if (argv.length !== 3 || (mode !== 'encrypt' && mode !== 'decrypt') || !input || !output) {
    throw new Refusal('usage: BACKUP_ENCRYPTION_KEY=... node archive-crypt.ts encrypt|decrypt <in> <out>');
  }
  const key = decodeKey(process.env.BACKUP_ENCRYPTION_KEY);
  if (lstatSync(output, { throwIfNoEntry: false })) throw new Refusal('the output already exists; refusing to overwrite it');
  const out = openSync(output, 'wx', 0o600);
  try {
    await (mode === 'encrypt' ? encrypt : decrypt)(key, input, out);
  } catch (error) {
    rmSync(output, { force: true });
    throw error;
  }
}

try {
  await main(process.argv.slice(2));
} catch (error) {
  // fixed messages and error codes only: nothing that could carry the key
  const reason = error instanceof Refusal ? error.message : (error as NodeJS.ErrnoException).code ?? 'unexpected error';
  process.stderr.write(`archive-crypt: ${reason}\n`);
  process.exitCode = 1;
}
