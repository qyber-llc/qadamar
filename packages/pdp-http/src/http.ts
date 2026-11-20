import type { IncomingMessage, ServerResponse } from 'node:http';

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown[];
  constructor(status: number, code: string, message = code, details?: unknown[]) {
    super(message); this.status = status; this.code = code; this.details = details;
  }
}
/** `message` says what was expected, so a client sees which field is wrong rather than a bare bad_request. */
export function object(value: unknown, message?: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new HttpError(400, 'bad_request', message);
  return value as Record<string, unknown>;
}
export function string(value: unknown): string {
  if (typeof value !== 'string' || !value.length) throw new HttpError(400, 'bad_request');
  return value;
}
export function reason(value: unknown): string {
  const result = string(value);
  if (result.trim().length < 20) throw new HttpError(422, 'unprocessable', 'Reason must contain at least 20 characters');
  return result;
}
const readBodies = new WeakMap<IncomingMessage, Promise<Buffer>>();
/** The request body (1 MB at most), read once: a cluster hop reads it to check its digest, then body() reuses it. */
export function rawBody(req: IncomingMessage): Promise<Buffer> {
  const known = readBodies.get(req);
  if (known) return known;
  const read = readRawBody(req);
  readBodies.set(req, read);
  return read;
}
function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((accept, reject) => {
    const chunks: Buffer[] = [];
    let size = 0, settled = false, tooLarge = false;
    const refuse = (err: HttpError): void => { if (!settled) { settled = true; reject(err); } };
    req.on('data', (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > 1_048_576) { chunks.length = 0; tooLarge = true; return; }
      if (!tooLarge) chunks.push(Buffer.from(chunk));
    });
    // Finish the upload before the 413 and close: an early answer can reset a client that is still writing.
    req.on('end', () => {
      if (settled) return;
      if (tooLarge) { refuse(new HttpError(413, 'payload_too_large', 'Body exceeds 1 MB')); return; }
      settled = true; accept(Buffer.concat(chunks));
    });
    req.on('error', () => refuse(new HttpError(400, 'bad_request', 'Incomplete body')));
    req.on('aborted', () => refuse(new HttpError(400, 'bad_request', 'Incomplete body')));
  });
}
export async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  // application/scim+json (SCIM) and application/xacml+json (XACML JSON Profile): like application/json, no cross-site form sends them
  if (!/^application\/(?:(?:scim|xacml)\+)?json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json');
  const raw = await rawBody(req);
  try { return object(JSON.parse(raw.toString('utf8'))); }
  catch (err) { if (err instanceof HttpError) throw err; throw new HttpError(400, 'bad_request', 'Invalid JSON'); }
}
/** `maxValue`: the longest value accepted (a posted SAML message is larger than the default). */
export async function formBody(req: IncomingMessage, maxValue = 16_384): Promise<URLSearchParams> {
  if (!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/x-www-form-urlencoded');
  const form = new URLSearchParams((await rawBody(req)).toString('utf8'));
  if ([...form.keys()].length > 8 || [...form.values()].some((value) => value.length > maxValue)) throw new HttpError(400, 'bad_request');
  return form;
}
/** Secure cookies whenever the console is reached over TLS: directly, or behind a TLS-terminating proxy declared by an
 *  https PUBLIC_ORIGIN (X-Forwarded-Proto is not trusted, since any client can send it). */
export function secureFlag(req: IncomingMessage, publicOrigin?: string): string {
  const tls = Boolean(req.socket && 'encrypted' in req.socket && req.socket.encrypted);
  return tls || publicOrigin?.startsWith('https://') ? '; Secure' : '';
}
export function headers(res: ServerResponse, api = true, hsts = false): void {
  if (hsts) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (api) res.setHeader('Cache-Control', 'no-store');
}
export function json(res: ServerResponse, value: unknown, status = 200, type = 'application/json'): void {
  res.statusCode = status;
  if (status === 204) { res.end(); return; }
  res.setHeader('Content-Type', `${type}; charset=utf-8`);
  res.end(JSON.stringify(value));
}
export function failure(res: ServerResponse, err: unknown): void {
  const e = err instanceof HttpError ? err : new HttpError(500, 'internal', 'Internal server error');
  json(res, { error: e.code, message: e.message, ...(e.details ? { details: e.details } : {}) }, e.status);
}
