// RFC 9110 §7.6.1: hop-by-hop fields, and any field the Connection header names, never cross the proxy.
import type { IncomingHttpHeaders, OutgoingHttpHeaders } from 'node:http';

const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

/** Request fields forwarded to every route; anything else the client sends is dropped unless the route declares it.
 *  No If-None-Match: the upstream would answer 304, which the gateway refuses as a non-2xx (502), and every released
 *  answer is no-store anyway. */
export const REQUEST_ALLOW = ['content-type', 'accept', 'accept-language', 'if-match'];
/** A request carrying one of these could run another method upstream than the one the PDP decided: refused (400). */
export const METHOD_OVERRIDE = ['x-http-method-override', 'x-method-override', 'x-http-method'];
/** Fields a route may not add to its allowlist: credentials, routing, framing, method overrides and the decision assertion stay with the gateway. */
const NEVER = new Set([...HOP_BY_HOP, ...METHOD_OVERRIDE, 'host', 'content-length', 'authorization', 'cookie', 'accept-encoding', 'expect', 'forwarded', 'gate-assertion']);
export const forbiddenRequestHeader = (name: string): boolean => NEVER.has(name) || name.startsWith('x-forwarded-');
/** A rewritten body gets its own length; validators of the original body would describe released-but-hidden content. */
export const REWRITE_DROP = ['content-length', 'content-encoding', 'etag', 'content-md5', 'digest', 'last-modified'];

export function endToEnd(headers: IncomingHttpHeaders, drop: readonly string[]): OutgoingHttpHeaders {
  const listed = String(headers.connection ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const out: OutgoingHttpHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    const name = key.toLowerCase();
    if (value === undefined || HOP_BY_HOP.has(name) || listed.includes(name)) continue;
    if (drop.some((d) => (d.endsWith('-') ? name.startsWith(d) : name === d))) continue;
    out[name] = value;
  }
  return out;
}

/** The client fields the upstream receives: the base allowlist plus the route's own extras, end-to-end fields only. */
export function allowedRequestHeaders(headers: IncomingHttpHeaders, extra: readonly string[] = []): OutgoingHttpHeaders {
  const allow = new Set([...REQUEST_ALLOW, ...extra]);
  return Object.fromEntries(Object.entries(endToEnd(headers, [])).filter(([name]) => allow.has(name)));
}
