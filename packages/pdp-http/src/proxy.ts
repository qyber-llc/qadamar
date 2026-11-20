// TRUSTED_PROXIES: the client address behind a reverse proxy (ingress controller, load balancer). X-Forwarded-For is
// read only when the connecting address is a trusted proxy; the client is then the rightmost entry that is not itself
// a trusted proxy, so entries a client wrote on the left of the header are never believed.
import type { IncomingMessage } from 'node:http';
import { BlockList, isIP } from 'node:net';

/** Parses a comma-separated list of addresses or CIDR ranges (IPv4 or IPv6). Empty: no proxy is trusted. */
export function trustedProxies(raw: string | undefined): BlockList | undefined {
  const entries = (raw ?? '').split(',').map((e) => e.trim()).filter(Boolean);
  if (!entries.length) return undefined;
  const list = new BlockList();
  for (const entry of entries) {
    const [address = '', prefix, extra] = entry.split('/');
    const family = isIP(address);
    const bits = prefix === undefined ? (family === 6 ? 128 : 32) : /^\d{1,3}$/.test(prefix) ? Number(prefix) : NaN;
    if (!family || extra !== undefined || !(bits >= 0 && bits <= (family === 6 ? 128 : 32))) {
      throw new Error(`TRUSTED_PROXIES: invalid address or CIDR range "${entry}"`);
    }
    list.addSubnet(address, bits, family === 6 ? 'ipv6' : 'ipv4');
  }
  return list;
}

/** An address as a socket or a proxy writes it: IPv4-mapped IPv6 unmapped, brackets and a port removed. */
export function normalizeAddress(raw: string): string | undefined {
  let value = raw.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed) value = bracketed[1]!;
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value)) value = value.slice(0, value.lastIndexOf(':'));
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1]!;
  return isIP(value) ? value : undefined;
}

const isTrusted = (list: BlockList, address: string): boolean => list.check(address, isIP(address) === 6 ? 'ipv6' : 'ipv4');

/** The address used for rate limiting, login lockouts, the audit and traces. */
export function clientAddress(req: IncomingMessage, proxies: BlockList | undefined): string {
  const peer = normalizeAddress(req.socket.remoteAddress ?? '');
  if (!peer) return req.socket.remoteAddress ?? 'unknown';
  if (!proxies || !isTrusted(proxies, peer)) return peer;
  const header = req.headers['x-forwarded-for'];
  const hops = (Array.isArray(header) ? header.join(',') : header ?? '').split(',').reverse();
  let client = peer;
  for (const hop of hops) {
    if (!hop.trim()) continue;
    const address = normalizeAddress(hop);
    if (!address) break; // malformed: keep the last address a trusted proxy vouched for
    client = address;
    if (!isTrusted(proxies, address)) break;
  }
  return client;
}
