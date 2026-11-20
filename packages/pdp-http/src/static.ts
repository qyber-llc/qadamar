import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { resolve, sep, extname } from 'node:path';
import type { ServerResponse } from 'node:http';
import { HttpError } from './http.ts';

export function safePath(raw: string): string {
  let path: string;
  const query = raw.indexOf('?');
  try { path = decodeURIComponent(query < 0 ? raw : raw.slice(0, query)); } catch { throw new HttpError(400, 'bad_request'); }
  if (!path.startsWith('/') || path.includes('\\') || path.includes('\0') || path.split('/').some((p) => p === '..' || p === '.' || p.startsWith('.'))) {
    if (path === '/.well-known/authzen-configuration' || path === '/.well-known/jwks.json') return path;
    throw new HttpError(400, 'bad_request', 'Unsafe path');
  }
  return path;
}
export function serveStatic(dir: string, path: string, res: ServerResponse): void {
  safePath(path);
  if (!existsSync(dir)) throw new HttpError(404, 'not_found');
  const root = realpathSync(dir);
  let target = resolve(root, `.${path}`);
  const inside = (file: string): boolean => file === root || file.startsWith(root + sep);
  if (!inside(target)) throw new HttpError(400, 'bad_request');
  if (!existsSync(target)) target = resolve(root, 'index.html');
  else if (statSync(target).isDirectory()) target = resolve(target, 'index.html');
  if (!existsSync(target) || !statSync(target).isFile()) throw new HttpError(404, 'not_found');
  if (!inside(realpathSync(target))) throw new HttpError(400, 'bad_request');
  const types: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };
  res.setHeader('Content-Type', types[extname(target)] ?? 'application/octet-stream');
  res.end(readFileSync(target));
}
