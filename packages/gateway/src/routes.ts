// Route table of the gateway: method + path pattern → resource type, id and action. Anything not declared is refused.
import { forbiddenRequestHeader } from './headers.ts';
import { Refusal } from './refusal.ts';

export interface RouteConfig {
  readonly method: string;
  /** Literal segments and `:name` parameters, e.g. `/cases/:id`. */
  readonly path: string;
  readonly resourceType: string;
  readonly action: string;
  /** Single resource: the parameter holding its id (default: the only parameter of the path). */
  readonly idParam?: string;
  /** List endpoint (GET only): where the items are in the JSON response ('' = top-level array) and each item's id field. */
  readonly list?: { readonly items: string; readonly idField?: string };
  /** Request fields forwarded beyond the base allowlist (content-type, accept, accept-language, if-match). */
  readonly headers?: readonly string[];
  /** Query parameters forwarded; any other parameter is dropped. `_method` is refused, never forwarded. */
  readonly query?: readonly string[];
  /** 'body': the JSON object body is the item's state the upstream commits; sent to the PDP as the post-state a certified
   *  command's integrity checks need. A route without it is refused when the PDP asks for a post-state. */
  readonly postState?: 'body';
}
export interface Route extends RouteConfig { readonly segments: readonly string[] }
export interface Matched { readonly route: Route; readonly id?: string }

const LITERAL = /^[A-Za-z0-9._~-]+$/;
const PARAM = /^:[A-Za-z][A-Za-z0-9_]*$/;
const UNSAFE_KEY = new Set(['__proto__', 'prototype', 'constructor']);
const TOKEN = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;

export function fieldPath(value: string): string[] {
  if (value === '') return [];
  const parts = value.split('.');
  if (parts.some((p) => p.length === 0 || UNSAFE_KEY.has(p))) throw new TypeError(`Invalid field path: ${value}`);
  return parts;
}

export function compileRoutes(routes: readonly RouteConfig[]): Route[] {
  if (!Array.isArray(routes) || routes.length === 0) throw new TypeError('At least one route is required');
  const compiled: Route[] = routes.map((r) => {
    if (!/^[A-Z]+$/.test(r.method)) throw new TypeError(`Invalid route method: ${String(r.method)}`);
    if (typeof r.path !== 'string' || !r.path.startsWith('/')) throw new TypeError(`Invalid route path: ${String(r.path)}`);
    const segments: string[] = r.path.split('/').slice(1);
    if (segments.some((s) => !LITERAL.test(s) && !PARAM.test(s))) throw new TypeError(`Invalid route path: ${r.path}`);
    if (!r.resourceType || !r.action) throw new TypeError(`Route ${r.method} ${r.path} needs a resource type and an action`);
    const params = segments.filter((s) => s.startsWith(':')).map((s) => s.slice(1));
    if (r.list) {
      // the upstream is called before the per-item decisions, so a list route must not change anything
      if (r.method !== 'GET') throw new TypeError(`List route ${r.path} must be GET`);
      fieldPath(r.list.items);
      fieldPath(r.list.idField ?? 'id');
    } else {
      const id = r.idParam ?? (params.length === 1 ? params[0] : undefined);
      if (!id || !params.includes(id)) throw new TypeError(`Route ${r.method} ${r.path} needs one id parameter`);
    }
    const where = `Route ${r.method} ${r.path}`;
    if (r.headers !== undefined && (!Array.isArray(r.headers) || r.headers.some((h: unknown) => typeof h !== 'string' || !TOKEN.test(h) || forbiddenRequestHeader(h)))) {
      throw new TypeError(`${where}: headers must be lower-case field names other than credentials, routing, framing or method overrides`);
    }
    if (r.query !== undefined && (!Array.isArray(r.query) || r.query.some((q: unknown) => typeof q !== 'string' || q.length === 0 || q === '_method'))) {
      throw new TypeError(`${where}: query must list parameter names (never _method)`);
    }
    if (r.postState !== undefined && (r.postState !== 'body' || r.list)) throw new TypeError(`${where}: postState must be 'body' on a single-resource route`);
    return { ...r, segments };
  });
  // match() takes the first route: one that an earlier route matches entirely would be decided with that route's action
  compiled.forEach((later, i) => {
    const earlier = compiled.slice(0, i).find((e) => e.method === later.method && e.segments.length === later.segments.length &&
      e.segments.every((s, k) => s.startsWith(':') || s === later.segments[k]));
    if (earlier) throw new TypeError(`Route ${later.method} ${later.path} is shadowed by ${earlier.method} ${earlier.path}: list the more specific route first`);
  });
  return compiled;
}

function param(raw: string): string {
  let value: string;
  try { value = decodeURIComponent(raw); } catch { throw new Refusal(400, 'bad_request'); }
  // an id the upstream could read as another path, or a control character, is refused rather than guessed
  if (value.length === 0 || value.length > 256 || /[/\\\u0000-\u001f\u007f]/.test(value) || value === '.' || value === '..') throw new Refusal(400, 'bad_request');
  return value;
}

export function match(routes: readonly Route[], method: string, pathname: string): Matched | undefined {
  const parts = pathname.split('/').slice(1);
  for (const route of routes) {
    if (route.method !== method || route.segments.length !== parts.length) continue;
    const values: Record<string, string> = {};
    const ok = route.segments.every((s, i) => {
      const part = parts[i] as string;
      if (!s.startsWith(':')) return s === part;
      values[s.slice(1)] = param(part);
      return true;
    });
    if (!ok) continue;
    if (route.list) return { route };
    const name = route.idParam ?? route.segments.find((s) => s.startsWith(':'))?.slice(1) ?? '';
    return { route, id: values[name] };
  }
  return undefined;
}
