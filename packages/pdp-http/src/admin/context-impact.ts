import { canonical, cidrParts, contentRules, validAuthMethods, validCountry, validInstant, validIp } from '../../../core/src/index.ts';
import type { Context, ContextRule, ContextTimeWindow, Expr, Json, Operand, PolicyBundle } from '../../../core/src/index.ts';

export const IMPACT_CONTEXT_CLASS_LIMIT = 32;

type AxisName = 'country' | 'ip' | 'now' | 'device' | 'mfaTime' | 'authTime' | 'authMethods' | 'riskScore' | 'sessionExpired';
type Axis = { readonly name: AxisName; readonly values: readonly unknown[] };
export interface ContextPartition {
  readonly contexts: readonly Context[];
  readonly truncated: boolean;
  readonly incomplete: boolean;
  readonly unsupported: readonly string[];
  readonly partitioned: boolean;
}
interface ExpressionRequirements {
  readonly paths: ReadonlySet<string>;
  readonly literals: Partial<Record<AxisName, unknown[]>>;
  readonly unsupported: readonly string[];
}

const unique = <T>(values: readonly T[]): T[] => [...new Map(values.map((value) => [canonical(value), value])).values()];
const sorted = <T>(values: readonly T[]): T[] => unique(values).sort((a, b) => canonical(a).localeCompare(canonical(b)));
const PATH_AXES: Readonly<Record<string, AxisName>> = {
  'context.country': 'country', 'context.ip': 'ip', 'context.now': 'now', 'context.device': 'device',
  'context.device.managed': 'device', 'context.device.compliant': 'device', 'context.mfaTime': 'mfaTime', 'context.authTime': 'authTime',
  'context.authMethods': 'authMethods', 'context.riskScore': 'riskScore', 'context.sessionExpired': 'sessionExpired',
};
const EXISTING_VARIANTS = new Set(['context.network', 'context.makerId', 'context.serverMakerId', 'context.priorActions']);
const ORDERED = new Set(['lt', 'le', 'gt', 'ge']);

function notePath(out: { paths: Set<string>; unsupported: Set<string> }, path: string): AxisName | undefined {
  if (!path.startsWith('context.')) return undefined;
  if (EXISTING_VARIANTS.has(path)) { out.paths.add(path); return undefined; }
  const axis = PATH_AXES[path];
  if (axis === undefined) out.unsupported.add(`context path ${path} cannot be partitioned`);
  else out.paths.add(path);
  return axis;
}

function validLiteral(axis: AxisName, value: Json): boolean {
  if (axis === 'country') return validCountry(value);
  if (axis === 'ip') return validIp(value);
  if (axis === 'now' || axis === 'mfaTime' || axis === 'authTime') return validInstant(value);
  if (axis === 'riskScore') return Number.isInteger(value) && Number(value) >= 0 && Number(value) <= 100;
  if (axis === 'authMethods') return validAuthMethods(value);
  if (axis === 'sessionExpired') return typeof value === 'boolean';
  return typeof value === 'boolean' || (typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length === 2 &&
    Object.entries(value).every(([key, item]) => ['managed', 'compliant'].includes(key) && typeof item === 'boolean'));
}

function addLiteral(out: { literals: Partial<Record<AxisName, unknown[]>>; unsupported: Set<string> }, axis: AxisName, value: Json): void {
  if (!validLiteral(axis, value)) { out.unsupported.add(`literal for ${axis} is outside the request grammar`); return; }
  (out.literals[axis] ??= []).push(value);
}

function addBoundary(out: { literals: Partial<Record<AxisName, unknown[]>>; unsupported: Set<string> }, axis: AxisName, value: Json, now: number): void {
  if (axis === 'riskScore' && typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 100) {
    for (const candidate of [Math.max(0, value - 1), value, Math.min(100, value + 1)]) addLiteral(out, axis, candidate);
    return;
  }
  if ((axis === 'now' || axis === 'mfaTime' || axis === 'authTime') && validInstant(value)) {
    const instant = Date.parse(value);
    if (axis === 'now') {
      for (const candidate of [instant - 1000, instant, instant + 1000]) addLiteral(out, axis, new Date(candidate).toISOString());
    } else {
      const age = Math.round((now - instant) / 1000);
      for (const candidate of [age - 1, age, age + 1]) (out.literals[axis] ??= []).push(candidate);
    }
    return;
  }
  out.unsupported.add(`ordered comparison for ${axis} has no supported boundary`);
}

function comparison(expr: Extract<Expr, { left: Operand }>, out: { paths: Set<string>; literals: Partial<Record<AxisName, unknown[]>>; unsupported: Set<string> }, now: number): void {
  const paths = [expr.left, expr.right].filter((operand) => 'path' in operand).map((operand) => (operand as { path: string }).path).filter((path) => path.startsWith('context.'));
  const axes = paths.map((path) => notePath(out, path));
  if (paths.length === 0) return;
  if (paths.length > 1 || axes[0] === undefined) {
    if (paths.some((path) => !EXISTING_VARIANTS.has(path))) out.unsupported.add(`${expr.op} comparison between context paths cannot be partitioned`);
    return;
  }
  const axis = axes[0];
  const path = paths[0]!;
  const other = 'path' in expr.left ? expr.right : expr.left;
  if (!('value' in other)) { out.unsupported.add(`${expr.op} comparison for ${path} has no literal`); return; }
  if (expr.op === 'eq' || expr.op === 'ne') { addLiteral(out, axis, other.value); return; }
  if (expr.op === 'in') {
    if ('path' in expr.left && Array.isArray(other.value)) for (const value of other.value) addLiteral(out, axis, value);
    else if ('path' in expr.right && axis === 'authMethods') addLiteral(out, axis, [other.value]);
    else out.unsupported.add(`in comparison for ${path} needs an array of literals`);
    return;
  }
  if (expr.op === 'contains') {
    if ('path' in expr.left && axis === 'authMethods') addLiteral(out, axis, [other.value]);
    else if ('path' in expr.left) addLiteral(out, axis, other.value);
    else out.unsupported.add(`contains comparison for ${path} needs the context value on the left`);
    return;
  }
  if (expr.op === 'subset') {
    if ('path' in expr.left && Array.isArray(other.value)) addLiteral(out, axis, other.value);
    else out.unsupported.add(`subset comparison for ${path} needs a literal array`);
    return;
  }
  if (ORDERED.has(expr.op)) { addBoundary(out, axis, other.value, now); return; }
  out.unsupported.add(`${expr.op} comparison for ${path} is not supported`);
}

function expressionPaths(expr: Expr, out: { paths: Set<string>; literals: Partial<Record<AxisName, unknown[]>>; unsupported: Set<string> }, now: number): void {
  if (expr.op === 'and' || expr.op === 'or') { for (const arg of expr.args) expressionPaths(arg, out, now); return; }
  if (expr.op === 'not') { expressionPaths(expr.arg, out, now); return; }
  if (expr.op === 'has') { notePath(out, expr.path); return; }
  if (expr.op === 'true' || expr.op === 'unknown') return;
  if ('left' in expr) comparison(expr, out, now);
}

function expressionRequirements(bundles: readonly PolicyBundle[], now: number): ExpressionRequirements {
  const out = { paths: new Set<string>(), literals: {} as Partial<Record<AxisName, unknown[]>>, unsupported: new Set<string>() };
  for (const bundle of bundles) {
    for (const rule of bundle.abac) expressionPaths(rule.when, out, now);
    for (const rule of contentRules(bundle)) if (rule.unless) expressionPaths(rule.unless, out, now);
  }
  for (const axis of Object.keys(out.literals) as AxisName[]) out.literals[axis] = sorted(out.literals[axis]!);
  return { paths: out.paths, literals: out.literals, unsupported: [...out.unsupported].sort() };
}

function outsideCountry(countries: readonly string[]): string[] {
  for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
    const candidate = `${String.fromCharCode(a)}${String.fromCharCode(b)}`;
    if (validCountry(candidate) && !countries.includes(candidate)) return [candidate];
  }
  return [];
}

interface Interval { readonly start: bigint; readonly end: bigint; readonly family: 4 | 6 }
function ipInteger(ip: string): bigint {
  if (validIp(ip) && !ip.includes(':')) return BigInt(ip.split('.').reduce((value, part) => value * 256 + Number(part), 0));
  const [head, tail] = ip.split('::');
  const convert = (part: string): string[] => part.includes('.') ? [(Number(part.split('.')[0]) * 256 + Number(part.split('.')[1])).toString(16),
    (Number(part.split('.')[2]) * 256 + Number(part.split('.')[3])).toString(16)] : [part || '0'];
  const left = (head ? head.split(':') : []).flatMap(convert);
  const right = (tail ? tail.split(':') : []).flatMap(convert);
  const groups = [...left, ...Array.from({ length: 8 - left.length - right.length }, () => '0'), ...right];
  return groups.reduce((value, group) => (value << 16n) + BigInt(`0x${group}`), 0n);
}
function ipText(value: bigint, family: 4 | 6): string {
  if (family === 4) return [24, 16, 8, 0].map((shift) => Number((value >> BigInt(shift)) & 255n)).join('.');
  const groups = Array.from({ length: 8 }, (_, i) => ((value >> BigInt((7 - i) * 16)) & 0xffffn).toString(16));
  let best = { start: -1, length: 0 };
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== '0') continue;
    let end = i;
    while (end < 8 && groups[end] === '0') end++;
    if (end - i > best.length) best = { start: i, length: end - i };
    i = end;
  }
  if (best.length < 2) return groups.join(':');
  const left = groups.slice(0, best.start).join(':'), right = groups.slice(best.start + best.length).join(':');
  return `${left}::${right}`;
}
function intervalOf(cidr: string): Interval | undefined {
  const parts = cidrParts(cidr);
  if (!parts) return undefined;
  const bits = BigInt(parts.family === 4 ? 32 : 128), prefix = BigInt(parts.prefix), size = 1n << (bits - prefix);
  const start = (ipInteger(parts.address) >> (bits - prefix)) << (bits - prefix);
  return { start, end: start + size - 1n, family: parts.family };
}
const contains = (interval: Interval, value: bigint): boolean => interval.start <= value && value <= interval.end;
function cidrRepresentatives(ranges: readonly string[]): { values: string[]; intervals: Interval[] } {
  const intervals = ranges.map(intervalOf).filter((value): value is Interval => value !== undefined);
  const cuts = [...new Set(intervals.flatMap((interval) => [interval.start, interval.end + 1n]))]
    .filter((cut) => intervals.some((interval) => cut < (1n << BigInt(interval.family === 4 ? 32 : 128)))).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  const classes = new Map<string, bigint>();
  for (const cut of cuts) {
    const signature = intervals.flatMap((interval, index) => contains(interval, cut) ? [index] : []);
    if (!classes.has(signature.join(','))) classes.set(signature.join(','), cut);
  }
  return { values: [...classes.entries()].map(([signature, value]) => {
    const family = signature.length ? intervals[Number(signature.split(',')[0])]!.family : intervals[0]?.family ?? 4;
    return ipText(value, family);
  }), intervals };
}

const IP_CANDIDATES = ['192.0.2.1', '198.51.100.1', '203.0.113.1', '10.0.0.1', '172.16.0.1', '2001:db8::1', '2001:db8:1::1', '::1'];
function ipValues(rules: readonly ContextRule[], referenced: boolean, literals: readonly unknown[]): unknown[] {
  const ranges = rules.flatMap((rule) => rule.ipRanges ?? []);
  const { values, intervals } = cidrRepresentatives(ranges);
  const outside = IP_CANDIDATES.find((ip) => intervals.every((interval) => !contains(interval, ipInteger(ip))));
  return sorted([...values, ...(outside ? [outside] : []), ...literals, ...(referenced && ranges.length === 0 ? IP_CANDIDATES.slice(0, 2) : []), undefined]);
}

interface LocalParts { readonly year: number; readonly month: number; readonly day: number; readonly weekday: number; readonly minutes: number }
const zoneFormatters = new Map<string, Intl.DateTimeFormat>();
function localParts(instant: number, timeZone: string): LocalParts {
  let format = zoneFormatters.get(timeZone);
  if (!format) {
    format = new Intl.DateTimeFormat('en-US', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit', weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
    zoneFormatters.set(timeZone, format);
  }
  const parts = format.formatToParts(instant);
  const value = (type: Intl.DateTimeFormatPartTypes): string => parts.find((part) => part.type === type)?.value ?? '';
  const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(value('weekday'));
  return { year: Number(value('year')), month: Number(value('month')), day: Number(value('day')), weekday: weekday === 0 ? 7 : weekday,
    minutes: Number(value('hour')) * 60 + Number(value('minute')) };
}

const utc = (year: number, month: number, day: number, minutes: number): number =>
  Date.UTC(year, month - 1, day, Math.floor(minutes / 60), minutes % 60);

/** Convert a local wall-clock minute to an instant; the search also handles a DST fold or gap. */
function zonedInstant(year: number, month: number, day: number, minutes: number, timeZone: string): number | undefined {
  const normalized = new Date(utc(year, month, day, minutes));
  year = normalized.getUTCFullYear(); month = normalized.getUTCMonth() + 1; day = normalized.getUTCDate();
  minutes = normalized.getUTCHours() * 60 + normalized.getUTCMinutes();
  const target = utc(year, month, day, minutes);
  const exact = (candidate: number): boolean => {
    const local = localParts(candidate, timeZone);
    return local.year === year && local.month === month && local.day === day && local.minutes === minutes;
  };
  let guess = target;
  for (let i = 0; i < 4; i++) {
    if (exact(guess)) return guess;
    const local = localParts(guess, timeZone);
    const observed = utc(local.year, local.month, local.day, local.minutes);
    const next = guess + target - observed;
    if (next === guess) break;
    guess = next;
  }
  for (let delta = -180; delta <= 180; delta++) {
    const candidate = guess + delta * 60_000;
    if (exact(candidate)) return candidate;
  }
  return undefined;
}

const clockMinutes = (value: string): number => Number(value.slice(0, 2)) * 60 + Number(value.slice(3, 5));
function windowInstants(window: ContextTimeWindow, now: number): number[] {
  const local = localParts(now, window.timeZone);
  const overnight = clockMinutes(window.from) >= clockMinutes(window.to);
  return window.days.flatMap((day) => {
    const delta = (day - local.weekday + 7) % 7;
    const start = new Date(Date.UTC(local.year, local.month - 1, local.day + delta));
    return [{ clock: window.from, offset: 0 }, { clock: window.to, offset: overnight ? 1 : 0 }].flatMap(({ clock, offset }) => {
      const date = new Date(start.getTime() + offset * 86_400_000);
      const year = date.getUTCFullYear(), month = date.getUTCMonth() + 1, monthDay = date.getUTCDate();
      const edge = clockMinutes(clock);
      return [edge - 1, edge, edge + 1].map((minutes) => zonedInstant(year, month, monthDay, minutes, window.timeZone))
        .filter((value): value is number => value !== undefined);
    });
  });
}

function timeValues(rules: readonly ContextRule[], now: number): unknown[] {
  const instants = rules.flatMap((rule) => (rule.timeWindows ?? []).flatMap((window) => windowInstants(window, now)));
  return [...new Set([now, ...instants].map((value) => new Date(value).toISOString()))].sort();
}

function ageValues(rules: readonly ContextRule[], key: 'mfaMaxAgeSeconds' | 'authMaxAgeSeconds', referenced: boolean): unknown[] {
  const limits = rules.map((rule) => rule[key]).filter((value): value is number => value !== undefined);
  const ages = limits.flatMap((limit) => [-1, Math.max(0, limit - 1), limit, limit + 1]);
  return [...new Set([...ages, ...(referenced && limits.length === 0 ? [-1, 0, 1] : []), undefined])].sort((a, b) => {
    if (a === undefined) return 1;
    if (b === undefined) return -1;
    return a - b;
  });
}

function riskValues(rules: readonly ContextRule[], referenced: boolean): unknown[] {
  const limits = rules.map((rule) => rule.maxRiskScore).filter((value): value is number => value !== undefined);
  const values = limits.flatMap((limit) => [Math.max(0, limit - 1), limit, Math.min(100, limit + 1)]);
  return sorted([...values, ...(referenced && limits.length === 0 ? [0, 100] : []), undefined]);
}

function methodValues(rules: readonly ContextRule[], referenced: boolean): unknown[] {
  const methods = rules.flatMap((rule) => rule.authMethodsAny ?? []);
  const listed = methods.map((method) => [method]);
  const outside = methods.length ? [['no-matching-method']] : [];
  return sorted([...listed, ...outside, ...(referenced && methods.length === 0 ? [['pwd'], ['webauthn']] : []), [], undefined]);
}

function axes(before: PolicyBundle, after: PolicyBundle, now: string): { dimensions: Axis[]; unsupported: readonly string[] } {
  const bundles = [before, after] as const;
  const rules = bundles.flatMap((bundle) => bundle.context ?? []);
  const requirements = expressionRequirements(bundles, Date.parse(now));
  const has = (path: string): boolean => requirements.paths.has(path);
  const literals = (axis: AxisName): unknown[] => requirements.literals[axis] ?? [];
  const out: Axis[] = [];
  const countries = rules.flatMap((rule) => rule.countries ?? []);
  if (countries.length || has('context.country')) {
    const perListOutside = unique(rules.flatMap((rule) => rule.countries ? [rule.countries] : [])).flatMap(outsideCountry);
    out.push({ name: 'country', values: sorted([...countries, ...perListOutside, ...literals('country'), ...(countries.length === 0 ? ['AE', 'US'] : []), undefined]) });
  }
  if (rules.some((rule) => rule.ipRanges !== undefined) || has('context.ip')) out.push({ name: 'ip', values: ipValues(rules, has('context.ip'), literals('ip')) });
  if (rules.some((rule) => rule.timeWindows !== undefined) || has('context.now')) out.push({ name: 'now', values: sorted([...timeValues(rules, Date.parse(now)), ...literals('now')]) });
  if (rules.some((rule) => rule.device !== undefined) || has('context.device') || has('context.device.managed') || has('context.device.compliant')) {
    out.push({ name: 'device', values: sorted([...[true, false].flatMap((managed) => [true, false].map((compliant) => ({ managed, compliant }))), ...literals('device'), undefined]) });
  }
  if (rules.some((rule) => rule.mfaMaxAgeSeconds !== undefined) || has('context.mfaTime')) out.push({ name: 'mfaTime', values: sorted([...ageValues(rules, 'mfaMaxAgeSeconds', has('context.mfaTime')), ...literals('mfaTime')]) });
  if (rules.some((rule) => rule.authMaxAgeSeconds !== undefined) || has('context.authTime')) out.push({ name: 'authTime', values: sorted([...ageValues(rules, 'authMaxAgeSeconds', has('context.authTime')), ...literals('authTime')]) });
  if (rules.some((rule) => rule.authMethodsAny !== undefined) || has('context.authMethods')) out.push({ name: 'authMethods', values: sorted([...methodValues(rules, has('context.authMethods')), ...literals('authMethods')]) });
  if (rules.some((rule) => rule.maxRiskScore !== undefined) || has('context.riskScore')) out.push({ name: 'riskScore', values: sorted([...riskValues(rules, has('context.riskScore')), ...literals('riskScore')]) });
  if (rules.length > 0 || has('context.sessionExpired')) out.push({ name: 'sessionExpired', values: [false, true] });
  return { dimensions: out, unsupported: requirements.unsupported };
}

function put(context: Context, axis: AxisName, value: unknown): Context {
  const next = { ...context } as { -readonly [K in keyof Context]: Context[K] };
  if (axis === 'now') {
    const delta = Date.parse(String(value)) - Date.parse(context.now);
    next.now = String(value);
    // Keep authentication ages fixed when a time-window variant isolates the decision clock.
    if (context.authTime !== undefined) next.authTime = new Date(Date.parse(context.authTime) + delta).toISOString();
    if (context.mfaTime !== undefined) next.mfaTime = new Date(Date.parse(context.mfaTime) + delta).toISOString();
    return next;
  }
  if (axis === 'mfaTime' || axis === 'authTime') {
    if (value === undefined) delete next[axis];
    else next[axis] = new Date(Date.parse(context.now) - Number(value) * 1000).toISOString();
    return next;
  }
  if (value === undefined) delete next[axis];
  else Object.assign(next, { [axis]: value });
  return next;
}

/** Representative contexts, with one-signal variants before the cross-product so a small cap still isolates each boundary. */
export function impactContexts(before: PolicyBundle, after: PolicyBundle, now: string, cap = IMPACT_CONTEXT_CLASS_LIMIT): ContextPartition {
  if (!Number.isSafeInteger(cap) || cap < 1) throw new Error('Impact context class cap must be a positive integer');
  const { dimensions, unsupported } = axes(before, after, now);
  const instant = new Date(now).toISOString();
  const base: Context = { network: 'trusted', now: instant, ip: '10.0.0.1', country: 'AE', device: { managed: true, compliant: true },
    authTime: instant, mfaTime: instant, authMethods: ['pwd', 'webauthn'], riskScore: 0 };
  const out: Context[] = [];
  const seen = new Set<string>();
  const add = (context: Context): boolean => {
    const key = canonical(context);
    if (seen.has(key)) return false;
    seen.add(key); out.push(context);
    return out.length > cap;
  };
  const finish = (contexts: readonly Context[], truncated: boolean): ContextPartition => ({ contexts, truncated,
    incomplete: truncated || unsupported.length > 0, unsupported, partitioned: dimensions.length > 0 || unsupported.length > 0 });
  if (add(base)) return finish(out.slice(0, cap), true);
  for (const axis of dimensions) for (const value of axis.values) {
    if (add(put(base, axis.name, value))) return finish(out.slice(0, cap), true);
  }
  const combine = (index: number, context: Context): boolean => {
    if (index === dimensions.length) return add(context);
    const axis = dimensions[index]!;
    for (const value of axis.values) if (combine(index + 1, put(context, axis.name, value))) return true;
    return false;
  };
  const truncated = dimensions.length > 0 && combine(0, base);
  return finish(out, truncated);
}
