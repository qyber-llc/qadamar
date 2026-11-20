// CBAC (context-based access control, Zero Trust): situational signals are checked again on every decision. A required signal that is
// absent is UNKNOWN, never an implicit pass; filters turn the same failed requirements into a resource-scoped residual.
import { BlockList, isIP } from 'node:net';
import { and, not, or, TRUE } from './conditions.ts';
import type { ActionKind, Context, ContextRule, ContextTimeWindow, Expr, Json, Request } from './types.ts';

export const MAX_AUTH_METHODS = 16;
export const MAX_AUTH_METHOD_LENGTH = 32;
export const COUNTRIES = new Set('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' '));
const ISO_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const CLOCK = /^(?:[01]\d|2[0-3]):[0-5]\d$/;

export function validInstant(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false;
  const match = ISO_INSTANT.exec(value);
  if (!match || !Number.isFinite(Date.parse(value))) return false;
  const year = Number(match[1]), month = Number(match[2]), day = Number(match[3]);
  const hour = Number(match[4]), minute = Number(match[5]), second = Number(match[6]);
  if (hour > 23 || minute > 59 || second > 59) return false;
  const calendar = new Date(Date.UTC(year, month - 1, day));
  return calendar.getUTCFullYear() === year && calendar.getUTCMonth() === month - 1 && calendar.getUTCDate() === day;
}
export const validCountry = (value: unknown): value is string => typeof value === 'string' && COUNTRIES.has(value);
// '%' (an IPv6 zone id) names a local interface, not an address: refused
export const validIp = (value: unknown): value is string => typeof value === 'string' && value.length <= 45 && !value.includes('%') && isIP(value) !== 0;
export const validAuthMethods = (value: unknown): value is readonly string[] => Array.isArray(value) && value.length <= MAX_AUTH_METHODS &&
  value.every((method) => typeof method === 'string' && /^[A-Za-z0-9_.-]{1,32}$/.test(method));

export function cidrParts(value: unknown): { address: string; prefix: number; family: 4 | 6 } | undefined {
  if (typeof value !== 'string' || value.length > 64 || value.includes('%')) return undefined;
  const parts = value.split('/');
  if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1] ?? '')) return undefined;
  const address = parts[0] as string;
  const family = isIP(address);
  const prefix = Number(parts[1]);
  if (!family || prefix > (family === 4 ? 32 : 128)) return undefined;
  return { address, prefix, family: family as 4 | 6 };
}

function blockList(ranges: readonly string[]): BlockList {
  const list = new BlockList();
  for (const cidr of ranges) {
    const range = cidrParts(cidr);
    if (range) list.addSubnet(range.address, range.prefix, range.family === 4 ? 'ipv4' : 'ipv6');
  }
  return list;
}
const inList = (list: BlockList, ip: string): boolean => {
  const family = validIp(ip) ? isIP(ip) : 0;
  return family !== 0 && list.check(ip, family === 4 ? 'ipv4' : 'ipv6');
};

export function ipInRange(ip: string, cidr: string): boolean {
  return cidrParts(cidr) !== undefined && inList(blockList([cidr]), ip);
}

/** One BlockList per rule, built on first use: a decision checks every range of a rule in one lookup. Bundles are
 *  immutable once loaded, so the rule object is the cache key. */
const ruleRanges = new WeakMap<ContextRule, BlockList>();
export function rangesOf(rule: ContextRule): BlockList {
  let list = ruleRanges.get(rule);
  if (!list) { list = blockList(rule.ipRanges ?? []); ruleRanges.set(rule, list); }
  return list;
}

export function validTimeZone(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) return false;
  try { new Intl.DateTimeFormat('en', { timeZone: value }); return true; } catch { return false; }
}

// one formatter per time zone (bounded by the IANA zones the validator accepts), not one per window and decision
const formatters = new Map<string, Intl.DateTimeFormat>();
function formatter(timeZone: string): Intl.DateTimeFormat {
  let f = formatters.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', { timeZone, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
    formatters.set(timeZone, f);
  }
  return f;
}

function localTime(now: string, timeZone: string): { day: number; minutes: number } {
  const parts = formatter(timeZone).formatToParts(Date.parse(now));
  const value = (type: string): string => parts.find((part) => part.type === type)?.value ?? '';
  const day = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(value('weekday'));
  return { day: day === 0 ? 7 : day, minutes: Number(value('hour')) * 60 + Number(value('minute')) };
}

const minutes = (value: string): number => Number(value.slice(0, 2)) * 60 + Number(value.slice(3, 5));
export const validClock = (value: unknown): value is string => typeof value === 'string' && CLOCK.test(value);

/** Start inclusive, end exclusive. Overnight windows test the current start day or the previous start day. */
export function inTimeWindow(now: string, window: ContextTimeWindow): boolean {
  const local = localTime(now, window.timeZone);
  const from = minutes(window.from), to = minutes(window.to);
  const current = window.days.includes(local.day);
  const previous = window.days.includes(local.day === 1 ? 7 : local.day - 1);
  return from < to ? current && local.minutes >= from && local.minutes < to
    : (current && local.minutes >= from) || (previous && local.minutes < to);
}

export interface ContextCheck {
  readonly requirement: string;
  readonly code: string;
  readonly observed: Json;
  readonly ok: boolean;
  readonly detail: string;
}

const check = (requirement: string, code: string, observed: Json, ok: boolean, detail: string): ContextCheck =>
  ({ requirement, code: ok ? code : observed === null ? 'CBAC.SIGNAL_MISSING' : code, observed, ok, detail });
const fresh = (now: string, asserted: string | undefined, maximum: number): boolean | undefined => {
  if (asserted === undefined) return undefined;
  const age = Date.parse(now) - Date.parse(asserted);
  return age >= 0 && age <= maximum * 1000;
};

/** One entry per declared requirement, including both device posture assertions independently. */
export function contextChecks(rule: ContextRule, ctx: Context): ContextCheck[] {
  const out: ContextCheck[] = [];
  if (rule.network !== undefined) out.push(check('network', 'CBAC.NETWORK', ctx.network, ctx.network === rule.network, `network must be ${rule.network}`));
  if (rule.countries !== undefined) out.push(check('countries', 'CBAC.COUNTRY', ctx.country ?? null, ctx.country !== undefined && rule.countries.includes(ctx.country), `country must be one of ${rule.countries.join(', ')}`));
  if (rule.ipRanges !== undefined) out.push(check('ipRanges', 'CBAC.IP_RANGE', ctx.ip ?? null, ctx.ip !== undefined && inList(rangesOf(rule), ctx.ip), `IP must be in ${rule.ipRanges.join(', ')}`));
  if (rule.timeWindows !== undefined) out.push(check('timeWindows', 'CBAC.TIME_WINDOW', ctx.now, rule.timeWindows.some((window) => inTimeWindow(ctx.now, window)), 'decision time must be inside an allowed local window'));
  if (rule.device?.managed !== undefined) out.push(check('device.managed', 'CBAC.DEVICE_UNMANAGED', ctx.device?.managed ?? null, ctx.device?.managed === rule.device.managed, `device managed must be ${rule.device.managed}`));
  if (rule.device?.compliant !== undefined) out.push(check('device.compliant', 'CBAC.DEVICE_NONCOMPLIANT', ctx.device?.compliant ?? null, ctx.device?.compliant === rule.device.compliant, `device compliant must be ${rule.device.compliant}`));
  if (rule.mfaMaxAgeSeconds !== undefined) {
    const ok = fresh(ctx.now, ctx.mfaTime, rule.mfaMaxAgeSeconds);
    out.push(check('mfaMaxAgeSeconds', 'CBAC.MFA_STALE', ctx.mfaTime ?? null, ok === true, `MFA age must be 0..${rule.mfaMaxAgeSeconds} seconds and not in the future`));
  }
  if (rule.authMaxAgeSeconds !== undefined) {
    const ok = fresh(ctx.now, ctx.authTime, rule.authMaxAgeSeconds);
    out.push(check('authMaxAgeSeconds', 'CBAC.AUTH_STALE', ctx.authTime ?? null, ok === true, `authentication age must be 0..${rule.authMaxAgeSeconds} seconds and not in the future`));
  }
  if (rule.authMethodsAny !== undefined) out.push(check('authMethodsAny', 'CBAC.AUTH_METHOD', ctx.authMethods === undefined ? null : [...ctx.authMethods], ctx.authMethods !== undefined && rule.authMethodsAny.some((method) => ctx.authMethods?.includes(method)), `one authentication method of ${rule.authMethodsAny.join(', ')} is required`));
  if (rule.maxRiskScore !== undefined) out.push(check('maxRiskScore', 'CBAC.RISK', ctx.riskScore ?? null, ctx.riskScore !== undefined && ctx.riskScore <= rule.maxRiskScore, `risk score must be at most ${rule.maxRiskScore}`));
  return out;
}

export function contextRuleSelected(rule: ContextRule, type: string, action: string, kind: ActionKind): boolean {
  return (!rule.resourceTypes || rule.resourceTypes.includes(type)) && (!rule.actions || rule.actions.includes(action)) &&
    (!rule.actionKinds || rule.actionKinds.includes(kind));
}

export function contextRuleApplies(rule: ContextRule, req: Request, kind: ActionKind): boolean {
  return contextRuleSelected(rule, req.resource.type, req.action, kind) &&
    (rule.minResourceLevel === undefined || req.resource.level >= rule.minResourceLevel) &&
    (!rule.contentClasses || rule.contentClasses.some((name) => req.resource.contentClasses?.includes(name)));
}

function resourceScope(rule: ContextRule): Expr {
  const parts: Expr[] = [];
  if (rule.minResourceLevel !== undefined) parts.push({ op: 'ge', left: { path: 'resource.level' }, right: { value: rule.minResourceLevel } });
  if (rule.contentClasses) parts.push(or(rule.contentClasses.map((name): Expr => ({ op: 'contains', left: { path: 'resource.contentClasses' }, right: { value: name } }))));
  return and(parts);
}

/** Request-level requirements become no-row predicates only where the resource selector matches. */
export function contextFilter(rules: readonly ContextRule[], type: string, action: string, kind: ActionKind, ctx: Context): Expr {
  const denies = rules.filter((rule) => contextRuleSelected(rule, type, action, kind) && contextChecks(rule, ctx).some((item) => !item.ok))
    .map((rule) => not(resourceScope(rule)));
  return denies.length ? and(denies) : TRUE;
}
