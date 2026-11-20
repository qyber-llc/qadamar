// Request validation inside the engine: every field the decision depends on is checked before any rule runs, so a
// missing or garbled value (an undefined level, a "Derived" integrity, an unparseable instant) denies instead of
// silently skipping a check. Found by adversarial review: comparisons like `a < b` are false for undefined and NaN.
import { INTEGRITY_RANK } from './mandatory.ts';
import { validAuthMethods, validCountry, validInstant, validIp } from './context.ts';
import type { Context, Request, Resource, Subject } from './types.ts';

export const MAX_DELEGATION_DEPTH = 4;

const isLevel = (v: unknown): boolean => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 3;
const isStrArr = (v: unknown): boolean => Array.isArray(v) && v.every((x) => typeof x === 'string');
const isId = (v: unknown): boolean => typeof v === 'string' && v.length > 0 && v.length <= 256;
const isIntegrity = (v: unknown): boolean => typeof v === 'string' && Object.hasOwn(INTEGRITY_RANK, v);

/** A number past 2^53 - 1: two different JSON integers there can round to the same double and compare equal. Walks
 *  every value the conditions can read, iteratively (no stack overflow) and once per object (a cycle terminates). */
export function hasUnsafeNumber(root: unknown): boolean {
  const stack = [root];
  const seen = new Set<object>();
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === 'number' && Math.abs(v) > Number.MAX_SAFE_INTEGER) return true;
    if (v !== null && typeof v === 'object' && !seen.has(v)) { seen.add(v); for (const x of Object.values(v)) stack.push(x); }
  }
  return false;
}

function subjectErrors(s: Subject | undefined, where: string, depth: number): string[] {
  if (!s || typeof s !== 'object') return [`${where} is missing`];
  const e: string[] = [];
  if (!isId(s.type) || !isId(s.id)) e.push(`${where}.type and .id must be non-empty strings`);
  if (typeof s.active !== 'boolean') e.push(`${where}.active must be a boolean`);
  if (!isStrArr(s.roles)) e.push(`${where}.roles must be a list of strings`);
  if (s.roleAssignments !== undefined && (!Array.isArray(s.roleAssignments) || s.roleAssignments.length > 256 || s.roleAssignments.some((a) =>
    a === null || typeof a !== 'object' || !isId(a.role) || Object.keys(a).some((k) => !['role', 'notBefore', 'notAfter'].includes(k)) ||
    (a.notBefore !== undefined && !validInstant(a.notBefore)) || (a.notAfter !== undefined && !validInstant(a.notAfter)) ||
    (a.notBefore !== undefined && a.notAfter !== undefined && Date.parse(a.notBefore) > Date.parse(a.notAfter))))) {
    e.push(`${where}.roleAssignments must be bounded role/notBefore/notAfter records`);
  }
  if (!isLevel(s.clearance)) e.push(`${where}.clearance must be an integer 0..3`);
  if (!isStrArr(s.compartments)) e.push(`${where}.compartments must be a list of strings`);
  if (!isIntegrity(s.integrity)) e.push(`${where}.integrity must be derived, extracted, system or verified`);
  if (s.type === 'agent' && !s.delegator) e.push(`${where}: an agent must carry the person it acts for`);
  if (s.delegator !== undefined) {
    if (depth >= MAX_DELEGATION_DEPTH) e.push(`${where}: delegation chain longer than ${MAX_DELEGATION_DEPTH}`);
    else e.push(...subjectErrors(s.delegator, `${where}.delegator`, depth + 1));
  }
  return e;
}

function resourceErrors(r: Resource | undefined): string[] {
  if (!r || typeof r !== 'object') return ['resource is missing'];
  const e: string[] = [];
  if (!isId(r.type) || !isId(r.id)) e.push('resource.type and .id must be non-empty strings');
  if (!isLevel(r.level)) e.push('resource.level must be an integer 0..3');
  if (!isStrArr(r.compartments)) e.push('resource.compartments must be a list of strings');
  if (!isIntegrity(r.integrity)) e.push('resource.integrity must be derived, extracted, system or verified');
  // an unscanned resource is not "free of sensitive content": the content scan result is mandatory
  if (!isStrArr(r.contentClasses)) e.push('resource.contentClasses must be a list (empty when scanned and clean)');
  if (r.version !== undefined && !Number.isInteger(r.version)) e.push('resource.version must be an integer');
  return e;
}

export function contextSignalErrors(c: Context): string[] {
  const e: string[] = [];
  if (c.ip !== undefined && !validIp(c.ip)) e.push('context.ip must be an IPv4 or IPv6 literal');
  if (c.country !== undefined && !validCountry(c.country)) e.push('context.country must be an ISO 3166-1 alpha-2 upper-case code');
  if (c.device !== undefined && (c.device === null || typeof c.device !== 'object' || Array.isArray(c.device) ||
    typeof c.device.managed !== 'boolean' || typeof c.device.compliant !== 'boolean' || Object.keys(c.device).some((k) => !['managed', 'compliant'].includes(k)))) {
    e.push('context.device must contain only managed and compliant booleans');
  }
  if (c.authTime !== undefined && !validInstant(c.authTime)) e.push('context.authTime must be an ISO-8601 instant');
  if (c.mfaTime !== undefined && !validInstant(c.mfaTime)) e.push('context.mfaTime must be an ISO-8601 instant');
  if (c.authMethods !== undefined && !validAuthMethods(c.authMethods)) e.push('context.authMethods must be at most 16 method names of at most 32 characters');
  if (c.riskScore !== undefined && (!Number.isInteger(c.riskScore) || c.riskScore < 0 || c.riskScore > 100)) e.push('context.riskScore must be an integer 0..100');
  return e;
}

export function requestErrors(req: Request): string[] {
  if (!req || typeof req !== 'object') return ['request is missing'];
  const e = [...subjectErrors(req.subject, 'subject', 0), ...resourceErrors(req.resource)];
  if (!isId(req.action)) e.push('action must be a non-empty string');
  const c = req.context;
  if (!c || typeof c !== 'object') return [...e, 'context is missing'];
  if (c.network !== 'trusted' && c.network !== 'untrusted') e.push('context.network must be trusted or untrusted');
  // an explicit zone: a zone-less instant would be read in the host's local time
  if (!validInstant(c.now)) e.push('context.now must be an ISO-8601 instant with Z or an offset');
  if (c.sessionLevel !== undefined && !isLevel(c.sessionLevel)) e.push('context.sessionLevel must be an integer 0..3');
  if (c.sessionId !== undefined && !isId(c.sessionId)) e.push('context.sessionId must be a string');
  if (c.highWater !== undefined && !isLevel(c.highWater)) e.push('context.highWater must be an integer 0..3');
  if (c.sessionRequired !== undefined && typeof c.sessionRequired !== 'boolean') e.push('context.sessionRequired must be a boolean');
  if (c.sessionExpired !== undefined && typeof c.sessionExpired !== 'boolean') e.push('context.sessionExpired must be a boolean');
  if (c.makerId !== undefined && !isId(c.makerId)) e.push('context.makerId must be a string');
  if (c.serverMakerId !== undefined && !isId(c.serverMakerId)) e.push('context.serverMakerId must be a string');
  if (c.priorActions !== undefined && !isStrArr(c.priorActions)) e.push('context.priorActions must be a list of strings');
  if (c.certified !== undefined && (!Array.isArray(c.certified) || !c.certified.every((x) => x !== null && typeof x === 'object' && isId(x.resourceType) && isId(x.action) && (x.by === undefined || isStrArr(x.by)) && (x.fingerprint === undefined || typeof x.fingerprint === 'string')))) {
    e.push('context.certified must be a list of { resourceType, action, by?, fingerprint? }');
  }
  if (c.pepSubjectTypes !== undefined && !isStrArr(c.pepSubjectTypes)) e.push('context.pepSubjectTypes must be a list of strings');
  if (c.input !== undefined && (c.input === null || typeof c.input !== 'object' || Array.isArray(c.input))) e.push('context.input must be an object');
  if (hasUnsafeNumber([req.subject, req.resource, c])) e.push('request numbers must lie within ±(2^53 - 1)');
  return [...e, ...contextSignalErrors(c)];
}

export const subjectChainErrors = (s: Subject): string[] => subjectErrors(s, 'subject', 0);

/** The subject, then each person it acts for (bounded). */
export function principals(s: Subject): Subject[] {
  const out: Subject[] = [];
  for (let cur: Subject | undefined = s; cur && out.length <= MAX_DELEGATION_DEPTH; cur = cur.delegator) out.push(cur);
  return out;
}
