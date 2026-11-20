// Search candidates in stored-array positions. Residual atoms share path indexes, and their TRUE/FALSE sets retain
// three-valued logic: UNKNOWN belongs to neither, so NOT and OR cannot turn a missing attribute into a match.
import { compare, evalTri, MISSING, resolvePath } from './conditions.ts';
import { actionDef, appliesTo, rbacGrant, withLiveRoles } from './evaluate.ts';
import { mandatoryFindings } from './mandatory.ts';
import { keyOf, knownSubjects, type Graph } from './relations.ts';
import { canonical } from './version.ts';
import type { Context, Expr, Json, Operand, PolicyBundle, Resource, Subject } from './types.ts';

const words = (length: number): number => Math.ceil(length / 32);

export class CandidateSet {
  readonly length: number;
  readonly bits: Uint32Array;

  constructor(length: number, bits?: Uint32Array) {
    this.length = length;
    this.bits = bits ?? new Uint32Array(words(length));
  }

  static all(length: number): CandidateSet {
    const bits = new Uint32Array(words(length));
    bits.fill(0xffffffff);
    if (length % 32 !== 0 && bits.length > 0) bits[bits.length - 1] = (1 << (length % 32)) - 1;
    return new CandidateSet(length, bits);
  }

  static empty(length: number): CandidateSet { return new CandidateSet(length); }

  static fromPositions(length: number, positions: readonly number[]): CandidateSet {
    const bits = new Uint32Array(words(length));
    for (const at of positions) bits[at >>> 5] = (bits[at >>> 5] ?? 0) | (1 << (at & 31));
    return new CandidateSet(length, bits);
  }

  next(from: number): number {
    let at = Math.max(0, Math.trunc(from));
    if (at >= this.length) return this.length;
    let word = at >>> 5;
    let values = (this.bits[word] ?? 0) & (0xffffffff << (at & 31));
    while (word < this.bits.length) {
      if (values !== 0) {
        const lowest = values & -values;
        const found = word * 32 + 31 - Math.clz32(lowest);
        return found < this.length ? found : this.length;
      }
      word++;
      values = this.bits[word] ?? 0;
    }
    return this.length;
  }
}

const map = (length: number, fn: (a: number, b: number) => number, a: CandidateSet, b: CandidateSet): CandidateSet => {
  const bits = new Uint32Array(words(length));
  for (let i = 0; i < bits.length; i++) bits[i] = fn(a.bits[i] ?? 0, b.bits[i] ?? 0);
  return new CandidateSet(length, bits);
};
const both = (a: CandidateSet, b: CandidateSet): CandidateSet => map(a.length, (x, y) => x & y, a, b);
const either = (a: CandidateSet, b: CandidateSet): CandidateSet => map(a.length, (x, y) => x | y, a, b);
const without = (a: CandidateSet, b: CandidateSet): CandidateSet => map(a.length, (x, y) => x & ~y, a, b);

interface Group { readonly value: Json; readonly positions: number[] }
interface PathIndex {
  readonly groups: ReadonlyMap<string, Group>;
  readonly defined: CandidateSet;
  readonly missing: CandidateSet;
}
interface Truth { readonly yes: CandidateSet; readonly no: CandidateSet }

const positions = (length: number, groups: Iterable<readonly number[]>): CandidateSet => {
  const bits = new Uint32Array(words(length));
  for (const group of groups) for (const at of group) bits[at >>> 5] = (bits[at >>> 5] ?? 0) | (1 << (at & 31));
  return new CandidateSet(length, bits);
};
const resourcePath = (operand: Operand): string | undefined =>
  'path' in operand && operand.path.startsWith('resource.') ? operand.path : undefined;
const literal = (operand: Operand): Json | typeof MISSING => 'value' in operand ? operand.value ?? MISSING : MISSING;

/** A reusable index for one immutable stored resource array. Attribute paths are indexed only when a residual uses them. */
export class ResourceCandidates {
  private readonly resources: readonly Resource[];
  private readonly types = new Map<string, CandidateSet>();
  private readonly paths = new Map<string, PathIndex>();

  constructor(resources: readonly Resource[]) { this.resources = resources; }

  match(expr: Expr, type: string): CandidateSet {
    const matches = this.evaluate(expr).yes;
    return both(matches, this.ofType(type));
  }

  private ofType(type: string): CandidateSet {
    const existing = this.types.get(type);
    if (existing) return existing;
    const at: number[] = [];
    for (const [i, resource] of this.resources.entries()) if (resource.type === type) at.push(i);
    const found = CandidateSet.fromPositions(this.resources.length, at);
    this.types.set(type, found);
    return found;
  }

  private path(path: string): PathIndex {
    const existing = this.paths.get(path);
    if (existing) return existing;
    const groups = new Map<string, { value: Json; positions: number[] }>();
    const missing: number[] = [];
    const defined: number[] = [];
    for (const [at, resource] of this.resources.entries()) {
      const value = resolvePath({ resource }, path);
      if (value === MISSING) { missing.push(at); continue; }
      defined.push(at);
      const key = canonical(value);
      const group = groups.get(key);
      if (group) group.positions.push(at);
      else groups.set(key, { value, positions: [at] });
    }
    const indexed = { groups, defined: CandidateSet.fromPositions(this.resources.length, defined),
      missing: CandidateSet.fromPositions(this.resources.length, missing) };
    this.paths.set(path, indexed);
    return indexed;
  }

  private evaluate(expr: Expr): Truth {
    switch (expr.op) {
      case 'true': return { yes: CandidateSet.all(this.resources.length), no: CandidateSet.empty(this.resources.length) };
      case 'unknown': return { yes: CandidateSet.empty(this.resources.length), no: CandidateSet.empty(this.resources.length) };
      case 'and': {
        const parts = expr.args.map((arg) => this.evaluate(arg));
        return { yes: parts.reduce((a, b) => both(a, b.yes), CandidateSet.all(this.resources.length)),
          no: parts.reduce((a, b) => either(a, b.no), CandidateSet.empty(this.resources.length)) };
      }
      case 'or': {
        const parts = expr.args.map((arg) => this.evaluate(arg));
        return { yes: parts.reduce((a, b) => either(a, b.yes), CandidateSet.empty(this.resources.length)),
          no: parts.reduce((a, b) => both(a, b.no), CandidateSet.all(this.resources.length)) };
      }
      case 'not': {
        const inner = this.evaluate(expr.arg);
        return { yes: inner.no, no: inner.yes };
      }
      case 'has': {
        if (!expr.path.startsWith('resource.')) return this.scan(expr);
        const path = this.path(expr.path);
        return { yes: path.defined, no: path.missing };
      }
      default: return this.comparison(expr);
    }
  }

  private comparison(expr: Extract<Expr, { left: Operand; right: Operand }>): Truth {
    const leftPath = resourcePath(expr.left), rightPath = resourcePath(expr.right);
    if ((leftPath === undefined) === (rightPath === undefined)) return this.scan(expr);
    const path = this.path((leftPath ?? rightPath) as string);
    const other = leftPath ? expr.right : expr.left;
    const value = literal(other);
    const empty = CandidateSet.empty(this.resources.length);

    // Equality and membership are defined for every present JSON value, including across types.
    if (value !== MISSING && (expr.op === 'eq' || expr.op === 'ne' || (expr.op === 'in' && leftPath && Array.isArray(value)))) {
      const wanted = new Set((expr.op === 'in' && Array.isArray(value) ? value : [value]).map(canonical));
      const yes = positions(this.resources.length, [[...wanted].flatMap((key) => path.groups.get(key)?.positions ?? [])]);
      const no = without(path.defined, yes);
      return expr.op === 'ne' ? { yes: no, no: yes } : { yes, no };
    }

    const yesGroups: number[][] = [], noGroups: number[][] = [];
    for (const group of path.groups.values()) {
      const result = compare(expr.op, leftPath ? group.value : value, leftPath ? value : group.value);
      if (result === true) yesGroups.push(group.positions);
      else if (result === false) noGroups.push(group.positions);
    }
    return { yes: yesGroups.length ? positions(this.resources.length, yesGroups) : empty,
      no: noGroups.length ? positions(this.resources.length, noGroups) : CandidateSet.empty(this.resources.length) };
  }

  private scan(expr: Expr): Truth {
    const yes: number[] = [], no: number[] = [];
    for (const [at, resource] of this.resources.entries()) {
      const result = evalTri(expr, { subject: null, resource, action: null, context: null });
      if (result === true) yes.push(at);
      else if (result === false) no.push(at);
    }
    return { yes: CandidateSet.fromPositions(this.resources.length, yes), no: CandidateSet.fromPositions(this.resources.length, no) };
  }
}

const eligible = (bundle: PolicyBundle, subject: Subject, resource: Resource, action: string, kind: string, ctx: Context): boolean => {
  if (rbacGrant(bundle, subject, resource.type, action, ctx.now)) return true;
  return bundle.abac.some((rule) => {
    if (rule.effect !== 'permit' || !appliesTo(rule, resource.type, action)) return false;
    try { return evalTri(rule.when, { subject, resource, action: { name: action, kind }, context: ctx }) === true; }
    catch { return false; }
  });
};

/** Conservative subject candidates: relation reachability is shared by the whole search, then the full decision checks
 *  every delegation link, forbid, certification and history. The optional context callback supplies server-side marks. */
export function subjectCandidates(bundle: PolicyBundle, subjects: readonly Subject[], type: string, resource: Resource | undefined,
  action: string, ctx: Context, graph: Graph, contextFor: (subject: Subject) => Context = () => ctx): CandidateSet {
  const typed = subjects.flatMap((subject, at) => subject.type === type ? [at] : []);
  if (!resource) return CandidateSet.empty(subjects.length);
  try {
    const def = actionDef(bundle, resource.type, action);
    if (!def) return CandidateSet.empty(subjects.length);
    const protect = Object.hasOwn(bundle.needToKnow.protect, resource.type) ? bundle.needToKnow.protect[resource.type] : undefined;
    const protectedRow = protect && bundle.needToKnow.mode !== 'off' && bundle.needToKnow.mode !== 'dry_run' && resource.level >= (protect.minLevel ?? 0);
    const reachable = protectedRow && protect ? knownSubjects(bundle, graph, resource, protect.relation, ctx.now) : undefined;
    const kept: number[] = [];
    for (const at of typed) {
      const subject = withLiveRoles(subjects[at]!, ctx.now);
      if (!subject.active || (reachable && !reachable.has(keyOf(subject)))) continue;
      const own = contextFor(subject);
      if (mandatoryFindings(bundle, subject, resource, action, def.kind, own).length > 0 || !eligible(bundle, subject, resource, action, def.kind, own)) continue;
      kept.push(at);
    }
    return CandidateSet.fromPositions(subjects.length, kept);
  } catch {
    // A malformed policy fails closed in the point evaluator; do not let an optimization change that into an HTTP error.
    return CandidateSet.fromPositions(subjects.length, typed);
  }
}
