import type {
  BinaryOp,
  ChangeKind,
  ChangePayload,
  Expr,
  Json,
  Level,
  Operand,
  Ref,
  RelationDef,
  RelationRewrite,
  Tuple,
} from '../api/types';
import { msgs } from '../i18n';
import { contentRules, windowOf } from '../api/coreTypes';

export {
  extractTenantSections,
  validateCandidateBundle,
  validateTenantCandidate,
  type EditableTenantSections,
} from './bundleValidator';

/** Getters, so the labels follow the console language. */
export const LEVEL_LABELS: Readonly<Record<Level, string>> = {
  get 0() { return msgs().common.levels[0]; },
  get 1() { return msgs().common.levels[1]; },
  get 2() { return msgs().common.levels[2]; },
  get 3() { return msgs().common.levels[3]; },
};

const OP_SYMBOLS: Readonly<Record<BinaryOp, string>> = {
  eq: '=',
  ne: '!=',
  lt: '<',
  le: '<=',
  gt: '>',
  ge: '>=',
  in: 'in',
  contains: 'contains',
  subset: 'subset of',
};

function formatJsonValue(val: Json): string {
  if (typeof val === 'string') return JSON.stringify(val);
  if (val === null || typeof val === 'number' || typeof val === 'boolean') return String(val);
  if (Array.isArray(val)) return `[${val.map(formatJsonValue).join(', ')}]`;
  return JSON.stringify(val);
}

function formatOperand(op: Operand): string {
  if ('path' in op) return op.path;
  return formatJsonValue(op.value);
}

export function formatExpr(expr: Expr | undefined): string {
  if (!expr) return 'true';
  switch (expr.op) {
    case 'true':
      return 'true';
    case 'has':
      return `has(${expr.path})`;
    case 'not':
      return `not (${formatExpr(expr.arg)})`;
    case 'and':
    case 'or': {
      if (expr.args.length === 0) return expr.op === 'and' ? 'true' : 'false';
      const joined = expr.args.map((a) => formatExpr(a)).join(` ${expr.op} `);
      return expr.args.length > 1 ? `(${joined})` : joined;
    }
    default: {
      const sym = OP_SYMBOLS[expr.op] ?? expr.op;
      return `${formatOperand(expr.left)} ${sym} ${formatOperand(expr.right)}`;
    }
  }
}

export function formatRewrite(rw: RelationRewrite): string {
  if ('this' in rw) return 'direct tuple (this)';
  if ('computed' in rw) return `computed(${rw.computed})`;
  if ('fromParent' in rw) return `fromParent(${rw.fromParent.relation} -> ${rw.fromParent.then})`;
  return `viaReports(${rw.viaReports.managerRelation} -> ${rw.viaReports.then}, maxDepth=${rw.viaReports.maxDepth})`;
}

export function formatRelationDef(def: RelationDef): string {
  return def.union.map(formatRewrite).join(' | ');
}

export function formatRef(ref: Ref | string | undefined): string {
  if (!ref) return '—';
  if (typeof ref === 'string') return ref;
  return `${ref.type}:${ref.id}`;
}

export function formatDateHuman(iso: string | undefined | null): string {
  if (!iso) return '—';
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return iso;
  const d = new Date(ms);
  const day = d.getUTCDate();
  const mon = msgs().common.months[d.getUTCMonth()] ?? '';
  const yr = d.getUTCFullYear();
  if (iso.length <= 10) return `${day} ${mon} ${yr}`;
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  return `${day} ${mon} ${yr}, ${hh}:${mm} UTC`;
}

export function formatHop(hop: string): string {
  const m = /^([^#:]+:)?([^#]+)#([^@]+)@(?:[^#:]+:)?([^#]+)(?:#(.+))?$/.exec(hop.trim());
  if (m && m[2] && m[3] && m[4]) {
    const obj = m[2];
    const rel = m[3].replace(/_/g, ' ');
    const sub = m[4];
    const subRel = m[5] ? ` (${m[5]})` : '';
    return msgs().common.hop(`${sub}${subRel}`, rel, obj);
  }
  return hop.replace(/->/g, '→');
}

export function formatTupleShort(t: Tuple): string {
  const obj = typeof t.object === 'string' ? t.object : t.object.id;
  const sub = typeof t.subject === 'string' ? t.subject : t.subject.id;
  const rel = t.relation.replace(/_/g, ' ');
  const subRel = t.subjectRelation ? ` (${t.subjectRelation})` : '';
  const c = msgs().common;
  const until = windowOf(t).to;
  const valid = until ? ` (${c.changes.until(formatDateHuman(until.slice(0, 10)))})` : '';
  const bg = t.breakGlass ? ` [${c.changes.breakGlass}]` : '';
  return `${c.hop(`${sub}${subRel}`, rel, obj)}${bg}${valid}`;
}

export function summarizeChangePayload(kind: ChangeKind, payload: ChangePayload): string {
  const m = msgs().common.changes;
  if (kind === 'add_tuple' && 'object' in payload) {
    return m.addTuple(formatTupleShort(payload));
  }
  if (kind === 'remove_tuple' && 'tupleId' in payload) {
    return m.removeTuple(payload.tupleId);
  }
  if (kind === 'update_subject' && 'id' in payload && 'set' in payload) {
    const parts: string[] = [];
    const s = payload.set;
    if ('clearance' in s && s.clearance !== undefined) parts.push(m.field(m.fields.clearance, `L${s.clearance}`));
    if ('compartments' in s && s.compartments !== undefined) parts.push(m.field(m.fields.compartments, `[${s.compartments.join(', ')}]`));
    if ('roles' in s && s.roles !== undefined) parts.push(m.field(m.fields.roles, `[${s.roles.join(', ')}]`));
    if ('active' in s && s.active !== undefined) parts.push(m.field(m.fields.active, String(s.active)));
    return m.updateSubject(payload.id, parts.join(', ') || m.noFields);
  }
  if (kind === 'update_resource' && 'id' in payload && 'set' in payload) {
    const parts: string[] = [];
    const s = payload.set;
    if ('level' in s && s.level !== undefined) parts.push(m.field(m.fields.level, `L${s.level}`));
    if ('compartments' in s && s.compartments !== undefined) parts.push(m.field(m.fields.compartments, `[${s.compartments.join(', ')}]`));
    if ('integrity' in s && s.integrity !== undefined) parts.push(m.field(m.fields.integrity, s.integrity));
    return m.updateResource(payload.id, parts.join(', ') || m.noFields);
  }
  if (kind === 'publish_policy' && 'bundle' in payload) {
    const b = payload.bundle;
    return m.publishPolicy(b.name, b.abac.length, contentRules(b).length, b.context?.length ?? 0, b.sod.length, b.needToKnow.mode);
  }
  if (kind === 'certify_tp' && 'resourceType' in payload) return m.certifyTp(payload.action, payload.resourceType);
  const subjects = (payload as { subjects?: unknown }).subjects;
  if (kind === 'scim_subjects' && Array.isArray(subjects)) {
    const ids = subjects.slice(0, 5).map((s: { id?: unknown }) => String(s?.id ?? '')).join(', ');
    return m.scimSubjects(subjects.length, subjects.length > 5 ? `${ids}, …` : ids);
  }
  return JSON.stringify(payload);
}
