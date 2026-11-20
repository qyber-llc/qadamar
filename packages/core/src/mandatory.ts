// Built-in mandatory models, never configurable away by tenant policy: Bell-LaPadula (confidentiality), compartments,
// the network condition, and Biba (integrity). A tenant only tunes the parameters declared in `bundle.mandatory`.
// Inputs are validated by request.ts first; checks are still written as !(allowed) so a bad value cannot pass.
import type { ActionKind, Context, Integrity, Level, PolicyBundle, Resource, Subject } from './types.ts';

export const INTEGRITY_RANK: Readonly<Record<Integrity, number>> = { derived: 0, extracted: 1, system: 2, verified: 3 };

export interface Finding {
  readonly rule: string;
  readonly reason: string;
}

export const ACTION_KINDS: ReadonlySet<string> = new Set(['read', 'write', 'delete', 'approve', 'execute']);

/** Every kind but read changes state (an approval or an execution is a write of its own record). */
export const isWrite = (kind: ActionKind): boolean => kind !== 'read';

/** The level the caller asks to work at: its clearance, or a lower session level it chose. */
export const requestedLevel = (s: Subject, c: Context): Level => Math.min(c.sessionLevel ?? s.clearance, s.clearance) as Level;
/** The level a subject works at. A session's high-water mark (the highest level it read, kept by the server) raises
 *  the requested level and is never lowered by it; the result never exceeds the clearance. */
export const sessionOf = (s: Subject, c: Context): Level => Math.min(Math.max(requestedLevel(s, c), c.highWater ?? 0), s.clearance) as Level;
/** Writes under the *-property: below the requested level is BLP.NO_WRITE_DOWN; at or above it but below what the
 *  session already read is BLP.HIGH_WATER (the mark is not capped by the clearance: a lowered clearance does not
 *  release what was read). Trusted roles are exempt from both. */
export const writeFloor = (s: Subject, c: Context): Level => Math.max(requestedLevel(s, c), c.highWater ?? 0) as Level;
/** BLP_SESSION_REQUIRED: without a session the PDP cannot keep a high-water mark, so a cleared subject's writes and
 *  every read above L0 need one (reads too: a read outside any session would leave no mark behind). */
export const sessionMissing = (s: Subject, c: Context, kind: ActionKind, level: Level): boolean =>
  c.sessionRequired === true && c.sessionId === undefined && (isWrite(kind) ? s.clearance > 0 : level > 0);

const rank = (i: Integrity): number => (Object.hasOwn(INTEGRITY_RANK, i) ? INTEGRITY_RANK[i] : -1);

export const bibaNoReadDown = (mandatory: PolicyBundle['mandatory'], action: string, kind: ActionKind): boolean =>
  mandatory.bibaNoReadDownScope === 'all' || (mandatory.bibaNoReadDownScope === 'reads' ? kind === 'read' : mandatory.bibaNoReadDownActions.includes(action));

export function mandatoryFindings(
  bundle: PolicyBundle, subject: Subject, resource: Resource, action: string, kind: ActionKind, context: Context,
): Finding[] {
  const m = bundle.mandatory;
  const out: Finding[] = [];
  const session = sessionOf(subject, context);
  if (!(session >= resource.level)) {
    out.push({ rule: 'BLP.NO_READ_UP', reason: `working level L${session} is below the resource level L${resource.level}` });
  }
  const missing = resource.compartments.filter((c) => !subject.compartments.includes(c));
  if (missing.length > 0) out.push({ rule: 'MAC.COMPARTMENT', reason: `compartment not held: ${missing.join(', ')}` });
  if (context.network !== 'trusted') {
    if (!(resource.level <= m.untrustedNetworkMaxLevel)) {
      out.push({ rule: 'NET.UNTRUSTED_LEVEL', reason: `L${resource.level} is reachable only from a trusted network (untrusted max L${m.untrustedNetworkMaxLevel})` });
    }
    if (m.compartmentsRequireTrustedNetwork !== false && resource.compartments.length > 0) {
      out.push({ rule: 'NET.UNTRUSTED_COMPARTMENT', reason: 'compartmented resources are reachable only from a trusted network' });
    }
  }
  if (sessionMissing(subject, context, kind, resource.level)) {
    out.push({ rule: 'BLP.SESSION_REQUIRED', reason: 'this deployment keeps a high-water mark: open a PDP session and send context.sessionToken' });
  }
  if (isWrite(kind)) {
    // *-property: no write down below the working level, unless a trusted subject (e.g. a declassification officer)
    const trusted = subject.roles.some((r) => m.trustedRoles.includes(r));
    const requested = requestedLevel(subject, context);
    if (!(resource.level >= requested) && !trusted) {
      out.push({ rule: 'BLP.NO_WRITE_DOWN', reason: `writing L${resource.level} from a session at L${requested} could leak higher data down` });
    } else if (!(resource.level >= writeFloor(subject, context)) && !trusted) {
      out.push({ rule: 'BLP.HIGH_WATER', reason: `this session already read L${context.highWater ?? 0}: writing L${resource.level} could leak it down` });
    }
    if (!(rank(subject.integrity) >= rank(resource.integrity))) {
      out.push({ rule: 'BIBA.NO_WRITE_UP', reason: `a ${subject.integrity} writer cannot change ${resource.integrity} data` });
    }
  }
  if (bibaNoReadDown(m, action, kind) && !(rank(resource.integrity) >= rank(subject.integrity))) {
    out.push({ rule: 'BIBA.NO_READ_DOWN', reason: `${action} cannot rely on ${resource.integrity} data` });
  }
  return out;
}

/** BLP effective level is max(resource, ancestors). The engine sees one resource, so the data must keep
 *  every child at or above its parent: then `level` is the effective level, in the engine and in SQL alike. */
export function levelInheritanceErrors(resources: readonly Resource[]): string[] {
  const byKey = new Map(resources.map((r) => [JSON.stringify([r.type, r.id]), r]));
  const out: string[] = [];
  for (const r of resources) {
    if (!r.parent) continue;
    const p = byKey.get(JSON.stringify([r.parent.type, r.parent.id]));
    if (!p) out.push(`${r.type}:${r.id} has an unknown parent ${r.parent.type}:${r.parent.id}`);
    else if (p.level > r.level) out.push(`${r.type}:${r.id} is L${r.level}, below its parent ${p.type}:${p.id} at L${p.level}`);
  }
  return out;
}
