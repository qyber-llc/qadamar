import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { AuditEvent, AuditRecord } from './audit.ts';

/** usedAt: last use as a PEP decision subject, at SUBJECT_TOUCH_MS granularity; absent for a mapping that is never purged:
 *  a world subject's, an id ever used as an actor or a person detail, or one stored before usedAt existed. */
export interface SubjectIdentity { pseudonym: string; id: string; key: string; usedAt?: string }
/** A mapping of an id that is not a world subject, unused this long, is deleted (storage review 2, owner decision). */
export const SUBJECT_IDLE_DAYS = 90;
/** Last use is written at most once a day per id, so the purge waits one day more than SUBJECT_IDLE_DAYS. */
export const SUBJECT_TOUCH_MS = 86_400_000;
export const idleCutoff = (now: string): string => new Date(Date.parse(now) - SUBJECT_IDLE_DAYS * 86_400_000 - SUBJECT_TOUCH_MS).toISOString();
export const subjectPseudonym = (key: Buffer, id: string): string => `ps.${createHmac('sha256', key).update(id, 'utf8').digest('hex').slice(0, 32)}`;
export const newSubjectIdentity = (id: string): SubjectIdentity => {
  const key = randomBytes(32);
  return { pseudonym: subjectPseudonym(key, id), id, key: key.toString('base64url') };
};
/** A stored mapping row is trusted only if its pseudonym is the HMAC of its id under its own key (file and PostgreSQL). */
export const validSubjectIdentity = (row: unknown): row is SubjectIdentity => {
  const r = row as Partial<SubjectIdentity> | null;
  return !!r && typeof r === 'object' && typeof r.pseudonym === 'string' && /^ps\.[0-9a-f]{32}$/.test(r.pseudonym) && typeof r.id === 'string' &&
    typeof r.key === 'string' && subjectPseudonym(Buffer.from(r.key, 'base64url'), r.id) === r.pseudonym;
};
export interface SubjectIdentities {
  /** decisionSubject: the subject of a decision row (PEP path), the only use that leaves a mapping purgeable. */
  pseudonym(id: string, decisionSubject?: boolean): string;
  lookup(id: string): string | undefined;
  identity(pseudonym: string): string | undefined;
  erase(id: string): string | undefined;
  /** Pins `keep` (never purged again), then removes idle mappings; `before(count)` runs first and may refuse. */
  purgeIdle?(keep: readonly string[], before: (count: number) => void): number;
}
export const PERSON_DETAILS = ['openedBy', 'makerId', 'checkerId', 'approvedBy', 'subjectIds'] as const;
const TECHNICAL_ACTORS = new Set(['pep', 'system', 'unknown', 'scim', 'bootstrap']);
const UNKNOWN_LOGIN = /^unknown:[0-9a-f]{32}$/;
export const technicalActor = (actor: string): boolean => TECHNICAL_ACTORS.has(actor) || actor.startsWith('pep:') || UNKNOWN_LOGIN.test(actor);
/** A failed sign-in by an id nobody mapped: a keyed hash under one server key instead of a new per-subject mapping, so a
 *  username spray grows no mapping rows; repeated tries of one id still correlate. */
export const unknownLoginActor = (key: Buffer, id: string): string => `unknown:${createHmac('sha256', key).update(id, 'utf8').digest('hex').slice(0, 32)}`;
const pseudonymous = (value: string): boolean => /^ps\.[0-9a-f]{32}$/.test(value);
/** Every id use but a decision row's subject protects the mapping for good (actors and person details are never purged). */
export function pseudonymiseEvent(event: AuditEvent, pseudonym: (id: string, decisionSubject: boolean) => string): AuditEvent {
  const details = event.details && Object.fromEntries(Object.entries(event.details).map(([key, value]) => {
    if (!(PERSON_DETAILS as readonly string[]).includes(key)) return [key, value];
    const map = (item: unknown): unknown => typeof item === 'string' ? pseudonym(item, false) : Array.isArray(item) ? item.map(map) : item;
    return [key, map(value)];
  }));
  return { ...event, actor: technicalActor(event.actor) ? event.actor : pseudonym(event.actor, false),
    ...(event.subject === undefined ? {} : { subject: pseudonym(event.subject, event.type === 'decision') }), ...(details ? { details } : {}) };
}
/** Console/API presentation only. Export and SIEM paths consume the stored pseudonymous record instead. */
export function presentAuditRow(row: AuditRecord, identity: (pseudonym: string) => string | undefined): AuditRecord {
  const show = (id: string): string => pseudonymous(id) ? identity(id) ?? id : id;
  const details = row.details && Object.fromEntries(Object.entries(row.details).map(([key, value]) => {
    if (!(PERSON_DETAILS as readonly string[]).includes(key)) return [key, value];
    const map = (item: unknown): unknown => typeof item === 'string' ? show(item) : Array.isArray(item) ? item.map(map) : item;
    return [key, map(value)];
  }));
  return { ...row, actor: show(row.actor), ...(row.subject === undefined ? {} : { subject: show(row.subject) }), ...(details ? { details } : {}) };
}

/** The direct id and its random HMAC key never enter the chain; deleting this file's entry is the crypto-shredding step. */
export class FileSubjectIdentities implements SubjectIdentities {
  private readonly byId: Map<string, SubjectIdentity>;
  private readonly byPseudonym = new Map<string, SubjectIdentity>();
  private readonly file: string;
  private readonly now: () => string;
  constructor(file: string, now: () => string = () => new Date().toISOString()) {
    this.file = file; this.now = now;
    const stored: unknown = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : [];
    if (!Array.isArray(stored) || !stored.every((row) => validSubjectIdentity(row) && (row.usedAt === undefined || Number.isFinite(Date.parse(String(row.usedAt)))))) {
      throw new Error('Invalid audit subject mapping');
    }
    this.byId = new Map(stored.map((row) => [row.id, row]));
    for (const row of stored) {
      if (this.byPseudonym.has(row.pseudonym)) throw new Error('Invalid audit subject mapping');
      this.byPseudonym.set(row.pseudonym, row);
    }
  }
  pseudonym(id: string, decisionSubject = false): string {
    const at = this.now();
    const identity = this.byId.get(id);
    if (!identity) {
      this.put({ ...newSubjectIdentity(id), ...(decisionSubject ? { usedAt: at } : {}) }); this.save();
    } else if (identity.usedAt !== undefined && !decisionSubject) {
      this.put({ pseudonym: identity.pseudonym, id: identity.id, key: identity.key }); this.save(); // pinned for good
    } else if (identity.usedAt !== undefined && Date.parse(at) - Date.parse(identity.usedAt) >= SUBJECT_TOUCH_MS) {
      this.put({ ...identity, usedAt: at }); this.save();
    }
    return this.byId.get(id)!.pseudonym;
  }
  purgeIdle(keep: readonly string[], before: (count: number) => void): number {
    let pinned = false;
    for (const id of keep) {
      const row = this.byId.get(id);
      if (row?.usedAt !== undefined) { this.put({ pseudonym: row.pseudonym, id: row.id, key: row.key }); pinned = true; }
    }
    const cutoff = Date.parse(idleCutoff(this.now()));
    const idle = [...this.byId.values()].filter((row) => row.usedAt !== undefined && Date.parse(row.usedAt) < cutoff);
    if (idle.length) before(idle.length);
    for (const row of idle) { this.byId.delete(row.id); this.byPseudonym.delete(row.pseudonym); }
    if (pinned || idle.length) this.save();
    return idle.length;
  }
  private put(identity: SubjectIdentity): void { this.byId.set(identity.id, identity); this.byPseudonym.set(identity.pseudonym, identity); }
  lookup(id: string): string | undefined { return this.byId.get(id)?.pseudonym; }
  identity(pseudonym: string): string | undefined { return this.byPseudonym.get(pseudonym)?.id; }
  erase(id: string): string | undefined {
    const identity = this.byId.get(id);
    if (!identity) return undefined;
    this.byId.delete(id); this.byPseudonym.delete(identity.pseudonym); this.save();
    return identity.pseudonym;
  }
  private save(): void {
    const temp = `${this.file}.${randomUUID()}.tmp`;
    writeFileSync(temp, JSON.stringify([...this.byId.values()], null, 2), { mode: 0o600 });
    renameSync(temp, this.file);
  }
}
