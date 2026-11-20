import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { Subject } from '../../core/src/index.ts';
import type { Runtime } from './runtime.ts';
import { allowed, hashMachineSecret, needsRehash, verifySecret, verifySecretAsync, randomSecret, type User } from './auth.ts';
import { candidate, propose } from './admin/changes.ts';
import { HttpError, object } from './http.ts';
import type { Backing, ScimCredentialOrigin } from './store.ts';

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
/** Not a console role: sign-in only ever grants console roles, so no person can act as the provisioning service. */
export const SCIM_SERVICE: User = { id: 'scim', name: 'SCIM provisioning', roles: ['scim_provisioner'] };

export interface ScimOptions {
  bearerToken?: string;
  /** IdP group (externalId or displayName) to PDP role, one group per role. */
  groupRoles?: Record<string, string>;
  /** False by default: every change is a pending proposal for two-person review. Needs bearerToken (set by the
   *  environment, not minted in the console), so no single console user can both mint the credential and write. */
  direct?: boolean;
}
export interface ScimResult { status: number; body?: unknown }
/** rotatedBy: the person who minted the credential; they cannot approve what it proposes. rotated: when (absent before this field existed). */
export type ScimCredential = Backing<{ hash: string; rotatedBy: string; rotated?: string }>;
type Kind = 'user' | 'group';
interface UserInput { userName: string; externalId?: string; displayName?: string; active: boolean; groups?: string[] }
interface GroupInput { externalId?: string; displayName: string; active: boolean; members: string[] }

export function scimFromEnv(env: NodeJS.ProcessEnv): ScimOptions {
  let groupRoles: unknown;
  if (env.SCIM_GROUP_ROLES) {
    try { groupRoles = JSON.parse(env.SCIM_GROUP_ROLES); } catch { throw new Error('SCIM_GROUP_ROLES must be a JSON object'); }
  }
  return { ...(env.SCIM_BEARER_TOKEN ? { bearerToken: env.SCIM_BEARER_TOKEN } : {}),
    ...(groupRoles === undefined ? {} : { groupRoles: groupRoles as Record<string, string> }),
    direct: /^(1|on|true|yes)$/i.test(env.SCIM_DIRECT ?? '') };
}

const bad = (message: string): never => { throw new HttpError(400, 'bad_request', message); };
const invalid = (message: string): never => { throw new HttpError(422, 'unprocessable', message); };
function fields(value: unknown, permitted: readonly string[]): Record<string, unknown> {
  const result = object(value);
  if (Object.keys(result).some((key) => !permitted.includes(key))) bad('Unsupported SCIM attribute');
  return result;
}
function text(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) return bad(`Invalid ${name}`);
  return value;
}
const optionalText = (value: unknown, name: string): string | undefined => value === undefined ? undefined : text(value, name);
function bool(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') return bad('active must be boolean');
  return value;
}
/** Some IdPs (Entra ID) send PATCH booleans as "True"/"False". */
const patchBool = (value: unknown): boolean => typeof value === 'string' && /^(true|false)$/i.test(value) ? value.toLowerCase() === 'true' : bool(value, false);
function schemas(value: unknown, expected: string): void {
  if (!Array.isArray(value) || value.length !== 1 || value[0] !== expected) bad('Unsupported SCIM schema');
}
function refs(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.length > 1000) return bad(`${name} must be an array`);
  const entries: unknown[] = value;
  const ids = entries.map((entry) => text(fields(entry, ['value', 'display']).value, name));
  if (new Set(ids).size !== ids.length) bad(`Duplicate ${name}`);
  return ids;
}
const attr = (subject: Subject, key: string): string | undefined => { const value = subject.attrs?.[key]; return typeof value === 'string' ? value : undefined; };
const userName = (subject: Subject): string => attr(subject, 'scimUserName') ?? subject.id;
const externalId = (subject: Subject): string | undefined => attr(subject, 'scimExternalId');
const displayName = (subject: Subject): string => attr(subject, 'scimDisplayName') ?? attr(subject, 'name') ?? subject.id;
const defined = <T extends Record<string, unknown>>(value: T): T => Object.fromEntries(Object.entries(value).filter((entry) => entry[1] !== undefined)) as T;
const digest = (token: string): Buffer => createHash('sha256').update(token).digest();

function validMapping(value: unknown): Record<string, string> {
  const roles = value ?? {};
  if (typeof roles !== 'object' || Array.isArray(roles) || Object.values(roles).some((role) => typeof role !== 'string' || !role)) {
    throw new Error('SCIM_GROUP_ROLES must be a JSON object of group names to role names');
  }
  const values = Object.values(roles as Record<string, string>);
  // membership is read back from roles, so two groups on one role could not be told apart
  if (new Set(values).size !== values.length) throw new Error('SCIM_GROUP_ROLES must map each role from one group only');
  return roles as Record<string, string>;
}

export class Scim {
  private readonly rt: Runtime;
  private readonly options: ScimOptions;
  private readonly mapping: Record<string, string>;
  private readonly store: ScimCredential;
  private readonly envDigest?: Buffer;
  /** Digest of the last good console-minted token, valid only while the stored hash is the one it was checked against:
   *  a rotation committed by another cluster node changes the hash and so revokes the cache here too. */
  private verified?: { digest: Buffer; hash: string };
  private readonly dummyHash = hashMachineSecret(randomSecret());

  constructor(rt: Runtime, store: ScimCredential, options: ScimOptions = {}) {
    this.rt = rt; this.store = store; this.options = options; this.mapping = validMapping(options.groupRoles);
    if (options.bearerToken !== undefined) {
      if (options.bearerToken.length < 32 || options.bearerToken.length > 256) throw new Error('SCIM_BEARER_TOKEN must contain 32..256 characters');
      this.envDigest = digest(options.bearerToken);
    } else if (options.direct) throw new Error('SCIM_DIRECT requires SCIM_BEARER_TOKEN: a console-minted credential needs two-person review');
    const stored = store.load() as { hash?: unknown; rotatedBy?: unknown } | undefined;
    if (stored !== undefined && (!stored || typeof stored.hash !== 'string' || typeof stored.rotatedBy !== 'string')) throw new Error('Invalid SCIM credential store');
  }

  /** The env token, or the stored hash (HMAC; a 0.8.3 scrypt hash is replaced on its first success); after one success
   *  the request digest is compared, as for the PEP key.
   *  Returns `scim:<fingerprint>`, 16 hex characters of the credential's SHA-256, never the secret. */
  /** authenticate for the router: a 0.8.3 scrypt hash is checked on the thread pool, then upgraded, before the sync path. */
  async authenticateAsync(req: IncomingMessage): Promise<string> {
    const header = req.headers.authorization ?? '';
    const stored = this.envDigest || !header.startsWith('Bearer ') || header.length > 263 ? undefined : this.store.load();
    if (stored && needsRehash(stored.hash, true) && this.verified?.hash !== stored.hash) {
      const token = header.slice(7);
      if (!await verifySecretAsync(token, stored.hash)) throw new HttpError(401, 'unauthenticated');
      // a rotation made during the scrypt run wins: the old token's hash is never saved back over it
      if (this.store.load()?.hash === stored.hash) this.remember(stored, token, digest(token));
    }
    return this.authenticate(req);
  }

  authenticate(req: IncomingMessage): string {
    const header = req.headers.authorization ?? '';
    if (!header.startsWith('Bearer ') || header.length > 263) throw new HttpError(401, 'unauthenticated');
    const token = header.slice(7); const presented = digest(token);
    const stored = this.store.load();
    const hash = stored?.hash;
    const known = this.envDigest ?? (this.verified && this.verified.hash === hash ? this.verified.digest : undefined);
    const valid = known ? timingSafeEqual(presented, known) : verifySecret(token, hash ?? this.dummyHash) && hash !== undefined;
    if (!valid) throw new HttpError(401, 'unauthenticated');
    if (!known && stored) this.remember(stored, token, presented);
    return `scim:${presented.toString('hex').slice(0, 16)}`;
  }

  /** After a success: a 0.8.3 scrypt hash becomes an HMAC, and the digest is cached against the stored hash. */
  private remember(stored: NonNullable<ReturnType<ScimCredential['load']>>, token: string, presented: Buffer): void {
    const current = needsRehash(stored.hash, true) ? hashMachineSecret(token) : stored.hash;
    if (current !== stored.hash) this.store.save({ ...stored, hash: current });
    this.verified = { digest: presented, hash: current };
  }

  /** Access admins only: they cannot approve changes, and the minter is also refused as checker of SCIM proposals. */
  rotateCredential(user: User): ScimResult {
    allowed(user, ['access_admin']);
    if (this.envDigest) throw new HttpError(409, 'conflict', 'The SCIM credential is set by SCIM_BEARER_TOKEN');
    const credential = randomSecret() + randomSecret();
    this.store.save({ hash: hashMachineSecret(credential), rotatedBy: user.id, rotated: this.rt.now() });
    this.verified = undefined;
    this.rt.audit.append({ type: 'change', actor: user.id, action: 'scim_credential_rotate' });
    return { status: 201, body: { credential } };
  }

  /** Who holds the credential and since when, never the hash: `env` (SCIM_BEARER_TOKEN), `none`, or `console`. */
  credentialInfo(user: User): { source: 'env' | 'none' } | { source: 'console'; rotatedBy: string; rotated?: string } {
    allowed(user, ['access_admin', 'security_officer']);
    if (this.envDigest) return { source: 'env' };
    const stored = this.store.load();
    if (!stored) return { source: 'none' };
    return { source: 'console', rotatedBy: stored.rotatedBy, ...(typeof stored.rotated === 'string' ? { rotated: stored.rotated } : {}) };
  }

  /** `credential` is what authenticate returned for this request. */
  handle(method: string, path: string, query: URLSearchParams, body: Record<string, unknown>, credential: string): ScimResult {
    const origin = { rotatedBy: this.envDigest ? 'env' : this.store.load()?.rotatedBy ?? 'unknown', fingerprint: credential.replace(/^scim:/, '') };
    const match = /^\/scim\/v2\/(Users|Groups)(?:\/([^/]+))?$/.exec(path);
    if (!match) throw new HttpError(404, 'not_found');
    const kind: Kind = match[1] === 'Users' ? 'user' : 'group';
    const id = match[2];
    if (method === 'GET') return id ? { status: 200, body: this.view(this.find(kind, id)) } : this.list(kind, query);
    if (method === 'POST' && !id) return kind === 'user' ? this.createUser(body, origin) : this.createGroup(body, origin);
    if (!id) throw new HttpError(404, 'not_found');
    if (method === 'PUT') return kind === 'user' ? this.replaceUser(id, body, origin) : this.replaceGroup(id, body, origin);
    if (method === 'PATCH') return this.patch(kind, id, body, origin);
    if (method === 'DELETE') return this.deactivate(kind, id, origin);
    throw new HttpError(404, 'not_found');
  }

  private subjects(kind: Kind, all = this.rt.store.state.subjects): readonly Subject[] {
    return all.filter((subject) => subject.type === kind);
  }
  private find(kind: Kind, id: string): Subject {
    const found = this.subjects(kind).find((subject) => subject.id === id);
    if (!found) throw new HttpError(404, 'not_found');
    return found;
  }
  private mappedRole(group: Subject): string | undefined {
    const keys = [externalId(group), displayName(group)].filter((key): key is string => key !== undefined && Object.hasOwn(this.mapping, key));
    const roles = [...new Set(keys.map((key) => this.mapping[key]!))];
    return roles.length === 1 && Object.hasOwn(this.rt.store.state.bundle.rbac.roles, roles[0]!) ? roles[0] : undefined;
  }
  private role(group: Subject): string {
    return this.mappedRole(group) ?? invalid('Group has no configured role mapping to a known role');
  }
  private view(subject: Subject, all = this.rt.store.state.subjects): Record<string, unknown> {
    const plural = subject.type === 'user' ? 'Users' : 'Groups';
    const common = defined({ id: subject.id, externalId: externalId(subject), displayName: displayName(subject), active: subject.active,
      meta: { resourceType: subject.type === 'user' ? 'User' : 'Group', location: `/scim/v2/${plural}/${encodeURIComponent(subject.id)}` } });
    if (subject.type === 'group') {
      const role = this.mappedRole(subject);
      const members = role === undefined ? [] : this.subjects('user', all).filter((user) => user.roles.includes(role));
      return { schemas: [GROUP_SCHEMA], ...common, members: members.map((user) => ({ value: user.id, display: userName(user) })) };
    }
    const groups = this.subjects('group', all).filter((group) => { const role = this.mappedRole(group); return role !== undefined && subject.roles.includes(role); });
    return { schemas: [USER_SCHEMA], ...common, userName: userName(subject), groups: groups.map((group) => ({ value: group.id, display: displayName(group) })) };
  }
  private list(kind: Kind, query: URLSearchParams): ScimResult {
    const start = Number(query.get('startIndex') ?? 1); const count = Math.min(Number(query.get('count') ?? 100), 200);
    if (!Number.isSafeInteger(start) || start < 1 || !Number.isSafeInteger(count) || count < 0) bad('Invalid pagination');
    let rows = this.subjects(kind);
    const filter = query.get('filter');
    if (filter !== null) {
      const match = /^(userName|externalId|displayName)\s+eq\s+("(?:\\.|[^"\\])*")$/i.exec(filter.trim());
      if (!match || (kind === 'group' && match[1]!.toLowerCase() === 'username')) return bad('Unsupported SCIM filter');
      let wanted: unknown;
      try { wanted = JSON.parse(match[2]!); } catch { return bad('Invalid SCIM filter'); }
      const attribute = match[1]!.toLowerCase();
      // userName is case-insensitive (RFC 7643 caseExact false); externalId and displayName compare exactly
      rows = rows.filter((subject) => attribute === 'username' ? userName(subject).toLowerCase() === String(wanted).toLowerCase()
        : (attribute === 'externalid' ? externalId(subject) : displayName(subject)) === wanted);
    }
    const resources = rows.slice(start - 1, start - 1 + count).map((subject) => this.view(subject));
    return { status: 200, body: { schemas: [LIST_SCHEMA], totalResults: rows.length, startIndex: start, itemsPerPage: resources.length, Resources: resources } };
  }

  private parseUser(body: Record<string, unknown>): UserInput {
    const value = fields(body, ['schemas', 'userName', 'externalId', 'displayName', 'active', 'groups']);
    schemas(value.schemas, USER_SCHEMA);
    return defined({ userName: text(value.userName, 'userName'), externalId: optionalText(value.externalId, 'externalId'),
      displayName: optionalText(value.displayName, 'displayName'), active: bool(value.active, true),
      groups: value.groups === undefined ? undefined : refs(value.groups, 'groups') });
  }
  private parseGroup(body: Record<string, unknown>): GroupInput {
    const value = fields(body, ['schemas', 'externalId', 'displayName', 'active', 'members']);
    schemas(value.schemas, GROUP_SCHEMA);
    return defined({ externalId: optionalText(value.externalId, 'externalId'), displayName: text(value.displayName, 'displayName'),
      active: bool(value.active, true), members: value.members === undefined ? [] : refs(value.members, 'members') });
  }
  private userSubject(input: UserInput, existing?: Subject): Subject {
    const name = input.userName.toLowerCase();
    if (this.subjects('user').some((user) => user.id !== existing?.id && (userName(user).toLowerCase() === name ||
      (input.externalId !== undefined && externalId(user) === input.externalId)))) throw new HttpError(409, 'conflict', 'userName or externalId already exists');
    let roles = [...(existing?.roles ?? [])];
    if (input.groups !== undefined) {
      // only roles of provisioned groups are SCIM's: a mapped role granted by hand, with no group yet, is kept
      const managed = new Set(this.subjects('group').map((group) => this.mappedRole(group)));
      const groups = input.groups.map((id) => this.find('group', id));
      if (groups.some((group) => !group.active)) invalid('Cannot add a user to an inactive group');
      roles = [...new Set([...roles.filter((role) => !managed.has(role)), ...groups.map((group) => this.role(group))])];
    }
    const { scimExternalId: dropped, ...kept } = existing?.attrs ?? {};
    return { type: 'user', id: existing?.id ?? randomUUID(), active: input.active, roles,
      clearance: existing?.clearance ?? 0, compartments: existing?.compartments ?? [], integrity: existing?.integrity ?? 'verified',
      attrs: { ...kept, name: input.displayName ?? input.userName, scimUserName: input.userName, ...(input.externalId === undefined ? {} : { scimExternalId: input.externalId }) } };
  }
  private groupSubject(input: GroupInput, existing?: Subject): Subject {
    if (this.subjects('group').some((group) => group.id !== existing?.id && (displayName(group) === input.displayName ||
      (input.externalId !== undefined && externalId(group) === input.externalId)))) throw new HttpError(409, 'conflict', 'displayName or externalId already exists');
    const { scimExternalId: dropped, ...kept } = existing?.attrs ?? {};
    const group: Subject = { type: 'group', id: existing?.id ?? randomUUID(), active: input.active, roles: [],
      clearance: existing?.clearance ?? 0, compartments: existing?.compartments ?? [], integrity: existing?.integrity ?? 'verified',
      attrs: { ...kept, name: input.displayName, scimDisplayName: input.displayName, ...(input.externalId === undefined ? {} : { scimExternalId: input.externalId }) } };
    this.role(group);
    return group;
  }
  /** Users whose mapped role must be added or removed so that the role holders are exactly the active group's members. */
  private membershipChanges(group: Subject, memberIds: readonly string[]): Subject[] {
    const role = this.role(group); const wanted = new Set(memberIds);
    for (const id of wanted) this.find('user', id);
    return this.subjects('user').filter((user) => user.roles.includes(role) !== (group.active && wanted.has(user.id)))
      .map((user) => ({ ...user, roles: user.roles.includes(role) ? user.roles.filter((item) => item !== role) : [...user.roles, role] }));
  }
  private createUser(body: Record<string, unknown>, origin: ScimCredentialOrigin): ScimResult {
    const user = this.userSubject(this.parseUser(body));
    return this.mutate('scim.user.create', [user], user, 201, origin);
  }
  private replaceUser(id: string, body: Record<string, unknown>, origin: ScimCredentialOrigin): ScimResult {
    const user = this.userSubject(this.parseUser(body), this.find('user', id));
    return this.mutate('scim.user.replace', [user], user, 200, origin);
  }
  private createGroup(body: Record<string, unknown>, origin: ScimCredentialOrigin): ScimResult {
    const input = this.parseGroup(body); const group = this.groupSubject(input);
    return this.mutate('scim.group.create', [group, ...this.membershipChanges(group, input.members)], group, 201, origin);
  }
  private replaceGroup(id: string, body: Record<string, unknown>, origin: ScimCredentialOrigin): ScimResult {
    const input = this.parseGroup(body); const group = this.groupSubject(input, this.find('group', id));
    return this.mutate('scim.group.replace', [group, ...this.membershipChanges(group, input.members)], group, 200, origin);
  }
  private deactivate(kind: Kind, id: string, origin: ScimCredentialOrigin): ScimResult {
    const changed = { ...this.find(kind, id), active: false };
    const members = kind === 'group' && this.mappedRole(changed) !== undefined ? this.membershipChanges(changed, []) : [];
    return this.mutate(`scim.${kind}.deactivate`, [changed, ...members], changed, 204, origin);
  }

  /** PatchOp on active and on groups (User) or members (Group) only, with or without a path, as IdPs send it. */
  private patch(kind: Kind, id: string, body: Record<string, unknown>, origin: ScimCredentialOrigin): ScimResult {
    const input = fields(body, ['schemas', 'Operations']); schemas(input.schemas, PATCH_SCHEMA);
    if (!Array.isArray(input.Operations) || !input.Operations.length || input.Operations.length > 100) return bad('Invalid PatchOp');
    const operations: unknown[] = input.Operations;
    const existing = this.find(kind, id);
    const list = kind === 'user' ? 'groups' : 'members';
    let active = existing.active;
    let ids = (this.view(existing)[list] as Array<{ value: string }>).map((ref) => ref.value);
    let listed = false;
    for (const raw of operations) {
      const operation = fields(raw, ['op', 'path', 'value']); const op = text(operation.op, 'op').toLowerCase();
      if (!['add', 'replace', 'remove'].includes(op)) bad('Unsupported PatchOp operation');
      for (const [target, value] of this.patchTargets(op, operation.path, operation.value, list)) {
        if (target === 'active') {
          if (op === 'remove') bad('active cannot be removed');
          active = patchBool(value);
          continue;
        }
        const values = value === undefined ? [] : refs(value, list); listed = true;
        ids = op === 'replace' ? values : op === 'add' ? [...new Set([...ids, ...values])] : value === undefined ? [] : ids.filter((item) => !values.includes(item));
      }
    }
    if (kind === 'user') {
      const user = this.userSubject(defined({ userName: userName(existing), externalId: externalId(existing), displayName: attr(existing, 'name'), active, groups: listed ? ids : undefined }), existing);
      return this.mutate('scim.user.patch', [user], user, 200, origin);
    }
    const group = this.groupSubject(defined({ externalId: externalId(existing), displayName: displayName(existing), active, members: ids }), existing);
    return this.mutate('scim.group.patch', [group, ...this.membershipChanges(group, ids)], group, 200, origin);
  }
  private patchTargets(op: string, path: unknown, value: unknown, list: string): Array<[string, unknown]> {
    if (path === undefined) {
      if (op === 'remove') bad('remove requires a path');
      return Object.entries(fields(value, ['active', list]));
    }
    const target = text(path, 'path');
    // Okta and others remove one member as members[value eq "id"]
    const one = new RegExp(`^${list}\\[value eq ("(?:\\\\.|[^"\\\\])*")\\]$`, 'i').exec(target);
    if (one && op === 'remove' && value === undefined) {
      let id: unknown;
      try { id = JSON.parse(one[1]!); } catch { return bad('Invalid path'); }
      return [[list, [{ value: id }]]];
    }
    const lower = target.toLowerCase();
    if (lower === 'active') return [['active', value]];
    if (lower === list) return [[list, value]];
    return bad('Only active and groups (User) or members (Group) can be patched');
  }

  private mutate(action: string, subjects: Subject[], viewOf: Subject, success: number, origin: ScimCredentialOrigin): ScimResult {
    if (!this.options.direct) {
      const change = propose(this.rt, SCIM_SERVICE, { kind: 'scim_subjects', payload: { subjects }, reason: `SCIM provisioning (${action}) awaiting two-person review` }, false, origin);
      const ids = new Set(subjects.map((subject) => subject.id));
      const projected = [...this.rt.store.state.subjects.filter((subject) => !ids.has(subject.id)), ...subjects];
      return { status: 202, body: { ...(success === 204 ? {} : this.view(viewOf, projected)), changeId: change.id, status: 'pending' } };
    }
    const result = candidate(this.rt, SCIM_SERVICE, 'scim_subjects', { subjects });
    this.rt.store.state = result.state; this.rt.store.save();
    this.rt.audit.append({ type: 'change', actor: SCIM_SERVICE.id, action, details: { direct: true, kind: 'scim_subjects', credential: origin.fingerprint, subjectIds: subjects.map((subject) => subject.id) } });
    return success === 204 ? { status: 204 } : { status: success, body: this.view(viewOf) };
  }
}
