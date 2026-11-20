// Resource registration (docs/API.md §2.2): requests are checked before they leave (the PDP checks them again against
// its policy schema), answers are checked before they are returned.
import { PdpResponseError, PepError } from './errors.ts';
import type { Ref, RegistrationItem, RegistrationResult, RegistrationStatus, ResourceListRequest, ResourceListResponse, ResourceRecord, ResourceSyncRequest } from './types.ts';
import { json, object } from './validation.ts';

export const MAX_SYNC = 1000;
const STATUSES: readonly RegistrationStatus[] = ['created', 'updated', 'unchanged', 'retired', 'proposed'];
const INTEGRITY = ['derived', 'extracted', 'system', 'verified'];
const RECORD_KEYS = new Set(['type', 'id', 'level', 'compartments', 'integrity', 'contentClasses', 'owner', 'parent', 'version', 'attrs']);
const invalid = (message: string): never => { throw new PepError('invalid_request', message); };
const text = (v: unknown): boolean => typeof v === 'string' && v.length > 0 && v.length <= 256 && !/[\u0000-\u001f\u007f]/.test(v);
const texts = (v: unknown): boolean => Array.isArray(v) && v.length <= 64 && v.every((x) => typeof x === 'string') && new Set(v).size === v.length;
const plain = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

function ref(value: unknown, where: string): Ref {
  if (!plain(value) || Object.keys(value).some((k) => k !== 'type' && k !== 'id') || !text(value.type) || !text(value.id)) return invalid(`${where} must be { type, id }`);
  return { type: value.type as string, id: value.id as string };
}
export function checkRecord(r: unknown, where: string): ResourceRecord {
  if (!plain(r)) return invalid(`${where} must be an object`);
  if (Object.keys(r).some((k) => !RECORD_KEYS.has(k))) invalid(`${where} has an unknown field`);
  ref({ type: r.type, id: r.id }, where);
  if (!Number.isInteger(r.level) || (r.level as number) < 0 || (r.level as number) > 3) invalid(`${where}.level must be an integer 0..3`);
  if (!texts(r.compartments)) invalid(`${where}.compartments must be a list of distinct strings`);
  if (!INTEGRITY.includes(r.integrity as string)) invalid(`${where}.integrity must be derived, extracted, system or verified`);
  if (!texts(r.contentClasses)) invalid(`${where}.contentClasses must be a list of distinct strings (empty when scanned and clean)`);
  if (r.owner !== undefined && !text(r.owner)) invalid(`${where}.owner must be a non-empty string`);
  if (r.parent !== undefined) ref(r.parent, `${where}.parent`);
  if (r.version !== undefined && (!Number.isSafeInteger(r.version) || (r.version as number) < 0)) invalid(`${where}.version must be a non-negative integer`);
  if (r.attrs !== undefined && !plain(r.attrs)) invalid(`${where}.attrs must be an object`);
  return r as unknown as ResourceRecord;
}
export function checkSync(request: ResourceSyncRequest): ResourceSyncRequest {
  const resources = request.resources ?? []; const retire = request.retire ?? [];
  if (!Array.isArray(resources) || !Array.isArray(retire)) return invalid('resources and retire must be lists');
  if (resources.length + retire.length < 1 || resources.length + retire.length > MAX_SYNC) invalid(`A sync names 1..${MAX_SYNC} resources`);
  resources.forEach((r, i) => checkRecord(r, `resources[${i}]`));
  retire.forEach((r, i) => ref(r, `retire[${i}]`));
  return request;
}
export function checkList(request: ResourceListRequest): ResourceListRequest {
  if (!text(request.type)) invalid('type must be a non-empty string');
  if (request.limit !== undefined && (!Number.isInteger(request.limit) || request.limit < 1 || request.limit > MAX_SYNC)) invalid(`limit must be an integer 1..${MAX_SYNC}`);
  if (request.cursor !== undefined && typeof request.cursor !== 'string') invalid('cursor must be a string');
  return request;
}
export const checkRef = ref;

function malformed(): never { throw new PdpResponseError(); }
function item(value: unknown): RegistrationItem {
  const v = object(value);
  if (!text(v.type) || !text(v.id) || !STATUSES.includes(v.status as RegistrationStatus)) malformed();
  if (v.version !== undefined && !Number.isSafeInteger(v.version)) malformed();
  if ((v.status === 'proposed') !== (typeof v.changeId === 'string' && v.changeId.length > 0)) malformed();
  return { type: v.type as string, id: v.id as string, status: v.status as RegistrationStatus,
    ...(v.version === undefined ? {} : { version: v.version as number }), ...(v.changeId === undefined ? {} : { changeId: v.changeId as string }) };
}
export function registration(value: unknown): RegistrationResult {
  const v = object(value);
  if (!Array.isArray(v.items)) malformed();
  const counts = object(v.counts);
  if (!STATUSES.every((s) => Number.isSafeInteger(counts[s]))) malformed();
  return { items: (v.items as unknown[]).map(item), counts: Object.fromEntries(STATUSES.map((s) => [s, counts[s] as number])) as Record<RegistrationStatus, number> };
}
export function listed(value: unknown): ResourceListResponse {
  const v = object(value);
  if (!Array.isArray(v.resources) || typeof v.next_cursor !== 'string') malformed();
  return { resources: (v.resources as unknown[]).map((x) => {
    const r = object(json(x));
    if (!text(r.type) || !text(r.id) || !Number.isSafeInteger(r.version)) malformed();
    return { type: r.type as string, id: r.id as string, version: r.version as number };
  }), next_cursor: v.next_cursor as string };
}
