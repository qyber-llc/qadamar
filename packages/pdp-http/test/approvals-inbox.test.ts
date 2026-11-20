import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { admin } from '../src/admin/index.ts';
import { propose } from '../src/admin/changes.ts';
import { forgetApprover } from '../src/admin/inbox.ts';
import { HttpError } from '../src/http.ts';
import { createServer } from '../src/server.ts';
import type { Runtime } from '../src/runtime.ts';
import type { Change } from '../src/store.ts';
import { fixture, users, user as userById, WHY, FIXED } from './helpers.ts';

const call = (rt: Runtime, user: string, path: string, method = 'GET', b: Record<string, unknown> = {}): unknown =>
  admin(rt, userById(user), method, new URL(`http://localhost/admin/v1${path}`), b).value;
const refused = (status: number, code?: string) => (e: unknown): boolean => e instanceof HttpError && e.status === status && (code === undefined || e.code === code);
const grant = (subject = 'bob', resource = 'CASE-15'): Record<string, unknown> => ({ kind: 'add_tuple', reason: WHY, payload: {
  object: { type: 'case', id: resource }, relation: 'allocated', subject: { type: 'user', id: subject }, validTo: '2026-12-08T10:00:00Z',
} });
const listMode = (rt: Runtime, id: string): void => { call(rt, 'amira', `/approval-modes/${id}`, 'PUT', { mode: 'list' }); };
const bulk = async (rt: Runtime, user: string, b: Record<string, unknown>) =>
  await call(rt, user, '/changes/decide', 'POST', b) as { approve: boolean; results: Array<{ id: string; ok: boolean; status?: string; error?: string }> };

test('only an access admin or a security officer sets an approver mode, at once and audited', (t) => {
  const { rt } = fixture(t);
  assert.deepEqual(call(rt, 'omar', '/inbox'), { approvalMode: 'individual', snoozes: [] }, 'individual by default');
  for (const who of ['omar', 'ruth', 'sam']) {
    assert.throws(() => call(rt, who, '/approval-modes/omar', 'PUT', { mode: 'list' }), refused(403), who);
    assert.throws(() => call(rt, who, '/approval-modes'), refused(403), who);
  }
  assert.equal((call(rt, 'amira', '/approval-modes/omar', 'PUT', { mode: 'list' }) as { mode: string }).mode, 'list');
  assert.equal((call(rt, 'omar', '/inbox') as { approvalMode: string }).approvalMode, 'list', 'effective immediately');
  call(rt, 'lina', '/approval-modes/lina', 'PUT', { mode: 'list' }); // an officer may set their own
  call(rt, 'lina', '/approval-modes/omar', 'PUT', { mode: 'individual' });
  const rows = rt.audit.records().filter((r) => r.action === 'approval_mode_set');
  assert.deepEqual(rows.map((r) => [r.type, r.actor, r.subject, r.details]), [
    ['security', 'amira', 'omar', { from: 'individual', to: 'list' }],
    ['security', 'lina', 'lina', { from: 'individual', to: 'list' }],
    ['security', 'lina', 'omar', { from: 'list', to: 'individual' }],
  ]);
  for (const bad of [{ mode: 'bulk' }, {}, { mode: 1 }]) assert.throws(() => call(rt, 'amira', '/approval-modes/omar', 'PUT', bad), refused(422));
  for (const id of ['__proto__', '%20omar', 'x'.repeat(257), '%E0%A4%A']) assert.throws(() => call(rt, 'amira', `/approval-modes/${id}`, 'PUT', { mode: 'list' }), (e) => e instanceof HttpError && e.status >= 400 && e.status < 500, id);
  call(rt, 'amira', '/approval-modes/sso%40example.org', 'PUT', { mode: 'list' });
  const listed = call(rt, 'lina', '/approval-modes') as { items: Array<{ id: string; mode: string }> };
  assert.deepEqual(listed.items.map((i) => [i.id, i.mode]), [['lina', 'list'], ['omar', 'individual'], ['sso@example.org', 'list']]);
});

test('bulk decisions are refused in individual mode and for a caller who cannot decide', async (t) => {
  const { rt } = fixture(t);
  const c = propose(rt, users.amira, grant());
  await assert.rejects(bulk(rt, 'omar', { ids: [c.id], approve: false, reason: WHY }), refused(403, 'individual_mode'));
  listMode(rt, 'amira');
  await assert.rejects(bulk(rt, 'amira', { ids: [c.id], approve: false, reason: WHY }), refused(403, 'forbidden'));
  assert.equal(rt.store.changes[0]!.status, 'pending');
});

test('bulk input: 1 to 50 distinct ids, a boolean decision and a note', async (t) => {
  const { rt } = fixture(t);
  listMode(rt, 'omar');
  const ids = (n: number): string[] => Array.from({ length: n }, (_, i) => `id-${i}`);
  for (const b of [{ ids: [] }, { ids: ids(51) }, { ids: ['a', 'a'] }, { ids: [1] }, { ids: [''] }, { ids: 'a' }, { ids: ['a'], approve: 'yes' }]) {
    await assert.rejects(bulk(rt, 'omar', { approve: true, reason: WHY, ...b }), refused(422), JSON.stringify(b).slice(0, 60));
  }
  await assert.rejects(bulk(rt, 'omar', { ids: ['a'], approve: true }), refused(400), 'the note is required');
  const fifty = await bulk(rt, 'omar', { ids: ids(50), approve: false, reason: WHY });
  assert.equal(fifty.results.length, 50);
  assert.ok(fifty.results.every((r) => !r.ok && r.error === 'not_found'));
});

test('bulk keeps every four-eyes check per item: own change and beneficiary refused, the others decided, one audit row each', async (t) => {
  const { rt } = fixture(t);
  listMode(rt, 'omar');
  const others = propose(rt, users.amira, grant());
  const own = propose(rt, { ...users.omar, roles: ['approver', 'access_admin'] }, grant('carol'));
  const beneficiary = propose(rt, users.amira, grant('omar', 'CASE-14'));
  const result = await bulk(rt, 'omar', { ids: [own.id, beneficiary.id, others.id], approve: true, reason: WHY });
  assert.deepEqual(result.results.map((r) => [r.id, r.ok, r.status ?? r.error]), [
    [own.id, false, 'self_approval'], [beneficiary.id, false, 'forbidden'], [others.id, true, 'applied'],
  ]);
  const status = (id: string): string => rt.store.changes.find((c) => c.id === id)!.status;
  assert.deepEqual([status(own.id), status(beneficiary.id), status(others.id)], ['pending', 'pending', 'applied']);
  const rows = rt.audit.records().filter((r) => ['approve', 'reject', 'refused'].includes(r.action));
  assert.deepEqual(rows.map((r) => [r.action, r.details]), [
    ['approve', { changeId: others.id, makerId: 'amira', checkerId: 'omar', kind: 'add_tuple' }],
    ['refused', { route: '/admin/v1/changes/decide', approve: true, refused: [{ changeId: own.id, error: 'self_approval' }, { changeId: beneficiary.id, error: 'forbidden' }] }],
  ]);
  assert.equal(rt.audit.verify().verified, true);
});

test('bulk rejection decides every item with its own audit row; a second ordinary approval in one batch is stale, as it would be alone', async (t) => {
  const { rt } = fixture(t);
  listMode(rt, 'lina');
  const a = propose(rt, users.amira, grant()); const b = propose(rt, users.amira, grant('carol'));
  const rejected = await bulk(rt, 'lina', { ids: [a.id, b.id], approve: false, reason: WHY });
  assert.ok(rejected.results.every((r) => r.ok && r.status === 'rejected'));
  assert.deepEqual(rt.audit.records().filter((r) => r.action === 'reject').map((r) => [r.actor, (r.details as { changeId: string }).changeId]), [['lina', a.id], ['lina', b.id]]);
  const c = propose(rt, users.amira, grant()); const d = propose(rt, users.amira, grant('carol'));
  const approved = await bulk(rt, 'lina', { ids: [c.id, d.id], approve: true, reason: WHY });
  assert.deepEqual(approved.results.map((r) => r.status ?? r.error), ['applied', 'stale']);
});

test('snooze: per user, after today and within 30 days, audited, back when the date passes or the item changes', (t) => {
  const { rt, setClock } = fixture(t);
  const c = propose(rt, users.amira, grant());
  const item = `change:${c.id}`;
  for (const until of ['2026-11-08', '2026-12-09', '2026-11-31', 'tomorrow', undefined]) {
    assert.throws(() => call(rt, 'omar', '/inbox/snoozes', 'POST', { item, until }), refused(422), String(until));
  }
  assert.throws(() => call(rt, 'omar', '/inbox/snoozes', 'POST', { item: 'change:nope', until: '2026-11-10' }), refused(404));
  const hidden = propose(rt, users.amira, { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY });
  assert.throws(() => call(rt, 'ruth', '/inbox/snoozes', 'POST', { item: `change:${hidden.id}`, until: '2026-11-10' }), refused(404), 'an item the user cannot see');
  assert.throws(() => call(rt, 'omar', '/inbox/snoozes', 'POST', { item: 'emergency:x', until: '2026-11-10' }), refused(404));
  call(rt, 'omar', '/inbox/snoozes', 'POST', { item, until: '2026-12-08' }); // 30 days ahead
  call(rt, 'omar', '/inbox/snoozes', 'POST', { item, until: '2026-11-10' }); // replaced
  assert.deepEqual((call(rt, 'omar', '/inbox') as { snoozes: unknown }).snoozes, [{ item, until: '2026-11-10' }]);
  assert.deepEqual((call(rt, 'lina', '/inbox') as { snoozes: unknown }).snoozes, [], 'only for the user who snoozed');
  setClock('2026-11-10T00:00:00Z');
  assert.deepEqual((call(rt, 'omar', '/inbox') as { snoozes: unknown }).snoozes, [], 'back on the date');
  setClock(FIXED);
  assert.equal((call(rt, 'omar', '/inbox') as { snoozes: unknown[] }).snoozes.length, 1);
  call(rt, 'lina', '/inbox/snoozes', 'POST', { item, until: '2026-11-12' });
  call(rt, 'omar', `/changes/${c.id}/reject`, 'POST', { reason: WHY });
  assert.deepEqual((call(rt, 'lina', '/inbox') as { snoozes: unknown }).snoozes, [], 'back once the item changed');
  assert.throws(() => call(rt, 'lina', `/inbox/snoozes/${encodeURIComponent(item)}`, 'DELETE'), refused(404));
  const e = propose(rt, users.amira, grant('carol'));
  call(rt, 'omar', '/inbox/snoozes', 'POST', { item: `change:${e.id}`, until: '2026-11-12' });
  assert.deepEqual(call(rt, 'omar', `/inbox/snoozes/${encodeURIComponent(`change:${e.id}`)}`, 'DELETE'), { item: `change:${e.id}` });
  assert.deepEqual((call(rt, 'omar', '/inbox') as { snoozes: unknown }).snoozes, []);
  assert.deepEqual(rt.audit.records().filter((r) => ['snooze', 'unsnooze'].includes(r.action)).map((r) => [r.actor, r.action]),
    [['omar', 'snooze'], ['omar', 'snooze'], ['lina', 'snooze'], ['omar', 'snooze'], ['omar', 'unsnooze']]);
});

test('an emergency can be snoozed by the roles that see break-glass, and returns once reviewed', (t) => {
  const { rt } = fixture(t);
  const opened = call(rt, 'amira', '/break-glass', 'POST', { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 1 }) as { id: string };
  const item = `emergency:${opened.id}`;
  assert.throws(() => call(rt, 'omar', '/inbox/snoozes', 'POST', { item, until: '2026-11-10' }), refused(404));
  call(rt, 'lina', '/inbox/snoozes', 'POST', { item, until: '2026-11-10' });
  assert.equal((call(rt, 'lina', '/inbox') as { snoozes: unknown[] }).snoozes.length, 1);
  call(rt, 'lina', `/break-glass/${opened.id}/review`, 'POST', { outcome: 'justified', note: 'checked' });
  assert.deepEqual((call(rt, 'lina', '/inbox') as { snoozes: unknown }).snoozes, []);
});

test('over HTTP: PUT and DELETE carry the CSRF check, the document is approval-prefs.json (0600), refusals are audited', async (t) => {
  const dir = mkdtempSync('/tmp/pdp-inbox-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const server = createServer({ port: 0, dataDir: dir, clock: `fixed:${FIXED}` });
  await server.listen(); t.after(() => server.close());
  const { passwords } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  const send = async (path: string, method: string, headers: Record<string, string>, body?: unknown) => {
    const res = await fetch(`${server.url}/admin/v1${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await res.text();
    return { status: res.status, data: (text ? JSON.parse(text) : {}) as Record<string, unknown> };
  };
  const login = async (id: string): Promise<Record<string, string>> => {
    const res = await fetch(`${server.url}/admin/v1/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: id, password: passwords[id] }) });
    const data = await res.json() as { csrfToken: string };
    return { cookie: String(res.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': data.csrfToken };
  };
  const amira = await login('amira'); const omar = await login('omar');
  assert.equal((await send('/approval-modes/omar', 'PUT', { cookie: amira.cookie! }, { mode: 'list' })).status, 403, 'no CSRF token');
  const set = await send('/approval-modes/omar', 'PUT', amira, { mode: 'list' });
  assert.equal(set.status, 200, JSON.stringify(set.data)); assert.equal(set.data.mode, 'list');
  assert.equal(statSync(resolve(dir, 'approval-prefs.json')).mode & 0o777, 0o600);
  assert.equal((await send('/inbox', 'GET', omar)).data.approvalMode, 'list');
  const proposed = await send('/changes', 'POST', amira, grant());
  const id = String(proposed.data.id);
  assert.equal((await send('/inbox/snoozes', 'POST', omar, { item: `change:${id}`, until: '2026-11-10' })).status, 201);
  assert.equal((await send(`/inbox/snoozes/${encodeURIComponent(`change:${id}`)}`, 'DELETE', { cookie: omar.cookie! })).status, 403, 'no CSRF token');
  assert.equal((await send(`/inbox/snoozes/${encodeURIComponent(`change:${id}`)}`, 'DELETE', omar)).status, 200);
  const decided = await send('/changes/decide', 'POST', omar, { ids: [id], approve: false, reason: WHY });
  assert.equal(decided.status, 200, JSON.stringify(decided.data));
  assert.deepEqual(decided.data.results, [{ id, ok: true, status: 'rejected' }]);
  assert.equal((await send('/changes/decide', 'POST', amira, { ids: [id], approve: false, reason: WHY })).status, 403);
  assert.equal((await send('/approval-modes/nobody', 'PUT', omar, { mode: 'list' })).status, 403);
  const audit = readFileSync(resolve(dir, 'audit.jsonl'), 'utf8');
  const modeRow = audit.split('\n').find((line) => line.includes('approval_mode_set'))!;
  assert.match(modeRow, /"subject":"ps\.[0-9a-f]{32}"/); assert.ok(!modeRow.includes('omar'), 'the target is pseudonymised like any person id');
  assert.match(audit, /"type":"security"[^\n]*"route":"\/admin\/v1\/approval-modes\/\{id\}"/, 'a refused mode change is a security row naming no person');
  assert.match(audit, /"type":"change"[^\n]*"action":"refused"[^\n]*"route":"\/admin\/v1\/inbox\/snoozes\//);
});

test('an erased approver keeps no mode or snooze, and modes they set name their pseudonym', (t) => {
  const { rt } = fixture(t);
  call(rt, 'lina', '/approval-modes/dan', 'PUT', { mode: 'list' });
  call(rt, 'amira', '/approval-modes/lina', 'PUT', { mode: 'list' });
  const c = propose(rt, users.amira, grant());
  call(rt, 'omar', '/inbox/snoozes', 'POST', { item: `change:${c.id}`, until: '2026-11-10' });
  forgetApprover(rt, 'omar', 'ps.x'); forgetApprover(rt, 'lina', 'ps.y'); forgetApprover(rt, 'nobody', 'ps.z');
  const stored = rt.approvalPrefs!.load()!;
  assert.deepEqual(stored.modes, { dan: { mode: 'list', setBy: 'ps.y', at: rt.now() } });
  assert.deepEqual(stored.snoozes, {});
});
