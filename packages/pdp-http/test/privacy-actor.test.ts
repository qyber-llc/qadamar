// The subject access report includes what the person did, not only what was done to them (admin-plane review finding 4).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { open, reviewEmergency } from '../src/admin/break-glass.ts';
import { subjectReport } from '../src/admin/privacy.ts';
import { createServer } from '../src/server.ts';
import type { AuditRecord } from '../src/audit.ts';
import { fixture, users, WHY } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

type Report = Record<string, any>;

test('the report lists grants, emergencies, certifications, publications and audit rows where the id is the actor', async (t) => {
  const f = fixture(t);
  const e = open(f.rt, users.amira, { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 1 });
  reviewEmergency(f.rt, users.lina, e.id, 'review', { outcome: 'justified', note: WHY });
  f.rt.store.state = { ...f.rt.store.state, certifications: [{ resourceType: 'payment', action: 'approve', certifiedBy: 'lina', approvedBy: 'omar',
    certifiedAt: f.rt.now(), policyVersion: 'pv.x', changeId: 'c-1', reason: WHY }] };
  f.rt.store.history = [...f.rt.store.history, { version: 'pv.y', publishedAt: f.rt.now(), publishedBy: 'amira', approvedBy: 'omar', reason: WHY }];

  const amira = await subjectReport(f.rt, users.lina, 'amira') as Report;
  assert.ok(amira.tuples.some((x: { id: string }) => x.id === e.tupleId), 'the grant she made');
  assert.ok(amira.emergencies.some((x: { id: string }) => x.id === e.id), 'the emergency she opened');
  assert.deepEqual(amira.publications.map((p: { version: string }) => p.version), ['pv.y']);
  assert.ok(amira.audit.rows.some((r: AuditRecord) => r.actor === 'amira' && r.type === 'break_glass' && r.action === 'open'), 'audit rows she wrote');
  assert.ok(amira.audit.rows.every((r: AuditRecord) => r.actor === 'amira' || r.subject === 'amira'));

  const lina = await subjectReport(f.rt, users.lina, 'lina') as Report;
  assert.ok(lina.emergencies.some((x: { id: string; reviewedBy: string }) => x.id === e.id && x.reviewedBy === 'lina'), 'the emergency she reviewed');
  assert.equal(lina.certifications.length, 1);
  const omar = await subjectReport(f.rt, users.lina, 'omar') as Report;
  assert.equal(omar.certifications.length, 1); assert.deepEqual(omar.publications.map((p: { version: string }) => p.version), ['pv.y']);
  const bob = await subjectReport(f.rt, users.lina, 'bob') as Report;
  assert.equal(bob.certifications.length, 0); assert.equal(bob.publications.length, 0);
});

test('PostgreSQL: the report finds rows by actor through the stored pseudonym, and only those', { skip, timeout: 60_000 }, async (t) => {
  const { url } = await throwawayDatabase(t, 'privacy_actor');
  const dir = mkdtempSync('/tmp/pdp-privacy-actor-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const server = createServer({ port: 0, dataDir: dir, databaseUrl: url, signingKeySeal: randomBytes(32).toString('base64url') });
  await server.listen(); t.after(() => server.close());
  const { passwords } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  const call = async (path: string, method: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(server.url + path, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const text = await res.text();
    return { status: res.status, cookie: res.headers.get('set-cookie')?.split(';')[0] ?? '', data: (text ? JSON.parse(text) : {}) as Report };
  };
  const session = async (id: string) => {
    const r = await call('/admin/v1/session', 'POST', { username: id, password: passwords[id] });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    return { cookie: r.cookie, 'x-csrf-token': String(r.data.csrfToken) };
  };
  const amira = await session('amira');
  assert.equal((await call('/admin/v1/break-glass', 'POST', { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 1 }, amira)).status, 201);
  const lina = await session('lina');
  const report = await call('/admin/v1/privacy/subjects/amira', 'GET', undefined, lina);
  assert.equal(report.status, 200, JSON.stringify(report.data));
  const rows = report.data.audit.rows as AuditRecord[];
  assert.ok(rows.some((r) => r.actor === 'amira' && r.type === 'break_glass'), JSON.stringify(rows));
  assert.ok(rows.every((r) => r.actor === 'amira' || r.subject === 'amira'), 'no row of anyone else');
});
