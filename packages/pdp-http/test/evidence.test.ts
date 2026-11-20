import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { canonical } from '../../core/src/index.ts';
import { admin } from '../src/admin/index.ts';
import { open, reviewEmergency } from '../src/admin/break-glass.ts';
import { decideChange } from '../src/admin/changes.ts';
import { dueGrants, review } from '../src/admin/reviews.ts';
import { EVIDENCE_FRAMEWORKS, evidencePack } from '../src/admin/evidence.ts';
import { auditRows, listCursor, MAX_REPORT_ROWS, pseudonym, pseudonymise, subjectReport } from '../src/admin/privacy.ts';
import { configurationBaseline } from '../src/profile.ts';
import { sha256, type AuditList, type AuditLog, type AuditRecord } from '../src/audit.ts';
import { auditCursor } from '../src/postgres-chains.ts';
import { pullAudit } from '../src/siem.ts';
import { HttpError } from '../src/http.ts';
import type { User } from '../src/auth.ts';
import { FIXED, fixture, users, WHY, type Fixture } from './helpers.ts';

const status = (code: number) => (e: unknown): boolean => e instanceof HttpError && e.status === code;
interface Pack { pack: { framework: { id: string; controls: Array<{ id: string; evidence: string[] }> }; pseudonymised: boolean; disclaimer: string;
  sections: Record<string, any> }; manifest: { packSha256: string; sections: Record<string, string> }; signature: string }
const get = (f: Fixture, user: User, query: string): Promise<Pack> =>
  admin(f.rt, user, 'GET', new URL(`http://local/admin/v1/compliance/evidence?${query}`), {}, f.auth).value as Promise<Pack>;

/** A world with an access review decision, an approval, a break-glass and a signing-key rotation. */
function activity(f: Fixture): void {
  // seed-4 ends within 30 days, so it is due for review (as in review-regressions.test.ts)
  f.rt.store.state = { ...f.rt.store.state, tuples: f.rt.store.state.tuples.map((x) => x.id === 'seed-4' ? { ...x, validTo: '2026-12-01T00:00:00Z' } : x) };
  const due = dueGrants(f.rt).find((x) => x.tupleId === 'seed-4') as { tupleId: string };
  const revoke = review(f.rt, users.lina, due.tupleId, { decision: 'revoke', reason: WHY });
  decideChange(f.rt, users.omar, revoke.id, true, { reason: WHY });
  const emergency = open(f.rt, users.amira, { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 4 });
  reviewEmergency(f.rt, users.lina, emergency.id, 'review', { outcome: 'justified', note: WHY });
  admin(f.rt, users.lina, 'POST', new URL('http://local/admin/v1/signing-keys/rotate'), {}, f.auth);
}

test('every framework exports a pack whose manifest is signed by the keyring and hashes each live section', async (t) => {
  const f = fixture(t); activity(f);
  assert.deepEqual(EVIDENCE_FRAMEWORKS.map((x) => x.id), ['iso27001', 'iso27017', 'iso27018', 'iso27701', 'iso42001', 'iec62443-4-1', 'iec62443-4-2', 'soc2']);
  for (const framework of EVIDENCE_FRAMEWORKS) {
    const before = f.rt.audit.records().length;
    const { pack, manifest, signature } = await get(f, users.sam, `framework=${framework.id}`);
    assert.equal(pack.framework.id, framework.id);
    assert.match(pack.disclaimer, /Not a certification, attestation or statement of compliance/);
    assert.equal(f.rt.tokens.verifyManifest(manifest, signature), true);
    assert.equal(manifest.packSha256, sha256(canonical(pack)));
    for (const [name, value] of Object.entries(pack.sections)) assert.equal(manifest.sections[name], sha256(canonical(value)), name);
    // every control cites only sections that exist in the pack
    for (const control of pack.framework.controls) for (const section of control.evidence) assert.ok(section in pack.sections, `${framework.id} ${control.id}`);
    const exported = f.rt.audit.records().at(-1)!;
    assert.equal(f.rt.audit.records().length, before + 1);
    assert.deepEqual([exported.type, exported.actor, exported.action, exported.details?.packSha256], ['security', 'sam', 'evidence_export', manifest.packSha256]);
  }
  const { pack, manifest, signature } = await get(f, users.lina, 'framework=iso27001');
  const s = pack.sections;
  assert.equal(s.audit.verification.verified, true);
  assert.equal(s.audit.head.seq, f.rt.audit.tip().seq - 1, 'the head before the export row was appended');
  assert.equal(s.audit.head.hash, f.rt.audit.records().at(-1)!.prevHash);
  assert.equal(s.configuration.available, false, 'a fixture runtime has no recorded baseline');
  assert.equal(s.accessReviews.decisions.length, 1);
  assert.deepEqual([s.accessReviews.decisions[0].makerId, s.accessReviews.decisions[0].checkerId, s.accessReviews.decisions[0].status], ['lina', 'omar', 'applied']);
  assert.ok(s.accessReviews.due.every((item: Record<string, unknown>) => !('reason' in item)), 'metadata only');
  assert.ok(s.approvals.some((c: { checkerId: string }) => c.checkerId === 'omar'));
  assert.ok(s.breakGlass.emergencies.some((e: { status: string; reviewedBy: string }) => e.reviewedBy === 'lina'));
  assert.deepEqual(s.breakGlass.events.items.map((r: AuditRecord) => r.action), ['open', 'review']);
  assert.equal(s.keys.signingKeys.length, 2);
  assert.ok(Array.isArray(s.keys.pepCredentials));
  assert.ok(s.securityEvents.items.some((r: AuditRecord) => r.action === 'signing_key_rotate'));
  assert.equal(s.time.serverTime, f.rt.now());
  // a section changed after signing no longer matches the signed manifest
  const forged = { ...manifest, sections: { ...manifest.sections, approvals: sha256(canonical([])) } };
  assert.equal(f.rt.tokens.verifyManifest(forged, signature), false);
});

test('evidence packs are for officers and auditors, with a known framework and strict parameters', async (t) => {
  const f = fixture(t);
  for (const user of [users.amira, users.omar, users.ruth]) await assert.rejects(get(f, user, 'framework=soc2'), status(403));
  for (const query of ['', 'framework=nist', 'framework=soc2&framework=soc2', 'framework=soc2&x=1', 'framework=soc2&pseudonymise=yes', 'framework=soc2&pseudonymise=1&pseudonymise=1']) {
    await assert.rejects(get(f, users.sam, query), status(400), query);
  }
  const listed = admin(f.rt, users.sam, 'GET', new URL('http://local/admin/v1/compliance'), {}).value as { evidenceFrameworks: Array<{ id: string }> };
  assert.deepEqual(listed.evidenceFrameworks.map((x) => x.id), EVIDENCE_FRAMEWORKS.map((x) => x.id));
});

test('a pseudonymised pack and audit export replace person ids with stable keyed pseudonyms', async (t) => {
  const f = fixture(t); activity(f);
  f.rt.pseudonymKey = randomBytes(32);
  const p = (id: string): string => pseudonym(f.rt.pseudonymKey!, id);
  const { pack } = await get(f, users.sam, 'framework=iso27701&pseudonymise=1');
  assert.equal(pack.pseudonymised, true);
  const text = JSON.stringify(pack.sections);
  for (const person of ['"lina"', '"omar"', '"amira"', '"bob"']) assert.ok(!text.includes(person), person);
  const decision = pack.sections.accessReviews.decisions[0];
  assert.deepEqual([decision.makerId, decision.checkerId], [p('lina'), p('omar')], 'maker and checker stay distinct and comparable');
  assert.ok(pack.sections.breakGlass.events.items.every((r: AuditRecord & { pseudonymised: boolean }) => r.pseudonymised && r.subject === p('bob')));
  const page = await pullAudit(f.rt.audit, users.sam, new URL('http://local/admin/v1/audit/export?limit=1000&pseudonymise=1'), f.rt.pseudonymKey);
  const rows = page.body.trim().split('\n').map((line) => JSON.parse(line) as AuditRecord & { pseudonymised: boolean });
  const approve = rows.find((r) => r.action === 'approve')!;
  assert.deepEqual([approve.actor, approve.details?.makerId, approve.details?.checkerId], [p('omar'), p('lina'), p('omar')]);
  assert.ok(rows.every((r) => r.pseudonymised));
  await assert.rejects(pullAudit(f.rt.audit, users.sam, new URL('http://local/admin/v1/audit/export?pseudonymise=1')), status(400), 'no key, no pseudonyms');
  await assert.rejects(pullAudit(f.rt.audit, users.sam, new URL('http://local/admin/v1/audit/export?pseudonymise=0'), f.rt.pseudonymKey), status(400));
});

test('a pseudonymised pack replaces the administrator who granted a due access review', async (t) => {
  const f = fixture(t);
  const original = f.rt.store.state.tuples.find((tuple) => tuple.id === 'seed-4')!;
  f.rt.store.state = { ...f.rt.store.state, tuples: f.rt.store.state.tuples.map((tuple) => tuple.id === original.id ? { ...tuple, validTo: '2026-12-01T00:00:00Z' } : tuple) };
  f.rt.pseudonymKey = randomBytes(32);
  const { pack } = await get(f, users.sam, 'framework=iso27701&pseudonymise=1');
  const due = pack.sections.accessReviews.due.find((item: { tupleId: string }) => item.tupleId === original.id);
  assert.ok(original.grantedBy);
  assert.equal(due.grantedBy, pseudonym(f.rt.pseudonymKey, original.grantedBy));
  assert.ok(!JSON.stringify(pack).includes(`"${original.grantedBy}"`));
});

test('pseudonymise keeps service actors, the row order and the original hash, and marks the row', () => {
  const key = randomBytes(32);
  const row: AuditRecord = { seq: 3, ts: 'x', type: 'change', actor: 'pep:abc', action: 'scim', details: { subjectIds: ['a', 'b'], kind: 'k', makerId: 7 }, prevHash: 'p', hash: 'h' };
  const out = pseudonymise(row, key);
  assert.deepEqual(out, { ...row, details: { subjectIds: [pseudonym(key, 'a'), pseudonym(key, 'b')], kind: 'k', makerId: 7 }, pseudonymised: true });
  assert.equal(pseudonymise({ ...row, actor: 'system', details: undefined }, key).actor, 'system');
  assert.notEqual(pseudonym(key, 'a'), pseudonym(randomBytes(32), 'a'), 'another key, another pseudonym');
});

test('the subject access report gathers the model, emergencies, changes and audit rows of one id, and is audited', async (t) => {
  const f = fixture(t); activity(f);
  const report = await subjectReport(f.rt, users.lina, 'bob') as Record<string, any>;
  assert.equal(report.subjectId, 'bob');
  assert.deepEqual(report.subjects.map((s: { id: string }) => s.id), ['bob']);
  assert.ok(report.tuples.length > 0 && report.tuples.every((x: { subject: { id: string }; grantedBy?: string }) => x.subject.id === 'bob' || x.grantedBy === 'bob'));
  assert.equal(report.emergencies.length, 1);
  assert.ok(report.audit.rows.length > 0 && report.audit.rows.every((r: AuditRecord) => r.subject === 'bob'));
  assert.equal(report.audit.complete, true);
  const last = f.rt.audit.records().at(-1)!;
  assert.deepEqual([last.action, last.actor, last.subject], ['subject_access_report', 'lina', 'bob']);
  const maker = await subjectReport(f.rt, users.lina, 'lina') as Record<string, any>;
  assert.ok(maker.changes.some((c: { makerId: string }) => c.makerId === 'lina'));
  await assert.rejects(subjectReport(f.rt, users.sam, 'bob'), status(403));
  await assert.rejects(subjectReport(f.rt, users.lina, '%E0%A4%A'), status(400));
  await assert.rejects(subjectReport(f.rt, users.lina, 'x'.repeat(257)), status(400));
  const routed = await (admin(f.rt, users.lina, 'GET', new URL('http://local/admin/v1/privacy/subjects/bob'), {}).value as Promise<{ subjectId: string }>);
  assert.equal(routed.subjectId, 'bob');
});

test('the configuration baseline names the controls in force and production deviations, never a secret', () => {
  const seal = 'd'.repeat(64);
  const demo = configurationBaseline({ signingKeySeal: seal, databaseUrl: 'postgres://gate:pw@db/gate', clock: 'fixed:2026-11-08T10:00:00Z',
    tsa: { url: 'https://user:pw@tsa.example/tsr?k=1' }, siem: { url: 'https://siem.example/in', secret: 's'.repeat(32) } }, undefined);
  const text = JSON.stringify(demo);
  for (const secret of [seal, 'pw', 'k=1', 's'.repeat(32)]) assert.ok(!text.includes(secret), secret);
  assert.equal((demo.audit as { tsa: string }).tsa, 'https://tsa.example');
  assert.equal(demo.clockPinned, true);
  assert.ok((demo.productionDeviations as string[]).includes('CLOCK must not be set: a fixed clock is for demos'));
  const production = configurationBaseline({ profile: 'production', publicOrigin: 'https://gate.example', oidc: { issuer: 'https://idp.example/realms/x', clientId: 'gate', idClaim: 'sub' },
    databaseUrl: 'postgres://gate_app@db/gate', signingKeySeal: seal, sodHistory: 'server', tsa: { url: 'https://tsa.example/tsr', caFile: '/ca.pem' },
    breakGlass: { url: 'https://hooks.example/bg', secret: 'c'.repeat(32) }, blpSessionRequired: true }, 'm'.repeat(32));
  assert.deepEqual(production.productionDeviations, []);
  assert.equal(production.blpSessionRequired, true);
  assert.ok((configurationBaseline({}, undefined).productionDeviations as string[]).some((f) => f.startsWith('BLP_SESSION_REQUIRED must be true')), 'required by the production profile');
  assert.deepEqual(production.consoleSignIn, { oidcIssuer: 'https://idp.example', oidcAcr: null, samlIdpSso: null, samlAuthnContext: null, passwordLogin: false });
  // SAML instead of OIDC satisfies the IdP requirement; its MFA classes are part of the baseline
  const saml = { idpEntityId: 'https://idp.example/saml', idpSsoUrl: 'https://idp.example/sso?tenant=x', idpCert: '', authnContext: ['urn:mfa'], idAttribute: 'uid' };
  const samlOnly = configurationBaseline({ profile: 'production', publicOrigin: 'https://gate.example', saml, databaseUrl: 'postgres://gate_app@db/gate', signingKeySeal: seal, sodHistory: 'server',
    tsa: { url: 'https://tsa.example/tsr', caFile: '/ca.pem' }, breakGlass: { url: 'https://hooks.example/bg', secret: 'c'.repeat(32) }, blpSessionRequired: true }, 'm'.repeat(32));
  assert.deepEqual(samlOnly.productionDeviations, []);
  assert.deepEqual(samlOnly.consoleSignIn, { oidcIssuer: null, oidcAcr: null, samlIdpSso: 'https://idp.example', samlAuthnContext: ['urn:mfa'], passwordLogin: false });
  assert.deepEqual(production.storage, { postgres: true, postgresTls: { mode: 'verify-full', privateCa: false, clientCertificate: false }, signingKeysSealed: true, clearSigningKeysAllowed: false, sealRotationInProgress: false, cluster: false, nodeId: '0', maxStalenessMs: null });
  const cluster = configurationBaseline({ databaseUrl: 'postgres://gate_app@db/gate', cluster: true, nodeId: 'b', trustedProxies: '10.0.0.0/8, 192.168.1.1' }, undefined);
  assert.deepEqual([(cluster.storage as Record<string, unknown>).cluster, (cluster.storage as Record<string, unknown>).nodeId, (cluster.storage as Record<string, unknown>).maxStalenessMs], [true, 'b', 2000]);
  assert.deepEqual((cluster.transport as { trustedProxies: string[] }).trustedProxies, ['10.0.0.0/8', '192.168.1.1']);
  assert.deepEqual((demo.transport as { trustedProxies: string[] }).trustedProxies, []);
  assert.equal(configurationBaseline({ publicOrigin: 'not a url' }, undefined).transport && (configurationBaseline({ publicOrigin: 'not a url' }, undefined).transport as { publicOrigin: unknown }).publicOrigin, null);
});

test('time evidence compares each anchor with the time of the row it anchors', async (t) => {
  const f = fixture(t); activity(f);
  const first = f.rt.audit.records()[0]!;
  f.rt.audit.anchors.push({ seq: 1, hash: first.hash, tsa: 'https://tsa.example', genTime: new Date(Date.parse(first.ts) + 90_000).toISOString(), token: 'dG9rZW4' });
  f.rt.anchoring = { url: 'https://tsa.example/tsr' };
  const { pack } = await get(f, users.sam, 'framework=iec62443-4-2');
  assert.deepEqual(pack.sections.time.anchors, [{ seq: 1, recordTs: first.ts, tsaGenTime: f.rt.audit.anchors[0]!.genTime, tsaMinusRecordSeconds: 90 }]);
  assert.deepEqual(pack.sections.audit.anchoring, { tsa: 'https://tsa.example', lastError: null });
  assert.equal(pack.sections.audit.anchors[0].tokenSha256, sha256('dG9rZW4'));
  assert.equal(pack.sections.audit.verification.verified, true);
});

// --- cluster mode (GATE_CLUSTER): one audit chain per node, listed chain by chain with "node:seq" cursors -------------
/** An audit log shaped like PostgreSQL's in cluster mode: chains "a" and "b", list() ordered by (node, seq). */
function chains(perChain: number): { audit: AuditLog; rows: AuditRecord[] } {
  const base = Date.parse(FIXED); const rows: AuditRecord[] = [];
  // a writes on even seconds, b on odd ones: by time the chains interleave
  for (const node of ['a', 'b']) for (let seq = 1; seq <= perChain; seq++) {
    rows.push({ node, seq, ts: new Date(base + (2 * seq + (node === 'a' ? 0 : 1)) * 1000).toISOString(), type: 'decision', actor: 'pep', action: 'read', subject: 'bob', prevHash: '', hash: `${node}${seq}` });
  }
  const list = async (q: AuditList): Promise<{ items: AuditRecord[]; next: string | null }> => {
    const after = q.node ?? (q.cursor > 0 ? '0' : null);
    const match = rows.filter((r) => (after === null || r.node! > after || (r.node === after && r.seq > q.cursor)) && (!q.type || r.type === q.type) && (!q.subject || r.subject === q.subject));
    const items = match.slice(0, q.limit);
    return { items, next: match.length > q.limit ? auditCursor(items.at(-1)!) : null };
  };
  const audit: AuditLog = { anchors: [], records: () => rows, tip: () => ({ seq: perChain, hash: `a${perChain}` }), verify: () => ({ verified: true, length: rows.length }),
    append: () => undefined, list };
  return { audit, rows };
}

test('cluster: reports page through every chain by its "node:seq" cursor and keep the newest rows by time', async (t) => {
  assert.deepEqual([listCursor('42'), listCursor('a:7'), listCursor('node.x:3')], [{ cursor: 42 }, { node: 'a', cursor: 7 }, { node: 'node.x', cursor: 3 }]);
  const f = fixture(t); const { audit } = chains(1200);
  const found = await auditRows({ ...f.rt, audit }, { subject: 'bob' });
  assert.equal(found.complete, false, '2400 rows, more than the report keeps');
  assert.equal(found.items.length, MAX_REPORT_ROWS);
  // the newest 1000 by time are seq 701..1200 of both chains, not the tail of the last chain listed
  assert.deepEqual([...new Set(found.items.map((r) => r.node))].sort(), ['a', 'b']);
  assert.ok(found.items.every((r) => r.seq > 700));
  assert.ok(found.items.every((r, i) => i === 0 || found.items[i - 1]!.ts <= r.ts), 'oldest first');
});

test('cluster: an anchor over several chain heads is timed by its newest anchored row and lists the heads', async (t) => {
  const f = fixture(t); const { audit, rows } = chains(30);
  const b20 = rows.find((r) => r.node === 'b' && r.seq === 20)!;
  audit.anchors.push({ seq: 30, hash: 'h', tsa: 'https://tsa.example', genTime: new Date(Date.parse(b20.ts) + 59_000).toISOString(), token: 'dG9rZW4',
    heads: { a: { seq: 10, hash: 'a10' }, b: { seq: 20, hash: 'b20' } } });
  const { pack } = await evidencePack({ ...f.rt, audit }, users.sam, new URL('http://local/admin/v1/compliance/evidence?framework=iso27001')) as unknown as Pack;
  assert.deepEqual(pack.sections.time.anchors, [{ seq: 30, recordTs: b20.ts, tsaGenTime: audit.anchors[0]!.genTime, tsaMinusRecordSeconds: 59 }]);
  assert.deepEqual(pack.sections.audit.anchors[0].heads, { a: { seq: 10, hash: 'a10' }, b: { seq: 20, hash: 'b20' } });
});
