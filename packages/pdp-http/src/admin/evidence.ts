// Per-framework evidence pack from live data, with a manifest signed by the decision-token keyring (docs/compliance).
// It is evidence an auditor can test, never a certification, attestation or compliance claim.
import { readFileSync } from 'node:fs';
import { canonical, policyVersion } from '../../../core/src/index.ts';
import type { Runtime } from '../runtime.ts';
import type { Auth, User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { HttpError } from '../http.ts';
import { LEGACY_NODE, sha256, type Anchor, type AuditRecord } from '../audit.ts';
import { readAuditBatch } from '../siem.ts';
import { dueGrants } from './reviews.ts';
import { auditRows, pseudonym, pseudonymKey, pseudonymise } from './privacy.ts';

type Section = 'configuration' | 'time' | 'policy' | 'audit' | 'accessReviews' | 'approvals' | 'breakGlass' | 'keys' | 'securityEvents' | 'ci';
export interface EvidenceFramework { id: string; name: string; mapping: string; controls: Record<string, Section[]> }
/** Controls with live evidence in the pack; every other control and its status is in the mapping document. */
export const EVIDENCE_FRAMEWORKS: readonly EvidenceFramework[] = [
  { id: 'iso27001', name: 'ISO/IEC 27001:2022 Annex A', mapping: 'docs/compliance/iso27001-annexA.md', controls: {
    '5.3': ['approvals'], '5.15': ['policy', 'approvals'], '5.16': ['approvals', 'configuration'], '5.17': ['keys', 'configuration'],
    '5.18': ['accessReviews', 'approvals'], '5.28': ['audit'], '5.33': ['audit'], '8.2': ['breakGlass', 'approvals'], '8.3': ['policy'],
    '8.5': ['configuration'], '8.9': ['configuration'], '8.15': ['audit', 'securityEvents'], '8.16': ['configuration', 'securityEvents'],
    '8.17': ['time'], '8.24': ['keys'], '8.25': ['ci'], '8.29': ['ci'], '8.32': ['approvals', 'policy'] } },
  { id: 'iso27017', name: 'ISO/IEC 27017:2015', mapping: 'docs/compliance/iso27017.md', controls: {
    'CLD.12.1.5': ['approvals', 'securityEvents'], 'CLD.12.4.5': ['audit', 'configuration'], '9.2.3': ['breakGlass', 'approvals'],
    '9.4.1': ['policy'], '10.1.2': ['keys'], '12.1.2': ['approvals'], '12.4.1': ['audit'], '12.4.3': ['securityEvents', 'approvals'], '12.4.4': ['time'] } },
  { id: 'iso27018', name: 'ISO/IEC 27018', mapping: 'docs/compliance/iso27018.md', controls: {
    'A.5.2': ['securityEvents'], 'A.10.9': ['accessReviews', 'approvals'], '10.1.1': ['keys'], '12.4.1': ['audit', 'securityEvents'] } },
  { id: 'iso27701', name: 'ISO/IEC 27701', mapping: 'docs/compliance/iso27701.md', controls: {
    'A.7.3.6': ['securityEvents'], 'A.7.4.9': ['configuration'], 'B.8.2.6': ['securityEvents'], 'B.8.5.3': ['securityEvents'] } },
  { id: 'iso42001', name: 'ISO/IEC 42001:2023 Annex A', mapping: 'docs/compliance/iso42001.md', controls: {
    'A.6.2.8': ['audit'], 'A.9.2': ['policy'], 'A.9.4': ['policy', 'approvals'] } },
  { id: 'iec62443-4-1', name: 'IEC 62443-4-1:2018', mapping: 'docs/compliance/iec62443-4-1.md', controls: {
    'SM-6': ['policy'], 'SM-8': ['keys'], 'SVV-1': ['ci'], 'SVV-3': ['ci'], 'SG-3': ['configuration'], 'SG-6': ['configuration'] } },
  { id: 'iec62443-4-2', name: 'IEC 62443-4-2:2019', mapping: 'docs/compliance/iec62443-4-2.md', controls: {
    'CR 1.1': ['configuration'], 'CR 1.2': ['keys'], 'CR 1.3': ['approvals', 'accessReviews'], 'CR 2.1': ['policy'], 'CR 2.8': ['audit'],
    'CR 2.11': ['time'], 'CR 2.12': ['audit', 'keys'], 'CR 3.4': ['policy'], 'CR 3.9': ['audit'], 'CR 4.3': ['keys'], 'CR 6.1': ['audit'], 'CR 7.6': ['configuration'] } },
  { id: 'soc2', name: 'AICPA Trust Services Criteria (2017, revised points of focus)', mapping: 'docs/compliance/soc2-tsc.md', controls: {
    'CC6.1': ['policy', 'configuration', 'keys'], 'CC6.2': ['approvals'], 'CC6.3': ['approvals', 'accessReviews', 'breakGlass'],
    'CC7.2': ['audit', 'securityEvents'], 'CC8.1': ['approvals', 'policy', 'ci'] } },
];
const DISCLAIMER = 'Product evidence for an auditor to test. Not a certification, attestation or statement of compliance: those come only from accredited certification bodies or CPA firms after auditing an organisation.';
const VERSION = (JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string }).version;
const ANCHORS_SHOWN = 20;

/** The newest row an anchor covers: its seq on chain "0", or, over several chains (`heads`), the latest of their heads. */
async function anchoredRow(rt: Runtime, a: Anchor): Promise<AuditRecord | undefined> {
  const heads = a.heads ? Object.entries(a.heads).map(([node, h]) => ({ node, seq: h.seq })) : [{ node: LEGACY_NODE, seq: a.seq }];
  const rows = await Promise.all(heads.filter((h) => h.seq > 0).map(async ({ node, seq }) => {
    const read = rt.audit.list ? (await rt.audit.list({ node, cursor: seq - 1, limit: 1 })).items : await readAuditBatch(rt.audit, seq - 1, 1);
    return read.find((r) => (r.node ?? LEGACY_NODE) === node && r.seq === seq);
  }));
  return rows.reduce<AuditRecord | undefined>((newest, r) => (r && (!newest || r.ts > newest.ts) ? r : newest), undefined);
}

/** GET /admin/v1/compliance/evidence?framework=<id>[&pseudonymise=1] → { pack, manifest, signature }. */
export async function evidencePack(rt: Runtime, user: User, url: URL, auth?: Auth): Promise<Record<string, unknown>> {
  allowed(user, ['security_officer', 'auditor']);
  for (const key of new Set(url.searchParams.keys())) if (key !== 'framework' && key !== 'pseudonymise') throw new HttpError(400, 'bad_request');
  const framework = EVIDENCE_FRAMEWORKS.find((f) => f.id === url.searchParams.get('framework'));
  const flag = url.searchParams.getAll('pseudonymise');
  if (!framework || url.searchParams.getAll('framework').length !== 1 || flag.length > 1 || (flag.length === 1 && flag[0] !== '1')) throw new HttpError(400, 'bad_request');
  const masked = flag.length === 1;
  const key = pseudonymKey(rt);
  const person = (id: string): string => masked ? pseudonym(key, id) : id;
  const rows = async (filter: Parameters<typeof auditRows>[1]): Promise<Record<string, unknown>> => {
    const found = await auditRows(rt, filter);
    return { complete: found.complete, items: masked ? found.items.map((row) => pseudonymise(row, key)) : found.items };
  };
  const checked = rt.audit.recheck ? await rt.audit.recheck() : undefined;
  const verification = rt.audit.verify();
  const anchors = rt.audit.anchors.slice(-ANCHORS_SHOWN);
  const reviewRows = await auditRows(rt, { rule: 'ADMIN.ACCESS_REVIEW' });
  const reviewChanges = new Set(reviewRows.items.map((row) => row.details?.changeId));
  const sections: Record<Section, unknown> = {
    configuration: rt.baseline ?? { available: false, reason: 'This runtime was not started by createServer, so no configuration baseline was recorded.' },
    time: { serverTime: rt.now(), clockPinned: rt.baseline?.clockPinned ?? null, anchors: await Promise.all(anchors.map(async (a) => {
      const row = await anchoredRow(rt, a);
      // negative: the node's clock was ahead of the timestamp authority when it wrote the anchored row
      return { seq: a.seq, recordTs: row?.ts ?? null, tsaGenTime: a.genTime, tsaMinusRecordSeconds: row ? (Date.parse(a.genTime) - Date.parse(row.ts)) / 1000 : null };
    })) },
    policy: { version: policyVersion(rt.store.state.bundle), stateDigest: rt.store.digest(),
      publications: rt.store.history.map((p) => ({ version: p.version, publishedAt: p.publishedAt, publishedBy: person(p.publishedBy), approvedBy: person(p.approvedBy), signatureKid: p.signature?.kid ?? null })),
      certifications: (rt.store.state.certifications ?? []).map((c) => ({ resourceType: c.resourceType, action: c.action, certifiedBy: person(c.certifiedBy), approvedBy: person(c.approvedBy), certifiedAt: c.certifiedAt, changeId: c.changeId })) },
    audit: { verification, head: rt.audit.tip(), ...(checked && checked.heads ? { heads: checked.heads } : {}), anchoring: { tsa: rt.anchoring?.url ? new URL(rt.anchoring.url).origin : null, lastError: rt.anchoring?.lastError ?? null },
      anchors: anchors.map((a) => ({ seq: a.seq, hash: a.hash, tsa: a.tsa, genTime: a.genTime, tokenSha256: sha256(a.token), ...(a.heads ? { heads: a.heads } : {}) })), anchorsTotal: rt.audit.anchors.length },
    accessReviews: { due: dueGrants(rt).map(({ reason: ignored, grantedBy, ...item }) => ({ ...item, subject: { ...(item.subject as object), id: person((item.subject as { id: string }).id) },
      ...(grantedBy === undefined ? {} : { grantedBy: person(String(grantedBy)) }) })),
      decisions: rt.store.changes.filter((c) => reviewChanges.has(c.id)).map((c) => ({ id: c.id, kind: c.kind, status: c.status, makerId: person(c.makerId), checkerId: c.checkerId ? person(c.checkerId) : null, createdAt: c.createdAt, decidedAt: c.decidedAt ?? null })),
      complete: reviewRows.complete },
    approvals: rt.store.changes.map((c) => ({ id: c.id, kind: c.kind, status: c.status, makerId: person(c.makerId), checkerId: c.checkerId ? person(c.checkerId) : null,
      createdAt: c.createdAt, decidedAt: c.decidedAt ?? null, broadens: c.broadens, weakensMandatory: c.weakensMandatory ?? [] })),
    breakGlass: { emergencies: rt.store.emergencies.map((e) => ({ id: e.id, subjectId: person(e.subjectId), resourceId: e.resourceId, openedBy: person(e.openedBy), openedAt: e.openedAt,
      expiresAt: e.expiresAt, status: e.status, reviewedBy: e.reviewedBy ? person(e.reviewedBy) : null, outcome: e.outcome ?? null })), events: await rows({ type: 'break_glass' }) },
    keys: { signingKeys: rt.tokens.signingKeys(), pepCredentials: auth?.pepCredentials() ?? null },
    securityEvents: await rows({ type: 'security' }),
    ci: { gate: 'bash tools/ci/local.sh', checks: 'tools/ci/checks.sh', workflow: '.github/workflows/ci.yml', coverage: 'docs/QUALITY.md', accessibility: 'docs/ACCESSIBILITY.md',
      note: 'References, not results: the CI run log and its exit status are the evidence; this pack runs no test.' },
  };
  const pack = { format: 'gate-evidence-pack/1', disclaimer: DISCLAIMER, product: { name: 'Qadamar', version: VERSION },
    framework: { id: framework.id, name: framework.name, mapping: framework.mapping,
      controls: Object.entries(framework.controls).map(([id, evidence]) => ({ id, evidence })) },
    generatedAt: rt.now(), generatedBy: person(user.id), pseudonymised: masked, sections };
  const manifest = { format: 'gate-evidence-manifest/1', framework: framework.id, generatedAt: pack.generatedAt, packSha256: sha256(canonical(pack)),
    sections: Object.fromEntries(Object.entries(sections).map(([name, value]) => [name, sha256(canonical(value))])),
    verify: 'Detached EdDSA JWS over canonical(manifest); public keys at /.well-known/jwks.json. Each hash is SHA-256 of canonical JSON.' };
  const signature = rt.tokens.detached(manifest);
  rt.audit.append({ type: 'security', actor: user.id, action: 'evidence_export', details: { framework: framework.id, packSha256: manifest.packSha256, pseudonymised: masked } });
  return { pack, manifest, signature };
}
