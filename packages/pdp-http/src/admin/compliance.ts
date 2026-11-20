import type { Runtime } from '../runtime.ts';
import type { User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { frameworks } from './compliance-map.ts';
import type { AuditEvidence } from '../audit.ts';
import { EVIDENCE_FRAMEWORKS } from './evidence.ts';

export function compliance(rt: Runtime, user: User, exportPack: boolean): unknown {
  allowed(user, ['security_officer', 'auditor']);
  const records = rt.audit.records(); const verified = rt.audit.verify().verified;
  const pack = { frameworks: frameworks.map((f) => ({ ...f, controls: f.controls.map((c) => {
    const includeAll = c.enforcedBy.includes('AUDIT.APPEND') || (c.enforcedBy.includes('AUDIT.HASH_CHAIN') && verified);
    const evidence = rt.audit.evidence ? rt.audit.evidence(c.enforcedBy, includeAll) : fileEvidence(records, c.enforcedBy, includeAll);
    return { ...c, evidence };
  }) })) };
  // the per-framework evidence packs (GET /compliance/evidence) the console can request
  return exportPack ? { pack, signature: rt.tokens.detached(pack) } : { ...pack, evidenceFrameworks: EVIDENCE_FRAMEWORKS.map((f) => ({ id: f.id, name: f.name })) };
}

function fileEvidence(records: ReturnType<Runtime['audit']['records']>, ruleIds: readonly string[], includeAll: boolean): AuditEvidence {
  const matching = records.filter((r) => includeAll || r.rules?.some((rule) => ruleIds.includes(rule)));
  return { decisions: matching.filter((r) => r.type === 'decision').length,
    denies: matching.filter((r) => r.type === 'decision' && r.effect === 'deny').length, lastSeen: matching.at(-1)?.ts ?? null };
}
