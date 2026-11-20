import { buildFilter, evaluate, type Context, type Graph, type PolicyBundle, type Resource, type Subject } from '../../packages/core/src/index.ts';
import { compile } from '../../packages/sql/src/index.ts';
import { enforce } from '../../packages/sdk/src/enforce.ts';
import type { JsonObject } from '../../packages/sdk/src/types.ts';

export interface CaseRow extends Record<string, unknown> {
  id: string; level: Resource['level']; compartments: string[]; integrity: Resource['integrity'];
  content_classes: string[]; maker: string | null; prior_actions: string[]; title: string; secret: string;
}
export interface CaseDatabase {
  query<R extends Record<string, unknown>>(text: string, values?: unknown[]): Promise<{ rows: R[] }>;
}

/** Use a transaction with authoritative rows and history; callers supply the authenticated subject and current policy. */
export async function filteredCases(db: CaseDatabase, bundle: PolicyBundle, graph: Graph, subject: Subject, action: string, context: Context): Promise<JsonObject[]> {
  const predicate = compile(buildFilter(bundle, subject, 'case', action, context, graph), {
    'resource.id': 'id', 'resource.level': { column: 'level', type: 'number' },
    'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.integrity': 'integrity', 'resource.contentClasses': { column: 'content_classes', kind: 'text[]' },
  });
  const { rows } = await db.query<CaseRow>(`SELECT * FROM example_cases WHERE (${predicate.text}) IS TRUE ORDER BY id FOR SHARE`, predicate.params);
  const visible: JsonObject[] = [];
  for (const row of rows) {
    const resource: Resource = { type: 'case', id: row.id, level: row.level, compartments: row.compartments, integrity: row.integrity, contentClasses: row.content_classes };
    // History is authoritative per row, never the caller's maker or prior-action claims.
    const { makerId: _maker, serverMakerId: _serverMaker, priorActions: _prior, ...signals } = context;
    const decision = evaluate(bundle, { subject, action, resource, context: {
      ...signals, ...(row.maker === null ? {} : { serverMakerId: row.maker }), priorActions: row.prior_actions,
    } }, graph);
    if (!decision.decision) continue;
    // This example only releases data; certified commands need token consumption and atomic execution too.
    if (decision.obligations.decisionToken) throw new Error('Certified commands require a command PEP');
    visible.push(enforce({ decision: true, context: { rules: decision.rules, reasons: decision.reasons,
      obligations: decision.obligations, policy_version: decision.policyVersion, would_deny: decision.wouldDeny } },
    { id: row.id, title: row.title, secret: row.secret }));
  }
  return visible;
}
