import type { Runtime } from '../runtime.ts';
import type { Auth, User } from '../auth.ts';
import { allowed } from '../auth.ts';
import { HttpError, string } from '../http.ts';
import { model } from './model.ts';
import { inventory } from './inventory.ts';
import { simulator } from './simulator.ts';
import { propose, decideChange, visibleChange, changeView } from './changes.ts';
import { emergencies, open, reviewEmergency } from './break-glass.ts';
import { reviews, review } from './reviews.ts';
import { audit } from './audit.ts';
import { compliance } from './compliance.ts';
import { overview } from './overview.ts';
import { securityAdmin } from './security.ts';
import { integrity } from './integrity.ts';
import { evidencePack } from './evidence.ts';
import { auditVerification } from './audit-verification.ts';
import { approveErasure, eraseSubject, subjectReport } from './privacy.ts';
import { approvalModes, decideMany, inbox, setApprovalMode, snooze, unsnooze } from './inbox.ts';

/** One change decision, as POST /changes/:id/(approve|reject) takes it; the bulk route runs the same per item. */
function decide(rt: Runtime, user: User, id: string, approve: boolean, b: Record<string, unknown>): unknown {
  if (rt.store.changes.find((item) => item.id === id)?.kind === 'erase_subject') return approveErasure(rt, user, id, approve, b);
  return decideChange(rt, user, id, approve, b);
}

interface AdminResult { value: unknown | Promise<unknown>; status: number }
/** `officersKnown`: false when SSO sign-in is configured, since security officers may then exist only at the identity
 *  provider; the break-glass access_admin fallback is then never offered (fail closed). */
export function admin(rt: Runtime, user: User, method: string, url: URL, b: Record<string, unknown>, auth?: Auth, { officersKnown = true }: { officersKnown?: boolean } = {}): AdminResult {
  const officers = (): string[] | undefined => (officersKnown ? auth?.holders('security_officer') : undefined);
  const path = url.pathname.slice('/admin/v1'.length);
  const ok = (value: AdminResult['value'], status = 200): AdminResult => ({ value, status });
  const security = securityAdmin(rt, auth, user, method, path, b);
  if (security) return security;
  const cw = integrity(rt, user, method, path);
  if (cw) return cw;
  if (method === 'GET') {
    if (path === '/overview') return ok(overview(rt, user));
    if (['/schema', '/policy', '/subjects', '/resources', '/tuples'].includes(path)) return ok(model(rt, user, path));
    if (path === '/resources/inventory' || path === '/resources/retired') return ok(inventory(rt, user, url, path === '/resources/retired'));
    if (path === '/changes') {
      const status = url.searchParams.get('status');
      if (status && !['pending', 'applied', 'rejected'].includes(status)) throw new HttpError(400, 'bad_request');
      return ok({ items: rt.store.changes.filter((c) => (!status || c.status === status) && visibleChange(rt, user, c)).map((c) => changeView(rt, user, c)) });
    }
    if (path === '/break-glass') {
      allowed(user, ['access_admin', 'security_officer']); return ok(emergencies(rt, user, officers()));
    }
    if (path === '/reviews') return ok(reviews(rt, user));
    if (path === '/inbox') return ok(inbox(rt, user));
    if (path === '/approval-modes') return ok(approvalModes(rt, user, auth));
    if (path === '/audit' || path === '/audit/verify' || path === '/audit/anchors') return ok(audit(rt, user, url));
    if (path === '/audit/verification') return ok(auditVerification(rt, user, url));
    if (path === '/compliance' || path === '/compliance/export') return ok(compliance(rt, user, path.endsWith('/export')));
    if (path === '/compliance/evidence') return ok(evidencePack(rt, user, url, auth));
    const personal = /^\/privacy\/subjects\/([^/]+)$/.exec(path);
    if (personal) return ok(subjectReport(rt, user, personal[1]!));
  }
  if (method === 'POST') {
    if (path.startsWith('/simulate/') || path === '/explain') return ok(simulator(rt, user, path, b));
    if (path === '/changes') return ok(changeView(rt, user, propose(rt, user, b)), 201);
    if (path === '/changes/decide') return ok(decideMany(rt, user, b, (id, approve, note) => decide(rt, user, id, approve, note)));
    const change = /^\/changes\/([^/]+)\/(approve|reject)$/.exec(path);
    if (change) return ok(decide(rt, user, string(change[1]), change[2] === 'approve', b));
    if (path === '/inbox/snoozes') return ok(snooze(rt, user, b), 201);
    if (path === '/break-glass') return ok(open(rt, user, b), 201);
    const erasure = /^\/privacy\/subjects\/([^/]+)\/erasure$/.exec(path);
    if (erasure) return ok(eraseSubject(rt, user, erasure[1]!), 201);
    const emergency = /^\/break-glass\/([^/]+)\/(revoke|review)$/.exec(path);
    if (emergency) return ok(reviewEmergency(rt, user, string(emergency[1]), string(emergency[2]), b, officers()));
    const rev = /^\/reviews\/([^/]+)$/.exec(path);
    if (rev) return ok(changeView(rt, user, review(rt, user, string(rev[1]), b)), 201);
  }
  const mode = method === 'PUT' ? /^\/approval-modes\/([^/]+)$/.exec(path) : null;
  if (mode) return ok(setApprovalMode(rt, user, mode[1]!, b));
  const snoozed = method === 'DELETE' ? /^\/inbox\/snoozes\/([^/]+)$/.exec(path) : null;
  if (snoozed) return ok(unsnooze(rt, user, snoozed[1]!));
  throw new HttpError(404, 'not_found');
}
