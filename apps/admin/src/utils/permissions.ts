import type { ChangeKind, ConsoleRole } from '../api/types';
import type { RoutePath } from './router';
import { msgs } from '../i18n';

// Role matrix enforcing docs/API.md §1
/** Getters, so the labels follow the console language. */
export const ROLE_LABELS: Readonly<Record<ConsoleRole, string>> = {
  get access_admin() { return msgs().common.roles.access_admin; },
  get policy_author() { return msgs().common.roles.policy_author; },
  get approver() { return msgs().common.roles.approver; },
  get security_officer() { return msgs().common.roles.security_officer; },
  get resource_owner() { return msgs().common.roles.resource_owner; },
  get auditor() { return msgs().common.roles.auditor; },
};

function hasAny(userRoles: readonly ConsoleRole[], allowed: readonly ConsoleRole[]): boolean {
  return userRoles.some((r) => allowed.includes(r));
}

export function canReadCore(roles: readonly ConsoleRole[]): boolean {
  return roles.length > 0;
}

export function canUseSimulator(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner']);
}

export function canProposeAnyChange(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin', 'policy_author', 'security_officer', 'resource_owner']);
}

export function canProposePolicyChange(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin', 'policy_author', 'security_officer']);
}

export function canProposeChangeKind(roles: readonly ConsoleRole[], kind: ChangeKind): boolean {
  if (kind === 'publish_policy') {
    return canProposePolicyChange(roles);
  }
  if (kind === 'remove_tuple') {
    return hasAny(roles, ['access_admin', 'security_officer', 'resource_owner']);
  }
  return hasAny(roles, ['access_admin', 'security_officer']);
}

export function canDecideChange(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['approver', 'security_officer']);
}

export function canOpenBreakGlass(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin', 'security_officer']);
}

export function canManageBreakGlass(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['security_officer']);
}

export function canReviewAccess(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['security_officer', 'resource_owner']);
}

/** docs/API.md §3.10: both can list PEP credentials and signing keys; only a security officer changes them. */
export function canViewCredentials(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin', 'security_officer']);
}

export function canManagePepCredentials(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['security_officer']);
}

/** docs/API.md §3.11: access admins only, since they cannot approve what the credential proposes. */
export function canRotateScimCredential(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin']);
}

/** docs/API.md §3.12: certification records for every console role but resource owners; reservations for three roles. */
export function canViewCertifications(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin', 'policy_author', 'approver', 'security_officer', 'auditor']);
}

export function canViewReservations(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['access_admin', 'security_officer', 'auditor']);
}

/** docs/API.md §3.3: the retired-id log keeps no owner, so a resource owner scope cannot list it. */
export function canViewRetiredResources(roles: readonly ConsoleRole[]): boolean {
  return roles.some((r) => r !== 'resource_owner');
}

export function canViewAuditAndCompliance(roles: readonly ConsoleRole[]): boolean {
  return hasAny(roles, ['security_officer', 'auditor']);
}

export function canAccessRoute(roles: readonly ConsoleRole[], path: RoutePath): boolean {
  switch (path) {
    case 'overview':
    case 'model':
    case 'policies':
    case 'approvals':
    case 'two-step':
      return canReadCore(roles);
    case 'simulator':
    case 'matrix':
      return canUseSimulator(roles);
    case 'break-glass':
      return hasAny(roles, ['access_admin', 'security_officer', 'auditor']);
    case 'reviews':
      return hasAny(roles, ['resource_owner', 'security_officer']); // docs/API.md §1 role matrix
    case 'credentials':
      return canViewCredentials(roles);
    case 'audit':
    case 'compliance':
      return canViewAuditAndCompliance(roles);
  }
}
