export interface Control { id: string; title: string; enforcedBy: string[] }
export interface Framework { id: string; name: string; controls: Control[] }
// Product evidence mapping, not a certification claim. UAE IA intentionally remains unmapped.
export const frameworks: Framework[] = [
  { id: 'nist-800-53-r5', name: 'NIST SP 800-53 Rev. 5', controls: [
    { id: 'AC-3', title: 'Access Enforcement', enforcedBy: ['RBAC.NOT_ELIGIBLE', 'NTK.NO_REASON'] },
    { id: 'AC-4', title: 'Information Flow Enforcement', enforcedBy: ['BLP.NO_READ_UP', 'BLP.NO_WRITE_DOWN', 'BLP.HIGH_WATER', 'BLP.SESSION_REQUIRED', 'MAC.COMPARTMENT', 'NET.UNTRUSTED_LEVEL', 'NET.UNTRUSTED_COMPARTMENT'] },
    { id: 'AC-5', title: 'Separation of Duties', enforcedBy: ['SOD.SELF_APPROVAL', 'SOD.MAKER_UNKNOWN', 'CW.UNCERTIFIED_TP'] },
    { id: 'AC-6', title: 'Least Privilege', enforcedBy: ['NTK.NO_REASON', 'RBAC.NOT_ELIGIBLE'] },
    { id: 'AC-16', title: 'Security and Privacy Attributes', enforcedBy: ['MAC.COMPARTMENT', 'BLP.NO_READ_UP', 'BIBA.NO_WRITE_UP'] },
    { id: 'AC-24', title: 'Access Control Decisions', enforcedBy: ['RBAC.NOT_ELIGIBLE', 'NTK.NO_REASON', 'BLP.NO_READ_UP'] },
    { id: 'AU-2', title: 'Event Logging', enforcedBy: ['AUDIT.APPEND'] },
    { id: 'AU-9', title: 'Protection of Audit Information', enforcedBy: ['AUDIT.HASH_CHAIN'] },
    { id: 'AU-10', title: 'Non-repudiation', enforcedBy: ['AUDIT.HASH_CHAIN', 'CW.DECISION_TOKEN'] },
  ] },
  { id: 'iso-27001-2022', name: 'ISO/IEC 27001:2022 Annex A', controls: [
    { id: '5.15', title: 'Access control', enforcedBy: ['RBAC.NOT_ELIGIBLE', 'NTK.NO_REASON'] },
    { id: '5.18', title: 'Access rights', enforcedBy: ['ADMIN.TWO_PERSON', 'ADMIN.ACCESS_REVIEW'] },
    { id: '8.3', title: 'Information access restriction', enforcedBy: ['BLP.NO_READ_UP', 'MAC.COMPARTMENT', 'NTK.NO_REASON'] },
    { id: '8.15', title: 'Logging', enforcedBy: ['AUDIT.APPEND', 'AUDIT.HASH_CHAIN'] },
  ] },
  { id: 'uae-ia', name: 'UAE Information Assurance', controls: [] },
];
