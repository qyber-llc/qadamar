# Security policy

## Supported versions

Only the current 0.12.x release line receives security fixes. Versions before 0.12.0 are unsupported. Qadamar has had internal pentests (Strix and Kimi, see docs/security/) but has not yet been independently penetration tested by a third party or certified; file-backed mode is for demonstrations only.

## Report a vulnerability

Report suspected vulnerabilities privately to the maintainers through the repository's private vulnerability reporting. Do not open a public issue or include exploit details, credentials, personal data or customer data in a public channel. If private reporting is not enabled, contact a maintainer privately and ask for the correct recipient.

Include the affected version or commit, the impacted component, reproduction steps, the security impact and any suggested mitigation. Use a throwaway demonstration environment and invented data. The maintainers will use the report only to investigate and address the issue. No response-time commitment, bug bounty or reward is promised.

## Scope

In scope for reports in this repository:

- authorization bypasses, wrong-allow decisions and cross-tenant or cross-scope disclosure;
- session, CSRF, OIDC, API-key, decision-token and role-enforcement failures;
- injection, unsafe request validation, secret exposure and audit-chain tampering not already documented as a limitation;
- denial of service caused by unbounded or malformed input within the documented request limits;
- vulnerabilities in the admin console, PDP API, policy engine, SQL compiler and bundled demonstration configuration.

Out of scope:

- attacks requiring an already-compromised host, database owner, administrator or deployment secret, unless they cross another documented security boundary;
- social engineering, physical attacks, volumetric network denial of service and issues in third-party services;
- use of generated demonstration credentials outside the local demonstration environment;
- database high availability, backups, encryption at rest and other hosting controls explicitly left to the deployer;
- findings that only report a missing best practice without a concrete security impact.

Third-party package vulnerabilities should also be reported to the affected upstream project. Their components retain their own licences and security processes.
