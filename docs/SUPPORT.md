# Support policy (template)

**Status: template. No support commitment exists yet beyond SECURITY.md.** Every line marked **TO DECIDE** is an owner
decision; until it is filled in, the maintainers offer no response time, no support period and no security-fix deadline for
Qadamar. SECURITY.md says only that the current release line (the latest minor, see its table) receives security fixes.
Do not quote this file to a buyer as a commitment before the placeholders are replaced and the owner has approved it.

## What the policy must state

| Item | Why a buyer asks | Decision |
|---|---|---|
| **Supported versions** | Which releases receive fixes, e.g. latest minor only, or the last N minors. | **TO DECIDE** |
| **Support period per release** | How long a release is supported after the next one ships (end-of-support date per version). | **TO DECIDE** |
| **Upgrade path** | Whether every supported version upgrades directly to the latest; data migration guarantees. | **TO DECIDE** |
| **Security fix SLA by severity** | Time from a confirmed report to a fixed release, per severity (critical, high, medium, low), and the severity scale used (e.g. CVSS). | **TO DECIDE** |
| **Vulnerability disclosure** | How to report (address, encryption key), acknowledgement time, disclosure policy, advisories. See [SECURITY.md](../SECURITY.md). | **TO DECIDE** |
| **Support contact** | Channel(s) and address for support requests; who may open them (named contacts per customer). | **TO DECIDE** |
| **Hours and languages** | Coverage window, time zone, public holidays, languages (English, French, Arabic?). | **TO DECIDE** |
| **Response and resolution targets** | Per priority: first response and, if any, workaround/resolution targets; whether these are targets or contractual. | **TO DECIDE** |
| **Scope** | What is covered (the released tarball, configurations documented in CONFIGURATION.md) and what is not (custom policies, the customer's IdP, database, hosting, network). | **TO DECIDE** |
| **Deployment models covered** | On-premise, air-gapped, managed: which are supported and with what access for support staff. | **TO DECIDE** |
| **Release signing and verification** | How releases are signed and how a customer verifies them ([RELEASE.md](RELEASE.md), signing hook). | **TO DECIDE** |
| **Dependency and SBOM updates** | How fast third-party vulnerabilities (SBOM components) are assessed and patched. | **TO DECIDE** |
| **End of life notice** | Minimum notice before a version or the product reaches end of life. | **TO DECIDE** |
| **Commercial terms** | Whether support is included in the licence or sold separately; credits for missed targets. | **TO DECIDE** |

## What exists today (facts, not commitments)

- One supported version line, `0.12.x` (latest release 0.12.2, CHANGELOG.md; [SECURITY.md](../SECURITY.md): versions
  before 0.12.0 are unsupported); releases are built by `scripts/release/pack.sh` with an SBOM and
  checksums, signed from 0.12.1 with an SSH key, 0.8.3 to 0.11.0 signed after the fact ([RELEASE.md](RELEASE.md)).
- [SECURITY.md](../SECURITY.md) is the current reporting route; the product is not externally reviewed or certified
  (README, "Not done yet").
