# Module N — Saudi NCA ECC and SAMA (technical mapping)

Apply when the client is a Saudi government entity, a government-owned company, a critical national infrastructure operator, or their vendors (NCA Essential Cybersecurity Controls), or a SAMA-regulated financial institution (SAMA Cyber Security Framework). This module maps what this skill can evidence technically; it does not replace a formal gap assessment against the official documents, and many controls are organizational (governance, HR, Saudization of cybersecurity roles, policies) that code cannot satisfy.

## NCA ECC-2:2024

Structure: 4 main domains, 28 subdomains, 108 main controls and 92 subcontrols (it replaced ECC-1:2018, which had 5 domains and 114 controls). Domain 2 (Cybersecurity Defense) holds 15 of the 28 subdomains and most technical controls. Verify the current text on nca.gov.sa before an assessment.

| ECC domain | What this skill can evidence | Skill items |
|---|---|---|
| 1. Cybersecurity Governance | Inputs only: risk findings, security requirements in the project, periodic review evidence (scan reports, CI history). Strategy, policies, roles and staffing are organizational. | Report, CI history |
| 2. Cybersecurity Defense | Asset and secret inventory; identity and access (login, MFA, admin lock, least privilege); system and network protection (headers, TLS, WAF, infra hardening); data protection and cryptography; backup; vulnerability management (dependency audit, scanner, CI); logging and monitoring; incident detection; web application security | C1–C27, E1–E9, P1–P7, D1–D9, I1–I6, scanner, authz tests |
| 3. Cybersecurity Resilience | Backups tested, incident runbook and kill switch, alerting, recovery steps | P5, P6, D-module, K7 runbook |
| 4. Third-Party and Cloud Computing | Inventory of vendors/cloud services touching data, cloud configuration (I5), data-transfer list (K8), DPAs | I5, K8, K9 |

Evidence pack to hand over: latest scan JSON + client report (before/after), authz test results, CI workflow runs, encryption summary (data map, algorithms, key storage), backup restore test record, alert test record, vendor/cloud inventory.

## SAMA Cyber Security Framework

Applies to all SAMA-regulated member organizations (banks, insurance, finance companies and others). Four domains: Cyber Security Leadership and Governance; Cyber Security Risk Management and Compliance; Cyber Security Operations and Technology; Third Party Cyber Security. Member organizations are expected to operate at maturity level 3 or higher, and new licensees or sandbox entrants start with SAMA's Cyber Resilience Fundamental Requirements. Technically, "Operations and Technology" maps to the same skill items as ECC Domain 2 above, and "Third Party" maps to I5, K8, K9.

Report section: a table of ECC domains (or SAMA domains) with: skill items covered, evidence file, status (Evidenced / Partial / Organizational, out of scope), and the gaps to raise with the client's compliance team.

Sources: NCA ECC-2:2024 (nca.gov.sa), SAMA Cyber Security Framework (rulebook.sama.gov.sa).
