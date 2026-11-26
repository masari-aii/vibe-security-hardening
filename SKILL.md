---
name: "vibe-security-hardening"
description: "Secure, encrypt, protect and monitor AI-built web apps: scanner with safe fixes, IDOR tests, client report, 27 controls, encryption, intrusion alerts + dashboard, AI security, infra, Saudi PDPL/NCA. Use for: أمّن موقعي، فحص أمني، security check."
---

# Vibe Security Hardening

Model-agnostic and stack-agnostic. Works with any LLM (Claude, GPT, Gemini, Llama, Qwen, DeepSeek...) and any agent or plain chat. No tool names are assumed: "read", "search", "run" mean whatever the host provides. If the host has no file or shell access, ask the user to paste the relevant files and output commands for them to run.

Scope: defensive only, on the user's own project. Never attack third-party systems. Never print secret values; show only name, file, line, and last 4 characters.

Reply in the user's language (Arabic RTL or English).

## Files in this skill

Read a reference file only when its module applies (paths are relative to this skill's folder). If the host cannot open files, use `ALL-IN-ONE.md`, which contains everything.

| File | Use when |
|---|---|
| `scripts/scan.py` + `references/scanner.md` | Always: automated scan (code, history, deps, infra, live site), `--fix`, `--deep`, CI |
| `scripts/authz_test.py` | Always when the app has logins: IDOR / admin-route tests (see `references/scanner.md`) |
| `scripts/report.py` | End of every audit: branded client report (AR/EN, score, before/after, PDF) |
| `references/stacks.md` | Always: fixes for the detected stack (Next.js, Supabase, Firebase, Vercel, Laravel, Django, Express, PHP/WordPress, mobile) |
| `references/encryption.md` | Module E: sensitive data map, encryption, keys (tested code) |
| `references/protection.md` | Module P: WAF/CDN, bots, admin MFA, backups, incident readiness |
| `references/intrusion-alerts.md` + `scripts/guard.mjs` / `scripts/guard.py` / `scripts/alerts_dashboard.py` | Module D: attack detection, alerts (email, webhook, Telegram), dashboard and daily digest |
| `references/infrastructure.md` | Module I: Docker, compose, nginx/Apache, Kubernetes, Terraform/cloud, CI/CD |
| `references/ai-security.md` | Module A: the app uses LLMs, RAG, agents, tool calling or MCP |
| `references/pdpl.md` | Module K: the app processes personal data of people in Saudi Arabia |
| `references/nca-ecc.md` | Module N: Saudi government/CNI clients (NCA ECC-2:2024) or SAMA-regulated finance |
| `templates/security-scan.yml` | GitHub Actions workflow that runs the scanner on every push |

## Workflow

1. DETECT: stack (open the matching sections of `references/stacks.md`), framework, DB, auth provider, hosting, payment provider, upload paths, and build the sensitive data map (Module E). Read manifests and config first (package.json, requirements.txt, composer.json, .env.example, framework config, DB rules/policies, deploy config).
2. AUDIT: run the scanner first and save the baseline (`python3 scripts/scan.py <project> --json scan-before.json [--url <own site>]`; if no shell, ask the user to run it and paste the output). Confirm each finding in the code. Run `scripts/authz_test.py` against a local/staging copy with two normal users and an admin. Then go through all 27 controls and modules E, P, D, I, plus A (AI apps), K (Saudi personal data) and N (NCA/SAMA clients) when they apply. For each: PASS / FAIL / N/A with evidence (file:line). No evidence = not PASS.
3. PLAN: list FAIL items by severity (Critical > High > Medium > Low). Critical = exposed secret, open DB, auth bypass, injection, client-trusted price, sensitive data stored in plaintext.
4. FIX: run `scan.py --fix` for the safe mechanical fixes, then the smallest targeted diff per remaining item. Preserve working functionality. Use the framework's built-in security feature before adding a library. Never weaken a control to make a test pass.
5. VERIFY: re-test each fix (control 27), rerun the scanner (`--json scan-after.json`) and authz tests until no critical/high findings remain, run build and existing tests. Offer the CI workflow so the scan runs on every push.
6. REPORT: output the report format below, and generate the client report: `python3 scripts/report.py scan-after.json --baseline scan-before.json --authz <authz json> --lang ar|en [--brand ... --logo ... --pdf]`.

Ask the user only when blocked: missing credentials, production access, or an irreversible action (key rotation, Git history rewrite, DB migration on live data). Otherwise proceed with safe defaults.

## The 27 controls

### A. Identity and access
1. Secure login: use a vetted auth library/provider; server-side sessions or short-lived signed tokens; generic error messages; lockout/backoff; MFA for admins where available.
5. Password hashing: Argon2id with pepper and the E9 parameters (preferred), else bcrypt/scrypt with per-user salt. Never plaintext, MD5, SHA-1, or reversible encryption. Rehash legacy hashes on next login.
9. Admin pages locked: authorization checked on the server for every admin route and API, deny by default; hiding the link is not protection.
15. Cookies: HttpOnly, Secure, SameSite=Lax or Strict, scoped path/domain, sensible expiry; rotate session ID on login and privilege change.
16. CSRF: anti-CSRF token or framework middleware on every state-changing request using cookie auth; no state change on GET.
17. Password reset: single-use, random (>=128-bit), stored hashed, expires in 15-60 min, invalidated after use or password change; same response whether the email exists or not.

### B. Secrets
2. API keys hidden: no secret in client bundle, repo, or logs; secret calls go through a server endpoint/proxy.
11. Environment variables: separate public from server-only (check prefixes like NEXT_PUBLIC_, VITE_, PUBLIC_, REACT_APP_); .env in .gitignore; provide .env.example with names only; least-privilege keys per environment.
24. Git history: scan full history for secrets (gitleaks or trufflehog if available, else grep history for key patterns: sk-, sk_live, AKIA, AIza, ghp_, xox, -----BEGIN, password=, secret=, token=).
25. Revoke and rotate: any key ever committed or shipped to the browser is compromised. Revoke at the provider, issue a new one, update env, then (with user approval) purge history. Removing the line is not enough.

### C. Data and input
3. Database secured: not publicly reachable; row-level/ownership rules so each user reads and writes only their own rows (RLS / security rules / policy checks); app uses a least-privilege DB user; backups enabled.
6. Server-side validation: every input validated on the server by schema (type, length, range, allow-list). Client validation is UX only.
7. XSS: output encoding by default; no raw HTML sinks (innerHTML, dangerouslySetInnerHTML, v-html, |safe) on user data; sanitize unavoidable rich text with a vetted sanitizer; add CSP.
10. Parameterized queries: prepared statements or ORM bindings everywhere; no string concatenation into SQL/NoSQL/shell; allow-list dynamic identifiers.
18. File uploads: allow-list type by content (magic bytes) not just extension; max size; random server-generated names; store outside web root or in object storage; never executable; scan if available.
19. Prices and payments: server computes price, discount, and total from its own DB; never trust amounts from the client; verify payment via signed provider webhook; idempotency keys; grant access only after verified payment.

### D. Transport and browser
4. Forced HTTPS: redirect HTTP to HTTPS; HSTS (max-age >= 15552000, includeSubDomains); no mixed content.
13. CORS restricted: explicit origin allow-list; never * with credentials; never reflect arbitrary Origin; limit methods and headers.
14. Security headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, frame-ancestors or X-Frame-Options, Referrer-Policy, Permissions-Policy; remove X-Powered-By/Server version.

### E. Abuse and operations
8. Monitoring: log auth events, failures, admin actions, permission denials with timestamp, user, IP; no secrets or passwords in logs; alert on spikes.
12. Rate limiting: per IP and per account on login, signup, reset, OTP, and costly or paid-API endpoints; return 429.
20. Debug off in production: no stack traces, debug toolbars, verbose errors, source maps with secrets, or open API docs/GraphQL introspection; generic error page with a reference ID.
21. Vulnerable dependencies: run the ecosystem audit (npm audit, pip-audit, composer audit, etc.); upgrade or patch High/Critical; commit lockfile.
22. Unused dependencies: remove packages that are not imported.
23. Exposed files: block public access to .env, .git, backups (.bak, .sql, .zip), config, logs, directory listing, default/admin install pages; each must return 403/404.

### F. Review and proof
26. Full security review: after fixes, re-read auth, authorization, data access, and payment flows end to end, looking for IDOR (changing an ID to reach another user's data), missing checks on new endpoints, and business-logic flaws.
27. Test the protection and report: prove each control with a real check against local or staging (never brute-force production). Examples: request admin route unauthenticated -> 401/403; user A requests user B's record -> 403/404; submit `' OR 1=1--` and `<script>alert(1)</script>` -> rejected or encoded; tamper price to 1 -> server rejects; 20 rapid logins -> 429; GET /.env and /.git/config -> 404; request with foreign Origin -> no CORS allow; upload .exe renamed .jpg -> rejected; inspect response headers and cookie flags.

## Modules (details in reference files)

- Module E — Encryption (`references/encryption.md`): classify every field with the sensitive data map, encrypt sensitive data by default with XChaCha20-Poly1305 (or AES-256-GCM), HKDF per-field keys, AAD bound to the record, blind indexes, KMS-held master key with rotation and offline backup, peppered Argon2id, encrypted files/backups, TLS 1.3. Items E1–E9.
- Module P — Active protection (`references/protection.md`): CDN/WAF and DDoS, bot challenge, admin MFA and allow-list, breached-password blocking, tested backups, incident kill switch, signed private media. Items P1–P7.
- Module D — Intrusion detection and email alerts (`references/intrusion-alerts.md`): detect SQLi/XSS/traversal/command injection/SSRF, probes for `.env`/`.git`, brute force, IDOR attempts, honeytokens; block and email the attack type, time, IP, approximate location, path and action, throttled, secrets masked. Items D1–D9.
- Module A — AI application security (`references/ai-security.md`), OWASP GenAI LLM Top 10 2026: prompt injection, data disclosure, excessive agency and MCP tools, supply chain, poisoning, cost limits, misinformation, hidden context exposure, vector store isolation, output handling. Items A1–A11.
- Module I — Infrastructure (`references/infrastructure.md`): containers, compose, web server, Kubernetes, Terraform/cloud IAM and network exposure, CI/CD pipeline hardening. Items I1–I6 (also checked by the scanner).
- Module Z — Authorization tests (`scripts/authz_test.py`): IDOR (Z3), broken admin role checks (Z2), unauthenticated access (Z1).
- Module N — NCA ECC-2:2024 and SAMA CSF (`references/nca-ecc.md`): map skill evidence to the four ECC domains / SAMA domains; organizational controls flagged out of scope.
- Module S — Stack playbooks (`references/stacks.md`): concrete config and code fixes per framework/platform.
- Module K — Saudi PDPL (`references/pdpl.md`): data inventory, consent, Arabic privacy notice, rights flows, retention, 72-hour breach notification to SDAIA, cross-border transfers, processors, DPO/registration. Items K1–K12.

## Report format

```
SECURITY REPORT — <project> — <date>
Stack: ...
Summary: X pass / Y fixed / Z open / N n-a

| # | Control | Status | Severity | Evidence (file:line) | Fix applied | Verification |
(27 core rows, then E1–E9, P1–P7, D1–D9, I1–I6, Z, and A1–A11 / K1–K12 / N when they apply)

Scanner: command run, counts before → after, remaining findings with reason
Authz: checks run, failures (IDOR / admin / unauthenticated) and fixes
Client report: file name, score before → after

Encryption summary: sensitive data map (field → class → treatment), algorithm, key storage, rotation plan, key backup status
Protection summary: WAF/CDN, bot protection, admin MFA, backups, incident plan
Alert summary: detectors enabled, mode (monitor/block), alert recipient, test alert received (yes/no)
AI summary (if applicable): tools and their permissions, tenant isolation test, cost limits
PDPL summary (if applicable): K1–K12 status, data flows leaving the Kingdom, items needing legal confirmation

Open items needing the user: (key rotation, provider settings, DNS/hosting, history purge)
Residual risk: ...
```

Rules for the report: every FIXED row names the changed file and the test that proved it; never claim verification that was not run — write NOT VERIFIED and why; this is a hardening pass, not a guarantee or a substitute for a professional penetration test.

## Use as a plain prompt (models without skill support)

Paste `ALL-IN-ONE.md` (this file, every reference and the scanner, in one document; other scripts are in the repository: https://github.com/masari-aii/vibe-security-hardening) as the system or first message, then: "Apply the full hardening workflow to my project. Stack: <...>. Here are the files: <...>"