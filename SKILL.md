---
name: "vibe-security-hardening"
description: "Pre-launch security hardening for AI-built (vibe-coded) web apps: 27-control audit, fix, and verification report. Use for: أمّن موقعي، فحص أمني، حماية من الاختراق، security check, harden before launch."
---

# Vibe Security Hardening (27 controls)

Model-agnostic and stack-agnostic. Works with any LLM (Claude, GPT, Gemini, Llama, Qwen, DeepSeek...) and any agent or plain chat. No tool names are assumed: "read", "search", "run" mean whatever the host provides. If the host has no file or shell access, ask the user to paste the relevant files and output commands for them to run.

Scope: defensive only, on the user's own project. Never attack third-party systems. Never print secret values; show only name, file, line, and last 4 characters.

Reply in the user's language (Arabic RTL or English).

## Workflow

1. DETECT: stack, framework, DB, auth provider, hosting, payment provider, upload paths. Read manifests and config first (package.json, requirements.txt, composer.json, .env.example, framework config, DB rules/policies, deploy config).
2. AUDIT: go through all 27 controls in order. For each: PASS / FAIL / N/A with evidence (file:line). No evidence = not PASS.
3. PLAN: list FAIL items by severity (Critical > High > Medium > Low). Critical = exposed secret, open DB, auth bypass, injection, client-trusted price.
4. FIX: smallest targeted diff per item. Preserve working functionality. Use the framework's built-in security feature before adding a library. Never weaken a control to make a test pass.
5. VERIFY: re-test each fix (control 27). Run build and existing tests.
6. REPORT: output the report format below.

Ask the user only when blocked: missing credentials, production access, or an irreversible action (key rotation, Git history rewrite, DB migration on live data). Otherwise proceed with safe defaults.

## The 27 controls

### A. Identity and access
1. Secure login: use a vetted auth library/provider; server-side sessions or short-lived signed tokens; generic error messages; lockout/backoff; MFA for admins where available.
5. Password hashing: Argon2id (preferred), else bcrypt/scrypt with per-user salt. Never plaintext, MD5, SHA-1, or reversible encryption. Rehash legacy hashes on next login.
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

## Report format

```
SECURITY REPORT — <project> — <date>
Stack: ...
Summary: X pass / Y fixed / Z open / N n-a

| # | Control | Status | Severity | Evidence (file:line) | Fix applied | Verification |

Open items needing the user: (key rotation, provider settings, DNS/hosting, history purge)
Residual risk: ...
```

Rules for the report: every FIXED row names the changed file and the test that proved it; never claim verification that was not run — write NOT VERIFIED and why; this is a hardening pass, not a guarantee or a substitute for a professional penetration test.

## Use as a plain prompt (models without skill support)

Paste this whole file as the system or first message, then: "Apply the 27-control hardening workflow to my project. Stack: <...>. Here are the files: <...>"