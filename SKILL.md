---
name: "vibe-security-hardening"
description: "Secure, encrypt and protect AI-built (vibe-coded) web apps before launch: 27-control audit plus encryption and active-protection modules, fixes and a verified report. Use for: أمّن موقعي، شفّر الموقع، احمِ الموقع، فحص أمني، security check."
---

# Vibe Security Hardening (27 controls + Encryption + Protection)

Model-agnostic and stack-agnostic. Works with any LLM (Claude, GPT, Gemini, Llama, Qwen, DeepSeek...) and any agent or plain chat. No tool names are assumed: "read", "search", "run" mean whatever the host provides. If the host has no file or shell access, ask the user to paste the relevant files and output commands for them to run.

Scope: defensive only, on the user's own project. Never attack third-party systems. Never print secret values; show only name, file, line, and last 4 characters.

Reply in the user's language (Arabic RTL or English).

## Workflow

1. DETECT: stack, framework, DB, auth provider, hosting, payment provider, upload paths. Read manifests and config first (package.json, requirements.txt, composer.json, .env.example, framework config, DB rules/policies, deploy config).
2. AUDIT: go through all 27 controls, then modules E (encryption) and P (active protection), in order. For each: PASS / FAIL / N/A with evidence (file:line). No evidence = not PASS.
3. PLAN: list FAIL items by severity (Critical > High > Medium > Low). Critical = exposed secret, open DB, auth bypass, injection, client-trusted price, sensitive data stored in plaintext.
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

## Module E — Encryption (encrypt the site and its data)

Rules: never write custom crypto; use the platform's vetted library. Banned: base64 or hex as "encryption", ECB mode, static or reused IV/nonce, MD5 or SHA-1 for anything security-related, keys in source or in the same DB as the data.

- E1. In transit (public): TLS 1.2+ only (prefer 1.3), modern ciphers, auto-renewing certificates, HSTS with preload once stable. Verify with an SSL test and `curl -I http://` redirect.
- E2. In transit (internal): DB connections with TLS (e.g. `sslmode=verify-full`), Redis/queues over TLS, outbound webhooks over HTTPS; verify incoming webhook signatures (HMAC) with constant-time compare.
- E3. At rest (platform): enable disk, database, object-storage and backup encryption at the provider. Private files in storage are private buckets served by short-lived signed URLs.
- E4. Field-level encryption for sensitive data (national ID, phone, IBAN, address, health, documents, API tokens of users): AES-256-GCM or libsodium secretbox, random nonce per value, AAD bound to the record (e.g. `user:<id>`), key version stored with the ciphertext. For fields that must be searchable, store a blind index (HMAC-SHA256 with a separate key) next to the ciphertext. Passwords are never encrypted, only hashed (control 5).
- E5. Key management: keys in a KMS or secret manager, loaded from env at runtime; 256-bit random (`openssl rand -base64 32`); separate keys per environment and per purpose (data, blind index, sessions); envelope encryption (per-tenant data key wrapped by a master key) for multi-tenant apps; documented rotation: add new version, encrypt new writes with it, re-encrypt old rows in a background job, then retire the old key.
- E6. Tokens and sessions: signing secrets >= 256-bit; pin the JWT algorithm (reject `none` and algorithm switching), short access-token lifetime, refresh-token rotation with reuse detection, revocation list or session table.
- E7. Backups and exports: encrypted, access-restricted, retention set; CSV/PDF exports of personal data generated on demand and served by expiring links.
- E8. Front-end code: production build minified, source maps not public, optional obfuscation for proprietary client logic, Subresource Integrity on third-party scripts. Tell the user plainly: anything shipped to the browser can be read; obfuscation only slows copying. Real secrets and business rules move to the server.

Reference implementation (tested; adapt naming, keep the scheme):

```js
// Node.js — AES-256-GCM, format: version:iv:ciphertext:tag
import crypto from 'node:crypto';
const KEYS = { v1: Buffer.from(process.env.DATA_KEY_B64, 'base64') };
const CUR = 'v1';
if (KEYS[CUR].length !== 32) throw new Error('DATA_KEY must be 32 bytes');
export function encrypt(plain, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEYS[CUR], iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return [CUR, iv.toString('base64'), ct.toString('base64'), c.getAuthTag().toString('base64')].join(':');
}
export function decrypt(blob, aad) {
  const [v, iv, ct, tag] = blob.split(':');
  const d = crypto.createDecipheriv('aes-256-gcm', KEYS[v], Buffer.from(iv, 'base64'));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
}
export const blindIndex = (v) =>
  crypto.createHmac('sha256', Buffer.from(process.env.IDX_KEY_B64, 'base64')).update(v.trim().toLowerCase()).digest('hex');
```

```python
# Python — cryptography.AESGCM, format: version:nonce:ciphertext+tag
import os, base64, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
KEYS = {"v1": base64.b64decode(os.environ["DATA_KEY_B64"])}
CUR = "v1"
assert len(KEYS[CUR]) == 32, "DATA_KEY must be 32 bytes"
def encrypt(plain: str, aad: str) -> str:
    n = os.urandom(12)
    ct = AESGCM(KEYS[CUR]).encrypt(n, plain.encode(), aad.encode())
    return ":".join([CUR, base64.b64encode(n).decode(), base64.b64encode(ct).decode()])
def decrypt(blob: str, aad: str) -> str:
    v, n, ct = blob.split(":")
    return AESGCM(KEYS[v]).decrypt(base64.b64decode(n), base64.b64decode(ct), aad.encode()).decode()
def blind_index(v: str) -> str:
    return hmac.new(base64.b64decode(os.environ["IDX_KEY_B64"]), v.strip().lower().encode(), hashlib.sha256).hexdigest()
```

Other stacks: PHP `sodium_crypto_secretbox` or `openssl_encrypt('aes-256-gcm')`; Go `crypto/cipher` GCM; .NET `AesGcm`; Java `Cipher.getInstance("AES/GCM/NoPadding")`.

Migrating existing plaintext data: add encrypted column + blind index, backfill in batches, switch reads, verify counts, then drop the plaintext column (with user approval and a backup).

Encryption tests: round-trip succeeds; wrong AAD or tampered ciphertext fails; two encryptions of the same value differ; DB dump shows no readable sensitive values; app still finds users by blind index.

## Module P — Active protection (keep attackers out)

- P1. Edge shield: put the site behind a CDN/WAF (e.g. Cloudflare or the host's WAF) with managed rules and DDoS protection; hide the origin IP; origin accepts traffic only from the CDN.
- P2. Bot protection: invisible challenge (e.g. Turnstile/hCaptcha/reCAPTCHA) on signup, login, reset, contact and checkout; honeypot field on public forms.
- P3. Admin hardening: MFA required for every admin; admin panel behind IP allow-list, VPN or SSO where possible; non-default admin path as an extra layer only; admin actions logged (control 8).
- P4. Account protection: minimum 12-character passwords, block breached passwords (k-anonymity range API), revoke all sessions on password change, notify on new-device login and email/password changes.
- P5. Backups: automated, encrypted (E7), off-site, versioned; restore tested before launch.
- P6. Incident readiness: alerts on spikes (control 8); a kill switch to revoke all sessions and rotate keys fast; `/.well-known/security.txt` with a contact; short runbook: contain, rotate, patch, notify.
- P7. Content protection: signed expiring URLs for private media, hotlink protection, robots rules do not hide sensitive paths (use auth instead).

Protection tests: origin IP direct request refused; form without challenge token rejected; admin login without MFA impossible; breached password rejected; backup restored to a scratch DB successfully.

## Report format

```
SECURITY REPORT — <project> — <date>
Stack: ...
Summary: X pass / Y fixed / Z open / N n-a

| # | Control | Status | Severity | Evidence (file:line) | Fix applied | Verification |
(27 core rows, then E1–E8, then P1–P7)

Encryption summary: data classes encrypted, algorithm, key storage, rotation plan
Protection summary: WAF/CDN, bot protection, admin MFA, backups, incident plan

Open items needing the user: (key rotation, provider settings, DNS/hosting, history purge)
Residual risk: ...
```

Rules for the report: every FIXED row names the changed file and the test that proved it; never claim verification that was not run — write NOT VERIFIED and why; this is a hardening pass, not a guarantee or a substitute for a professional penetration test.

## Use as a plain prompt (models without skill support)

Paste this whole file as the system or first message, then: "Apply the hardening workflow (27 controls + encryption + protection) to my project. Stack: <...>. Here are the files: <...>"