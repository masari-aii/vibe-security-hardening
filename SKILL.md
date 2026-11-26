---
name: "vibe-security-hardening"
description: "Secure, encrypt and protect AI-built (vibe-coded) web apps before launch: 27-control audit plus encryption and active-protection modules, fixes and a verified report. Use for: أمّن موقعي، شفّر الموقع، احمِ الموقع، فحص أمني، security check."
---

# Vibe Security Hardening (27 controls + Encryption + Protection + Intrusion Alerts)

Model-agnostic and stack-agnostic. Works with any LLM (Claude, GPT, Gemini, Llama, Qwen, DeepSeek...) and any agent or plain chat. No tool names are assumed: "read", "search", "run" mean whatever the host provides. If the host has no file or shell access, ask the user to paste the relevant files and output commands for them to run.

Scope: defensive only, on the user's own project. Never attack third-party systems. Never print secret values; show only name, file, line, and last 4 characters.

Reply in the user's language (Arabic RTL or English).

## Workflow

1. DETECT: stack, framework, DB, auth provider, hosting, payment provider, upload paths, and build the sensitive data map (Module E). Read manifests and config first (package.json, requirements.txt, composer.json, .env.example, framework config, DB rules/policies, deploy config).
2. AUDIT: go through all 27 controls, then modules E (encryption), P (active protection) and D (intrusion detection and email alerts), in order. For each: PASS / FAIL / N/A with evidence (file:line). No evidence = not PASS.
3. PLAN: list FAIL items by severity (Critical > High > Medium > Low). Critical = exposed secret, open DB, auth bypass, injection, client-trusted price, sensitive data stored in plaintext.
4. FIX: smallest targeted diff per item. Preserve working functionality. Use the framework's built-in security feature before adding a library. Never weaken a control to make a test pass.
5. VERIFY: re-test each fix (control 27). Run build and existing tests.
6. REPORT: output the report format below.

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

## Module E — Encryption (encrypt the site and its data)

Rules: never write custom crypto; use the platform's vetted library. Banned: base64 or hex as "encryption", ECB mode, static or reused IV/nonce, MD5 or SHA-1 for anything security-related, keys in source or in the same DB as the data.

- E1. In transit (public): TLS 1.2+ only (prefer 1.3), modern ciphers, auto-renewing certificates, HSTS with preload once stable. Verify with an SSL test and `curl -I http://` redirect.
- E2. In transit (internal): DB connections with TLS (e.g. `sslmode=verify-full`), Redis/queues over TLS, outbound webhooks over HTTPS; verify incoming webhook signatures (HMAC) with constant-time compare.
- E3. At rest (platform): enable disk, database, object-storage and backup encryption at the provider. Private files in storage are private buckets served by short-lived signed URLs.
- E4. Field-level encryption for every field in the sensitive data map below (national ID, phone, IBAN, address, health, documents, API tokens of users): XChaCha20-Poly1305 per E9, or AES-256-GCM, random nonce per value, AAD bound to the record (e.g. `user:<id>`), key version stored with the ciphertext. For fields that must be searchable, store a blind index (HMAC-SHA256 with a separate key) next to the ciphertext. Passwords are never encrypted, only hashed (control 5).
- E5. Key management: keys in a KMS or secret manager, loaded from env at runtime; 256-bit random (`openssl rand -base64 32`); separate keys per environment and per purpose (data, blind index, sessions); envelope encryption (per-tenant data key wrapped by a master key) for multi-tenant apps; documented rotation: add new version, encrypt new writes with it, re-encrypt old rows in a background job, then retire the old key.
- E6. Tokens and sessions: signing secrets >= 256-bit; pin the JWT algorithm (reject `none` and algorithm switching), short access-token lifetime, refresh-token rotation with reuse detection, revocation list or session table.
- E7. Backups and exports: encrypted, access-restricted, retention set; CSV/PDF exports of personal data generated on demand and served by expiring links.
- E8. Front-end code: production build minified, source maps not public, optional obfuscation for proprietary client logic, Subresource Integrity on third-party scripts. Tell the user plainly: anything shipped to the browser can be read; obfuscation only slows copying. Real secrets and business rules move to the server.

### Sensitive data map — encrypt by default

During DETECT, list every table/collection/file store and classify each field. Everything in the "Encrypt" rows is encrypted (E4/E9) unless the user explicitly opts out in writing.

| Class | Examples | Treatment |
|---|---|---|
| Identity | national ID / Iqama, passport, DOB, full address | Encrypt + blind index if searched |
| Contact | phone, personal email (when not the login key) | Encrypt + blind index |
| Login email | email used to sign in | Blind index for lookup + encrypted copy, or plaintext only if the user accepts the trade-off |
| Financial | IBAN, card last-4 + token (never full card numbers: use the payment provider), salary, invoices | Encrypt |
| Health / personal | medical notes, disability, family data | Encrypt |
| Documents | uploaded IDs, contracts, CVs, images of people | Encrypt the file (streaming AEAD) + private bucket |
| Secrets of users | OAuth/refresh tokens, integration API keys, webhook secrets, TOTP secrets | Encrypt |
| One-way only | passwords, recovery codes, reset tokens, API keys you issue | Hash (Argon2id or SHA-256 of a high-entropy token), never encrypt |
| Messages | private chats, support tickets with personal data | Encrypt when they may contain the above |
| Public | product names, prices, public posts | No encryption needed |

### E9. Maximum-strength profile (default in this skill)

- Cipher: XChaCha20-Poly1305 (libsodium) preferred: 192-bit random nonce removes nonce-collision risk at any volume and is fast without AES hardware. AES-256-GCM is acceptable with AES-NI; rotate a GCM key before 2^32 encryptions. Never AES-CBC/CTR without a MAC.
- Key hierarchy: master key (KEK) lives in a KMS/HSM or secret manager and never in code, repo or DB; per-tenant or per-table data keys stored wrapped; per-purpose sub-keys derived with HKDF-SHA256 (`info = "field:national_id"`), so one leaked sub-key exposes one field only.
- Context binding: AAD = table + record id (+ tenant id), so ciphertext copied to another row or user fails to decrypt.
- Least-privilege decryption: only the backend service that needs plaintext holds key access; DB admins, backups, logs, analytics and the front end see ciphertext only; log every decrypt of high-sensitivity classes.
- Passwords: Argon2id m=64 MiB, t=3, p=1 (floor: m=19 MiB, t=2), unique salt, plus a pepper (HMAC-SHA256 with a secret kept outside the DB) applied before hashing; rehash old hashes on login.
- Files: encrypt sensitive uploads before storage with libsodium secretstream (or AES-GCM per chunk), random file key wrapped by the data key.
- Transport: TLS 1.3 preferred, TLS 1.2 only with ECDHE + AEAD suites, HSTS preload, CAA DNS records; enable hybrid post-quantum key exchange (X25519MLKEM768) at the CDN/server when available.
- Hygiene: decrypt only at the point of use, never log or return plaintext sensitive fields in errors or analytics, mask in UIs (e.g. `•••• 4417`), wipe exports after expiry.
- Rotation: data keys yearly, immediately on suspected leak; prefix ciphertext with a key version; re-encrypt in background.
- State it plainly in the report: these ciphers cannot be brute-forced in practice; real breaches come from stolen keys, injection, broken access control or over-broad decrypt access, so E5/E9 key isolation and the 27 controls carry the real weight.

Maximum-strength reference (tested):

```js
// Node.js — XChaCha20-Poly1305 + HKDF sub-keys + peppered Argon2id
// npm i libsodium-wrappers argon2
import crypto from 'node:crypto';
import sodium from 'libsodium-wrappers';
import argon2 from 'argon2';
await sodium.ready;
const MASTER = Buffer.from(process.env.MASTER_KEY_B64, 'base64'); // 32 bytes, from KMS/secret manager
const subKey = (purpose) => Buffer.from(crypto.hkdfSync('sha256', MASTER, Buffer.alloc(0), purpose, 32));
export function seal(plain, purpose, aad) {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, aad, null, nonce, subKey(purpose));
  return ['x1', sodium.to_base64(nonce), sodium.to_base64(ct)].join(':');
}
export function open(blob, purpose, aad) {
  const [, n, ct] = blob.split(':');
  return sodium.to_string(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, sodium.from_base64(ct), aad, sodium.from_base64(n), subKey(purpose)));
}
const PEPPER = Buffer.from(process.env.PEPPER_B64, 'base64');
const pep = (pw) => crypto.createHmac('sha256', PEPPER).update(pw).digest();
export const hashPassword = (pw) => argon2.hash(pep(pw), { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
export const verifyPassword = (hash, pw) => argon2.verify(hash, pep(pw));
// usage: seal(iban, 'field:iban', `users:${id}`)
```

```python
# Python — XChaCha20-Poly1305 + HKDF sub-keys + peppered Argon2id
# pip install pynacl cryptography argon2-cffi
import os, base64, hmac, hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from nacl.bindings import (crypto_aead_xchacha20poly1305_ietf_encrypt as xenc,
                           crypto_aead_xchacha20poly1305_ietf_decrypt as xdec)
from argon2 import PasswordHasher
MASTER = base64.b64decode(os.environ["MASTER_KEY_B64"])
def sub_key(purpose: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose.encode()).derive(MASTER)
def seal(plain: str, purpose: str, aad: str) -> str:
    n = os.urandom(24)
    ct = xenc(plain.encode(), aad.encode(), n, sub_key(purpose))
    return ":".join(["x1", base64.b64encode(n).decode(), base64.b64encode(ct).decode()])
def open_(blob: str, purpose: str, aad: str) -> str:
    _, n, ct = blob.split(":")
    return xdec(base64.b64decode(ct), aad.encode(), base64.b64decode(n), sub_key(purpose)).decode()
PEPPER = base64.b64decode(os.environ["PEPPER_B64"])
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
def _pep(pw: str) -> bytes:
    return hmac.new(PEPPER, pw.encode(), hashlib.sha256).digest()
def hash_password(pw: str) -> str:
    return ph.hash(_pep(pw))
def verify_password(h: str, pw: str) -> bool:
    try:
        return ph.verify(h, _pep(pw))
    except Exception:
        return False
```

Generate keys once per environment: `openssl rand -base64 32` for MASTER_KEY_B64, PEPPER_B64 and IDX_KEY_B64; store them in the secret manager, never in the repo. Losing the master key means losing the data: require an offline, access-controlled backup of keys before encrypting production data.

Baseline reference (AES-256-GCM, tested; use when libsodium is unavailable):

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

## Module D — Intrusion detection and email alerts

Goal: when someone attacks the site, the owner gets an email saying what the attack was, where it came from, and what it targeted, while the request is blocked.

- D1. Detect: inspect URL, query and body for SQL injection, XSS, path traversal, command injection, SSRF and template injection; trap routes that real users never request (`/.env`, `/.git/`, `/wp-admin`, `/phpmyadmin`, backups) and answer them 404.
- D2. Detect behaviour: brute-force login (5 / 20 / 100 failures per IP in 15 min), access-denied events on other users' records or admin routes (IDOR attempts), CSRF and signature failures, rate-limit hits (control 12), webhook signature failures.
- D3. Honeytokens: plant a fake admin user, a fake API key in a decoy config and a fake row in sensitive tables; any use of them triggers an alert and means a leak.
- D4. Alert email contains: attack type, time (UTC), IP, approximate location (city/region/country), method and path, matched pattern (masked), user agent, logged-in user if any, and the recommended action. Secrets, passwords, cookies and tokens are masked; never include full request bodies.
- D5. Location: read CDN geo headers (Cloudflare `CF-IPCountry`, `CF-IPCity`, `CF-Region` via "Add visitor location headers"; Vercel `x-vercel-ip-country`; CloudFront `CloudFront-Viewer-Country`) or a local GeoIP database (MaxMind GeoLite2). Take the client IP only from the trusted proxy header (`CF-Connecting-IP`, or `X-Forwarded-For` with trust-proxy set to the real hop count), never from a header the client can forge.
- D6. Noise control: one email per IP per attack type per 10 minutes, every event still logged; optional daily digest; `GUARD_MODE=monitor` (log + email, no blocking) for the first days to tune false positives, then `block`.
- D7. Delivery: SMTP from a dedicated sender (e.g. `security@yourdomain`) with SPF/DKIM, or a transactional email API; credentials in env; alert recipient in `ALERT_TO`; optional second channel (Telegram/Slack/WhatsApp webhook) for critical events (honeytoken, admin login from a new country).
- D8. Response: repeated or high-severity attackers are blocked at the WAF (P1) automatically or by the owner; never counter-attack or scan the attacker's systems.
- D9. Edge alerts: also enable the CDN/WAF's own notifications (e.g. Cloudflare security event and DDoS alerts) so attacks stopped before reaching the app are reported too.

Tell the user plainly: IP location is approximate and attackers often use VPNs, Tor or cloud servers, so the location shows where the traffic came from, not who the person is. Pattern rules catch common automated attacks, not every attack; they complement the 27 controls, they do not replace them.

Env: `ALERT_TO`, `ALERT_FROM`, and `ALERT_SMTP_URL` (Node, e.g. `smtps://user:pass@smtp.host:465`) or `ALERT_SMTP_HOST/PORT/USER/PASS` (Python); `GUARD_MODE=monitor|block`.

Detection tests: normal search, an apostrophe name (O'Reilly) and text with `--` pass; `' OR 1=1 --`, `<script>`, `../../etc/passwd` and `/.env` are blocked and produce one email with type, IP and location; a second identical attack within 10 minutes is logged but not emailed; 5 failed logins produce a brute-force alert.

Reference (tested, Node.js + Express):

```js
// Intrusion detection + email alert middleware (Express). npm i nodemailer
import nodemailer from 'nodemailer';

const RULES = [
  ['SQL injection', /(\bunion\b[\s\S]*\bselect\b|\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|;\s*(drop|delete|truncate|alter)\s|'\s*(--|#)|\/\*[\s\S]*\*\/|\bsleep\s*\(|\bbenchmark\s*\(|information_schema)/i],
  ['XSS', /(<\s*script|javascript\s*:|on(error|load|mouseover|focus)\s*=|<\s*(iframe|svg|img)[^>]*\bon\w+\s*=|document\.cookie)/i],
  ['Path traversal', /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\/etc\/passwd|win\.ini)/i],
  ['Command injection', /([;&|`]\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh|powershell)\b|\$\([^)]*\))/i],
  ['SSRF', /(169\.254\.169\.254|metadata\.google\.internal|localhost:\d+|127\.0\.0\.1)/i],
  ['Template injection', /(\{\{[\s\S]*\}\}|\$\{[\s\S]*\}|<%[\s\S]*%>)/],
];
const TRAPS = /^\/(\.env|\.git\/|wp-admin|wp-login\.php|phpmyadmin|admin\.php|config\.php|backup\.(zip|sql)|\.aws\/|server-status)/i;

const transport = process.env.ALERT_SMTP_URL
  ? nodemailer.createTransport(process.env.ALERT_SMTP_URL)
  : nodemailer.createTransport({ jsonTransport: true });
const lastSent = new Map();
const THROTTLE_MS = 10 * 60 * 1000;
const fails = new Map();

const clientIp = (req) => req.headers['cf-connecting-ip'] || req.ip || req.socket?.remoteAddress || 'unknown';
const location = (req) => {
  const h = req.headers;
  const parts = [h['cf-ipcity'], h['cf-region'], h['cf-ipcountry'] || h['x-vercel-ip-country'] || h['cloudfront-viewer-country']]
    .filter(Boolean).map(decodeURIComponent);
  return parts.length ? parts.join(', ') : 'unknown (enable CDN geo headers or a GeoIP DB)';
};
const mask = (s) => String(s).replace(/(password|pass|token|secret|authorization|cookie|api[_-]?key)=([^&\s]+)/gi, '$1=***').slice(0, 300);

export async function alert(req, type, detail) {
  const ip = clientIp(req);
  const key = `${ip}:${type}`;
  const now = Date.now();
  const event = {
    time: new Date(now).toISOString(), type, ip, location: location(req),
    method: req.method, path: mask(req.originalUrl || req.url),
    userAgent: (req.headers['user-agent'] || '').slice(0, 200),
    user: req.user?.id ?? 'anonymous', detail: mask(detail),
  };
  console.warn('[SECURITY]', JSON.stringify(event));
  if (now - (lastSent.get(key) || 0) < THROTTLE_MS) return event;
  lastSent.set(key, now);
  const text = Object.entries(event).map(([k, v]) => `${k}: ${v}`).join('\n');
  const info = await transport.sendMail({
    from: process.env.ALERT_FROM || 'security@localhost',
    to: process.env.ALERT_TO || 'admin@localhost',
    subject: `[Security alert] ${type} from ${ip} (${event.location})`,
    text: `${text}\n\nAction: review logs, block the IP at the WAF if repeated, rotate keys if data may be exposed.`,
  });
  event.emailed = Boolean(info);
  return event;
}

// GUARD_MODE=monitor (log + email, never block) or block (default). Start with monitor for a few days to tune.
const BLOCK = (process.env.GUARD_MODE || 'block') === 'block';
export function guard() {
  return async (req, res, next) => {
    try {
      const path = decodeURIComponent(req.path || '');
      if (TRAPS.test(path)) { await alert(req, 'Probe for sensitive file', path); return res.status(404).end(); }
      const haystack = [req.originalUrl, JSON.stringify(req.query || {}), JSON.stringify(req.body || {})].join(' ');
      let decoded = haystack; try { decoded = decodeURIComponent(haystack); } catch {}
      for (const [type, re] of RULES) {
        const m = decoded.match(re);
        if (m) { await alert(req, type, m[0]); if (BLOCK) return res.status(400).json({ error: 'Bad request' }); break; }
      }
    } catch (e) { console.error('guard error', e.message); }
    next();
  };
}

export async function onLoginFailure(req, account) {
  const ip = clientIp(req);
  const n = (fails.get(ip) || 0) + 1;
  fails.set(ip, n);
  setTimeout(() => fails.set(ip, Math.max(0, (fails.get(ip) || 1) - 1)), 15 * 60 * 1000).unref?.();
  if (n === 5 || n === 20 || n === 100) await alert(req, 'Brute-force login', `${n} failures in 15 min, last account: ${account}`);
}
export const onAccessDenied = (req, resource) => alert(req, 'Unauthorized access attempt (IDOR/admin)', resource);
export const onHoneytoken = (req, which) => alert(req, 'Honeytoken used (credential leak)', which);

// wiring:
// app.set('trust proxy', 1); app.use(express.json()); app.use(guard());
// in login handler on failure: await onLoginFailure(req, email);
// in authorization checks on deny: await onAccessDenied(req, `${req.method} ${req.path}`);
```

Reference (tested, Python core for Flask/FastAPI/Django middleware):

```python
# Intrusion detection + email alert core (framework-agnostic). Wire into Flask/FastAPI/Django middleware.
import os, re, json, time, smtplib, logging
from email.message import EmailMessage
from urllib.parse import unquote

RULES = [
    ("SQL injection", re.compile(r"(\bunion\b[\s\S]*\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|;\s*(drop|delete|truncate|alter)\s|'\s*(--|#)|\bsleep\s*\(|\bbenchmark\s*\(|information_schema)", re.I)),
    ("XSS", re.compile(r"(<\s*script|javascript\s*:|on(error|load|mouseover|focus)\s*=|<\s*(iframe|svg|img)[^>]*\bon\w+\s*=|document\.cookie)", re.I)),
    ("Path traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|win\.ini)", re.I)),
    ("Command injection", re.compile(r"([;&|`]\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh|powershell)\b|\$\([^)]*\))", re.I)),
    ("SSRF", re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|localhost:\d+|127\.0\.0\.1)", re.I)),
]
TRAPS = re.compile(r"^/(\.env|\.git/|wp-admin|wp-login\.php|phpmyadmin|admin\.php|config\.php|backup\.(zip|sql)|\.aws/|server-status)", re.I)
THROTTLE = 600
_last = {}
log = logging.getLogger("security")

def _mask(s: str) -> str:
    return re.sub(r"(password|pass|token|secret|authorization|cookie|api[_-]?key)=([^&\s]+)", r"\1=***", str(s), flags=re.I)[:300]

def location(headers: dict) -> str:
    h = {k.lower(): v for k, v in headers.items()}
    parts = [h.get("cf-ipcity"), h.get("cf-region"), h.get("cf-ipcountry") or h.get("x-vercel-ip-country") or h.get("cloudfront-viewer-country")]
    parts = [unquote(p) for p in parts if p]
    return ", ".join(parts) if parts else "unknown (enable CDN geo headers or a GeoIP DB)"

def alert(ip, headers, method, path, attack, detail, user="anonymous"):
    ev = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "type": attack, "ip": ip,
          "location": location(headers), "method": method, "path": _mask(path),
          "userAgent": str(headers.get("User-Agent", headers.get("user-agent", "")))[:200], "user": user, "detail": _mask(detail)}
    log.warning("[SECURITY] %s", json.dumps(ev))
    key = f"{ip}:{attack}"
    if time.time() - _last.get(key, 0) < THROTTLE:
        ev["emailed"] = False
        return ev
    _last[key] = time.time()
    msg = EmailMessage()
    msg["Subject"] = f"[Security alert] {attack} from {ip} ({ev['location']})"
    msg["From"] = os.environ.get("ALERT_FROM", "security@localhost")
    msg["To"] = os.environ.get("ALERT_TO", "admin@localhost")
    msg.set_content("\n".join(f"{k}: {v}" for k, v in ev.items()) + "\n\nAction: review logs, block the IP at the WAF if repeated, rotate keys if data may be exposed.")
    host = os.environ.get("ALERT_SMTP_HOST")
    if host:
        with smtplib.SMTP(host, int(os.environ.get("ALERT_SMTP_PORT", "587")), timeout=10) as s:
            s.starttls()
            s.login(os.environ["ALERT_SMTP_USER"], os.environ["ALERT_SMTP_PASS"])
            s.send_message(msg)
    ev["emailed"] = True
    ev["_message"] = msg
    return ev

def inspect(ip, headers, method, path, query="", body=""):
    """Return (attack_type, event) or (None, None). Caller blocks with 400/404 when GUARD_MODE != 'monitor'."""
    p = unquote(path)
    if TRAPS.match(p):
        return "Probe for sensitive file", alert(ip, headers, method, path, "Probe for sensitive file", p)
    text = unquote(f"{path} {query} {body}")
    for name, rx in RULES:
        m = rx.search(text)
        if m:
            return name, alert(ip, headers, method, path, name, m.group(0))
    return None, None

# Flask wiring example:
# @app.before_request
# def _guard():
#     ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
#     t, _ = inspect(ip, dict(request.headers), request.method, request.path,
#                    request.query_string.decode(), request.get_data(as_text=True)[:5000])
#     if t and os.environ.get("GUARD_MODE", "block") != "monitor":
#         abort(404 if t.startswith("Probe") else 400)
```

## Report format

```
SECURITY REPORT — <project> — <date>
Stack: ...
Summary: X pass / Y fixed / Z open / N n-a

| # | Control | Status | Severity | Evidence (file:line) | Fix applied | Verification |
(27 core rows, then E1–E9, P1–P7, D1–D9)

Encryption summary: sensitive data map (field → class → treatment), algorithm, key storage, rotation plan, key backup status
Protection summary: WAF/CDN, bot protection, admin MFA, backups, incident plan
Alert summary: detectors enabled, mode (monitor/block), alert recipient, test alert received (yes/no)

Open items needing the user: (key rotation, provider settings, DNS/hosting, history purge)
Residual risk: ...
```

Rules for the report: every FIXED row names the changed file and the test that proved it; never claim verification that was not run — write NOT VERIFIED and why; this is a hardening pass, not a guarantee or a substitute for a professional penetration test.

## Use as a plain prompt (models without skill support)

Paste this whole file as the system or first message, then: "Apply the hardening workflow (27 controls + encryption + protection + intrusion alerts) to my project. Stack: <...>. Here are the files: <...>"