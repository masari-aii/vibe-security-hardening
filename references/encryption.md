# Module E — Encryption (encrypt the site and its data)

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
