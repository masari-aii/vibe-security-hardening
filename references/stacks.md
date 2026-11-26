# Module S — Stack playbooks

Use the section for each technology found in DETECT. Each item maps to a core control (C#) or module item. Always run the stack's own audit tool too.

## Next.js (App Router / Pages)

- C11: only `NEXT_PUBLIC_*` reaches the browser; secrets never get that prefix. Add `import 'server-only'` at the top of modules that read secrets so a client import fails the build.
- C9/C6: Server Actions and Route Handlers are public HTTP endpoints. Inside every one: validate input (zod/valibot) and check the session and the user's right to the specific record. Middleware is an extra layer, never the only authorization check.
- C21: keep Next.js and React patched. Examples: CVE-2025-29927 (middleware authorization bypass via `x-middleware-subrequest`, fixed in 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5) and React2Shell CVE-2025-55182 / CVE-2025-66478 (RCE in React Server Components; upgrade to the patched release in the Vercel React2Shell bulletin). Run `npm audit` and upgrade.
- C14: set headers in `next.config.js`:

```js
const csp = "default-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
module.exports = {
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  async headers() {
    return [{ source: '/(.*)', headers: [
      { key: 'Content-Security-Policy', value: csp },
      { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
      { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
    ] }];
  },
};
```
  Tighten `script-src` with nonces if inline scripts are needed.
- C7: `dangerouslySetInnerHTML` only with DOMPurify-sanitized content.
- SSRF: restrict `images.remotePatterns` to known hosts; validate any server-side `fetch(userUrl)` against an allow-list.

## Supabase

- The anon key is public by design; security comes from Row Level Security. The `service_role` key bypasses RLS: server only, never in client code or `NEXT_PUBLIC_*`/`VITE_*`.
- C3: enable RLS on every table in exposed schemas, with explicit policies per operation:

```sql
alter table public.profiles enable row level security;
create policy "read own profile"   on public.profiles for select using ((select auth.uid()) = id);
create policy "update own profile" on public.profiles for update using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
create policy "insert own profile" on public.profiles for insert with check ((select auth.uid()) = id);
-- no delete policy = nobody can delete via the API
```
- Views: `create view ... with (security_invoker = true)` so RLS applies. `security definer` functions: `set search_path = ''` and check `auth.uid()` inside.
- Storage: private buckets with policies on `storage.objects` (e.g. path prefix = `auth.uid()`); signed URLs for downloads.
- Auth: enable email confirmation, leaked-password protection and MFA for admins; disable sign-ups if the app is invite-only; restrict redirect URLs.
- Run the dashboard Security Advisor and fix every error before launch.

## Firebase

- C3: rules are the only server-side guard for client SDK access. Never `allow read, write: if true`.

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read:   if request.auth != null && request.auth.uid == userId;
      allow update: if request.auth != null && request.auth.uid == userId
                    && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['name', 'avatar', 'updatedAt']);
      allow create: if request.auth != null && request.auth.uid == userId;
      allow delete: if false;
    }
  }
}
```
- Storage rules by `request.auth.uid` path, size and content type limits.
- Enable App Check; restrict the browser API key in Google Cloud Console (HTTP referrers + allowed APIs); Admin SDK credentials only on the server; test rules with the Emulator Suite.

## Vercel / Netlify / similar hosting

- Env vars scoped per environment (Production / Preview / Development); production secrets not exposed to preview builds of forks.
- Enable deployment protection for previews; custom domain with HTTPS only; headers via framework config or `vercel.json` / `_headers`.
- Put a WAF/firewall rule set and bot protection in front (P1, P2).

## Laravel

- `.env`: `APP_ENV=production`, `APP_DEBUG=false`, strong `APP_KEY`; web root is `public/` only; `php artisan config:cache`.
- C6/C10: Form Requests for validation; Eloquent/Query Builder bindings, never raw concatenation; `$fillable` on models (no `$guarded = []`).
- C7: `{{ }}` escapes; avoid `{!! !!}` with user data.
- C16: keep `VerifyCsrfToken`; C12: `throttle` middleware on login, API and AI routes.
- C5: `config/hashing.php` driver `argon2id`. Module E: `'encrypted'` casts are convenient but use `APP_KEY` for everything; for high-sensitivity fields prefer the E9 per-field keys or at least a separate key.
- Check `php artisan route:list` for routes missing `auth`/policies; `storage/` and logs not web-accessible.

## Django

- `DEBUG=False`, `SECRET_KEY` from env, `ALLOWED_HOSTS` set; `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS=31536000`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_CONTENT_TYPE_NOSNIFF`; run `python manage.py check --deploy` and fix all warnings.
- C5: `PASSWORD_HASHERS` with `Argon2PasswordHasher` first (`pip install argon2-cffi`).
- C10: ORM; `raw()`/`extra()` only with params. C7: avoid `|safe` and `mark_safe` on user data.
- Admin: non-default URL, MFA (e.g. django-otp), staff accounts minimal.

## Express / Node.js APIs

```js
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
app.disable('x-powered-by');
app.set('trust proxy', 1);                       // real hop count behind your proxy/CDN
app.use(helmet());
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }));
```
- Validate every body/query with zod; parameterized queries (pg `$1`, Prisma, Drizzle); session cookies `httpOnly`, `secure`, `sameSite: 'lax'`; central error handler that hides stack traces in production.

## Plain PHP / WordPress

- PDO prepared statements; `password_hash($p, PASSWORD_ARGON2ID)`; `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` on output; `session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Lax'])`.
- WordPress: core/plugins/themes updated, remove unused plugins, `define('DISALLOW_FILE_EDIT', true);`, MFA for admins, limit login attempts, disable XML-RPC if unused, least-privilege DB user.

## Mobile (React Native / Expo / Flutter)

- `EXPO_PUBLIC_*` and anything in the bundle is public: no secrets in the app; call your backend.
- Tokens in SecureStore / Keychain / Keystore, not AsyncStorage/SharedPreferences.
- Backend enforces all authorization; consider certificate pinning for high-risk apps.
