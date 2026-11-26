# Tools: scanner, safe fixes, authorization tests, client report, CI

All tools are Python 3.8+ standard library only. Run them in AUDIT and again in VERIFY.

## 1. Scanner — `scripts/scan.py`

```bash
python3 scripts/scan.py /path/to/project                          # code, git history, dependencies, infrastructure
python3 scripts/scan.py . --url https://your-site.com             # + live headers, cookies, CORS, HTTPS, exposed paths
python3 scripts/scan.py . --json scan.json --fail-on high         # JSON for the report; exit 1 on high or critical
python3 scripts/scan.py . --deep                                  # + semgrep, gitleaks, trivy when installed
python3 scripts/scan.py . --fix                                   # + safe, non-destructive fixes (see below)
python3 scripts/scan.py . --no-history --no-deps --no-infra       # fast local pass
```

Checks (each finding names its control):
- Secrets in files and in all git history (AWS, Stripe live, OpenAI, Anthropic, GitHub, Google, Slack, SendGrid, Twilio, private keys, Supabase service_role JWTs, DB URLs with passwords, hardcoded secret assignments). Values are masked to the last 4 characters.
- Tracked sensitive files (`.env`, keys, dumps, backups, credentials JSON); `.env` missing from `.gitignore`; secret-looking variables behind public prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_` ...).
- Dangerous code: raw HTML sinks, SQL built with interpolation, eval/shell, MD5/SHA-1 passwords, JWT `none`, TLS verification off, CORS `*`, debug on, `Math.random()` tokens, open Firebase rules, insecure cookies, user input in LLM system prompts; Supabase/SQL tables without RLS.
- Infrastructure (I1–I6): Dockerfile, docker-compose, nginx/Apache, Kubernetes manifests, Terraform, GitHub Actions workflows.
- Dependencies: `npm audit`, `pip-audit`, `composer audit`.
- Live site (only your own): HTTPS redirect, HSTS, CSP and other headers, cookie flags, CORS reflection, version leaks, exposed `/.env`, `/.git/config`, backups, API docs / GraphQL introspection, `security.txt`.
- `--deep`: merges semgrep (`SEMGREP_CONFIG`, default `p/default`; set a local rules folder when the registry is unreachable), gitleaks (files + history) and trivy (vulnerabilities, misconfigurations, secrets) results when those tools are installed.

Suppress a reviewed false positive with a comment containing `vibe-scan: ignore` on that line, or `vibe-scan: ignore-file` near the top of a file. Record why in the report.

## 2. Safe fixes — `--fix`

Never edits source code, never deletes, never rewrites history. It only:
- appends missing patterns (`.env`, keys, dumps) to `.gitignore`;
- creates `.env.example` with variable names only;
- writes review files to `.security/`: `untrack-sensitive-files.sh` (`git rm --cached` commands), `draft-enable-rls.sql` (RLS + policy templates; enabling RLS without policies blocks API access), `security.txt` template, `security-headers.txt` baseline.
Re-running is safe (idempotent). Everything else is fixed by hand in FIX, with tests.

## 3. Authorization tests — `scripts/authz_test.py`

Proves user A cannot reach user B's data and normal users cannot reach admin routes (IDOR and broken access control, which pattern scanners cannot see). Local/staging only unless `--allow-remote`; `DELETE` checks need `--allow-destructive`; tokens come from env vars (`${ALICE_TOKEN}`), never the file.

```json
{
  "base_url": "http://localhost:3000",
  "users": {
    "alice": {"headers": {"Authorization": "Bearer ${ALICE_TOKEN}"}},
    "bob":   {"headers": {"Authorization": "Bearer ${BOB_TOKEN}"}},
    "admin": {"headers": {"Authorization": "Bearer ${ADMIN_TOKEN}"}}
  },
  "checks": [
    {"name": "Alice's order", "method": "GET", "path": "/api/orders/101", "owner": "alice", "deny": ["anonymous", "bob"]},
    {"name": "Admin users", "method": "GET", "path": "/api/admin/users", "owner": "admin", "deny": ["anonymous", "alice", "bob"]},
    {"name": "Edit Alice", "method": "PATCH", "path": "/api/users/1", "body": {"name": "x"}, "owner": "alice", "deny": ["bob"]}
  ]
}
```
```bash
ALICE_TOKEN=... BOB_TOKEN=... ADMIN_TOKEN=... python3 scripts/authz_test.py authz.json --json authz.json.out
```
Build the check list from the app's routes (every route with an ID or an admin prefix). Each check first confirms the owner can access it (otherwise the config is wrong), then that every user in `deny` gets 401/403/404.

## 4. Client report — `scripts/report.py`

```bash
python3 scripts/report.py scan-after.json --baseline scan-before.json --authz authz.json.out \
  --project "Client website" --brand "Masari AI" --logo logo.png --color "#1d4ed8" --lang ar --pdf
```
Produces a branded HTML report (Arabic RTL or English) and a PDF when Chrome/Chromium is installed: executive summary, security score 0–100 with grade (any critical caps the score at 59), counts by severity, before/after comparison (resolved / new / still open), findings table mapped to controls and areas, next steps, scope and disclaimer. `--manual manual.json` merges findings from the manual review (`[{control, severity, title, where, detail}]`).

## 5. CI

Copy `templates/security-scan.yml` to `.github/workflows/security-scan.yml` and `scripts/scan.py` to `.security/scan.py` in the project (a pinned, reviewed copy; do not download it at build time). It runs on every push, pull request and weekly, fails on high/critical findings, uploads the JSON report, and scans the live site when the repository variable `SITE_URL` is set.

Rules: a scanner finding is evidence to confirm, not an automatic verdict; regex checks miss logic flaws, so the manual 27-control review and authz tests still run; any secret found in history is compromised (revoke and rotate, C25); scan only systems you own or are authorized to test.
