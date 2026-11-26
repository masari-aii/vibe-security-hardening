# Commands and detailed usage

[النسخة العربية](COMMANDS.md) · [Back to README](../README.md)

Every command in the skill: what it does, every option, ready examples, and how to read the output. Use the skill in two ways: **ask the model** (Claude or any LLM) and it runs the tools, or **run the tools yourself** in a terminal.

## Contents

1. [Requirements](#1-requirements)
2. [Quick index](#2-quick-index)
3. [Prompts for the model](#3-prompts-for-the-model)
4. [Scanner `scan.py`](#4-scanner-scanpy)
5. [Authorization tests `authz_test.py`](#5-authorization-tests-authz_testpy)
6. [Client report `report.py`](#6-client-report-reportpy)
7. [Protection and alerts `guard.mjs` / `guard.py`](#7-protection-and-alerts-guardmjs--guardpy)
8. [Alerts dashboard `alerts_dashboard.py`](#8-alerts-dashboard-alerts_dashboardpy)
9. [Continuous scanning in GitHub Actions](#9-continuous-scanning-in-github-actions)
10. [Maintenance: tests and build](#10-maintenance-tests-and-build)
11. [End-to-end scenarios](#11-end-to-end-scenarios)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Requirements

| Requirement | Why | Notes |
|---|---|---|
| Python 3.8+ | All tools | Standard library only. On Windows use `python` instead of `python3` |
| Git | Git history scan | Optional; skipped without it |
| npm / pip-audit / composer | Dependency audit | Optional; whatever is installed is used |
| Chrome, Chromium or Edge | PDF reports | Optional; otherwise open the HTML and print to PDF |
| Semgrep / Gitleaks / Trivy | `--deep` | Optional |
| Node.js + `express` + `nodemailer` | `guard.mjs` for Node apps | Only if you use the Node guard |

```bash
git clone https://github.com/masari-aii/vibe-security-hardening
cd vibe-security-hardening
python3 scripts/scan.py --help
```

> Every tool prints its options with `--help`.

---

## 2. Quick index

| Command | What it does | When |
|---|---|---|
| `python3 scripts/scan.py ./app` | Full scan: code, git history, dependencies, infrastructure | Before launch and after big features |
| `python3 scripts/scan.py ./app --url https://site.com` | + live site checks | When the site is deployed |
| `python3 scripts/scan.py ./app --fix` | Safe automatic fixes | After the first scan |
| `python3 scripts/scan.py ./app --json before.json` | Save results (for report and comparison) | Before and after fixing |
| `python3 scripts/authz_test.py authz.json` | Can a user see another user's data? | Any app with logins |
| `python3 scripts/report.py after.json --baseline before.json --pdf` | Client report | End of the audit |
| `python3 scripts/alerts_dashboard.py alerts.jsonl` | Intrusion dashboard | After enabling the guard |
| `python3 scripts/alerts_dashboard.py alerts.jsonl --digest --send` | Daily email digest | Daily, scheduled |
| `python3 tests/run_tests.py` | Check the tools work | After changing the skill |

---

## 3. Prompts for the model

After installing the skill in Claude (or pasting `ALL-IN-ONE.md` into any model):

| You want | Type |
|---|---|
| Full audit and fix | `Secure, encrypt and protect my project with the full skill. Stack: Next.js + Supabase + Vercel` |
| Audit only | `Audit my project without modifying any file; list issues by severity` |
| Client report | `Scan the project and give me the client report in English as PDF, brand Masari AI, with before/after` |
| Secrets only | `Run controls 2, 11, 24, 25 (secrets) on this repo` |
| Authorization | `Test authorization: can a user see another user's orders? Are admin routes protected?` |
| Encryption | `Build the sensitive data map and encrypt every sensitive field with the strongest settings` |
| Intrusion alerts | `Enable intrusion detection and send alerts to my email and Telegram` |
| Infrastructure | `Review the Dockerfile, docker-compose, nginx and Terraform files` |
| AI app | `Review my AI chatbot against the OWASP LLM Top 10` |
| Saudi PDPL | `Is my app compliant with the Saudi PDPL? Give me the K1–K12 table` |
| NCA ECC | `Map the findings to NCA ECC for a government client` |
| CI | `Add the security scan to GitHub Actions in my project` |

Tips: name your stack so the right playbook is used; without file access, paste the key files or run `scan.py` yourself and paste the output; the model asks before anything irreversible (key rotation, history rewrite, live DB migrations).

---

## 4. Scanner `scan.py`

Scans the project and prints each finding with severity, location and action. It never modifies files except with `--fix` (which still never touches code).

```bash
python3 scripts/scan.py [path] [options]
```

| Option | What it does | Example |
|---|---|---|
| `path` | Project folder (default: current folder) | `./my-app` |
| `--url URL` | Adds live-site checks: HTTPS, headers, cookies, CORS, exposed files. **Your own site only** | `--url https://shop.com` |
| `--json FILE` | Save results as JSON (report, comparison, CI) | `--json before.json` |
| `--fail-on LEVEL` | Exit code 1 if a finding has this severity or worse: `critical` (default), `high`, `medium`, `low`, `info` | `--fail-on high` |
| `--no-history` | Skip the git history scan (faster) | |
| `--no-deps` | Skip npm / pip / composer audits | |
| `--no-infra` | Skip Docker, nginx, Kubernetes, Terraform, CI checks | |
| `--deep` | Merge Semgrep, Gitleaks, Trivy results when installed | |
| `--fix` | Safe automatic fixes (below) | |

```bash
python3 scripts/scan.py ./my-app                                             # full scan
python3 scripts/scan.py ./my-app --no-history --no-deps                      # quick pass while coding
python3 scripts/scan.py ./my-app --url https://my-site.com --json scan.json  # code + live site, saved
python3 scripts/scan.py . --no-history --no-deps --no-infra --url https://my-site.com   # live site only
python3 scripts/scan.py . --fail-on high                                     # strict, for CI
python3 scripts/scan.py ./my-app --deep                                      # with extra tools
```

**Reading the output**

```
summary: critical=2  high=3  medium=1  low=0  info=0
[CRITICAL] C24  Secret in git history: Stripe live secret key  @ commit b4aac5aa34  — value …K6J0 — revoke and rotate it (C25)
```

| Part | Meaning |
|---|---|
| `summary` | Counts by severity |
| `[CRITICAL]` | Severity: critical › high › medium › low › info |
| `C24` | Control ID (table below) |
| `@ ...` | Location: `file:line`, commit, or URL |
| `— ...` | Action or code excerpt |
| `…K6J0` | Secrets show only their last 4 characters |

| Prefix | Area | Examples |
|---|---|---|
| `C` | 27 core controls | `C2` secret in file, `C3` database, `C10` SQL injection, `C11` env vars, `C24` git history |
| `E` | Encryption | `E2` TLS verification off, `E6` weak tokens/randomness |
| `I` | Infrastructure | `I1` Docker, `I2` compose, `I3` nginx, `I4` Kubernetes, `I5` cloud, `I6` GitHub Actions |
| `A` | AI | `A1` user input in the system prompt |
| `P` | Protection | `P6` security.txt |
| `Z` | Authorization (from `authz_test.py`) | `Z1` unauthenticated, `Z2` admin, `Z3` IDOR |
| `SEM` | Semgrep (deep mode) | |

Exit code: `0` = nothing at `--fail-on` level, `1` = found.

**What `--fix` does** (never edits code, never deletes, never rewrites history): appends `.env`, keys and dumps to `.gitignore`; creates `.env.example` with names only; writes review files to `.security/`: `untrack-sensitive-files.sh`, `draft-enable-rls.sql` (enabling RLS without policies blocks all access, so review first), `security.txt`, `security-headers.txt`. Safe to re-run. Any key found in history must still be revoked and rotated at the provider.

**Suppress a reviewed false positive:** add `// vibe-scan: ignore` on the line, or `vibe-scan: ignore-file` at the top of a file. Record why in the report.

**Deep mode:** uses only installed tools and reports missing ones. Semgrep defaults to `p/default` from the registry; on restricted networks use local rules: `SEMGREP_CONFIG=./rules python3 scripts/scan.py . --deep`.

---

## 5. Authorization tests `authz_test.py`

Proves each user reaches only their own data, normal users cannot reach admin routes, and protected routes reject anonymous users (IDOR and broken access control, which pattern scanners cannot see).

Safety: local targets only (`localhost`, `127.0.0.1`, `.test`, `.local`) unless `--allow-remote` for a system you own or are authorized to test; `DELETE` checks need `--allow-destructive`; tokens come from environment variables.

```bash
python3 scripts/authz_test.py authz.json [--json results.json] [--allow-remote] [--allow-destructive]
```

```json
{
  "base_url": "http://localhost:3000",
  "users": {
    "alice": {"headers": {"Authorization": "Bearer ${ALICE_TOKEN}"}},
    "bob":   {"headers": {"Authorization": "Bearer ${BOB_TOKEN}"}},
    "admin": {"headers": {"Cookie": "session=${ADMIN_SESSION}"}}
  },
  "checks": [
    {"name": "Alice's order 101", "method": "GET", "path": "/api/orders/101", "owner": "alice", "deny": ["anonymous", "bob"]},
    {"name": "Admin user list", "method": "GET", "path": "/api/admin/users", "owner": "admin", "deny": ["anonymous", "alice", "bob"]},
    {"name": "Bob edits Alice", "method": "PATCH", "path": "/api/users/1", "body": {"name": "x"}, "owner": "alice", "deny": ["bob"]}
  ]
}
```

| Field | Meaning |
|---|---|
| `base_url` | App URL (local or staging copy) |
| `users` | Users and how they authenticate (Authorization header or Cookie); `${NAME}` is replaced by the env var |
| `anonymous` | Built-in user with no credentials |
| `checks[].method` | `GET` (default), `POST`, `PATCH`, `PUT`, `DELETE` |
| `checks[].body` | Optional JSON body |
| `checks[].owner` | Data owner; must get access (proves the config is right) |
| `checks[].deny` | Users that must be refused |
| `deny_status` | Optional accepted denial codes (default `[401, 403, 404]`) |

Build the list from every route with an ID (`/orders/:id`, `/users/:id`) and every admin route.

```bash
ALICE_TOKEN=xxx BOB_TOKEN=yyy ADMIN_SESSION=zzz python3 scripts/authz_test.py authz.json --json authz.out.json
```
```powershell
$env:ALICE_TOKEN="xxx"; $env:BOB_TOKEN="yyy"; $env:ADMIN_SESSION="zzz"; python scripts/authz_test.py authz.json --json authz.out.json
```

| Status | Meaning | Action |
|---|---|---|
| `PASS` | Correctly refused | None |
| `FAIL`, `anonymous -> 200` | Protected route open without login (Z1, critical) | Check the session on the server |
| `FAIL`, normal user on admin route | Broken role check (Z2, critical) | Check the role on every admin route |
| `FAIL`, user on another user's data | IDOR (Z3, high) | Verify the record belongs to the current user |
| `CONFIG` | The owner could not access | Expired token or wrong path |
| `SKIP` | `DELETE` without `--allow-destructive` | Add the flag on a staging copy |

Exit code `1` if any check fails.

---

## 6. Client report `report.py`

Turns scan results into a branded report: score out of 100, grade, before/after, findings table, next steps. HTML always, PDF optional.

```bash
python3 scripts/report.py scan.json [options]
```

| Option | What it does | Default |
|---|---|---|
| `scan` | JSON from `scan.py --json` (current state) | required |
| `--baseline FILE` | Earlier scan for before/after | none |
| `--authz FILE` | `authz_test.py --json` results | none |
| `--manual FILE` | Manual review findings | none |
| `--project NAME` | Project or client name | `Web application` |
| `--brand NAME` | Your company name | `Security report` |
| `--logo FILE/URL` | Your logo | none |
| `--color HEX` | Brand color | `#2563eb` |
| `--lang ar\|en` | Language | `ar` |
| `--out FILE` | HTML file | `security-report.html` |
| `--pdf` | Also write a PDF (needs Chrome/Chromium/Edge) | off |

```bash
python3 scripts/report.py scan.json --project "Client site" --lang en
python3 scripts/report.py after.json --baseline before.json --authz authz.out.json \
  --project "Client store" --brand "Masari AI" --logo logo.png --color "#1d4ed8" --lang en --pdf
```

Scoring: starts at 100 and decays with weighted findings (critical 15, high 7, medium 3, low 1) so progress stays visible; **any critical finding caps the score at 59**; grades A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F. Examples: one high = 92, one critical = 59, none = 100.

Manual findings file:
```json
[{"control": "C19", "severity": "critical", "title": "Price sent from the browser is trusted", "where": "api/checkout.ts:42", "detail": "Compute the price on the server from the database"}]
```

---

## 7. Protection and alerts `guard.mjs` / `guard.py`

Inspects every request. On an attack (SQL injection, XSS, path traversal, command injection, SSRF, `.env`/`.git` probes, brute force) it blocks it and alerts with type, time, IP, approximate location, target path and suggested action.

**Node.js (Express)**
```bash
npm i nodemailer
cp vibe-security-hardening/scripts/guard.mjs ./security/guard.mjs
```
```js
import express from 'express';
import { guard, onLoginFailure, onAccessDenied, onHoneytoken } from './security/guard.mjs';
const app = express();
app.set('trust proxy', 1);       // real proxy hop count (Cloudflare = 1)
app.use(express.json());
app.use(guard());                // before all routes
// failed login:       await onLoginFailure(req, email);
// authorization deny: await onAccessDenied(req, `${req.method} ${req.path}`);
// honeytoken used:    await onHoneytoken(req, 'decoy admin');
```

**Python (Flask)**
```python
import os
from flask import Flask, request, abort
from security.guard import inspect
app = Flask(__name__)

@app.before_request
def _guard():
    ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    attack, _ = inspect(ip, dict(request.headers), request.method, request.path,
                        request.query_string.decode(), request.get_data(as_text=True)[:5000])
    if attack and os.environ.get("GUARD_MODE", "block") != "monitor":
        abort(404 if attack.startswith("Probe") else 400)
```

| Variable | Channel / setting | Example |
|---|---|---|
| `ALERT_TO` / `ALERT_FROM` | Recipient / sender email | `security@your.com` |
| `ALERT_SMTP_URL` | SMTP (Node) | `smtps://user:pass@smtp.host:465` |
| `ALERT_SMTP_HOST` / `PORT` / `USER` / `PASS` | SMTP (Python) | `smtp.host` / `587` |
| `ALERT_WEBHOOK_URL` | Slack, Discord, Teams, n8n, any JSON webhook | `https://hooks.slack.com/...` |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Telegram | from BotFather + chat id |
| `ALERT_LOG_FILE` | JSONL log for the dashboard | `/var/log/app/alerts.jsonl` |
| `GUARD_MODE` | `block` (default) or `monitor` (alert only) | `monitor` |

WhatsApp: point `ALERT_WEBHOOK_URL` to an n8n/Zapier flow that sends through WhatsApp Business. Start with `GUARD_MODE=monitor` for a few days, then `block`. One alert per IP per attack type per 10 minutes; every attempt is logged. Enable Cloudflare "Add visitor location headers" to get city and country.

Test it:
```bash
curl "http://localhost:3000/search?q=%27%20OR%201=1%20--"   # SQLi: 400 + alert
curl "http://localhost:3000/.env"                          # probe: 404 + alert
curl "http://localhost:3000/search?q=shoes"                # normal: passes
```

---

## 8. Alerts dashboard `alerts_dashboard.py`

Builds an HTML dashboard from `ALERT_LOG_FILE` (totals, types, countries, top IPs, targeted paths, attempts per day, latest 50 events), or prints/emails a daily digest.

```bash
python3 scripts/alerts_dashboard.py LOG [LOG ...] [options]
```

| Option | What it does | Default |
|---|---|---|
| `logs` | One or more JSONL logs (or logs with `[SECURITY]` lines) | required |
| `--out FILE` | Dashboard file | `security-dashboard.html` |
| `--days N` | Days to include | `30` |
| `--brand NAME` | Company name | `Security` |
| `--lang ar\|en` | Language | `ar` |
| `--digest` | Print the last-24-hours summary instead | |
| `--send` | With `--digest`: email it (`ALERT_SMTP_*`, `ALERT_TO`) | |

```bash
python3 scripts/alerts_dashboard.py alerts.jsonl --out dashboard.html --brand "Masari AI" --lang en
python3 scripts/alerts_dashboard.py alerts.jsonl --digest --send
# cron, daily at 08:00:
0 8 * * * cd /srv/app && python3 security/alerts_dashboard.py /var/log/app/alerts.jsonl --digest --send
```

---

## 9. Continuous scanning in GitHub Actions

```bash
mkdir -p .github/workflows .security
cp vibe-security-hardening/templates/security-scan.yml .github/workflows/security-scan.yml
cp vibe-security-hardening/scripts/scan.py .security/scan.py
git add .github .security && git commit -m "Add security scan" && git push
```
Optional: **Settings > Secrets and variables > Actions > Variables** → `SITE_URL` = `https://your-site.com` to scan the live site too. Runs on every push, pull request and weekly; fails on high/critical findings; JSON report kept 30 days in the run's artifacts. Change `--fail-on high` to tune strictness.

---

## 10. Maintenance: tests and build

```bash
python3 tests/run_tests.py                      # 33 tests + benchmark
python3 tests/run_tests.py --json benchmark.json
pip install pynacl argon2-cffi cryptography     # optional: encryption reference tests
npm i --no-save express nodemailer              # optional: Node guard test
python3 tools/build.py                          # builds ALL-IN-ONE.md and dist/vibe-security-hardening.zip
```

---

## 11. End-to-end scenarios

**A) Secure my project before launch**
```bash
python3 scripts/scan.py ./my-app --json before.json
python3 scripts/scan.py ./my-app --fix
# fix the rest (or ask the model)
python3 scripts/scan.py ./my-app --json after.json     # repeat until no critical/high
```
Revoke and rotate any key that appears in the results.

**B) Security service for a client with a report**
```bash
python3 scripts/scan.py ./client-app --url https://client.com --json before.json
python3 scripts/authz_test.py authz.json --json authz-before.json
# ... fixes ...
python3 scripts/scan.py ./client-app --url https://client.com --json after.json
python3 scripts/authz_test.py authz.json --json authz-after.json
python3 scripts/report.py after.json --baseline before.json --authz authz-after.json \
  --project "Client" --brand "Masari AI" --logo logo.png --lang en --pdf
```

**C) Monitoring after launch:** install the guard (section 7), set `ALERT_TO` plus a second channel and `ALERT_LOG_FILE`, start in `monitor` mode and test with the `curl` commands, switch to `block`, schedule the daily digest (section 8), review the dashboard weekly.

**D) Continuous scanning:** follow section 9; any pull request that introduces a high/critical issue shows a red check before merge.

---

## 12. Troubleshooting

| Problem | Cause and fix |
|---|---|
| `python3: command not found` | On Windows use `python`; install Python 3.8+ |
| Git history scan skipped | Not a git repo, or git not installed |
| `npm audit failed` | No `package-lock.json` or no network; or use `--no-deps` |
| `pip-audit not installed` | `pip install pip-audit` (optional) |
| `semgrep returned no results for config 'p/default'` | Registry blocked; set `SEMGREP_CONFIG` to local rules |
| False positive | Review, add `// vibe-scan: ignore`, record the reason |
| `refusing non-local target` | Safety guard; test a local copy or add `--allow-remote` for a system you own |
| `CONFIG` in authz results | Owner token expired or wrong path |
| No PDF | No Chrome/Chromium/Edge; open the HTML and print to PDF |
| Location `unknown` in alerts | Enable Cloudflare visitor location headers or a GeoIP database |
| Too many alerts | Already throttled per IP/type per 10 min; block repeat IPs at the WAF |
| Guard blocks a normal request | Run `GUARD_MODE=monitor`, review the log, and report the example |

> Only for systems you own or are authorized to test. A hardening toolset, not a guarantee or a substitute for a professional penetration test.
