# Automated scanner and CI

`scripts/scan.py` gives repeatable, evidence-based findings in seconds. Run it first in AUDIT and again in VERIFY. Python 3.8+, standard library only; uses `git`, `npm`, `pip-audit`, `composer` when present.

```bash
python3 scripts/scan.py /path/to/project                          # code, git history, dependencies
python3 scripts/scan.py . --url https://your-site.com             # + live headers, cookies, CORS, HTTPS, exposed paths
python3 scripts/scan.py . --json report.json --fail-on high       # CI: exit 1 on high or critical
python3 scripts/scan.py . --no-history --no-deps                  # fast local pass
```

What it checks (each finding names the control):
- Secrets in files and in all git history (AWS, Stripe live, OpenAI, Anthropic, GitHub, Google, Slack, SendGrid, Twilio, private keys, Supabase service_role JWTs, DB URLs with passwords, hardcoded secret assignments). Values are masked to the last 4 characters.
- Tracked sensitive files (`.env`, keys, dumps, backups, credentials JSON) and `.env` missing from `.gitignore`.
- Secret-looking variables behind public prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, ...).
- Dangerous code: raw HTML sinks, SQL built with interpolation, eval/shell, MD5/SHA-1 passwords, JWT `none`/disabled verification, TLS verification off, CORS `*`, debug on, `Math.random()` tokens, open Firebase rules, insecure cookies, user input in LLM system prompts.
- Supabase/SQL migrations creating tables without `ENABLE ROW LEVEL SECURITY`.
- Dependencies: `npm audit`, `pip-audit`, `composer audit`.
- Live site (only your own): HTTPS redirect, HSTS, CSP and other headers, cookie flags, CORS reflection, version leaks, exposed `/.env`, `/.git/config`, backups, API docs / GraphQL introspection, `security.txt`.

Rules for using results:
- A scanner finding is evidence to confirm, not an automatic verdict: open the file, confirm, then fix. Regex checks miss logic flaws (IDOR, business logic, broken authorization), so the manual 27-control review still runs.
- Any secret found in history is compromised: revoke and rotate (C25) even after deleting it.
- Only scan URLs you own or are authorized to test.

CI: copy `templates/security-scan.yml` to `.github/workflows/security-scan.yml` and `scripts/scan.py` to `.security/scan.py` in the project (a pinned, reviewed copy; do not download it at build time). It runs on every push, pull request and weekly, fails the build on high/critical findings, uploads the JSON report, and scans the live site if the repository variable `SITE_URL` is set.
