# Module D — Intrusion detection and email alerts

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

Ready-to-use code (tested): `scripts/guard.mjs` (Node.js + Express) and `scripts/guard.py` (framework-agnostic core for Flask/FastAPI/Django). Copy the file into the project; do not rewrite it from memory.

Alert channels (any combination, all optional except one):

| Env var | Channel |
|---|---|
| `ALERT_TO`, `ALERT_FROM` + `ALERT_SMTP_URL` (Node, e.g. `smtps://user:pass@smtp.host:465`) or `ALERT_SMTP_HOST/PORT/USER/PASS` (Python) | Email |
| `ALERT_WEBHOOK_URL` | Slack, Discord, Microsoft Teams, n8n, Zapier or any endpoint that accepts JSON (`text`, `content`, `event` fields are sent) |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Telegram bot message |
| `ALERT_LOG_FILE` | JSON lines file for the dashboard and audits |
| `GUARD_MODE=monitor` or `block` | Monitor = log and alert only; block = also reject the request (default) |

WhatsApp: route through `ALERT_WEBHOOK_URL` to an n8n/Zapier flow or the WhatsApp Business API provider you already use.

Wiring, Node.js:

```js
import { guard, onLoginFailure, onAccessDenied, onHoneytoken } from './security/guard.mjs';
app.set('trust proxy', 1);          // real hop count behind your proxy/CDN
app.use(express.json());
app.use(guard());
// on failed login:        await onLoginFailure(req, email);
// on authorization deny:  await onAccessDenied(req, `${req.method} ${req.path}`);
// on honeytoken use:      await onHoneytoken(req, 'decoy admin account');
```

Wiring, Flask:

```python
from security.guard import inspect
@app.before_request
def _guard():
    ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    t, _ = inspect(ip, dict(request.headers), request.method, request.path,
                   request.query_string.decode(), request.get_data(as_text=True)[:5000])
    if t and os.environ.get("GUARD_MODE", "block") != "monitor":
        abort(404 if t.startswith("Probe") else 400)
```

Dashboard and daily digest (`scripts/alerts_dashboard.py`, stdlib only):

```bash
python3 scripts/alerts_dashboard.py alerts.jsonl --out dashboard.html --brand "Your Co" --lang ar   # charts: types, countries, top IPs, per day, latest 50
python3 scripts/alerts_dashboard.py alerts.jsonl --digest --send                                  # email the last 24 h summary (run daily via cron)
```

Detection tests: normal search, an apostrophe name (O'Reilly) and text with `--` pass; `' OR 1=1 --`, `<script>`, `../../etc/passwd` and `/.env` are blocked and produce one alert with type, IP and location; a second identical attack within 10 minutes is logged but not re-sent; 5 failed logins produce a brute-force alert; the webhook endpoint receives the JSON payload. These are covered by `tests/run_tests.py`.
