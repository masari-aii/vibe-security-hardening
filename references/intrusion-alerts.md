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
