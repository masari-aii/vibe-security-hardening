# vibe-security-hardening: intrusion detection + alerts core (framework-agnostic). Wire into Flask/FastAPI/Django middleware.
# Channels: email (ALERT_SMTP_HOST/PORT/USER/PASS, ALERT_TO), webhook (ALERT_WEBHOOK_URL), Telegram (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID),
# JSONL log for the dashboard (ALERT_LOG_FILE).
import os, re, json, time, smtplib, logging, urllib.request
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
    if os.environ.get("ALERT_LOG_FILE"):
        try:
            with open(os.environ["ALERT_LOG_FILE"], "a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        except OSError as e:
            log.error("alert log write failed: %s", e)
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
    _notify_channels(msg["Subject"], msg.get_content(), {k: v for k, v in ev.items() if not k.startswith("_")})
    return ev

def _post(url, payload):
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=8) as r:
            return 200 <= r.status < 300
    except Exception as e:
        log.error("alert channel failed: %s", e)
        return False

def _notify_channels(title, text, event):
    if os.environ.get("ALERT_WEBHOOK_URL"):
        _post(os.environ["ALERT_WEBHOOK_URL"], {"text": f"{title}\n{text}", "content": f"{title}\n{text}"[:1900], "event": event})
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if tok and chat:
        _post(f"https://api.telegram.org/bot{tok}/sendMessage", {"chat_id": chat, "text": f"{title}\n{text}"[:4000]})

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
