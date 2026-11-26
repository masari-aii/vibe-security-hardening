// vibe-security-hardening: intrusion detection + alerts (Express). npm i nodemailer
// Channels: email (ALERT_SMTP_URL/ALERT_TO), webhook (ALERT_WEBHOOK_URL: Slack/Discord/Teams/n8n/any JSON endpoint),
// Telegram (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID), JSONL log for the dashboard (ALERT_LOG_FILE).
import nodemailer from 'nodemailer';
import fs from 'node:fs';

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
  if (process.env.ALERT_LOG_FILE) {
    try { fs.appendFileSync(process.env.ALERT_LOG_FILE, JSON.stringify(event) + '\n'); } catch (e) { console.error('alert log write failed', e.message); }
  }
  if (now - (lastSent.get(key) || 0) < THROTTLE_MS) return event;
  lastSent.set(key, now);
  const text = Object.entries(event).map(([k, v]) => `${k}: ${v}`).join('\n');
  await notifyChannels(event, text);
  const info = await transport.sendMail({ // counted

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
async function post(url, body) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: ctrl.signal });
    return r.ok;
  } catch (e) { console.error('alert channel failed', e.message); return false; } finally { clearTimeout(t); }
}
async function notifyChannels(event, text) {
  const title = `[Security alert] ${event.type} from ${event.ip} (${event.location})`;
  const jobs = [];
  if (process.env.ALERT_WEBHOOK_URL) jobs.push(post(process.env.ALERT_WEBHOOK_URL, { text: `${title}\n${text}`, content: `${title}\n${text}`.slice(0, 1900), event }));
  if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
    jobs.push(post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, { chat_id: process.env.TELEGRAM_CHAT_ID, text: `${title}\n${text}`.slice(0, 4000) }));
  }
  await Promise.allSettled(jobs);
}

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
