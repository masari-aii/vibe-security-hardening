#!/usr/bin/env python3
"""vibe-security-hardening: intrusion alerts dashboard + daily digest. Stdlib only.

Reads ALERT_LOG_FILE (JSON lines written by scripts/guard.mjs or scripts/guard.py) or any log
containing lines like "[SECURITY] {json}".

  python3 alerts_dashboard.py alerts.jsonl --out dashboard.html [--days 30] [--brand "Masari AI"] [--lang ar|en]
  python3 alerts_dashboard.py alerts.jsonl --digest            # print the last 24h summary
  python3 alerts_dashboard.py alerts.jsonl --digest --send     # email it (ALERT_SMTP_HOST/PORT/USER/PASS, ALERT_TO, ALERT_FROM)
"""
import argparse, collections, datetime as dt, html, json, os, re, smtplib, sys
from email.message import EmailMessage

LINE = re.compile(r"\[SECURITY\]\s*(\{.*\})\s*$")

def load(paths):
    events = []
    for p in paths:
        with open(p, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                m = LINE.search(line)
                raw = m.group(1) if m else (line if line.startswith("{") else None)
                if not raw:
                    continue
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                try:
                    e["_t"] = dt.datetime.fromisoformat(str(e.get("time", "")).replace("Z", "+00:00"))
                except ValueError:
                    continue
                events.append(e)
    events.sort(key=lambda e: e["_t"])
    return events

def country(loc):
    loc = str(loc or "")
    if loc.startswith("unknown"):
        return "??"
    return loc.split(",")[-1].strip() or "??"

def summarize(events):
    return {
        "total": len(events),
        "ips": len({e.get("ip") for e in events}),
        "by_type": collections.Counter(e.get("type", "?") for e in events).most_common(),
        "by_country": collections.Counter(country(e.get("location")) for e in events).most_common(10),
        "top_ips": collections.Counter((e.get("ip"), country(e.get("location"))) for e in events).most_common(10),
        "by_day": sorted(collections.Counter(e["_t"].date().isoformat() for e in events).items()),
        "paths": collections.Counter(e.get("path", "")[:60] for e in events).most_common(8),
    }

T = {
    "en": dict(title="Security alerts dashboard", total="Attack attempts", ips="Unique IPs", types="Attack types", period="Period",
               by_type="By attack type", by_country="By country", top_ips="Top attacking IPs", timeline="Attempts per day",
               paths="Most targeted paths", latest="Latest events", time="Time (UTC)", type="Type", ip="IP", loc="Location",
               path="Path", none="No events in this period.", note="Locations are approximate (IP-based; VPNs and proxies hide the real origin).",
               digest="Security digest (last 24 hours)"),
    "ar": dict(title="لوحة تنبيهات الاختراق", total="محاولات الهجوم", ips="عناوين IP مختلفة", types="أنواع الهجمات", period="الفترة",
               by_type="حسب نوع الهجوم", by_country="حسب الدولة", top_ips="أكثر العناوين هجومًا", timeline="المحاولات يوميًا",
               paths="أكثر الصفحات استهدافًا", latest="آخر الأحداث", time="الوقت (UTC)", type="النوع", ip="IP", loc="الموقع",
               path="الصفحة", none="لا توجد أحداث في هذه الفترة.", note="الموقع الجغرافي تقريبي (حسب IP، وقد يخفيه VPN أو بروكسي).",
               digest="ملخص الأمان (آخر 24 ساعة)"),
}

AR_TYPES = {
    "SQL injection": "حقن SQL", "XSS": "حقن سكربت (XSS)", "Probe for sensitive file": "محاولة الوصول لملف حساس",
    "Path traversal": "تجاوز المسارات", "Brute-force login": "تخمين كلمات المرور", "Command injection": "حقن أوامر",
    "Unauthorized access attempt (IDOR/admin)": "وصول غير مصرّح (IDOR/أدمن)", "SSRF": "طلب من الخادم (SSRF)",
    "Template injection": "حقن القوالب", "Honeytoken used (credential leak)": "استخدام بيانات فخ (تسريب)",
}

def tname(t, lang):
    return AR_TYPES.get(t, t) if lang == "ar" else t

def bars(items, color="#2563eb"):
    if not items:
        return ""
    mx = max(v for _, v in items) or 1
    rows = "".join(
        f'<div class="bar"><span class="lbl" dir="auto" title="{html.escape(str(k))}">{html.escape(str(k))}</span>'
        f'<span class="track"><span class="fill" style="width:{v / mx * 100:.1f}%;background:{color}"></span></span>'
        f'<span class="num">{v}</span></div>' for k, v in items)
    return f'<div class="bars">{rows}</div>'

def timeline_svg(by_day):
    """Bar per day with the count above each bar and the date under it (always LTR so dates read correctly)."""
    if not by_day:
        return ""
    n = len(by_day)
    pad_x, top, bottom = 16, 22, 34
    bw = max(min((900 - 2 * pad_x) / n, 70), 14)
    w = int(2 * pad_x + bw * n)
    h = 220
    mx = max(v for _, v in by_day) or 1
    step = 1 if n <= 16 else (2 if n <= 32 else 7)
    parts = []
    for i, (d, v) in enumerate(by_day):
        bh = (v / mx) * (h - top - bottom)
        x = pad_x + i * bw
        y = h - bottom - bh
        parts.append(f'<rect x="{x + 3:.1f}" y="{y:.1f}" width="{bw - 6:.1f}" height="{bh:.1f}" rx="4" fill="#dc2626"><title>{d}: {v}</title></rect>')
        parts.append(f'<text x="{x + bw / 2:.1f}" y="{y - 6:.1f}" font-size="12" text-anchor="middle" fill="currentColor">{v}</text>')
        if i % step == 0:
            parts.append(f'<text x="{x + bw / 2:.1f}" y="{h - 12}" font-size="11" text-anchor="middle" fill="#64748b">{d[5:]}</text>')
    axis = f'<line x1="{pad_x}" y1="{h - bottom}" x2="{w - pad_x}" y2="{h - bottom}" stroke="#cbd5e1"/>'
    return f'<div dir="ltr" style="overflow-x:auto"><svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" style="max-width:100%;height:auto" role="img">{axis}{"".join(parts)}</svg></div>'

def render(events, lang, brand, days):
    t = T[lang]
    s = summarize(events)
    rtl = lang == "ar"
    period = f"{events[0]['_t'].date()} → {events[-1]['_t'].date()}" if events else "-"
    rows = "".join(
        f"<tr><td>{e['_t'].strftime('%Y-%m-%d %H:%M')}</td><td>{html.escape(tname(str(e.get('type')), lang))}</td>"
        f"<td dir='ltr'>{html.escape(str(e.get('ip')))}</td><td>{html.escape(str(e.get('location')))}</td>"
        f"<td dir='ltr'><code>{html.escape(str(e.get('path', ''))[:70])}</code></td></tr>"
        for e in reversed(events[-50:]))
    body = f"""
<header><div><div class="brand">{html.escape(brand)}</div><h1>{t['title']}</h1><div class="muted">{t['period']}: {period}</div></div></header>
<section class="kpis">
  <div class="kpi"><div class="v">{s['total']}</div><div class="k">{t['total']}</div></div>
  <div class="kpi"><div class="v">{s['ips']}</div><div class="k">{t['ips']}</div></div>
  <div class="kpi"><div class="v">{len(s['by_type'])}</div><div class="k">{t['types']}</div></div>
</section>
{"<p class='muted'>" + t['none'] + "</p>" if not events else ""}
<section class="grid">
  <div class="card"><h2>{t['by_type']}</h2>{bars([(tname(k, lang), v) for k, v in s['by_type']], '#dc2626')}</div>
  <div class="card"><h2>{t['by_country']}</h2>{bars(s['by_country'], '#7c3aed')}</div>
  <div class="card"><h2>{t['top_ips']}</h2>{bars([(f"{ip} ({c})", n) for (ip, c), n in s['top_ips']], '#ea580c')}</div>
  <div class="card"><h2>{t['paths']}</h2>{bars(s['paths'], '#0891b2')}</div>
</section>
<section class="card"><h2>{t['timeline']}</h2>{timeline_svg(s['by_day'])}</section>
<section class="card"><h2>{t['latest']}</h2><div class="tbl"><table><thead><tr><th>{t['time']}</th><th>{t['type']}</th><th>{t['ip']}</th><th>{t['loc']}</th><th>{t['path']}</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<p class="muted small">{t['note']}</p>"""
    return f"""<!DOCTYPE html><html lang="{lang}" dir="{'rtl' if rtl else 'ltr'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{t['title']} · {html.escape(brand)}</title>
<style>
:root{{--bg:#f8fafc;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0b1220;--card:#111a2e;--ink:#e2e8f0;--muted:#94a3b8;--line:#1e293b}}}}
*{{box-sizing:border-box}}body{{margin:0;padding:24px;font-family:system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;background:var(--bg);color:var(--ink)}}
header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}}h1{{margin:4px 0;font-size:24px}}h2{{font-size:15px;margin:0 0 12px}}
.brand{{font-weight:700;color:#2563eb}}.muted{{color:var(--muted)}}.small{{font-size:12px}}
.kpis{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:12px}}.kpi,.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}}
.kpi .v{{font-size:28px;font-weight:800}}.kpi .k{{color:var(--muted);font-size:13px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin-bottom:12px}}.card{{margin-bottom:12px}}
.bar{{display:grid;grid-template-columns:minmax(90px,38%) 1fr 40px;gap:8px;align-items:center;font-size:13px;margin:6px 0}}
.lbl{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.track{{background:var(--line);border-radius:6px;height:10px;overflow:hidden}}.fill{{display:block;height:100%;border-radius:6px}}.num{{text-align:end;font-variant-numeric:tabular-nums}}
.tbl{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:8px;border-bottom:1px solid var(--line);text-align:start;white-space:nowrap}}code{{font-size:12px}}
</style></head><body>{body}</body></html>"""

def digest(events, lang):
    t = T[lang]
    now = max((e["_t"] for e in events), default=dt.datetime.now(dt.timezone.utc))
    recent = [e for e in events if e["_t"] >= now - dt.timedelta(hours=24)]
    s = summarize(recent)
    lines = [t["digest"], f"{t['total']}: {s['total']} | {t['ips']}: {s['ips']}", "", t["by_type"] + ":"]
    lines += [f"  - {tname(k, lang)}: {v}" for k, v in s["by_type"]]
    lines += ["", t["top_ips"] + ":"] + [f"  - {ip} ({c}): {n}" for (ip, c), n in s["top_ips"][:5]]
    lines += ["", t["note"]]
    return "\n".join(lines), s["total"]

def main():
    ap = argparse.ArgumentParser(description="Intrusion alerts dashboard (HTML) and daily digest from ALERT_LOG_FILE (JSON lines).",
                                 epilog="examples:\n  alerts_dashboard.py alerts.jsonl --out dashboard.html --brand \"Masari AI\"\n  alerts_dashboard.py alerts.jsonl --digest --send",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", help="one or more JSONL log files (or logs containing [SECURITY] lines)")
    ap.add_argument("--out", default="security-dashboard.html", help="output HTML file")
    ap.add_argument("--days", type=int, default=30, help="how many days back to include (default: 30)")
    ap.add_argument("--brand", default="Security", help="your company name shown at the top")
    ap.add_argument("--lang", choices=["ar", "en"], default="ar", help="dashboard language (default: ar)")
    ap.add_argument("--digest", action="store_true", help="print the last-24-hours summary instead of building the dashboard")
    ap.add_argument("--send", action="store_true", help="with --digest: email it (ALERT_SMTP_HOST/PORT/USER/PASS, ALERT_TO, ALERT_FROM)")
    a = ap.parse_args()
    events = load(a.logs)
    if events:
        cutoff = events[-1]["_t"] - dt.timedelta(days=a.days)
        events = [e for e in events if e["_t"] >= cutoff]
    if a.digest:
        text, n = digest(events, a.lang)
        print(text)
        if a.send and n:
            msg = EmailMessage()
            msg["Subject"] = f"[{a.brand}] {T[a.lang]['digest']}: {n}"
            msg["From"] = os.environ.get("ALERT_FROM", "security@localhost")
            msg["To"] = os.environ["ALERT_TO"]
            msg.set_content(text)
            with smtplib.SMTP(os.environ["ALERT_SMTP_HOST"], int(os.environ.get("ALERT_SMTP_PORT", "587")), timeout=15) as smtp:
                smtp.starttls()
                smtp.login(os.environ["ALERT_SMTP_USER"], os.environ["ALERT_SMTP_PASS"])
                smtp.send_message(msg)
            print("digest emailed to", os.environ["ALERT_TO"])
        return
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(render(events, a.lang, a.brand, a.days))
    print(f"dashboard written: {a.out} ({len(events)} events)")

if __name__ == "__main__":
    main()
