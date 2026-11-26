#!/usr/bin/env python3
"""vibe-security-hardening: client-ready security report (HTML, optional PDF). Stdlib only.

  python3 report.py scan.json --project "Client site" --out report.html
  python3 report.py after.json --baseline before.json --authz authz.json --lang ar --brand "Masari AI" --logo logo.png --pdf

Inputs: JSON from scan.py (--json), optional authz_test.py JSON, optional manual findings JSON
(list of {control, severity, title, where, detail}). PDF uses headless Chrome/Chromium if installed,
otherwise open the HTML and print to PDF (print styles included).
"""
import argparse, base64, datetime as dt, html, json, math, mimetypes, os, shutil, subprocess, sys

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
WEIGHT = {"critical": 15, "high": 7, "medium": 3, "low": 1, "info": 0}
COLORS = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#64748b"}

L = {
  "en": dict(title="Security Assessment Report", severity="Severity", project="Project", date="Date", score="Security score", grade="Grade",
    exec="Executive summary", sev={"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
    findings="Findings", control="Control", area="Area", issue="Issue", where="Location", detail="Detail / action",
    compare="Before vs after", resolved="Resolved", new="New", remaining="Still open", prev="Previous score",
    next="Recommended next steps", method="Scope and method", none="No issues found by the automated checks.",
    disclaimer="Automated and guided checks; not a guarantee of security and not a substitute for a professional penetration test. Re-run after every significant change.",
    method_text="Automated scan of source code, git history, dependencies, infrastructure configuration{url}, plus authorization tests where provided. Findings are mapped to the vibe-security-hardening controls.",
    s_good="The application is in good shape: no critical or high-severity issues were found.",
    s_bad="{c} critical and {h} high-severity issues need attention before launch.",
    steps=["Fix all critical and high findings first (secrets: revoke and rotate keys immediately).",
           "Re-run the scanner and authorization tests to confirm each fix.",
           "Enable the CI workflow so every push is scanned automatically.",
           "Turn on intrusion alerts (Module D) and review the dashboard weekly."]),
  "ar": dict(title="تقرير التقييم الأمني", severity="الخطورة", project="المشروع", date="التاريخ", score="درجة الأمان", grade="التقدير",
    exec="الملخص التنفيذي", sev={"critical": "حرج", "high": "عالٍ", "medium": "متوسط", "low": "منخفض", "info": "معلومة"},
    findings="النتائج", control="البند", area="المجال", issue="المشكلة", where="الموقع", detail="التفاصيل / الإجراء",
    compare="قبل وبعد الإصلاح", resolved="تم حلها", new="جديدة", remaining="ما زالت مفتوحة", prev="الدرجة السابقة",
    next="الخطوات الموصى بها", method="النطاق والمنهجية", none="لم تكتشف الفحوص الآلية أي مشاكل.",
    disclaimer="فحوص آلية وموجّهة؛ ليست ضمانًا للأمان ولا بديلًا عن اختبار اختراق احترافي. أعد الفحص بعد كل تغيير مهم.",
    method_text="فحص آلي للكود المصدري وتاريخ Git والمكتبات وإعدادات البنية التحتية{url}، مع اختبارات الصلاحيات عند توفرها. كل نتيجة مربوطة ببنود مهارة vibe-security-hardening.",
    s_good="وضع التطبيق جيد: لا توجد مشاكل حرجة أو عالية الخطورة.",
    s_bad="يوجد {c} مشكلة حرجة و{h} مشكلة عالية الخطورة تحتاج معالجة قبل الإطلاق.",
    steps=["عالج المشاكل الحرجة والعالية أولًا (المفاتيح المسرّبة: ألغها وبدّلها فورًا).",
           "أعد تشغيل الفاحص واختبارات الصلاحيات للتأكد من كل إصلاح.",
           "فعّل ملف GitHub Actions ليُفحص كل رفع تلقائيًا.",
           "فعّل تنبيهات الاختراق (الوحدة D) وراجع اللوحة أسبوعيًا."]),
}
AREAS = {
  "en": {"C": "Core controls", "E": "Encryption", "P": "Protection", "D": "Intrusion alerts", "A": "AI security", "K": "PDPL",
         "I": "Infrastructure", "S": "Static analysis", "Z": "Authorization tests", "N": "NCA ECC"},
  "ar": {"C": "البنود الأساسية", "E": "التشفير", "P": "الحماية", "D": "تنبيهات الاختراق", "A": "أمان الذكاء الاصطناعي", "K": "حماية البيانات الشخصية",
         "I": "البنية التحتية", "S": "التحليل الثابت", "Z": "اختبارات الصلاحيات", "N": "ضوابط NCA"},
}

def load(p):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)

def findings_of(doc):
    if isinstance(doc, list):
        return doc
    return doc.get("findings", [])

def key(f):
    return (f.get("control"), f.get("title"), f.get("where"))

def score(fs):
    """100 = nothing found. Decays with weighted findings so progress stays visible; any critical caps at 59."""
    pts = sum(WEIGHT.get(f.get("severity", "info"), 0) for f in fs)
    s = round(100 * math.exp(-pts / 80))
    return min(s, 59) if any(f.get("severity") == "critical" for f in fs) else s

def grade(s):
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"

def gauge(s):
    color = "#16a34a" if s >= 75 else "#ca8a04" if s >= 50 else "#b91c1c"
    r, c = 52, 2 * 3.14159 * 52
    return (f'<svg viewBox="0 0 120 120" width="150" height="150" role="img" aria-label="{s}/100">'
            f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="#e2e8f0" stroke-width="12"/>'
            f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{c * s / 100:.1f} {c:.1f}" transform="rotate(-90 60 60)"/>'
            f'<text x="60" y="58" text-anchor="middle" font-size="30" font-weight="800" fill="currentColor">{s}</text>'
            f'<text x="60" y="80" text-anchor="middle" font-size="12" fill="#64748b">/ 100</text></svg>')

def logo_tag(path):
    if not path:
        return ""
    if path.startswith(("http://", "https://", "data:")):
        src = path
    else:
        mt = mimetypes.guess_type(path)[0] or "image/png"
        with open(path, "rb") as fh:
            src = f"data:{mt};base64,{base64.b64encode(fh.read()).decode()}"
    return f'<img class="logo" src="{html.escape(src)}" alt="">'

def render(a, fs, base_fs, url):
    t, areas = L[a.lang], AREAS[a.lang]
    fs = [f for f in fs if f.get("severity") != "info"]
    s = score(fs)
    counts = {k: sum(1 for f in fs if f.get("severity") == k) for k in SEV_ORDER}
    summary = t["s_good"] if counts["critical"] + counts["high"] == 0 else t["s_bad"].format(c=counts["critical"], h=counts["high"])
    chips = "".join(f'<div class="chip" style="--c:{COLORS[k]}"><b>{counts[k]}</b><span>{t["sev"][k]}</span></div>'
                    for k in SEV_ORDER[:4])
    compare = ""
    if base_fs is not None:
        base_fs = [f for f in base_fs if f.get("severity") != "info"]
        bk, nk = {key(f) for f in base_fs}, {key(f) for f in fs}
        resolved, new, remaining = len(bk - nk), len(nk - bk), len(bk & nk)
        compare = (f'<section class="card"><h2>{t["compare"]}</h2><div class="cmp">'
                   f'<div><b>{score(base_fs)}</b><span>{t["prev"]}</span></div><div class="arrow">→</div>'
                   f'<div><b>{s}</b><span>{t["score"]}</span></div>'
                   f'<div class="ok"><b>{resolved}</b><span>{t["resolved"]}</span></div>'
                   f'<div class="bad"><b>{new}</b><span>{t["new"]}</span></div>'
                   f'<div><b>{remaining}</b><span>{t["remaining"]}</span></div></div></section>')
    rows = []
    for sev in SEV_ORDER[:4]:
        for f in [x for x in fs if x.get("severity") == sev]:
            ctrl = str(f.get("control", ""))
            rows.append(f'<tr><td><span class="sev" style="--c:{COLORS[sev]}">{t["sev"][sev]}</span></td>'
                        f'<td dir="ltr">{html.escape(ctrl)}</td><td>{areas.get(ctrl[:1], "-")}</td>'
                        f'<td dir="auto">{html.escape(str(f.get("title", "")))}</td>'
                        f'<td dir="ltr"><code>{html.escape(str(f.get("where", ""))[:90])}</code></td>'
                        f'<td dir="auto">{html.escape(str(f.get("detail", ""))[:160])}</td></tr>')
    table = (f'<table><thead><tr><th>{t["severity"]}</th><th>{t["control"]}</th><th>{t["area"]}</th>'
             f'<th>{t["issue"]}</th><th>{t["where"]}</th><th>{t["detail"]}</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'
             if rows else f'<p class="muted">{t["none"]}</p>')
    steps = "".join(f"<li>{html.escape(x)}</li>" for x in t["steps"])
    date = dt.date.today().isoformat()
    rtl = a.lang == "ar"
    return f"""<!DOCTYPE html><html lang="{a.lang}" dir="{'rtl' if rtl else 'ltr'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{t['title']} · {html.escape(a.project)}</title>
<style>
:root{{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--card:#fff;--bg:#f8fafc;--brand:{html.escape(a.color)}}}
*{{box-sizing:border-box}}body{{margin:0;padding:28px;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",Tahoma,"Noto Naskh Arabic",sans-serif;line-height:1.55}}
.wrap{{max-width:1080px;margin:auto}}header{{display:flex;justify-content:space-between;align-items:center;gap:16px;border-bottom:4px solid var(--brand);padding-bottom:16px;margin-bottom:20px}}
.logo{{height:56px}}.brand{{font-weight:800;color:var(--brand);font-size:18px}}h1{{margin:4px 0;font-size:26px}}h2{{font-size:17px;margin:0 0 12px}}
.meta{{color:var(--muted);font-size:14px}}.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px;break-inside:avoid}}
.hero{{display:grid;grid-template-columns:170px 1fr;gap:18px;align-items:center}}.grade{{font-size:14px;color:var(--muted)}}.grade b{{font-size:22px;color:var(--ink)}}
.chips{{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}}.chip{{border:1px solid var(--line);border-inline-start:5px solid var(--c);border-radius:10px;padding:8px 14px;min-width:96px}}
.chip b{{display:block;font-size:22px}}.chip span{{color:var(--muted);font-size:13px}}
.cmp{{display:flex;flex-wrap:wrap;gap:18px;align-items:center}}.cmp div{{text-align:center;min-width:80px}}.cmp b{{display:block;font-size:24px}}.cmp span{{font-size:12px;color:var(--muted)}}
.cmp .ok b{{color:#16a34a}}.cmp .bad b{{color:#b91c1c}}.arrow{{font-size:22px;color:var(--muted)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:8px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}}th{{background:#f1f5f9;font-size:12px}}
.sev{{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;background:var(--c);font-size:12px;white-space:nowrap}}code{{font-size:12px;word-break:break-all}}
.muted{{color:var(--muted)}}footer{{color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}}
.findings{{break-inside:auto}}tr{{break-inside:avoid}}
@media print{{body{{background:#fff;padding:0}}.card{{border-color:#cbd5e1}}@page{{size:A4;margin:14mm}}}}
@media (max-width:640px){{.hero{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">
<header><div><div class="brand">{html.escape(a.brand)}</div><h1>{t['title']}</h1>
<div class="meta">{t['project']}: <b>{html.escape(a.project)}</b> · {t['date']}: {date}{(' · <span dir="ltr">' + html.escape(url) + '</span>') if url else ''}</div></div>{logo_tag(a.logo)}</header>
<section class="card hero"><div>{gauge(s)}</div><div><h2>{t['exec']}</h2><p>{html.escape(summary)}</p>
<div class="grade">{t['grade']}: <b>{grade(s)}</b></div><div class="chips">{chips}</div></div></section>
{compare}
<section class="card findings"><h2>{t['findings']}</h2>{table}</section>
<section class="card"><h2>{t['next']}</h2><ol>{steps}</ol></section>
<section class="card"><h2>{t['method']}</h2><p>{html.escape(t['method_text'].format(url=(', live site ' if a.lang == 'en' else '، والموقع المباشر') if url else '')).replace('vibe-security-hardening', '<bdi dir="ltr">vibe-security-hardening</bdi>').replace('Git', '<bdi dir="ltr">Git</bdi>')}</p></section>
<footer>{html.escape(t['disclaimer'])} · vibe-security-hardening</footer>
</div></body></html>"""

def to_pdf(html_path, pdf_path):
    for b in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        exe = shutil.which(b)
        if exe:
            subprocess.run([exe, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
                            f"--print-to-pdf={os.path.abspath(pdf_path)}", "file://" + os.path.abspath(html_path)],
                           capture_output=True, timeout=120)
            return os.path.exists(pdf_path)
    return False

def main():
    ap = argparse.ArgumentParser(description="Client-ready security report (HTML, optional PDF) from scan.py JSON.",
                                 epilog="example:\n  report.py after.json --baseline before.json --authz authz.json.out --project \"Client\" --brand \"Masari AI\" --lang ar --pdf",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scan", help="scan.py JSON (current state)")
    ap.add_argument("--baseline", help="earlier scan JSON for before/after comparison")
    ap.add_argument("--authz", help="authz_test.py JSON to merge")
    ap.add_argument("--manual", help="manual findings JSON to merge")
    ap.add_argument("--project", default="Web application", help="project/client name shown in the report")
    ap.add_argument("--brand", default="Security report", help="your company name shown at the top")
    ap.add_argument("--logo", help="logo file or URL")
    ap.add_argument("--color", default="#2563eb", help="brand color, e.g. \"#1d4ed8\"")
    ap.add_argument("--lang", choices=["ar", "en"], default="ar", help="report language (default: ar, right-to-left)")
    ap.add_argument("--out", default="security-report.html", help="output HTML file (default: security-report.html)")
    ap.add_argument("--pdf", action="store_true", help="also write a PDF next to the HTML (needs Chrome/Chromium/Edge)")
    a = ap.parse_args()
    doc = load(a.scan)
    fs = list(findings_of(doc))
    for extra in (a.authz, a.manual):
        if extra:
            fs += findings_of(load(extra))
    base = list(findings_of(load(a.baseline))) if a.baseline else None
    url = doc.get("url") if isinstance(doc, dict) else None
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(render(a, fs, base, url))
    s = score([f for f in fs if f.get("severity") != "info"])
    print(f"report written: {a.out} (score {s}/100, grade {grade(s)})")
    if a.pdf:
        pdf = os.path.splitext(a.out)[0] + ".pdf"
        print("pdf written: " + pdf if to_pdf(a.out, pdf) else "no Chrome/Chromium found: open the HTML and print to PDF")

if __name__ == "__main__":
    main()
