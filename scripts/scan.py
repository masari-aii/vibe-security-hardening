#!/usr/bin/env python3
"""vibe-security-hardening scanner. Stdlib only, Python 3.8+.  vibe-scan: ignore-file

Usage:
  python3 scan.py [PATH] [--url https://your-site] [--json report.json] [--fail-on high] [--no-history]

Suppress a reviewed false positive: add "vibe-scan: ignore" on that line, or "vibe-scan: ignore-file" near the top of a file.

Scans YOUR OWN project: leaked secrets (files + git history), exposed/tracked sensitive files,
public env misuse, dangerous code patterns, missing RLS/rules, dependency audit, and (with --url)
live headers, cookies, CORS, HTTPS and exposed paths. Secret values are never printed (last 4 chars only).
"""
import argparse, json, os, re, shutil, subprocess, sys, ssl, urllib.request, urllib.error

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt", ".output", "out", "coverage",
             "venv", ".venv", "env", "__pycache__", ".turbo", ".vercel", ".svelte-kit", "target", "bin", "obj", ".idea"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3",
            ".woff", ".woff2", ".ttf", ".eot", ".lock", ".map", ".min.js", ".exe", ".dll", ".so", ".dylib", ".bin"}
MAX_FILE = 1_500_000

SECRETS = [
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", "critical"),
    ("Stripe live secret key", r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b", "critical"),
    ("OpenAI API key", r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b", "critical"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{32,}\b", "critical"),
    ("GitHub token", r"\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b", "critical"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", "high"),
    ("Slack token", r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b", "critical"),
    ("Private key", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical"),
    ("Supabase service_role JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*c2VydmljZV9yb2xl[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{10,}", "critical"),
    ("Database URL with password", r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^\s:@/]+:[^\s@/]{4,}@[^\s'\"]+", "critical"),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "critical"),
    ("Twilio key", r"\bSK[0-9a-fA-F]{32}\b", "high"),
    ("Hardcoded secret assignment",
     r"(?i)\b(secret|passwd|password|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']([^\"'\s$<>{}]{12,})[\"']", "high"),
]
SECRETS = [(n, re.compile(p), s) for n, p, s in SECRETS]
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[_-]|xxxx|<|\*\*\*|dummy|sample|test[_-]?key|process\.env|os\.environ|getenv)")

CODE = [
    ("C7", "Raw HTML sink (XSS risk)", r"dangerouslySetInnerHTML|\.innerHTML\s*=|v-html=|\|\s*safe\b|\{\{\{\s*\w+|html_safe|mark_safe\(|bypassSecurityTrust", "medium"),
    ("C10", "SQL built by string concatenation/interpolation",
     r"(?i)(query|execute|exec|raw|prepare)\s*\(\s*[`\"'][^`\"']*\b(select|insert|update|delete)\b[^`\"']*(\$\{|\"\s*\+|'\s*\+|%s'|\{\})|f[\"'][^\"']*\b(select|insert|update|delete)\b[^\"']*\{", "high"),
    ("C10", "Dynamic code execution", r"\beval\s*\(|new\s+Function\s*\(|child_process\.exec\s*\(\s*`|os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True", "high"),
    ("C5", "Weak hash used for passwords", r"(?i)(md5|sha1)\s*\(?[^\n]{0,40}pass|createHash\(\s*['\"](md5|sha1)['\"]\)[^\n]{0,60}pass", "high"),
    ("E6", "JWT verification disabled or 'none' alg", r"(?i)algorithms?\s*[:=]\s*\[?\s*['\"]none['\"]|verify_signature['\"]?\s*:\s*False|ignoreExpiration\s*:\s*true", "critical"),
    ("E2", "TLS verification disabled", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|verify\s*=\s*False\b|InsecureSkipVerify:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)", "high"),
    ("C13", "CORS allows any origin", r"(?i)origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|allow_origins\s*=\s*\[\s*['\"]\*['\"]|CORS_ALLOW_ALL_ORIGINS\s*=\s*True", "medium"),
    ("C20", "Debug enabled", r"(?i)^\s*DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|APP_DEBUG\s*=\s*true", "high"),
    ("E6", "Insecure randomness for secrets", r"Math\.random\(\)[^\n]{0,60}(token|secret|otp|code|password|key)|(token|secret|otp|password)[^\n]{0,40}Math\.random\(\)|random\.random\(\)[^\n]{0,40}(token|otp|secret)", "medium"),
    ("C3", "Firebase rules open to everyone", r"allow\s+(read|write|read,\s*write)\s*:\s*if\s+true|\"\.(read|write)\"\s*:\s*true", "critical"),
    ("C15", "Cookie without security flags", r"(?i)(httpOnly|http_only)\s*[:=]\s*false|secure\s*:\s*false|SESSION_COOKIE_SECURE\s*=\s*False", "medium"),
    ("A1", "User input concatenated into LLM system prompt",
     r"(?i)(role['\"]?\s*:\s*['\"]system['\"][^\n]{0,120}(\$\{|\+\s*req\.|\{req|request\.|body\.|input))|(system_prompt|systemPrompt)\s*[+=][^\n]{0,80}(req\.|request\.|body\.|user_input|userInput)", "high"),
]
CODE = [(c, n, re.compile(p, re.M), s) for c, n, p, s in CODE]
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py", ".php", ".rb", ".go", ".java",
            ".cs", ".kt", ".rules", ".json", ".html", ".erb", ".blade.php", ".twig", ".env", ".yml", ".yaml", ".ini", ".cfg", ".toml"}

PUBLIC_PREFIX = re.compile(r"\b(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)([A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|SK_|ADMIN|WEBHOOK)[A-Z0-9_]*)")
SENSITIVE_TRACKED = re.compile(r"(^|/)(\.env(\.(?!example$|sample$|template$)[^/]*)?|.*\.(pem|key|p12|pfx|sqlite3?|db|bak|dump)|.*(dump|backup|bak|export|prod)[^/]*\.sql|id_rsa|credentials\.json|service-account.*\.json|\.npmrc|\.pypirc)$", re.I)

findings = []

IGNORED_LINES = {}

def add(control, sev, title, where="", detail=""):
    if ":" in where and not where.startswith(("http", "commit")):
        f, _, ln = where.rpartition(":")
        if ln.isdigit() and int(ln) in IGNORED_LINES.get(f, ()):
            return
    findings.append({"control": control, "severity": sev, "title": title, "where": where, "detail": detail})

def mask(v):
    v = str(v)
    return ("…" + v[-4:]) if len(v) > 4 else "****"

def iter_files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".cache")]
        for fn in fns:
            p = os.path.join(dp, fn)
            low = fn.lower()
            if any(low.endswith(e) for e in SKIP_EXT) or low in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock"):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
            except OSError:
                continue
            yield p

def read(p):
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""

def scan_secrets(text, where, control="C2", in_history=False):
    for name, rx, sev in SECRETS:
        for m in rx.finditer(text):
            val = m.group(m.lastindex) if name == "Hardcoded secret assignment" and m.lastindex else m.group(0)
            ctx = text[max(0, m.start() - 40): m.end() + 10]
            if PLACEHOLDER.search(val) or (name == "Hardcoded secret assignment" and PLACEHOLDER.search(ctx)):
                continue
            ln = text.count("\n", 0, m.start()) + 1
            add("C24" if in_history else control, sev, ("Secret in git history: " if in_history else "Secret in file: ") + name,
                where if in_history else f"{where}:{ln}", f"value {mask(val)} — revoke and rotate it (C25)")

def scan_files(root):
    for p in iter_files(root):
        rel = os.path.relpath(p, root)
        text = read(p)
        if not text or "vibe-scan: ignore-file" in text[:600]:
            continue
        if "vibe-scan: ignore" in text:
            IGNORED_LINES[rel] = {i + 1 for i, l in enumerate(text.splitlines()) if "vibe-scan: ignore" in l}
        scan_secrets(text, rel)
        ext = os.path.splitext(p)[1].lower()
        if ext in CODE_EXT or rel.endswith(".rules") or os.path.basename(p).startswith(".env"):
            for control, name, rx, sev in CODE:
                for m in rx.finditer(text):
                    ln = text.count("\n", 0, m.start()) + 1
                    add(control, sev, name, f"{rel}:{ln}", m.group(0)[:80].strip())
        for m in PUBLIC_PREFIX.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            add("C11", "critical", "Secret-looking variable exposed to the browser via public prefix", f"{rel}:{ln}", m.group(0))
        if ext == ".sql" or "/migrations/" in rel.replace("\\", "/"):
            tables = re.findall(r"(?i)create\s+table\s+(if\s+not\s+exists\s+)?([\"\w.]+)", text)
            for _, t in tables:
                tn = t.strip('"').split(".")[-1]
                if not re.search(r"(?i)alter\s+table\s+[\"\w.]*" + re.escape(tn) + r"[\"]?\s+enable\s+row\s+level\s+security", text):
                    add("C3", "high", f"Table '{tn}' created without ENABLE ROW LEVEL SECURITY in this file", rel,
                        "verify RLS is enabled elsewhere, with policies per role")

def git(root, *args):
    try:
        return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ""

def scan_git(root, history=True):
    if not os.path.isdir(os.path.join(root, ".git")) or not shutil.which("git"):
        add("C24", "info", "Not a git repository or git not installed; history scan skipped")
        return
    for f in git(root, "ls-files").splitlines():
        if SENSITIVE_TRACKED.search(f):
            add("C11" if ".env" in f else "C23", "critical", "Sensitive file is tracked by git", f, "remove from repo, add to .gitignore, rotate any secret it contained")
    gi = read(os.path.join(root, ".gitignore"))
    if ".env" not in gi:
        add("C11", "high", ".env is not in .gitignore", ".gitignore")
    if history:
        log = git(root, "log", "-p", "--all", "--no-color", "-U0", "--max-count=2000")
        commit = ""
        chunk = []
        for line in log.splitlines():
            if line.startswith("commit "):
                if chunk:
                    scan_secrets("\n".join(chunk), f"commit {commit[:10]}", in_history=True)
                commit, chunk = line.split()[1], []
            elif line.startswith("+") and not line.startswith("+++"):
                chunk.append(line[1:])
        if chunk:
            scan_secrets("\n".join(chunk), f"commit {commit[:10]}", in_history=True)

def audit_deps(root):
    ran = False
    if os.path.exists(os.path.join(root, "package-lock.json")) and shutil.which("npm"):
        ran = True
        try:
            out = subprocess.run(["npm", "audit", "--json", "--omit=dev"], cwd=root, capture_output=True, text=True, timeout=180).stdout
            v = json.loads(out or "{}").get("metadata", {}).get("vulnerabilities", {})
            for level in ("critical", "high"):
                if v.get(level):
                    add("C21", level, f"npm audit: {v[level]} {level} vulnerable dependencies", "package-lock.json", "run npm audit fix / upgrade")
        except Exception as e:
            add("C21", "info", "npm audit failed", "", str(e)[:120])
    for req in ("requirements.txt", "pyproject.toml"):
        if os.path.exists(os.path.join(root, req)):
            ran = True
            if shutil.which("pip-audit"):
                r = subprocess.run(["pip-audit", "-r", req] if req.endswith(".txt") else ["pip-audit"], cwd=root, capture_output=True, text=True, timeout=300)
                if r.returncode not in (0,):
                    add("C21", "high", "pip-audit reported vulnerable Python packages", req, (r.stdout or r.stderr)[-300:])
            else:
                add("C21", "info", "pip-audit not installed; Python dependency audit skipped", req, "pip install pip-audit")
            break
    if os.path.exists(os.path.join(root, "composer.lock")) and shutil.which("composer"):
        ran = True
        r = subprocess.run(["composer", "audit", "--no-interaction"], cwd=root, capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            add("C21", "high", "composer audit reported vulnerable packages", "composer.lock", r.stdout[-300:])
    if not ran:
        add("C21", "info", "No supported lockfile/tool found; dependency audit skipped")

def http(url, method="GET", headers=None, follow=True):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "vibe-security-scan/1.0", **(headers or {})})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)) if follow else \
        urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    try:
        r = opener.open(req, timeout=15)
        return r.status, dict(r.headers), r.read(2048)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), b""
    except Exception as e:
        return None, {}, str(e).encode()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def scan_url(url):
    url = url.rstrip("/")
    if not re.match(r"^https?://", url):
        url = "https://" + url
    base = url
    host = re.sub(r"^https?://", "", url)
    if url.startswith("https://"):
        st, h, _ = http("http://" + host + "/", follow=False)
        loc = {k.lower(): v for k, v in h.items()}.get("location", "")
        if st and not (300 <= st < 400 and loc.startswith("https://")):
            add("C4", "high", "HTTP does not redirect to HTTPS", "http://" + host, f"status {st}")
    else:
        add("C4", "high", "Site scanned over plain HTTP", url, "use HTTPS in production")
    st, h, body = http(base + "/")
    if st is None:
        add("C4", "high", "Request to site failed", url, body.decode(errors="ignore")[:150])
        return
    hl = {k.lower(): v for k, v in h.items()}
    need = {"strict-transport-security": "C4", "content-security-policy": "C14", "x-content-type-options": "C14",
            "referrer-policy": "C14", "permissions-policy": "C14"}
    for name, c in need.items():
        if name not in hl:
            add(c, "medium" if name != "strict-transport-security" else "high", f"Missing header: {name}", url)
    if "x-frame-options" not in hl and "frame-ancestors" not in hl.get("content-security-policy", ""):
        add("C14", "medium", "Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)", url)
    hsts = hl.get("strict-transport-security", "")
    m = re.search(r"max-age=(\d+)", hsts)
    if hsts and (not m or int(m.group(1)) < 15552000):
        add("C4", "low", "HSTS max-age below 180 days", url, hsts)
    for leak in ("x-powered-by", "server"):
        if leak in hl and re.search(r"\d", hl[leak]):
            add("C14", "low", f"Version disclosed in {leak} header", url, hl[leak])
    for k, v in h.items():
        if k.lower() == "set-cookie":
            for cookie in v.split("\n"):
                low = cookie.lower()
                miss = [f for f in ("httponly", "secure", "samesite") if f not in low]
                if miss:
                    add("C15", "medium", "Cookie missing flags: " + ", ".join(miss), url, cookie.split("=")[0])
    st, h, _ = http(base + "/", headers={"Origin": "https://evil.example"})
    hl = {k.lower(): v for k, v in h.items()}
    acao = hl.get("access-control-allow-origin", "")
    if acao in ("*", "https://evil.example"):
        sev = "high" if hl.get("access-control-allow-credentials", "").lower() == "true" or acao == "https://evil.example" else "medium"
        add("C13", sev, "CORS accepts an arbitrary origin", url, f"ACAO={acao}")
    for path in ("/.env", "/.env.local", "/.git/config", "/.git/HEAD", "/backup.zip", "/backup.sql", "/db.sql", "/.DS_Store",
                 "/wp-config.php.bak", "/config.json", "/phpinfo.php", "/server-status", "/.vscode/settings.json", "/docker-compose.yml"):
        st, _, body = http(base + path, follow=False)
        if st == 200 and body and b"<html" not in body[:300].lower():
            add("C23", "critical", "Sensitive path publicly accessible", base + path, "block it at the server/CDN")
    for path in ("/api/docs", "/swagger", "/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"):
        st, _, body = http(base + path)
        if st == 200 and (b"swagger" in body.lower() or b"__schema" in body or b"openapi" in body.lower()):
            add("C20", "medium", "API docs or GraphQL introspection exposed in production", base + path)
    st, _, _ = http(base + "/.well-known/security.txt")
    if st != 200:
        add("P6", "low", "No /.well-known/security.txt", url)

def main():
    ap = argparse.ArgumentParser(description="vibe-security-hardening scanner")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--url", help="your own live site, e.g. https://example.com")
    ap.add_argument("--json", help="write JSON report to this file")
    ap.add_argument("--fail-on", default="critical", choices=list(SEV))
    ap.add_argument("--no-history", action="store_true")
    ap.add_argument("--no-deps", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.path)
    scan_files(root)
    scan_git(root, history=not a.no_history)
    if not a.no_deps:
        audit_deps(root)
    if a.url:
        scan_url(a.url)
    seen, uniq = set(), []
    for f in findings:
        k = (f["control"], f["title"], f["where"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    uniq.sort(key=lambda f: (-SEV[f["severity"]], f["control"], f["where"]))
    counts = {s: sum(1 for f in uniq if f["severity"] == s) for s in SEV}
    print(f"vibe-security-hardening scan: {root}" + (f"  url: {a.url}" if a.url else ""))
    print("summary: " + "  ".join(f"{s}={counts[s]}" for s in SEV))
    for f in uniq:
        print(f"[{f['severity'].upper():8}] {f['control']:4} {f['title']}" + (f"  @ {f['where']}" if f['where'] else "") + (f"  — {f['detail']}" if f['detail'] else ""))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"root": root, "url": a.url, "summary": counts, "findings": uniq}, fh, indent=2, ensure_ascii=False)
    worst = max([SEV[f["severity"]] for f in uniq] or [0])
    sys.exit(1 if worst >= SEV[a.fail_on] and worst > 0 else 0)

if __name__ == "__main__":
    main()
