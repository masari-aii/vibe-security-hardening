#!/usr/bin/env python3
"""vibe-security-hardening test suite + accuracy benchmark.  vibe-scan: ignore-file (contains deliberate vulnerable fixtures). Stdlib only (Python 3.8+, git).

  python3 tests/run_tests.py            # all tests, prints recall / false positives
  python3 tests/run_tests.py --json bench.json

Fixtures are generated at runtime in a temp folder (no secret-looking strings are stored in this repo).
Node-based checks run only when node + the needed packages are present.
"""
import argparse, base64, http.server, json, os, random, re, shutil, string, subprocess, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "scripts")
PY = sys.executable
RESULTS = []

def rnd(n, alphabet=string.ascii_letters + string.digits):
    return "".join(random.choice(alphabet) for _ in range(n))

def check(name, cond, info=""):
    RESULTS.append((name, bool(cond), info))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({info})" if info and not cond else ""))

def write(base, rel, text):
    p = os.path.join(base, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)

def git(base, *args):
    subprocess.run(["git", "-C", base, *args], capture_output=True, check=False)

def scan(path, *extra, env=None):
    out = os.path.join(tempfile.mkdtemp(), "r.json")
    r = subprocess.run([PY, "-I", os.path.join(S, "scan.py"), path, "--no-deps", "--json", out, *extra],
                       capture_output=True, text=True, env=env, timeout=600)
    data = json.load(open(out, encoding="utf-8"))
    return data["findings"], r

# ---------- fixtures ----------
def make_vuln(base):
    git(base, "init", "-q", "-b", "main"); git(base, "config", "user.email", "t@t"); git(base, "config", "user.name", "t")
    openai = "sk-" + "proj-" + rnd(40)
    stripe = "sk_" + "live_" + rnd(28)
    write(base, "src/old.js", f"const k = '{openai}';\n")
    git(base, "add", "-A"); git(base, "commit", "-qm", "key")
    os.remove(os.path.join(base, "src/old.js")); git(base, "add", "-A"); git(base, "commit", "-qm", "rm")
    write(base, ".env", f"STRIPE_SECRET_KEY={stripe}\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=abc\n")
    write(base, ".gitignore", "node_modules\n")
    write(base, "src/api.js", "\n".join([
        "app.use(cors({ origin: '*', credentials: true }));",
        "app.get('/u', async (req, res) => { const r = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`); res.json(r); });",
        "const hash = crypto.createHash('md5').update(password).digest('hex');",
        "const token = Math.random().toString(36);",
        "jwt.verify(t, key, { algorithms: ['none'] });",
        "el.innerHTML = userComment;",
        "const messages = [{ role: 'system', content: `You are helpful. ${req.body.instructions}` }];",
        "eval(req.query.code);", ""]))
    write(base, "app/settings.py", "DEBUG = True\nrequests.get(url, verify=False)\nmessages=[{'role': 'system', 'content': 'Be nice ' + user_message}]\n")
    write(base, "firestore.rules", "service cloud.firestore { match /{d=**} { allow read, write: if true; } }\n")
    write(base, "supabase/migrations/001.sql", "create table profiles (id uuid primary key, phone text);\n")
    write(base, "prod_backup.sql", "dump\n")
    write(base, "Dockerfile", "FROM node:latest\nENV DB_PASSWORD=supersecret123\nRUN curl -fsSL https://x.example/i.sh | bash\nCOPY . /app\n")
    write(base, "docker-compose.yml", "services:\n  app:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n  db:\n    image: postgres:16\n    environment:\n      - POSTGRES_PASSWORD=admin1234\n    ports:\n      - \"5432:5432\"\n")
    write(base, "nginx/site.conf", "server {\n  server_tokens on;\n  autoindex on;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n")
    write(base, "k8s/deploy.yaml", "kind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - securityContext:\n            privileged: true\n            allowPrivilegeEscalation: true\n")
    write(base, "tf/main.tf", 'resource "x" "ssh" {\n  from_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\nresource "y" "b" { acl = "public-read" }\nresource "z" "db" {\n  publicly_accessible = true\n  storage_encrypted = false\n}\n')
    write(base, ".github/workflows/pr.yml", "on: pull_request_target\npermissions: write-all\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo \"${{ github.event.issue.title }}\"\n")
    git(base, "add", "-A"); git(base, "commit", "-qm", "app")

EXPECTED = [  # (control, title substring) the scanner must report on make_vuln()
    ("C24", "OpenAI API key"), ("C2", "Stripe live secret key"), ("C11", "public prefix"), ("C11", "tracked by git"),
    ("C11", ".env is not in .gitignore"), ("C23", "tracked by git"), ("C3", "Firebase rules"), ("C3", "ROW LEVEL SECURITY"),
    ("C13", "CORS"), ("C10", "SQL built"), ("C10", "Dynamic code"), ("C5", "Weak hash"), ("E6", "Insecure randomness"),
    ("E6", "JWT"), ("C7", "Raw HTML"), ("A1", "LLM system prompt"), ("A1", "LLM system prompt"), ("C20", "Debug"), ("E2", "TLS verification"),
    ("I1", "runs as root"), ("I1", "latest"), ("I1", "Secret baked"), ("I1", "piped to shell"),
    ("I2", "Privileged"), ("I2", "Docker socket"), ("I2", "all interfaces"), ("I2", "Hardcoded password"),
    ("I3", "server_tokens"), ("I3", "Directory listing"), ("I3", "Legacy TLS"),
    ("I4", "privileged"), ("I4", "escalation"), ("I4", "hostNetwork"),
    ("I5", "open to the internet"), ("I5", "Public S3"), ("I5", "encryption disabled"), ("I5", "publicly accessible"),
    ("I6", "pull_request_target"), ("I6", "script injection"), ("I6", "write-all"),
]

def make_clean(base):
    git(base, "init", "-q", "-b", "main"); git(base, "config", "user.email", "t@t"); git(base, "config", "user.name", "t")
    write(base, ".gitignore", ".env\nnode_modules\n")
    write(base, "src/api.js", "\n".join([
        "const key = process.env.OPENAI_API_KEY;",
        "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
        "const r = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);",
        "const token = crypto.randomBytes(32).toString('hex');",
        "const password = \"your-password-here\";",
        "el.textContent = userComment; // price -- discount",
        "const messages = [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: input }];", ""]))
    write(base, "app/settings.py", "DEBUG = os.environ.get('DEBUG') == '1'\nrequests.get(url, timeout=10)\nsystem_prompt = load_prompt('base')\n")
    write(base, "supabase/migrations/001.sql", "create table profiles (id uuid primary key);\nalter table profiles enable row level security;\n")
    write(base, "Dockerfile", "FROM node:20.11-alpine\nRUN adduser -D app\nUSER app\nCOPY . /app\n")
    write(base, "docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    environment:\n      - POSTGRES_PASSWORD=${DB_PASSWORD}\n    ports:\n      - \"127.0.0.1:5432:5432\"\n")
    write(base, "nginx.conf", "server {\n  server_tokens off;\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n")
    write(base, "README.md", "Search for O'Reilly books -- best prices. Example key: sk_live_EXAMPLE\n")
    git(base, "add", "-A"); git(base, "commit", "-qm", "clean")

# ---------- tests ----------
def test_scanner(tmp, bench):
    v, c = os.path.join(tmp, "vuln"), os.path.join(tmp, "clean")
    os.makedirs(v); os.makedirs(c)
    make_vuln(v); make_clean(c)
    fv, r = scan(v)
    check("scanner exits 1 on critical findings", r.returncode == 1, r.stderr[-200:])
    hits = 0
    for ctrl, sub in EXPECTED:
        ok = any(f["control"] == ctrl and sub.lower() in f["title"].lower() for f in fv)
        hits += ok
        if not ok:
            check(f"detects {ctrl} {sub}", False)
    recall = hits / len(EXPECTED)
    check(f"recall on vulnerable fixture = {hits}/{len(EXPECTED)}", recall == 1.0)
    fc, rc = scan(c)
    real = [f for f in fc if f["severity"] != "info"]
    check("no false positives on clean fixture", not real, "; ".join(f"{f['control']} {f['title']} @ {f['where']}" for f in real))
    check("scanner exits 0 on clean fixture", rc.returncode == 0)
    check("secret values are masked in output", not re.search(r"sk_live_[A-Za-z0-9]{20,}", r.stdout))
    bench.update(expected=len(EXPECTED), detected=hits, recall=round(recall, 3), false_positives_clean=len(real),
                 total_findings_vuln=len([f for f in fv if f["severity"] != "info"]))
    return v

def test_ignore_and_fix(tmp, v):
    d = os.path.join(tmp, "fix"); shutil.copytree(v, d)
    p = os.path.join(d, "src/api.js")
    lines = open(p).read().splitlines(); lines[0] += " // vibe-scan: ignore"; open(p, "w").write("\n".join(lines) + "\n")
    f, _ = scan(d, "--no-history")
    check("inline 'vibe-scan: ignore' suppresses a line", not any(x["where"] == "src/api.js:1" for x in f))
    before = {q: open(os.path.join(d, q)).read() for q in ("src/api.js", "app/settings.py")}
    subprocess.run([PY, "-I", os.path.join(S, "scan.py"), d, "--no-deps", "--no-history", "--fix"], capture_output=True, timeout=300)
    gi = open(os.path.join(d, ".gitignore")).read()
    check("--fix adds .env to .gitignore", ".env" in gi.splitlines())
    check("--fix writes .env.example without values", open(os.path.join(d, ".env.example")).read().count("=\n") >= 2
          and "sk_" not in open(os.path.join(d, ".env.example")).read())
    check("--fix writes RLS draft and untrack script", os.path.exists(os.path.join(d, ".security/draft-enable-rls.sql"))
          and os.path.exists(os.path.join(d, ".security/untrack-sensitive-files.sh")))
    check("--fix never edits source files", all(open(os.path.join(d, q)).read() == t for q, t in before.items()))
    subprocess.run([PY, "-I", os.path.join(S, "scan.py"), d, "--no-deps", "--no-history", "--fix"], capture_output=True, timeout=300)
    check("--fix is idempotent", open(os.path.join(d, ".gitignore")).read() == gi)

def test_deep_parsers(tmp, v):
    b = os.path.join(tmp, "bin"); os.makedirs(b)
    gl = [{"RuleID": "stripe-access-token", "File": "a.env", "StartLine": 3, "Commit": "abcdef1234567"}]
    tv = {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [{"PkgName": "lodash", "InstalledVersion": "4.17.15",
          "VulnerabilityID": "CVE-2021-23337", "Severity": "HIGH", "FixedVersion": "4.17.21"}]},
          {"Target": "Dockerfile", "Misconfigurations": [{"ID": "DS002", "Title": "Image user should not be 'root'", "Severity": "HIGH", "Message": "m"}]}]}
    write(b, "gitleaks", "#!/usr/bin/env python3\nimport sys,json\na=sys.argv\np=a[a.index('--report-path')+1]\njson.dump(%s,open(p,'w'))\n" % json.dumps(gl))
    write(b, "trivy", "#!/usr/bin/env python3\nimport json\nprint(json.dumps(%s))\n" % json.dumps(tv))
    for x in ("gitleaks", "trivy"):
        os.chmod(os.path.join(b, x), 0o755)
    env = dict(os.environ, PATH=b + os.pathsep + os.environ.get("PATH", ""))
    f, _ = scan(v, "--no-history", "--deep", env=env)
    check("deep: gitleaks results parsed (recorded sample)", any("gitleaks: stripe-access-token" in x["title"] for x in f))
    check("deep: trivy vulnerabilities parsed (recorded sample)", any("CVE-2021-23337" in x["title"] for x in f))
    check("deep: trivy misconfigurations parsed (recorded sample)", any("trivy: Image user" in x["title"] for x in f))
    check("deep: temporary gitleaks report removed", not os.path.exists(os.path.join(v, ".gitleaks-report.tmp.json")))

class App(http.server.BaseHTTPRequestHandler):
    TOK = {"Bearer a1": "alice", "Bearer b2": "bob", "Bearer ad": "admin"}
    def log_message(self, *a): pass
    def do_GET(self):
        u = self.TOK.get(self.headers.get("Authorization", ""))
        code = 404
        if self.path == "/api/orders/101": code = 200 if u else 401                       # IDOR
        elif self.path == "/api/secure/101": code = (200 if u == "alice" else 404) if u else 401
        elif self.path == "/api/admin/users": code = 200 if u else 401                    # broken role check
        elif self.path == "/api/admin/stats": code = 200 if u == "admin" else (403 if u else 401)
        elif self.path == "/": code = 200
        self.send_response(code); self.send_header("Set-Cookie", "sid=1; Path=/"); self.end_headers(); self.wfile.write(b"{}")

def serve():
    srv = http.server.HTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def test_authz_and_live(tmp):
    srv = serve(); port = srv.server_address[1]
    cfg = {"base_url": f"http://127.0.0.1:{port}", "users": {"alice": {"headers": {"Authorization": "Bearer ${T_ALICE}"}},
           "bob": {"headers": {"Authorization": "Bearer b2"}}, "admin": {"headers": {"Authorization": "Bearer ad"}}},
           "checks": [{"name": "idor", "path": "/api/orders/101", "owner": "alice", "deny": ["anonymous", "bob"]},
                      {"name": "secure", "path": "/api/secure/101", "owner": "alice", "deny": ["anonymous", "bob"]},
                      {"name": "admin-broken", "path": "/api/admin/users", "owner": "admin", "deny": ["alice"]},
                      {"name": "admin-ok", "path": "/api/admin/stats", "owner": "admin", "deny": ["anonymous", "bob"]}]}
    cp = os.path.join(tmp, "authz.json"); json.dump(cfg, open(cp, "w"))
    out = os.path.join(tmp, "authz-out.json")
    r = subprocess.run([PY, "-I", os.path.join(S, "authz_test.py"), cp, "--json", out], capture_output=True, text=True,
                       env=dict(os.environ, T_ALICE="a1"), timeout=120)
    f = json.load(open(out))["findings"]
    check("authz: IDOR detected", any(x["control"] == "Z3" for x in f))
    check("authz: broken admin role detected", any(x["control"] == "Z2" for x in f))
    check("authz: secure endpoints pass (exactly 2 failures)", len([x for x in f if x["severity"] != "info"]) == 2, str(len(f)))
    r2 = subprocess.run([PY, "-I", os.path.join(S, "authz_test.py"), cp], capture_output=True, text=True, timeout=60,
                        env=dict(os.environ, T_ALICE="a1"))
    remote = dict(cfg, base_url="https://example.com"); rp = os.path.join(tmp, "remote.json"); json.dump(remote, open(rp, "w"))
    r3 = subprocess.run([PY, "-I", os.path.join(S, "authz_test.py"), rp], capture_output=True, text=True, timeout=60)
    check("authz: refuses non-local targets without --allow-remote", "refusing non-local" in (r3.stdout + r3.stderr))
    lf, _ = scan(os.path.join(tmp, "clean"), "--no-history", "--no-infra", "--url", f"http://127.0.0.1:{port}")
    titles = " | ".join(x["title"] for x in lf)
    check("live: missing headers reported", "Missing header: content-security-policy" in titles)
    check("live: insecure cookie reported", "Cookie missing flags" in titles)
    srv.shutdown()
    return out

def test_report(tmp, v, authz_json):
    before = os.path.join(tmp, "before.json")
    subprocess.run([PY, "-I", os.path.join(S, "scan.py"), v, "--no-deps", "--json", before], capture_output=True, timeout=300)
    after = os.path.join(tmp, "after.json")
    subprocess.run([PY, "-I", os.path.join(S, "scan.py"), os.path.join(tmp, "clean"), "--no-deps", "--json", after], capture_output=True, timeout=300)
    for lang in ("ar", "en"):
        out = os.path.join(tmp, f"report_{lang}.html")
        r = subprocess.run([PY, "-I", os.path.join(S, "report.py"), after, "--baseline", before, "--authz", authz_json,
                            "--lang", lang, "--brand", "Test Co", "--project", "Fixture", "--out", out], capture_output=True, text=True, timeout=120)
        h = open(out, encoding="utf-8").read()
        check(f"report ({lang}) generated with score and comparison", "/ 100" in h and ("قبل وبعد" in h if lang == "ar" else "Before vs after" in h), r.stderr[-200:])
    check("report: RTL for Arabic", 'dir="rtl"' in open(os.path.join(tmp, "report_ar.html"), encoding="utf-8").read())
    sys.path.insert(0, S)
    import report as rep
    check("report: score 100 when clean, capped 59 with a critical",
          rep.score([]) == 100 and rep.score([{"severity": "critical"}]) == 59 and rep.score([{"severity": "low"}]) > 95)

def test_guard_and_dashboard(tmp):
    log = os.path.join(tmp, "alerts.jsonl")
    code = (f"import sys,os; sys.path.insert(0,{S!r}); os.environ['ALERT_LOG_FILE']={log!r}\n"
            "import guard\n"
            "h={'cf-ipcountry':'NL','cf-ipcity':'Amsterdam','User-Agent':'sqlmap'}\n"
            "r=[guard.inspect('203.0.113.9',h,'GET','/s',\"q=' OR 1=1 --\")[0], guard.inspect('203.0.113.9',h,'GET','/.env')[0],"
            " guard.inspect('203.0.113.9',h,'POST','/c','', '<img src=x onerror=alert(1)>')[0],"
            " guard.inspect('1.1.1.1',h,'GET','/s',\"q=O'Reilly -- best price & 50% off\")[0]]\n"
            "e1=guard.inspect('198.51.100.1',h,'GET','/s','q=1 union select 1')[1]; e2=guard.inspect('198.51.100.1',h,'GET','/s','q=1 union select 2')[1]\n"
            "print(json.dumps(r) if False else '|'.join(map(str,r)), e1['emailed'], e2['emailed'])\n")
    r = subprocess.run([PY, "-I", "-c", "import json\n" + code], capture_output=True, text=True, timeout=60)
    out = r.stdout.strip()
    check("guard.py: SQLi/probe/XSS detected, legit text passes", out.startswith("SQL injection|Probe for sensitive file|XSS|None"), out + r.stderr[-300:])
    check("guard.py: second identical alert within 10 min is throttled", out.endswith("True False"), out)
    check("guard.py: events logged to JSONL", os.path.exists(log) and len(open(log).read().splitlines()) >= 5)
    dash = os.path.join(tmp, "dash.html")
    subprocess.run([PY, "-I", os.path.join(S, "alerts_dashboard.py"), log, "--out", dash, "--brand", "T"], capture_output=True, timeout=60)
    h = open(dash, encoding="utf-8").read()
    check("dashboard: built with totals and Arabic attack-type labels", "حقن SQL" in h and "Amsterdam" in h)
    d = subprocess.run([PY, "-I", os.path.join(S, "alerts_dashboard.py"), log, "--digest", "--lang", "en"], capture_output=True, text=True, timeout=60)
    check("dashboard: digest text produced", "Attack attempts" in d.stdout)

def test_encryption_reference():
    md = open(os.path.join(ROOT, "references", "encryption.md"), encoding="utf-8").read()
    blocks = re.findall(r"```python\n(.*?)```", md, re.S)
    try:
        import nacl, argon2, cryptography  # noqa: F401
    except ImportError:
        check("encryption reference code (skipped: pip install pynacl argon2-cffi cryptography)", True)
        return
    env = {"MASTER_KEY_B64": base64.b64encode(os.urandom(32)).decode(), "PEPPER_B64": base64.b64encode(os.urandom(32)).decode(),
           "DATA_KEY_B64": base64.b64encode(os.urandom(32)).decode(), "IDX_KEY_B64": base64.b64encode(os.urandom(32)).decode()}
    os.environ.update(env)
    ns1, ns2 = {}, {}
    exec(blocks[0], ns1)
    b = ns1["seal"]("1012345678", "field:national_id", "users:1")
    ok = ns1["open_"](b, "field:national_id", "users:1") == "1012345678"
    try:
        ns1["open_"](b, "field:phone", "users:1"); ok = False
    except Exception:
        pass
    h = ns1["hash_password"]("correct horse battery")
    check("encryption: XChaCha20 + HKDF + Argon2id reference code works", ok and ns1["verify_password"](h, "correct horse battery")
          and not ns1["verify_password"](h, "wrong"))
    exec(blocks[1], ns2)
    b2 = ns2["encrypt"]("SA03", "users:1")
    check("encryption: AES-256-GCM baseline reference code works", ns2["decrypt"](b2, "users:1") == "SA03")

def test_node_guard(tmp):
    node = shutil.which("node")
    nm = os.path.join(ROOT, "node_modules")
    if not node or not os.path.isdir(os.path.join(nm, "express")):
        check("guard.mjs (skipped: run `npm i express nodemailer` in the repo root to enable)", True)
        return
    t = os.path.join(ROOT, ".t_guard.mjs")
    write(ROOT, ".t_guard.mjs", """import express from 'express'; import { guard } from './scripts/guard.mjs';
const app = express(); app.use(express.json()); app.use(guard()); app.get('/s', (q, r) => r.json({ ok: 1 }));
const s = app.listen(0, async () => { const b = `http://127.0.0.1:${s.address().port}`; const out = [];
for (const p of ["/s?q=' OR 1=1 --", '/.env', '/s?q=shoes', "/s?q=O'Reilly -- deals"]) out.push((await fetch(b + p)).status);
console.log(out.join(',')); s.close(); });""")
    r = subprocess.run([node, t], capture_output=True, text=True, timeout=60, cwd=ROOT)
    os.remove(t)
    check("guard.mjs: blocks attacks (400/404), passes normal traffic (200)", r.stdout.strip() == "400,404,200,200", r.stdout + r.stderr[-200:])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()
    random.seed()
    tmp = tempfile.mkdtemp(prefix="vsh-tests-")
    bench = {}
    t0 = time.time()
    try:
        v = test_scanner(tmp, bench)
        test_ignore_and_fix(tmp, v)
        test_deep_parsers(tmp, v)
        authz = test_authz_and_live(tmp)
        test_report(tmp, v, authz)
        test_guard_and_dashboard(tmp)
        test_encryption_reference()
        test_node_guard(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    passed = sum(1 for r in RESULTS if r[1])
    bench.update(tests_passed=passed, tests_total=len(RESULTS), seconds=round(time.time() - t0, 1))
    print(f"\n{passed}/{len(RESULTS)} tests passed | recall {bench.get('detected')}/{bench.get('expected')} "
          f"| false positives on clean fixture: {bench.get('false_positives_clean')} | {bench['seconds']}s")
    if a.json:
        json.dump(bench, open(a.json, "w"), indent=2)
    sys.exit(0 if passed == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
