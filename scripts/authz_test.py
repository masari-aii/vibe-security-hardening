#!/usr/bin/env python3
"""vibe-security-hardening: authorization / IDOR tester. Stdlib only.

Proves that each user can reach only their own data and that admin routes reject normal users.
Run it against LOCAL or STAGING copies you own.

  python3 authz_test.py authz.json [--json authz-report.json] [--allow-remote] [--allow-destructive]

Config (JSON; ${ENV_VAR} values are expanded, so tokens stay out of the file):
{
  "base_url": "http://localhost:3000",
  "users": {
    "alice": {"headers": {"Authorization": "Bearer ${ALICE_TOKEN}"}},
    "bob":   {"headers": {"Cookie": "session=${BOB_SESSION}"}},
    "admin": {"headers": {"Authorization": "Bearer ${ADMIN_TOKEN}"}}
  },
  "checks": [
    {"name": "Alice reads her order", "method": "GET", "path": "/api/orders/101", "owner": "alice", "deny": ["anonymous", "bob"]},
    {"name": "Admin user list", "method": "GET", "path": "/api/admin/users", "owner": "admin", "deny": ["anonymous", "alice", "bob"]},
    {"name": "Bob edits Alice", "method": "PATCH", "path": "/api/users/1", "body": {"name": "x"}, "owner": "alice", "deny": ["bob"]}
  ]
}
"anonymous" is built in (no credentials). A denial is HTTP 401/403/404 (configurable with "deny_status").
"""
import argparse, json, os, re, sys, urllib.error, urllib.parse, urllib.request

LOCAL = re.compile(r"^(localhost|127\.0\.0\.1|\[::1\]|::1|[\w.-]+\.(localhost|test|local))$", re.I)
UNSAFE = {"DELETE"}

def expand(v):
    if isinstance(v, str):
        return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v

def request(base, method, path, headers, body):
    data = json.dumps(body).encode() if body is not None else None
    h = {"User-Agent": "vibe-authz-test/1.0", "Accept": "application/json", **headers}
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(urllib.parse.urljoin(base, path), data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read(400)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception as e:
        return None, str(e).encode()

def main():
    ap = argparse.ArgumentParser(description="Authorization / IDOR tests: proves each user reaches only their own data and admin routes reject normal users.",
                                 epilog="example:\n  ALICE_TOKEN=... BOB_TOKEN=... ADMIN_TOKEN=... authz_test.py authz.json --json authz.json.out\nexit code: 1 when any check fails.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", help="JSON config: base_url, users (headers with ${ENV} tokens), checks")
    ap.add_argument("--json", help="write findings JSON (merge into report.py with --authz)")
    ap.add_argument("--allow-remote", action="store_true", help="allow a non-local base_url you are authorized to test")
    ap.add_argument("--allow-destructive", action="store_true", help="allow DELETE checks")
    a = ap.parse_args()
    cfg = expand(json.load(open(a.config, encoding="utf-8")))
    base = cfg["base_url"].rstrip("/") + "/"
    host = urllib.parse.urlparse(base).hostname or ""
    if not LOCAL.match(host) and not a.allow_remote:
        sys.exit(f"refusing non-local target '{host}': test local/staging, or pass --allow-remote for a system you own")
    users = {"anonymous": {"headers": {}}, **cfg.get("users", {})}
    for name, u in users.items():
        if name != "anonymous" and any(v.strip() in ("", "Bearer", "session=") for v in u.get("headers", {}).values()):
            print(f"warning: user '{name}' has an empty credential (missing env var?)")
    deny_status = set(cfg.get("deny_status", [401, 403, 404]))
    findings, results = [], []
    for c in cfg.get("checks", []):
        method = c.get("method", "GET").upper()
        if method in UNSAFE and not a.allow_destructive:
            results.append((c["name"], "SKIP", "DELETE needs --allow-destructive"))
            continue
        owner = c.get("owner")
        if owner:
            st, _ = request(base, method, c["path"], users[owner].get("headers", {}), c.get("body"))
            if st is None or not (200 <= st < 300):
                results.append((c["name"], "CONFIG", f"owner '{owner}' got {st}: fix the config/credentials first"))
                findings.append({"control": "Z0", "severity": "info", "title": f"Owner cannot access: {c['name']}",
                                 "where": f"{method} {c['path']}", "detail": f"owner {owner} got {st}"})
                continue
        for who in c.get("deny", []):
            st, body = request(base, method, c["path"], users[who].get("headers", {}), c.get("body"))
            if st in deny_status:
                results.append((c["name"], "PASS", f"{who} -> {st}"))
                continue
            is_admin = "admin" in c["path"].lower() or owner == "admin"
            sev = "critical" if (who == "anonymous" or is_admin) else "high"
            kind = ("Unauthenticated access" if who == "anonymous" else "Normal user reached admin route" if is_admin
                    else "IDOR: user reached another user's data")
            results.append((c["name"], "FAIL", f"{who} -> {st}"))
            findings.append({"control": "Z1" if who == "anonymous" else ("Z2" if is_admin else "Z3"), "severity": sev,
                             "title": f"{kind}: {c['name']}", "where": f"{method} {c['path']}",
                             "detail": f"as '{who}' got HTTP {st}; expected one of {sorted(deny_status)}. Enforce ownership/role checks on the server (C9, C27)."})
    w = max([len(r[0]) for r in results] + [10])
    for name, status, info in results:
        print(f"[{status:6}] {name.ljust(w)}  {info}")
    fails = sum(1 for r in results if r[1] == "FAIL")
    print(f"\n{sum(1 for r in results if r[1] == 'PASS')} passed, {fails} failed, "
          f"{sum(1 for r in results if r[1] in ('SKIP', 'CONFIG'))} skipped/config")
    if a.json:
        json.dump({"tool": "vibe-authz-test", "base_url": base, "findings": findings}, open(a.json, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
