# Changelog

## 3.0.0 — 2026-11-26
- Client report generator `scripts/report.py`: branded HTML/PDF, Arabic RTL or English, security score and grade, before/after comparison, authz and manual findings merge.
- Authorization tester `scripts/authz_test.py`: IDOR, broken admin role, unauthenticated access; local-only by default, tokens from env.
- Scanner: infrastructure checks (Dockerfile, compose, nginx/Apache, Kubernetes, Terraform, GitHub Actions); `--deep` merges semgrep, gitleaks, trivy; `--fix` safe non-destructive fixes; inline `vibe-scan: ignore`; tighter LLM system-prompt rule.
- Intrusion alerts: code moved to `scripts/guard.mjs` and `scripts/guard.py`; new webhook (Slack/Discord/Teams/n8n), Telegram and JSONL log channels; `scripts/alerts_dashboard.py` dashboard and daily digest.
- New modules: Infrastructure (I1–I6), NCA ECC-2:2024 and SAMA mapping (N).
- Test suite and benchmark `tests/run_tests.py` (runtime fixtures, recall and false-positive metrics) with a GitHub Actions workflow.

## 2.0.0 — 2026-11-26
- Automated scanner and CI template; AI/LLM security (OWASP GenAI LLM Top 10 2026); stack playbooks; Saudi PDPL module; split into references; all-in-one edition.

## 1.x — 2026-11-26
- 27 core controls; encryption module (XChaCha20-Poly1305, AES-256-GCM, HKDF, Argon2id); active protection; intrusion detection with email alerts.
