# Module P — Active protection (keep attackers out)

- P1. Edge shield: put the site behind a CDN/WAF (e.g. Cloudflare or the host's WAF) with managed rules and DDoS protection; hide the origin IP; origin accepts traffic only from the CDN.
- P2. Bot protection: invisible challenge (e.g. Turnstile/hCaptcha/reCAPTCHA) on signup, login, reset, contact and checkout; honeypot field on public forms.
- P3. Admin hardening: MFA required for every admin; admin panel behind IP allow-list, VPN or SSO where possible; non-default admin path as an extra layer only; admin actions logged (control 8).
- P4. Account protection: minimum 12-character passwords, block breached passwords (k-anonymity range API), revoke all sessions on password change, notify on new-device login and email/password changes.
- P5. Backups: automated, encrypted (E7), off-site, versioned; restore tested before launch.
- P6. Incident readiness: alerts on spikes (control 8); a kill switch to revoke all sessions and rotate keys fast; `/.well-known/security.txt` with a contact; short runbook: contain, rotate, patch, notify.
- P7. Content protection: signed expiring URLs for private media, hotlink protection, robots rules do not hide sensitive paths (use auth instead).

Protection tests: origin IP direct request refused; form without challenge token rejected; admin login without MFA impossible; breached password rejected; backup restored to a scratch DB successfully.
