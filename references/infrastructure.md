# Module I — Infrastructure and deployment security

Many breaches come from configuration, not code. The scanner checks these files automatically (`I1`–`I6`); this module explains the fixes. Review any infrastructure the project ships: containers, web server config, Kubernetes, Terraform/IaC, CI pipelines, cloud accounts.

- I1. Containers (Dockerfile): pinned base image (`node:20.11-alpine`, ideally by digest), multi-stage build, non-root `USER`, no secrets in `ENV`/`ARG` (use runtime env or build secrets), no `curl | sh`, `COPY` instead of remote `ADD`, `.dockerignore` excluding `.env`, `.git`, `node_modules`; scan the image (`trivy image`).
- I2. Docker Compose: no `privileged`, no `/var/run/docker.sock` mounts, no `network_mode: host`; databases and caches bound to `127.0.0.1` or internal networks only; passwords via `${VAR}` from an untracked `.env`; resource limits; read-only filesystems where possible.
- I3. Web server (nginx/Apache): `server_tokens off` / `ServerTokens Prod`; no directory listing (`autoindex off`, `Options -Indexes`); `ssl_protocols TLSv1.2 TLSv1.3`; HTTP→HTTPS redirect; security headers (C14); deny dotfiles and backups:

```nginx
location ~ /\.(?!well-known) { deny all; }
location ~* \.(bak|sql|zip|tar|gz|env|log)$ { deny all; }
client_max_body_size 10m;
```
- I4. Kubernetes: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, drop all capabilities, no `privileged`/`hostNetwork`/`hostPID`; resource requests/limits; secrets from a secret store (not plain env in manifests); NetworkPolicies default-deny; least-privilege service accounts.
- I5. Cloud and Terraform: no `0.0.0.0/0` on SSH/RDP/database ports (use VPN, bastion or SSM); databases `publicly_accessible = false`; encryption at rest on for disks, databases, buckets and backups; S3/GCS buckets private with public access block; IAM least privilege (no `"Action": "*"` on `"Resource": "*"`), MFA on root/admin accounts; CloudTrail/audit logs on; Terraform state stored encrypted and access-controlled (it contains secrets).
- I6. CI/CD (GitHub Actions and similar): minimal `permissions:` per workflow (never `write-all`); never check out PR head code in `pull_request_target`; never interpolate `${{ github.event.* }}` text into `run:` (pass via `env:`); pin third-party actions to a commit SHA; secrets only in protected environments; branch protection with required reviews and the security-scan workflow as a required check.

Infrastructure tests: `docker run` the image and check `id -u` is not 0; `nmap`/`curl` from outside shows only 80/443 open; database port unreachable from the internet; `curl https://site/.git/config` returns 403/404; a PR from a fork cannot read secrets.
