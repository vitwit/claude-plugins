# Security checklist: deploying and maintaining products at scale

Tags show how each item is verified:

- `[auto]`: `scripts/scan.py` checks it.
- `[code]`: verify by reading code or config in the repo.
- `[manual]`: only the owner can confirm it (dashboards, processes, drills). Ask; never assume.

Five rules apply to every section:

1. No long-lived secret lives outside the secrets manager.
2. Every key is scoped and can be revoked in under 15 minutes without a deploy.
3. There is no single point of failure.
4. Least privilege by default.
5. Assume breach.

## Contents

1. Secrets and key management
2. Client and edge exposure
3. AI gateway and LLM providers
4. Payments
5. Analytics and telemetry
6. Identity, authentication and authorization
7. Infrastructure and network
8. CI/CD and supply chain
9. Data protection
10. Resilience (no single point of failure)
11. Monitoring, detection and incident response
12. Maintenance cadence
13. Pre-launch release gate
14. Emerging risks (2025–2026)

---

## 1. Secrets and key management

- 1.1 `[auto]` No secrets in source, git history, images or env files committed to git.
- 1.2 `[code]` Secrets come from a managed store (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Vault, Doppler, Infisical) and are injected at runtime, never as build args or image layers.
- 1.3 `[code]` Encryption keys live in KMS or an HSM, with envelope encryption. Apps never hold raw master keys.
- 1.4 `[manual]` Each environment has its own store or namespace. Non-prod cannot read prod.
- 1.5 `[code]` IaC state is encrypted and secret values are marked `sensitive`.
- 1.6 `[code]` Workloads use workload identity (IAM roles, workload identity federation, SPIFFE), not static cloud keys.
- 1.7 `[manual]` Each service reads only its own secret path. No human has standing read access to prod secrets; access is just-in-time and audit-logged.
- 1.8 `[manual]` Short-lived tokens (15–60 minutes) are used wherever the provider supports them.
- 1.9 `[manual]` Third-party keys have minimum scope (restricted keys, read-only, IP-allowlisted), one per service per environment.
- 1.10 `[manual]` Every metered key (AI, SMS, maps, email) has a hard spend cap at the provider.
- 1.11 `[manual]` Rotation is automated: DB credentials at most every 30 days (or dynamic), API keys at most every 90 days, with two keys valid during the overlap.
- 1.12 `[manual]` Each provider has a rehearsed revocation path that takes under 15 minutes.
- 1.13 `[manual]` A secrets inventory records owner, provider, scope, created date, last rotation and consumers.
- 1.14 `[code]` The logger redacts `sk-`, `Bearer`, `password` and card numbers. Errors and debug endpoints never echo config or headers.

## 2. Client and edge exposure

- 2.1 `[auto]` Only publishable keys reach clients, and only behind public env prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_` and similar). Those keys are domain-restricted.
- 2.2 `[auto]` Built bundles, source maps and APK/IPA files are scanned in CI, which fails on a match.
- 2.3 `[auto]` Production source maps are not public.
- 2.4 `[code]` Mobile apps hold no secret keys. They call the backend, which checks App Attest or Play Integrity.
- 2.5 `[code]` A backend-for-frontend (BFF) or API gateway proxies every secret-bearing provider. Proxies require auth, rate-limit per user and tenant, and allowlist operations; they are never an open relay.
- 2.6 `[code]` No secrets in URLs or query strings.
- 2.7 `[manual]` The edge blocks `.git`, `.env`, backups, `/debug`, `/actuator`, `/metrics` and admin panels, and an external scan confirms it.
- 2.8 `[code]` Security headers are set: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy` and `frame-ancestors`. CORS allows exact origins only, never `*` with credentials.
- 2.9 `[manual]` Secret scanning and push protection are on at the git host, covering public repos and package registries.

## 3. AI gateway and LLM providers

- 3.1 `[auto]`/`[code]` Provider keys exist only in the gateway or backend. Apps authenticate to the gateway with their own identity.
- 3.2 `[code]` Cloud-native auth (Bedrock IAM, Vertex service accounts, Azure managed identity) is used where available.
- 3.3 `[manual]` Each environment and product line has its own key or project, with spend limits and alerts at 50%, 80% and 100%.
- 3.4 `[manual]` A hosted gateway's admin keys are rotated like prod secrets.
- 3.5 `[code]` Rate limits apply per user and per tenant, on requests and tokens. The server enforces maximum input and output tokens.
- 3.6 `[code]` Each endpoint has a model allowlist. Clients cannot choose the model freely.
- 3.7 `[manual]` Spend anomalies trigger alerts and automatic throttling.
- 3.8 `[code]` Model output is untrusted: it is escaped or validated before use as HTML, SQL, shell or API input.
- 3.9 `[code]` Tools run with the end user's permissions. Destructive or financial actions need human confirmation or a policy check outside the model.
- 3.10 `[code]` Retrieved content (web, docs, email, RAG) cannot change instructions or tool permissions.
- 3.11 `[code]` System prompts contain no secrets or internal URLs.
- 3.12 `[code]` RAG queries are filtered by tenant ID on the server.
- 3.13 `[code]` PII and secrets are redacted before prompts leave your boundary.
- 3.14 `[manual]` Each provider's retention and training terms (ZDR or no-training) and data residency are recorded.
- 3.15 `[code]` Prompt and response logs are encrypted, access-controlled, redacted and kept only for the retention period.
- 3.16 `[code]` At least two providers or regions are configured, with failover on 429, 5xx or timeout. Each provider has a timeout, jittered retries and a circuit breaker, and there is a defined degraded mode. `[manual]` Failover is tested monthly.
- 3.17 `[code]` Indirect prompt injection is contained. Any content the model reads — documents, web pages, transcripts, emails, tool results, RAG chunks — is treated as untrusted *data*, never as instructions. It is clearly delimited in the prompt, cannot invoke tools or change policy on its own, and high-impact tool calls still require the checks in 3.9 regardless of what the content says. This is distinct from 3.8 (which covers the model's *output*); 3.17 covers the model's *input*. Maps to OWASP LLM01.
- 3.18 `[code]` File inputs to the model or its tools are validated before parsing: allowlisted MIME type and extension (verified by content, not just the name), a size cap, a page/dimension/duration cap, and rejection or safe handling of archives (zip-bomb and path-traversal defence). Office, PDF and image parsing runs in a sandbox with no network and a timeout. Extracted text is treated as untrusted per 3.17.
- 3.19 `[code]` URLs the model or a tool fetches (for example an image, video or document URL from the request, as in a `*_url` parameter) are SSRF-guarded: scheme allowlist (`https` only), DNS resolved and re-checked against blocked ranges (private, loopback, link-local and the cloud metadata endpoint `169.254.169.254`), redirects re-validated, and ideally routed through an egress proxy. See 14.6.

## 4. Payments

- 4.1 `[code]` Hosted fields or hosted checkout keep card numbers off your servers (PCI SAQ A or A-EP).
- 4.2 `[code]` Card data and bank details are never logged or sent to analytics, AI or support tools. Only provider tokens and IDs are stored.
- 4.3 `[auto]`/`[code]` Secret keys are server-side only. Each service has a restricted key. Test and live keys are separate, and CI cannot read live keys.
- 4.4 `[manual]` The provider dashboard uses SSO and hardware-key MFA, with least-privilege roles.
- 4.5 `[auto]`/`[code]` Webhook signatures are verified on the raw body, and events older than 5 minutes are rejected.
- 4.6 `[code]` Webhook handlers are idempotent (event-ID dedupe), re-fetch the object from the provider before changing state, ack fast and retry through a DLQ.
- 4.7 `[code]` Amounts, currency and discounts are computed on the server. Every charge, refund and payout call has an idempotency key.
- 4.8 `[manual]` 3DS/SCA and fraud tools are enabled, with velocity limits.
- 4.9 `[code]` Payout or bank-detail changes require re-authentication and notify the owner.
- 4.10 `[manual]` The ledger is reconciled daily against settlements, with an alert on mismatch.
- 4.11 `[manual]` There is a processor outage plan (queued retries, customer messaging, secondary processor).

## 5. Analytics and telemetry

- 5.1 `[code]` Only write-only ingestion keys reach clients. Read, export and admin keys are server-only.
- 5.2 `[manual]` Ingestion keys are domain- or app-restricted.
- 5.3 `[code]` Sensitive events (purchases, sign-ups) are sent server-side.
- 5.4 `[code]` Events carry no PII: no emails, tokens, card data, full IPs or free text, and query strings are stripped.
- 5.5 `[code]` Session replay masks all inputs and is off on payment, auth and settings pages.
- 5.6 `[code]` Error trackers scrub headers, cookies, bodies and environment variables.
- 5.7 `[code]` A consent manager gates non-essential tags (GDPR, CCPA, DPDP).
- 5.8 `[code]` Third-party scripts use SRI or are self-hosted, and a tag inventory exists.
- 5.9 `[manual]` BI and warehouse access goes through SSO, with per-pipeline service accounts.
- 5.10 `[manual]` A DPA is signed with each vendor, and retention is set to the minimum.
- 5.11 `[code]` Analytics calls are async and non-blocking, so the product works when a vendor is down.

## 6. Identity, authentication and authorization

- 6.1 `[manual]` SSO covers cloud, git, CI and every vendor dashboard (AI, payments, analytics, DNS, registrar).
- 6.2 `[manual]` Admins and prod users have phishing-resistant MFA (passkeys or FIDO2).
- 6.3 `[manual]` There are no shared accounts, break-glass accounts are tested quarterly, SCIM handles offboarding, and access is removed within 24 hours of departure.
- 6.4 `[code]` Passwords are hashed with Argon2id or bcrypt and checked against breached-password lists. MFA or passkeys are available to all users.
- 6.5 `[code]` Cookies are Secure, HttpOnly and SameSite. Access tokens are short-lived and refresh tokens rotate. The server can revoke sessions.
- 6.6 `[code]` Login, OTP and password reset are rate-limited and do not reveal whether an account exists.
- 6.7 `[code]` OAuth uses PKCE, exact redirect-URI matching, and state and nonce checks.
- 6.8 `[code]` Object-level authorization is checked on every request (no IDOR). Tenant ID comes from the session, never from client input, and is enforced in a shared data layer or with row-level security.
- 6.9 `[code]` Automated tests try cross-tenant access.
- 6.10 `[code]` Admin and internal APIs run on a separate host or network.
- 6.11 `[code]` Service-to-service calls use mTLS or short-lived signed tokens.
- 6.12 `[code]` Customer API keys are hashed at rest, carry a scannable prefix, are scoped and expirable, and are shown only once.

## 7. Infrastructure and network

- 7.1 `[code]` All infrastructure is in IaC with reviewed PRs, and console drift is detected.
- 7.2 `[manual]` Each environment has its own account, and prod has org guardrails (SCPs or org policies).
- 7.3 `[code]` Data stores and internal services sit in private subnets with no public IPs.
- 7.4 `[code]` Traffic enters through a single ingress with a WAF and DDoS protection. Rate limits apply at the edge and per tenant.
- 7.5 `[code]` Egress is allowlisted to approved vendor hosts.
- 7.6 `[code]` Admin access goes through SSO plus a bastion, SSM or IAP. SSH and RDP are closed to the internet.
- 7.7 `[code]` TLS 1.2+ everywhere, with auto-renewed certificates and HSTS preload.
- 7.8 `[auto]`/`[code]` Containers use minimal images and run as non-root with a read-only filesystem, no privileged mode and resource limits.
- 7.9 `[code]` Kubernetes uses least-privilege RBAC, default-deny network policies and the "restricted" Pod Security Standard, with an external secrets operator.
- 7.10 `[code]` IMDSv2 is required.
- 7.11 `[manual]` The registrar has registry lock and MFA, with DNSSEC and CAA records set.
- 7.12 `[manual]` Cloud posture scanning alerts on public buckets, open ports and wildcard IAM.

## 8. CI/CD and supply chain

- 8.1 `[auto]` CI authenticates to the cloud with OIDC, never with static keys.
- 8.2 `[manual]` Prod deploy credentials are limited to protected branches and environments with approvals.
- 8.3 `[auto]` Fork PRs never get secrets (`pull_request_target` is reviewed).
- 8.4 `[auto]`/`[manual]` Secret scanning runs at pre-commit, in CI and as push protection. Full history has been scanned.
- 8.5 `[manual]` Branch protection is on, with required reviews and CODEOWNERS on infrastructure and auth code.
- 8.6 `[code]` Lockfiles are used, with automated updates and SCA that blocks critical CVEs.
- 8.7 `[auto]` Actions are pinned to full commit SHAs. `[auto]` A `permissions:` block is set.
- 8.8 `[manual]` SAST and IaC scanning run on every PR.
- 8.9 `[manual]` Images are scanned and signed (cosign), and admission control admits only signed images. Each release has an SBOM and SLSA L2+ provenance.
- 8.10 `[auto]` Logs never print secrets.
- 8.11 `[manual]` Git, CI and registry admins are a small group with hardware MFA.

## 9. Data protection

- 9.1 `[manual]` Data is classified with handling rules for each class.
- 9.2 `[code]` Data is encrypted at rest with KMS, and restricted fields also have field-level encryption. TLS covers internal traffic and DB connections.
- 9.3 `[code]` Tenant data is separated by RLS, schema or database. BYOK is available for enterprise.
- 9.4 `[manual]` Backups are automated, encrypted, cross-region and immutable (object or vault lock). A restore is tested quarterly, and RPO and RTO are measured.
- 9.5 `[manual]` Retention and deletion are automated, including logs, analytics, AI logs and backups.
- 9.6 `[manual]` Prod data is never used unmasked in dev or staging.
- 9.7 `[manual]` Data-subject requests reach every vendor. A vendor inventory records the data each receives, DPA, region and sub-processors.

## 10. Resilience (no single point of failure)

| Dependency | Required fallback | Test cadence |
| --- | --- | --- |
| Compute / region | Multi-zone always; warm standby or active-active for tier-1 | Quarterly failover |
| Database | Multi-zone replicas, PITR, cross-region replica | Quarterly restore |
| Secrets manager | Regional replication, client cache with TTL, retry with backoff | Twice a year |
| KMS | Multi-region keys, deletion protection, deletion window of 30 days or more | Yearly |
| AI providers | Two or more providers or regions, circuit breakers, degraded mode | Monthly |
| Payment processor | Queued retries, secondary processor or method | Twice a year |
| Analytics | Async, buffered; product works without it | Per integration |
| IdP / SSO | Break-glass accounts with hardware MFA | Quarterly |
| DNS / CDN | Secondary DNS, registrar lock, low-TTL failover plan | Yearly |
| CI/CD / git host | Manual deploy path, mirrored repos, signed artifacts | Yearly |
| People | Runbooks, two or more owners per critical system, on-call rotation | Ongoing |

- 10.1 `[code]` Every vendor call has a timeout, jittered retries, a circuit breaker and a bulkhead.
- 10.2 `[code]` Health checks, autoscaling and load shedding are in place, and each feature's degraded mode is documented.
- 10.3 `[manual]` Destructive admin actions need two-person approval.
- 10.4 `[manual]` Root and owner accounts use hardware MFA, with sealed split credentials and alerts on any use.

## 11. Monitoring, detection and incident response

- 11.1 `[manual]` Central, immutable logs (cloud audit, app, IdP, git, CI, vendors) are kept in a security account for at least one year.
- 11.2 `[manual]` Alerts cover: secret reads by unexpected identities, new IAM keys, MFA disabled, a public bucket or port, prod elevation, spend spikes, failed-login surges and webhook signature failures.
- 11.3 `[manual]` Canary tokens are planted in repos, CI and secret stores. Provider leak detection (GitHub partner program) is on.
- 11.4 `[manual]` A leaked-key runbook exists (see `leaked-key-runbook.md`), with a target of revocation within 15 minutes.
- 11.5 `[manual]` The IR plan covers roles, severity, comms and legal (72-hour GDPR notice). Tabletops run quarterly and leaked-key drills twice a year.
- 11.6 `[manual]` `security.txt` and a disclosure policy are published, with a bug bounty at scale. Post-incident reviews are blameless.

## 12. Maintenance cadence

| Cadence | Tasks |
| --- | --- |
| Daily | Triage alerts; check spend anomalies on AI and payment keys; check backup failures |
| Weekly | Patch CVEs (critical within 7 days, high within 30); merge dependency updates; review new IAM grants |
| Monthly | Access review; AI failover test; WAF and rate-limit review; secrets inventory diff; rerun this scanner on main |
| Quarterly | Rotate due keys; restore test; region failover; tabletop; break-glass test; vendor and scope review |
| Yearly | Pen test; threat model refresh; full DR exercise; policy refresh; SOC 2 / ISO 27001 / PCI audits |
| New integration | Threat-model the flow; scoped key in the vault with a spend cap; DPA; inventory, monitoring and runbook updated |
| Departure | Revoke SSO within 24 hours; rotate any secret they could read; transfer ownership |

## 13. Pre-launch release gate

- 13.1 Secret scans of the tree, history, bundles, images and mobile binaries are clean. `[auto]`
- 13.2 No secret key is reachable from a client. `[auto]`/`[code]`
- 13.3 Every third-party key has scope, a spend cap, an owner and a tested revocation path. `[manual]`
- 13.4 Webhooks are verified and idempotent, and amounts are computed on the server. `[code]`
- 13.5 AI endpoints are rate-limited per tenant, tools are permissioned and a failover provider is configured. `[code]`
- 13.6 Cross-tenant authorization tests pass. `[code]`
- 13.7 Infrastructure is in IaC, no data store is public, and the WAF and rate limits are live. `[code]`/`[manual]`
- 13.8 A restore has been verified, and RPO and RTO are documented. `[manual]`
- 13.9 Alerts route to on-call, and the runbook is linked. `[manual]`
- 13.10 There are no open critical or high findings from SCA, SAST, IaC or image scans. `[manual]`
- 13.11 New auth, payment or AI features have had a pen test or focused review. `[manual]`
- 13.12 Security owner sign-off is recorded. `[manual]`

## 14. Emerging risks (2025–2026)

- 14.1 `[auto]` Coding agents are denied read access to `.env` files (in Claude Code, `permissions.deny` with `Read(./.env)` and `Read(./.env.*)`). Because deny takes precedence over allow, a broad `Read(./.env.*)` also blocks committed templates like `.env.example`, and an allow rule will not re-open them. To keep templates readable, deny the specific secret-bearing files instead — `Read(./.env)`, `Read(./.env.local)`, `Read(./.env.*.local)`, `Read(./.env.production)`, `Read(./.env.development)` — rather than the catch-all glob. `.gitignore` and `.claudeignore` do not block agent reads.
- 14.2 `[manual]` No plaintext secrets are on developer disks; secrets are injected at runtime (`doppler run`, `infisical run`, `op run`). Agents never hold prod credentials and run sandboxed.
- 14.3 `[code]` MCP servers accept only tokens issued to them (audience check); token passthrough is forbidden.
- 14.4 `[code]` MCP proxies with a static client ID implement per-client consent, exact redirect-URI matching, and single-use `state` that expires in about 10 minutes.
- 14.5 `[code]` MCP scopes are minimal and step up when needed; no wildcard scopes.
- 14.6 `[code]` URL-fetching agents block private IPs and `169.254.169.254`, ideally behind an egress proxy (for example Smokescreen).
- 14.7 `[manual]` Third-party MCP servers, plugins and skills are reviewed, version-pinned and re-reviewed when tool descriptions change.
- 14.8 `[code]` AI features are mapped to OWASP LLM01–LLM10 (2025). Check LLM07 system-prompt leakage, LLM08 vector/embedding weaknesses and LLM10 unbounded consumption (including model extraction: per-key query caps).
- 14.9 `[manual]` Non-human identities follow the OWASP NHI Top 10 2025: offboarding the same day a service or vendor is retired, one identity per workload, and no human use of service accounts.
- 14.10 `[auto]` CI installs run with `--ignore-scripts`, with an allowlist for exceptions.
- 14.11 `[code]` Dependency installs run in a step with no secrets.
- 14.12 `[code]` New dependency versions wait out a cooldown (for example `minimumReleaseAge` of 3 days in Renovate or pnpm).
- 14.13 `[manual]` npm packages publish through OIDC trusted publishing. npm revoked classic tokens on 9 Dec 2025, and granular write tokens last at most 90 days.
- 14.14 `[manual]` Alerts fire on new workflow files, self-hosted runners and public repos in the org.
- 14.15 `[manual]` PCI DSS v4.0.1: on pages hosting the payment iframe, every script is inventoried, authorised by CSP, pinned with SRI and monitored through CSP reports. That is the SAQ A eligibility condition. SAQ D and onsite merchants must meet 6.4.3 and 11.6.1 in full (mandatory since 31 Mar 2025).
