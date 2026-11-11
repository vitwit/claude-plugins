---
name: deploy-security-gate
description: Security gate for shipping and running products at scale. Finds exposed API keys and secrets (source, git history, frontend/mobile bundles, Dockerfiles, CI workflows, coding-agent configs), reviews AI gateway / LLM, payment and analytics integrations, flags single points of failure, and produces a go/no-go report against a fixed checklist. Use this skill whenever the user is about to deploy, release, launch, go live or cut a production build; adds or changes an integration such as OpenAI, Anthropic, Bedrock, Vertex, an AI gateway, MCP server, Stripe, Razorpay, Adyen, PayPal, Segment, PostHog, Mixpanel, Sentry or Google Analytics; asks for a security audit, pre-launch review, hardening pass, key rotation or "are any of our keys exposed"; or sets up CI/CD, Docker, Terraform or Kubernetes, even if they never say "security".
---

# Deploy security gate

This skill enforces one checklist: **no key is ever exposed, and no single failure takes the product down**. It runs in three passes:

1. An automated scan with `scripts/scan.py`, which is fast, deterministic and read-only.
2. A code review of each detected integration, guided by `references/integrations.md`.
3. A manual gate for everything that can't be seen from the repo, such as provider dashboards, rotation, backups and drills. These items come from `references/checklist.md`.

The scan alone is not a pass. It covers roughly a third of the checklist. The value of this skill is in walking all three passes and being honest about what was verified and what still needs a human to confirm.

## Workflow

### 1. Scope

Work out what is shipping:

- the repo root
- frontend or mobile build output, if any
- the deployment target, such as containers, serverless or Kubernetes
- whether this is a first launch, a new integration or routine maintenance

If the user named a specific change, such as "adding Stripe", focus the review on it. Still run the full scan, because a leak elsewhere blocks the release just the same.

### 2. Run the scanner

```bash
python3 <skill-dir>/scripts/scan.py <repo> --history
```

- Add `--build-dir <dir>` for each built bundle (`dist`, `.next/static`, an unzipped APK/IPA). Shipped bundles are where "public" keys turn out to be secret ones. Common build directories are detected automatically; build the app first if none exist.
- `--format json` gives machine-readable output. `--fail-on high|medium|low|never` controls the exit code, which is useful in CI.
- The scanner masks secret values. Keep it that way in everything you write: never echo a full key into chat, files, commits or PR text, because that creates a second leak.

The scanner checks:

- secret patterns (AWS, Anthropic, OpenAI, Stripe live keys and webhook secrets, GitHub, GitLab, Slack, Google, npm, PyPI, SendGrid, Hugging Face, private keys, DB URLs with passwords, hard-coded `*_SECRET` / `*_TOKEN` assignments) in the working tree, build output and git history
- committed `.env` files and a missing `.gitignore` entry
- secret-looking variables behind client-exposed prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_` and similar), and direct LLM calls from client code
- source maps in build output
- GitHub Actions workflows: tag-pinned actions, `pull_request_target`, a missing `permissions:` block, echoed secrets, static cloud keys instead of OIDC, and installs that run lifecycle scripts
- Dockerfiles: secrets in `ARG`/`ENV`, copied `.env` files, and running as root
- payment webhook handlers with no signature verification
- coding-agent read access to `.env` files
- the integrations in use, plus single-provider (single point of failure) hints for AI and payments

### 3. Triage the findings

The scanner works by pattern matching, so confirm each finding by reading the code before you report it.

- **Live secret found** (in the tree, history or a bundle): treat it as leaked even if the repo is private. Follow `references/leaked-key-runbook.md`, where revoking comes first and cleanup comes later. Revoking or rotating a key changes production, so tell the user exactly which key, where it was found and the revocation step. Let them do it, or confirm before you do anything yourself.
- **False positive** (a test fixture, a documented public key): say why it's safe and move on.
- **Heuristic findings** (webhook verification, client-side LLM call): open the file and check the real control flow. Verification might live in middleware elsewhere.

### 4. Review each detected integration

For every integration the scanner listed, or that you find in the code, read the matching section of `references/integrations.md` and check the code against it. This step catches what patterns can't, such as:

- a backend proxy that is an open relay
- a model name taken from the request body
- amounts computed on the client
- tool calls that run with admin credentials
- PII sent to analytics
- RAG queries without a tenant filter

### 5. Check for single points of failure

Use checklist section 10 and look in code and IaC for:

- one LLM provider with no fallback
- HTTP clients to vendors with no timeout or retry
- vendor calls on the request path that block when analytics is down
- a single-region or single-zone database
- a secrets fetch with no cache
- one person who alone holds root or owner access, according to what the user tells you

### 6. Manual gate

Many checklist items can't be checked from a repo, for example:

- spend caps on provider dashboards
- rotation schedules
- SSO and MFA on vendor accounts
- backup restore tests
- failover drills
- DPAs
- PCI script inventory on payment pages

List these as **Needs confirmation**, each with a one-line question for the owner. Never mark them as passed on assumption. A gate that silently passes unverified items is worse than no gate.

### 7. Report

Use this structure so results are comparable across releases:

```markdown
# Security gate: <product / change> — <GO | NO-GO | GO WITH EXCEPTIONS>

## Blockers (must fix before deploy)
- [check id] file:line — what is wrong — the fix

## Should fix (this sprint)
- ...

## Integrations reviewed
| Integration | Server-side only | Scoped key + spend cap | Webhooks/outputs verified | Fallback | Notes |

## Needs confirmation (manual)
- [ ] <question for the owner> (checklist §n)

## Passed (verified)
- <item> — how it was verified
```

**Verdict rule:**

- **NO-GO:** any confirmed HIGH finding, which covers a live secret, a client-exposed secret key, an unverified payment webhook or a secret in CI logs.
- **GO WITH EXCEPTIONS:** only medium or low findings remain, and the user accepts them with an owner and a date.
- **GO:** nothing open, and every manual item has been confirmed.

## Fixing issues

When the user asks you to fix findings, prefer these remedies, which address the root cause rather than the symptom:

- **Key in code:** replace it with a runtime lookup, either from env injected by the secrets manager or through the provider's SDK. Add a placeholder to `.env.example`. Never write the real value anywhere. Tell the user the key still needs revoking, because removing it from code does not un-leak it.
- **Secret reaching the client:** move the call behind a backend route or AI gateway that authenticates the user, rate-limits per user and tenant, allowlists models and operations, and holds the key. Keep only publishable keys in the client.
- **Unverified webhook:** verify the signature on the raw body with the provider SDK. Reject stale timestamps, deduplicate by event ID and re-fetch the object from the provider before changing state.
- **CI issues:** pin actions to commit SHAs (resolve the SHA with `git ls-remote`, keep the tag in a comment). Add `permissions: contents: read`. Replace static cloud keys with OIDC. Use `npm ci --ignore-scripts`.
- **Docker issues:** use BuildKit `RUN --mount=type=secret` for build-time secrets and a non-root `USER`.
- **Agent access:** add `permissions.deny` entries `Read(./.env)` and `Read(./.env.*)` to `.claude/settings.json`. Recommend runtime injection (`doppler run`, `infisical run`, `op run`) so no plaintext file exists at all.

## Continuous use

Suggest wiring the scanner into CI so the gate runs on every PR, not just at launch:

```yaml
- run: python3 tools/deploy-security-gate/scripts/scan.py . --fail-on high
```

Also suggest a recurring review at the cadence in checklist section 12.

## Reference files

- `references/checklist.md`: the full checklist (sections 1–14), with each item tagged `[auto]` (scanner), `[code]` (code review) or `[manual]` (owner confirms). Read it for steps 5–6 and whenever you need the exact control.
- `references/integrations.md`: what good looks like for AI gateways and LLM providers, MCP servers, payments, analytics and auth, with patterns to look for. Read the sections for the integrations in scope.
- `references/leaked-key-runbook.md`: the step-by-step response when a live key is found, with revocation pointers per provider.
