# Changelog

All notable changes to this repository are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the plugins follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each plugin's version is
declared in its `plugin.json` and mirrored in `.claude-plugin/marketplace.json`.

## [Unreleased]

## [1.0.0] — 2026-11-11

Initial release of the `deploy-security-gate` plugin and the `vitwit` marketplace.

### Added

- **`deploy-security-gate` skill** — a pre-deploy security gate that runs in three passes:
  an automated scan, a per-integration code review, and a manual gate for what can't be
  seen from the repo. Activates on deploy/release, new integrations, or a security-audit
  request.
- **Scanner (`scripts/scan.py`)** — standard-library, read-only, secret-masking. Covers:
  - Secrets in the working tree, build output, and git history for AWS, Anthropic, OpenAI,
    OpenRouter, Groq, xAI, Perplexity, Replicate, fal, Google (API keys and OAuth secrets),
    Stripe, Razorpay, GitHub, GitLab, Slack, GCP, npm, PyPI, SendGrid, Hugging Face,
    DigitalOcean, New Relic, Shopify, Square, Databricks, Doppler, PlanetScale, Linear,
    Azure Storage, Mailgun, Telegram, Discord, JWTs, private keys, DB URLs, and hard-coded
    `*_SECRET` / `*_TOKEN` / `*_SERVICE_ROLE` assignments (quoted — including JSON/MCP
    configs — or unquoted).
  - Committed `.env` files and `.gitignore` coverage, client-exposed env prefixes and
    client-side LLM calls, build-output secrets and source maps, GitHub Actions hardening
    (unpinned actions, `pull_request_target`, missing `permissions`, secret echo/`$GITHUB_ENV`
    writes, static cloud keys, install scripts), Dockerfile secrets and root user, payment
    webhook signature verification, coding-agent `.env` access, and single-point-of-failure
    hints for AI and payments.
  - `--entropy` pass for high-entropy strings no named pattern catches.
  - `--history` streamed scan of all git history (bounded memory, 5-minute budget).
  - Output as Markdown, JSON, or SARIF; `--fail-on` for CI exit codes.
  - Suppression via a `.security-gate-ignore` baseline or inline `# security-gate: allow`.
- **Reference docs** — `checklist.md` (sections 1–14, including indirect prompt injection,
  file-upload validation, and SSRF), `integrations.md`, and `leaked-key-runbook.md`.
- **Regression suite** — 34 standard-library unit tests (`scripts/test_scan.py`).
- **Marketplace** — `.claude-plugin/marketplace.json`, installable via
  `/plugin marketplace add vitwit/claude-plugins`.
- **CI** — unit tests, a `--fail-on high` self-scan, and `claude plugin validate --strict`
  on both the marketplace and plugin manifests.

[Unreleased]: https://github.com/vitwit/claude-plugins/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vitwit/claude-plugins/releases/tag/v1.0.0
