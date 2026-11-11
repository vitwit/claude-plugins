# Vitwit Claude Code plugins

A [Claude Code](https://claude.com/claude-code) plugin marketplace maintained by [Vitwit](https://vitwit.com).

## Install

Add the marketplace, then install a plugin:

```
/plugin marketplace add vitwit/claude-plugins
/plugin install deploy-security-gate@vitwit
```

## Plugins

| Plugin | Description |
| --- | --- |
| [`deploy-security-gate`](./deploy-security-gate) | Pre-deploy security gate: finds exposed keys (source, git history, bundles, Dockerfiles, CI), reviews AI/payment/analytics integrations, flags single points of failure, and produces a go/no-go report. |

## deploy-security-gate

Enforces one checklist: **no key is ever exposed, and no single failure takes the product down.** It runs in three passes — an automated scan, a code review of each detected integration, and a manual gate for what can't be seen from the repo (dashboards, rotation, backups, drills).

The skill activates automatically when you are about to deploy, add an integration (OpenAI, Anthropic, Bedrock, Stripe, Razorpay, Segment, PostHog, Sentry, and more), or ask for a security audit or key-rotation check.

### Run the scanner directly

The scanner is standard-library Python 3, read-only, and never prints a full secret value:

```bash
python3 deploy-security-gate/skills/deploy-security-gate/scripts/scan.py <repo> --history
```

Useful flags:

- `--build-dir <dir>` — scan built frontend/mobile output (`dist`, `.next/static`, an unzipped APK/IPA). Repeatable.
- `--history` — also scan all git history for secrets (streamed, so large repos don't blow memory).
- `--entropy` — additionally flag high-entropy strings that no named pattern caught (low severity; catches custom/novel secrets).
- `--format json|sarif` — machine-readable output. `sarif` uploads to GitHub code scanning (Security tab).
- `--fail-on high|medium|low|never` — controls the exit code for CI (`0` = clean, `1` = findings at/above the threshold, `2` = usage error).

### Suppressing findings

Confirmed false positives can be suppressed two ways:

- **Inline:** add `# security-gate: allow` (or `# pragma: allowlist secret`) to the flagged line.
- **Baseline:** a `.security-gate-ignore` file at the repo root. One rule per line:

  ```
  secret:stripe-test-secret        # ignore a check everywhere
  path:vendored/**                 # ignore a path glob
  secret:high-entropy-string *test_*.py   # ignore a check within matching paths
  ```

### Use it in CI

```yaml
- run: python3 deploy-security-gate/skills/deploy-security-gate/scripts/scan.py . --fail-on high
```

### Tests

The scanner has a standard-library regression suite (no dependencies):

```bash
cd deploy-security-gate/skills/deploy-security-gate/scripts
python3 -m unittest test_scan
```

## Repository layout

```
.claude-plugin/marketplace.json   Marketplace manifest
deploy-security-gate/
  .claude-plugin/plugin.json       Plugin manifest
  skills/deploy-security-gate/
    SKILL.md                       Skill instructions and workflow
    scripts/scan.py                Static scanner (stdlib only)
    references/
      checklist.md                 Full checklist (sections 1–14)
      integrations.md              What good looks like per integration
      leaked-key-runbook.md        Response steps when a live key is found
```

## Changelog

See [CHANGELOG.md](./CHANGELOG.md). Releases are versioned per plugin via the `version`
field in `plugin.json` (mirrored in `marketplace.json`); git tags mark release points.

## License

[MIT](./LICENSE)
