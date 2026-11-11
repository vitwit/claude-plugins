# Vitwit Claude Code plugins

A [Claude Code](https://claude.com/claude-code) plugin marketplace maintained by [Vitwit](https://vitwit.com).

## Install

Add the marketplace, then install a plugin:

```
/plugin marketplace add vitwit/claude-skills
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
- `--history` — also scan all git history for secrets.
- `--format json` — machine-readable output.
- `--fail-on high|medium|low|never` — controls the exit code for CI (`0` = clean, `1` = findings at/above the threshold, `2` = usage error).

### Use it in CI

```yaml
- run: python3 deploy-security-gate/skills/deploy-security-gate/scripts/scan.py . --fail-on high
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

## License

[MIT](./LICENSE)
