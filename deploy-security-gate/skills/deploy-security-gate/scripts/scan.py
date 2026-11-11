#!/usr/bin/env python3
"""deploy-security-gate scanner.

Static, read-only checks for the "Security Checklist: Deploying & Maintaining
Products at Scale". Standard library only. It never prints a full secret value.

Usage:
    python3 scan.py <repo> [--build-dir DIR ...] [--history] [--entropy]
                           [--format md|json|sarif] [--fail-on high|medium|low|never]

Findings can be suppressed with a `.security-gate-ignore` file at the repo root or an
inline `# security-gate: allow` comment on the flagged line.

Exit codes: 0 = no findings at or above --fail-on, 1 = findings at or above it,
2 = usage error.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", ".terraform", "coverage", ".turbo", ".cache",
    "bower_components", "Pods", ".gradle", "target",
}
BUILD_DIR_CANDIDATES = ["dist", "build", "out", ".next/static", ".output/public", "public/build"]
MAX_FILE_BYTES = 2_000_000
# Shipped bundles are routinely larger than MAX_FILE_BYTES and are the whole point
# of the build-output pass, so they get a much higher cap.
BUILD_MAX_FILE_BYTES = 25_000_000
TEXT_EXT_BLOCKLIST = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wasm", ".jar", ".class",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".lock",
}

# ---------------------------------------------------------------- patterns
# (id, label, regex, severity). Live/secret keys are high; test keys low.
SECRET_PATTERNS = [
    ("aws-access-key", "AWS access key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("anthropic-key", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "high"),
    ("openai-key", "OpenAI API key", r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}", "high"),
    ("stripe-live-secret", "Stripe live secret/restricted key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}", "high"),
    ("stripe-webhook-secret", "Stripe webhook signing secret", r"\bwhsec_[A-Za-z0-9]{20,}", "high"),
    ("stripe-test-secret", "Stripe test secret key", r"\b(?:sk|rk)_test_[A-Za-z0-9]{20,}", "low"),
    ("github-token", "GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}", "high"),
    ("gitlab-token", "GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}", "high"),
    ("slack-token", "Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", "high"),
    ("slack-webhook", "Slack webhook URL", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", "medium"),
    ("google-api-key", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "medium"),
    ("gcp-service-account", "GCP service-account private key JSON", r"\"type\":\s*\"service_account\"", "high"),
    ("private-key", "Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY", "high"),
    ("npm-token", "npm token", r"\bnpm_[A-Za-z0-9]{36}\b", "high"),
    ("pypi-token", "PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "high"),
    ("sendgrid-key", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high"),
    ("twilio-key", "Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", "medium"),
    ("huggingface-token", "Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b", "high"),
    ("db-url-with-password", "Connection string with inline password",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^:\s/'\"]+:[^@\s'\"]{6,}@[^\s'\"]+", "high"),
    ("slack-app-token", "Slack app-level token", r"\bxapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+", "high"),
    ("digitalocean-token", "DigitalOcean personal access token", r"\bdop_v1_[a-f0-9]{64}\b", "high"),
    ("new-relic-key", "New Relic API key", r"\bNRAK-[A-Z0-9]{27}\b", "high"),
    ("shopify-token", "Shopify access token", r"\bshp(?:at|ss|pa|ca)_[a-fA-F0-9]{32}\b", "high"),
    ("square-token", "Square OAuth secret", r"\bsq0csp-[A-Za-z0-9_\-]{43}\b", "high"),
    ("databricks-token", "Databricks personal access token", r"\bdapi[0-9a-f]{32}\b", "high"),
    ("doppler-token", "Doppler token", r"\bdp\.(?:pt|st|sa|ct|scim)\.[A-Za-z0-9]{40,44}\b", "high"),
    ("planetscale-token", "PlanetScale token", r"\bpscale_(?:pw|tkn)_[A-Za-z0-9_\-]{32,}\b", "high"),
    ("linear-key", "Linear API key", r"\blin_api_[A-Za-z0-9]{40}\b", "high"),
    ("azure-storage-key", "Azure Storage account key", r"AccountKey=[A-Za-z0-9+/]{86}==", "high"),
    ("telegram-bot-token", "Telegram bot token", r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{32,35}\b", "medium"),
    ("discord-webhook", "Discord webhook URL", r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9_\-]{60,}", "medium"),
    ("mailgun-key", "Mailgun API key", r"\bkey-[0-9a-f]{32}\b", "medium"),
    ("jwt", "JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "low"),
]
_SECRET_NAME = r"[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH_?TOKEN|TOKEN|SERVICE_ROLE|CREDENTIALS?)[A-Z0-9_]*"
# Inter-token whitespace is horizontal only ([ \t]); a blank/empty value such as
# `API_KEY=` must not let the match run onto the next line and capture the next
# variable (that produced .env.example false positives).
GENERIC_ASSIGN = re.compile(r"(?ix)\b(" + _SECRET_NAME + r')[ \t]*[:=][ \t]*["\']([^"\'\s]{16,})["\']')
# Unquoted assignments: env/YAML/TOML/INI style (`API_KEY=abc…`, `password: abc…`).
# Only applied to config-ish files to avoid matching expressions in real code.
GENERIC_ASSIGN_UNQUOTED = re.compile(r"(?ix)(?:^|\b)(" + _SECRET_NAME + r")[ \t]*[:=][ \t]*([^\s\"'#]{16,})")
CONFIG_SUFFIXES = {".yml", ".yaml", ".toml", ".ini", ".properties", ".conf", ".cfg", ".env"}
ENV_FILE_RX = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$")
# High-confidence live-credential formats: never downgrade these, even in a test or
# example path. A real AKIA/sk-ant/sk_live value in a fixture is still a leaked key.
NEVER_DOWNGRADE = {
    "aws-access-key", "anthropic-key", "openai-key", "stripe-live-secret", "stripe-webhook-secret",
    "github-token", "gitlab-token", "slack-token", "gcp-service-account", "private-key",
    "npm-token", "pypi-token", "sendgrid-key", "huggingface-token", "db-url-with-password",
    "slack-app-token", "digitalocean-token", "new-relic-key", "shopify-token", "square-token",
    "databricks-token", "doppler-token", "planetscale-token", "linear-key", "azure-storage-key",
}

# Entropy detection: catch custom/novel secrets no vendor regex knows. Deliberately
# conservative (low severity, tight heuristics) to stay usable in CI.
ENTROPY_STRING_RX = re.compile(r"""["'`]([A-Za-z0-9+/_\-]{24,}={0,2})["'`]""")
ENTROPY_FILE_SKIP = re.compile(
    r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|Cargo\.lock|composer\.lock|"
    r"Gemfile\.lock|poetry\.lock)$|\.min\.(js|css)$|\.map$|\.snap$", re.I)
ENTROPY_LINE_SKIP = re.compile(r"sha(1|256|384|512)|integrity|checksum|digest|data:|base64,|-----BEGIN", re.I)
ENTROPY_EXT_SKIP = {".md", ".rst", ".txt", ".csv", ".svg"}
ENTROPY_MIN_BITS = 4.0
# Split into two groups. STRUCTURAL hints are matched as substrings (they can't be
# part of a real secret). WORD hints are English words that routinely appear *inside*
# real tokens ("latest" contains "test", "yourco" contains "your"), so they are only
# treated as placeholders when they stand alone, i.e. not flanked by other letters.
PLACEHOLDER_STRUCTURAL = ("xxx", "<", "${", "{{", "process.env", "os.environ", "getenv", "****", "...")
PLACEHOLDER_WORDS = (
    "example", "your", "changeme", "change_me", "placeholder", "dummy", "sample",
    "redacted", "todo", "fake", "test", "secret_here", "insert",
)

PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "NUXT_PUBLIC_",
                   "GATSBY_", "PUBLIC_", "VUE_APP_")
PUBLIC_ENV_RX = re.compile(r"\b(" + "|".join(sorted(PUBLIC_PREFIXES, key=len, reverse=True)) + r")([A-Z0-9_]+)")
SECRETISH_NAME = re.compile(
    r"SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|ADMIN|(?<!PUBLISHABLE_)(?<!PUBLIC_)API_?KEY(?!_ID)"
    r"|OPENAI|ANTHROPIC|GEMINI|MISTRAL|GROQ|COHERE|STRIPE_SK|SK_LIVE|WEBHOOK|DATABASE_URL|TOKEN"
)
PUBLIC_OK_NAME = re.compile(r"PUBLISHABLE|PUBLIC_KEY|_PK_|ANON_KEY|SITE_KEY|MEASUREMENT_ID|WRITE_KEY|DSN|CLIENT_ID|POSTHOG_KEY")

CLIENT_LLM = re.compile(r"dangerouslyAllowBrowser\s*:\s*true|https://api\.(?:openai|anthropic)\.com|generativelanguage\.googleapis\.com")

INTEGRATIONS = {
    "ai": {
        "openai": "OpenAI", "@anthropic-ai/sdk": "Anthropic", "anthropic": "Anthropic",
        "@aws-sdk/client-bedrock-runtime": "AWS Bedrock", "boto3": "AWS SDK (check Bedrock)",
        "@google-cloud/vertexai": "Google Vertex AI", "google-genai": "Google Gemini",
        "@google/genai": "Google Gemini", "@google/generative-ai": "Google Gemini",
        "litellm": "LiteLLM gateway", "portkey-ai": "Portkey gateway", "ai": "Vercel AI SDK",
        "@ai-sdk/openai": "Vercel AI SDK (OpenAI)", "@ai-sdk/anthropic": "Vercel AI SDK (Anthropic)",
        "langchain": "LangChain", "@langchain/core": "LangChain", "llamaindex": "LlamaIndex",
        "groq-sdk": "Groq", "mistralai": "Mistral", "@mistralai/mistralai": "Mistral", "cohere": "Cohere",
        "@modelcontextprotocol/sdk": "MCP", "mcp": "MCP",
    },
    "payments": {
        "stripe": "Stripe", "@stripe/stripe-js": "Stripe.js (client)", "razorpay": "Razorpay",
        "@adyen/api-library": "Adyen", "braintree": "Braintree", "@paypal/checkout-server-sdk": "PayPal",
        "paddle": "Paddle", "@paddle/paddle-node-sdk": "Paddle", "@lemonsqueezy/lemonsqueezy.js": "Lemon Squeezy",
    },
    "analytics": {
        "@segment/analytics-node": "Segment", "@segment/analytics-next": "Segment", "analytics-node": "Segment",
        "posthog-js": "PostHog", "posthog-node": "PostHog", "posthog": "PostHog", "mixpanel": "Mixpanel",
        "mixpanel-browser": "Mixpanel", "@amplitude/analytics-browser": "Amplitude",
        "@sentry/node": "Sentry", "@sentry/nextjs": "Sentry", "@sentry/react": "Sentry", "sentry-sdk": "Sentry",
        "dd-trace": "Datadog", "@datadog/browser-rum": "Datadog RUM", "@vercel/analytics": "Vercel Analytics",
        "react-ga4": "Google Analytics", "@rudderstack/analytics-js": "RudderStack", "logrocket": "LogRocket",
        "@fullstory/browser": "FullStory", "hotjar": "Hotjar",
    },
}

WEBHOOK_RULES = [
    # (integration label, regex marking a webhook handler, regex marking verification)
    ("Stripe", re.compile(r"stripe", re.I), re.compile(r"constructEvent|construct_event|verifyHeader|verify_header|Webhook\.construct")),
    ("Razorpay", re.compile(r"razorpay", re.I), re.compile(r"validateWebhookSignature|verify_webhook_signature|verifyWebhook")),
    ("PayPal", re.compile(r"paypal", re.I), re.compile(r"verify-webhook-signature|verifyWebhookSignature")),
    ("GitHub", re.compile(r"x-hub-signature", re.I), re.compile(r"timingSafeEqual|compare_digest|verify")),
]


@dataclass
class Finding:
    severity: str
    check: str
    ref: str
    location: str
    detail: str


@dataclass
class Report:
    repo: str
    findings: list = field(default_factory=list)
    integrations: dict = field(default_factory=dict)
    scanned_files: int = 0
    notes: list = field(default_factory=list)
    reported_values: set = field(default_factory=set)

    def add(self, severity, check, ref, location, detail):
        self.findings.append(Finding(severity, check, ref, location, detail))


# ---------------------------------------------------------------- helpers
def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 10:
        return value[:2] + "…" + f" ({len(value)} chars)"
    return f"{value[:6]}…{value[-2:]} ({len(value)} chars)"


KEY_PLACEHOLDER_STRUCTURAL = ("xxxx", "<", "${", "{{", "****", "...")
KEY_PLACEHOLDER_WORDS = ("example", "your", "placeholder", "dummy", "redacted", "changeme")


def _word_present(word: str, low: str) -> bool:
    # A standalone occurrence: not flanked by other ASCII letters. Underscores, digits
    # and punctuation count as boundaries, so "your_token" matches but "yourcompany"
    # and "latest" do not.
    return re.search(r"(?<![a-z])" + re.escape(word) + r"(?![a-z])", low) is not None


def is_placeholder(value: str, strict: bool = False) -> bool:
    """strict=True for values that already match a known key format (narrower hint list)."""
    low = value.lower()
    structural = KEY_PLACEHOLDER_STRUCTURAL if strict else PLACEHOLDER_STRUCTURAL
    words = KEY_PLACEHOLDER_WORDS if strict else PLACEHOLDER_WORDS
    if any(h in low for h in structural):
        return True
    if any(_word_present(w, low) for w in words):
        return True
    if len(set(value)) <= 3:  # "aaaaaaaa", "00000000"
        return True
    return False


def run_git(repo: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", errors="replace")


def list_files(repo: Path) -> tuple[list[Path], bool]:
    tracked = run_git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if tracked is not None:
        files = [repo / p for p in tracked.split("\0") if p]
        return [f for f in files if f.is_file() and not (set(f.relative_to(repo).parts) & SKIP_DIRS)], True
    files = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        files.extend(Path(root) / n for n in names)
    return files, False


def read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str | None:
    if path.suffix.lower() in TEXT_EXT_BLOCKLIST:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)  # read a prefix rather than skip large files
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def rel(repo: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo))
    except ValueError:
        return str(path)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def shannon_bits(s: str) -> float:
    from math import log2
    n = len(s)
    if n == 0:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((c / n) * log2(c / n) for c in counts.values())


def looks_like_secret_blob(s: str) -> bool:
    # Require a base64-ish mix (lower + upper + digit) so plain hex digests, English
    # words and all-one-case identifiers don't trip the entropy check.
    return (any(c.islower() for c in s) and any(c.isupper() for c in s)
            and any(c.isdigit() for c in s))


# ---------------------------------------------------------------- checks
def scan_secrets(report: Report, repo: Path, path: Path, text: str, where: str = "source"):
    is_example = re.search(r"(example|sample|template|\.dist)$|\.example\.|fixtures?/|__tests__|/tests?/", rel(repo, path), re.I)
    for pid, label, rx, sev in SECRET_PATTERNS:
        for m in re.finditer(rx, text):
            value = m.group(0)
            if is_placeholder(value, strict=True) and pid not in ("private-key", "gcp-service-account"):
                continue
            report.reported_values.add(value)
            s = sev
            # Only downgrade in example/test paths for weaker heuristics; a high-confidence
            # live-credential format is a leaked key wherever it sits.
            if is_example and s == "high" and pid not in NEVER_DOWNGRADE:
                s = "medium"
            report.add(s, f"secret:{pid}", "1 Secrets / 13 Gate",
                       f"{rel(repo, path)}:{line_of(text, m.start())}",
                       f"{label} in {where}: {mask(value)}")
    if where == "source" and path.suffix.lower() not in (".md", ".rst", ".txt"):
        r = rel(repo, path)
        is_config = path.suffix.lower() in CONFIG_SUFFIXES or ENV_FILE_RX.search(r)
        patterns = [GENERIC_ASSIGN]
        if is_config:
            patterns.append(GENERIC_ASSIGN_UNQUOTED)
        seen_spans: set[tuple[int, int]] = set()
        for rx in patterns:
            for m in rx.finditer(text):
                name, value = m.group(1), m.group(2).strip()
                span = (m.start(2), m.end(2))
                if span in seen_spans:
                    continue
                seen_spans.add(span)
                if len(value) < 16 or is_placeholder(value) or PUBLIC_OK_NAME.search(name.upper()):
                    continue
                if any(re.fullmatch(prx, value) for _, _, prx, _ in SECRET_PATTERNS):
                    continue  # already reported
                report.add("medium", "secret:hardcoded-assignment", "1 Secrets",
                           f"{r}:{line_of(text, m.start())}",
                           f"Hard-coded value assigned to `{name}`: {mask(value)}")


def check_entropy(report: Report, repo: Path, path: Path, text: str):
    """Flag high-entropy string literals that no named pattern caught. Low severity:
    these are candidates to verify, not confirmed secrets."""
    r = rel(repo, path)
    if ENTROPY_FILE_SKIP.search(r) or path.suffix.lower() in ENTROPY_EXT_SKIP:
        return
    for m in ENTROPY_STRING_RX.finditer(text):
        value = m.group(1)
        if value in report.reported_values or is_placeholder(value):
            continue
        if not looks_like_secret_blob(value) or shannon_bits(value) < ENTROPY_MIN_BITS:
            continue
        ls = text.rfind("\n", 0, m.start()) + 1
        le = text.find("\n", m.end())
        line = text[ls: le if le != -1 else len(text)]
        if ENTROPY_LINE_SKIP.search(line):
            continue
        report.reported_values.add(value)
        report.add("low", "secret:high-entropy-string", "1 Secrets",
                   f"{r}:{line_of(text, m.start())}",
                   f"High-entropy string ({shannon_bits(value):.1f} bits/char), no known format: "
                   f"{mask(value)}. Verify it is not a secret.")


def gitignore_covers_env(gi: Path) -> bool:
    """True only if a .gitignore line actually matches the `.env` file itself.
    A line like `.env.local` or `.envrc` does not count (substring matching is wrong)."""
    try:
        lines = gi.read_text(errors="replace").splitlines()
    except OSError:
        return False
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.lstrip("/").rstrip("/")
        if fnmatch.fnmatch(".env", line):
            return True
    return False


def check_env_files(report: Report, repo: Path, files: list[Path], is_git: bool):
    env_rx = ENV_FILE_RX
    ok_rx = re.compile(r"\.(example|sample|template|dist|defaults)$")
    tracked = set()
    if is_git:
        out = run_git(repo, "ls-files", "-z") or ""
        tracked = {p for p in out.split("\0") if p}
    for f in files:
        r = rel(repo, f)
        if env_rx.search(r) and not ok_rx.search(r):
            if r in tracked:
                report.add("high", "env-file-committed", "1 Secrets", r,
                           "Environment file is committed to git. Remove it, purge history, and rotate every value in it.")
            elif is_git:
                pass  # untracked and ignored: fine for local dev, but see agent rule below
            else:
                report.add("low", "env-file-present", "1 Secrets", r,
                           "Plaintext env file on disk. Prefer runtime injection from the secrets manager.")
    gi = repo / ".gitignore"
    has_env = any(env_rx.search(rel(repo, f)) for f in files) or (repo / ".env").exists()
    if (is_git or has_env) and not (gi.exists() and gitignore_covers_env(gi)):
        report.add("medium", "gitignore-env", "1 Secrets", ".gitignore",
                   "`.env` files are not ignored by git.")


def check_client_exposure(report: Report, repo: Path, path: Path, text: str):
    r = rel(repo, path)
    for m in PUBLIC_ENV_RX.finditer(text):
        name = m.group(1) + m.group(2)
        if SECRETISH_NAME.search(m.group(2)) and not PUBLIC_OK_NAME.search(name):
            report.add("high", "client-exposed-env", "2 Client & edge",
                       f"{r}:{line_of(text, m.start())}",
                       f"`{name}` uses a client-exposed prefix but its name suggests a secret. "
                       "Anything with this prefix is inlined into the browser bundle.")
    is_client = (
        re.search(r"(^|/)(components|app|pages|src|client|frontend|web)/", r)
        and not re.search(r"(^|/)(api|server|functions|lambda|backend|routes/api)/|route\.(t|j)s$|\.server\.", r)
        and path.suffix in (".tsx", ".jsx", ".ts", ".js", ".vue", ".svelte")
    ) or "\"use client\"" in text or "'use client'" in text
    if is_client:
        for m in CLIENT_LLM.finditer(text):
            report.add("high", "client-llm-call", "2 Client & edge / 3 AI",
                       f"{r}:{line_of(text, m.start())}",
                       "LLM provider called from client-side code. Route it through the backend/AI gateway so the key never ships to browsers.")


def check_build_output(report: Report, repo: Path, build_dirs: list[Path]):
    for bd in build_dirs:
        if not bd.is_dir():
            continue
        maps = 0
        for root, _, names in os.walk(bd):
            for n in names:
                p = Path(root) / n
                if n.endswith(".map"):
                    maps += 1
                    continue
                if p.suffix.lower() in (".js", ".mjs", ".cjs", ".html", ".json", ".css", ".txt", ".xml"):
                    # Shipped bundles are often larger than the default cap; use the build cap.
                    text = read_text(p, max_bytes=BUILD_MAX_FILE_BYTES)
                    if text:
                        scan_secrets(report, repo, p, text, where="build output")
        if maps:
            report.add("medium", "source-maps-in-build", "2 Client & edge", rel(repo, bd),
                       f"{maps} source map file(s) in build output. Upload them privately to the error tracker instead of serving them.")


def check_workflows(report: Report, repo: Path):
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    for wf in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        text = read_text(wf) or ""
        r = rel(repo, wf)
        for m in re.finditer(r"uses:\s*['\"]?([^\s'\"#]+)@([^\s'\"#]+)", text):
            action, ref = m.group(1), m.group(2)
            if action.startswith("./") or action.startswith("docker://"):
                continue
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                report.add("medium", "ci-unpinned-action", "8 CI/CD / 14 Supply chain",
                           f"{r}:{line_of(text, m.start())}",
                           f"`{action}@{ref}` is pinned to a tag or branch. Pin to a full commit SHA (tags were repointed in the tj-actions attack).")
        if re.search(r"^\s*pull_request_target\s*:", text, re.M) or re.search(r"on:\s*\[?[^\n]*pull_request_target", text):
            report.add("high", "ci-pull-request-target", "8 CI/CD", r,
                       "`pull_request_target` runs with secrets on fork PRs. Make sure it never checks out or runs PR code.")
        if not re.search(r"^permissions\s*:", text, re.M):
            report.add("medium", "ci-no-permissions", "8 CI/CD / 14 Supply chain", r,
                       "No top-level `permissions:` block. Set it explicitly (default `contents: read`).")
        for m in re.finditer(r"(echo|printf)[^\n]*\$\{\{\s*secrets\.", text):
            report.add("high", "ci-secret-echo", "8 CI/CD", f"{r}:{line_of(text, m.start())}",
                       "A secret is echoed in a run step; it may reach logs or files.")
        for m in re.finditer(r"(?m)^.*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}.*$", text):
            line = m.group(0)
            if re.search(r"echo|printf", line):
                continue  # already covered by ci-secret-echo
            if re.search(r">>|>\s|\btee\b|\$GITHUB_ENV|\$GITHUB_OUTPUT|::set-output|::save-state", line):
                report.add("high", "ci-secret-to-file", "8 CI/CD", f"{r}:{line_of(text, m.start())}",
                           "A secret is written to a file, `$GITHUB_ENV` or `$GITHUB_OUTPUT`; "
                           "it can persist on disk or leak into later steps and logs.")
        for m in re.finditer(r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_CREDENTIALS|AZURE_CREDENTIALS|GCP_SA_KEY)\s*:\s*\$\{\{\s*secrets\.", text):
            report.add("medium", "ci-static-cloud-keys", "8 CI/CD / 14 NHI",
                       f"{r}:{line_of(text, m.start())}",
                       f"Long-lived cloud credential `{m.group(1)}` stored as a CI secret. Use OIDC federation instead.")
        for m in re.finditer(r"\b(npm (?:ci|install|i)|yarn install|pnpm install)\b(?![^\n]*--ignore-scripts)", text):
            report.add("low", "ci-install-scripts", "14 Supply chain", f"{r}:{line_of(text, m.start())}",
                       f"`{m.group(1)}` runs package lifecycle scripts. Use `--ignore-scripts` and allowlist exceptions (Shai-Hulud ran at install time).")


def check_dockerfiles(report: Report, repo: Path, files: list[Path]):
    for f in files:
        # Matches Dockerfile, Dockerfile.prod, app.Dockerfile, api.dockerfile, Containerfile.
        if not re.search(r"(?i)(?:^|\.)(?:docker|container)file(?:$|\.)", f.name):
            continue
        text = read_text(f) or ""
        r = rel(repo, f)
        for m in re.finditer(r"^\s*(ARG|ENV)\s+([A-Z0-9_]*(SECRET|PASSWORD|TOKEN|API_?KEY|PRIVATE)[A-Z0-9_]*)", text, re.M | re.I):
            report.add("high", "docker-secret-arg", "1 Secrets / 7 Infra", f"{r}:{line_of(text, m.start())}",
                       f"`{m.group(1)} {m.group(2)}` bakes a secret into image layers or metadata. Use BuildKit `--mount=type=secret` or runtime injection.")
        for m in re.finditer(r"^\s*(COPY|ADD)\s+[^\n]*\.env\b", text, re.M):
            report.add("high", "docker-copies-env", "1 Secrets", f"{r}:{line_of(text, m.start())}",
                       "An env file is copied into the image.")
        if not re.search(r"^\s*USER\s+(?!root\b)", text, re.M):
            report.add("low", "docker-runs-as-root", "7 Infra", r, "No non-root `USER` instruction.")


def check_webhooks(report: Report, repo: Path, path: Path, text: str):
    if path.suffix.lower() not in (".ts", ".js", ".mjs", ".py", ".rb", ".go", ".php", ".java", ".kt", ".cs"):
        return
    r = rel(repo, path)
    if not re.search(r"webhook", r + text[:20000], re.I):
        return
    for label, marker, verify in WEBHOOK_RULES:
        if marker.search(text) and re.search(r"webhook", text, re.I) and not verify.search(text):
            report.add("high", "webhook-unverified", "4 Payments", r,
                       f"{label} webhook handling found without signature verification in this file. Confirm verification happens before any state change.")


def check_agent_config(report: Report, repo: Path, files: list[Path]):
    settings = repo / ".claude" / "settings.json"
    has_env = any(re.search(r"(^|/)\.env", rel(repo, f)) for f in files)
    if has_env or (repo / ".env").exists():
        denied = False
        if settings.exists():
            denied = bool(re.search(r"Read\([^)]*\.env", settings.read_text(errors="replace")))
        if not denied:
            report.add("low", "agent-env-deny", "14 AI coding agents", ".claude/settings.json",
                       "Env files exist but no `permissions.deny` rule like `Read(./.env)` / `Read(./.env.*)`. "
                       "`.gitignore` does not stop coding agents reading them.")


def detect_integrations(report: Report, repo: Path, files: list[Path]):
    deps: set[str] = set()
    for f in files:
        name = f.name
        text = None
        if name == "package.json" and "node_modules" not in f.parts:
            text = read_text(f)
            if text:
                try:
                    pj = json.loads(text)
                    for key in ("dependencies", "devDependencies", "peerDependencies"):
                        deps.update((pj.get(key) or {}).keys())
                except json.JSONDecodeError:
                    pass
        elif name in ("requirements.txt", "pyproject.toml", "Pipfile", "go.mod", "Gemfile", "composer.json"):
            text = read_text(f) or ""
            for tok in re.findall(r"[A-Za-z0-9@/_.\-]+", text):
                tok = tok.lower()
                deps.add(tok)
                # Path-style deps (go.mod: github.com/sashabaranov/go-openai) stay one token,
                # so add the final path segment and its last hyphen piece (len>=4 to avoid
                # matching short names like "ai" against unrelated modules).
                if "/" in tok:
                    seg = tok.rsplit("/", 1)[-1]
                    deps.add(seg)
                    tail = seg.rsplit("-", 1)[-1]
                    if len(tail) >= 4:
                        deps.add(tail)
    for cat, table in INTEGRATIONS.items():
        found = sorted({label for pkg, label in table.items() if pkg in deps})
        if found:
            report.integrations[cat] = found
    ai = [x for x in report.integrations.get("ai", []) if "gateway" not in x.lower() and x not in ("MCP", "LangChain", "LlamaIndex")]
    if len(set(ai)) == 1 and not any("gateway" in x.lower() for x in report.integrations.get("ai", [])):
        report.add("info", "single-ai-provider", "10 Resilience / 3 AI", "dependencies",
                   f"Only one LLM provider detected ({ai[0]}). Confirm a fallback provider or region and a degraded mode.")
    if len(report.integrations.get("payments", [])) == 1:
        report.add("info", "single-payment-processor", "10 Resilience / 4 Payments", "dependencies",
                   "One payment processor detected. Confirm the outage plan (queued retries, customer messaging, secondary processor).")


def scan_history(report: Report, repo: Path, budget_seconds: int = 300):
    """Stream `git log -p` line by line so a large monorepo's history does not have
    to fit in memory. Stops after budget_seconds and notes the truncation."""
    import time
    try:
        proc = subprocess.Popen(
            ["git", "-C", str(repo), "log", "--all", "-p", "--no-color", "--unified=0", "--format=COMMIT %h"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        report.notes.append("Git history scan skipped (not a git repo or git failed).")
        return
    if proc.stdout is None:
        return
    commit, fname = "?", "?"
    seen = set(report.reported_values)
    deadline = time.monotonic() + budget_seconds
    produced = truncated = False
    for raw in proc.stdout:
        if time.monotonic() > deadline:
            truncated = True
            proc.kill()
            break
        line = raw.decode("utf-8", errors="replace").rstrip("\n")
        if line.startswith("COMMIT "):
            commit, produced = line[7:], True
        elif line.startswith("+++ b/"):
            fname = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            for pid, label, rx, sev in SECRET_PATTERNS:
                for m in re.finditer(rx, line):
                    value = m.group(0)
                    if is_placeholder(value, strict=True) and pid not in ("private-key", "gcp-service-account"):
                        continue
                    if value in seen:
                        continue
                    seen.add(value)
                    report.add(sev, f"history:{pid}", "1 Secrets / 11 Runbook", f"{fname} @ {commit}",
                               f"{label} in git history: {mask(value)}. Treat as leaked: revoke, then purge.")
    proc.stdout.close()
    rc = proc.wait()
    if truncated:
        report.notes.append(f"Git history scan stopped after {budget_seconds}s; some history was not scanned.")
    elif not produced and rc != 0:
        report.notes.append("Git history scan skipped (not a git repo or git failed).")


# ---------------------------------------------------------------- output
def render_md(report: Report) -> str:
    fs = sorted(report.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.check, f.location))
    counts = {s: sum(1 for f in fs if f.severity == s) for s in SEVERITY_ORDER}
    out = [f"# Security gate scan: {report.repo}", "",
           f"Files scanned: {report.scanned_files}. Findings: "
           + ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low", "info")), ""]
    if report.integrations:
        out.append("## Integrations detected")
        out.append("")
        for cat, items in report.integrations.items():
            out.append(f"- **{cat}**: {', '.join(items)}")
        out.append("")
    out.append("## Findings")
    out.append("")
    if not fs:
        out.append("No automated findings. Automated checks cover only part of the checklist; run the manual review.")
    else:
        out.append("| Severity | Check | Checklist | Location | Detail |")
        out.append("| --- | --- | --- | --- | --- |")
        for f in fs:
            detail = f.detail.replace("|", "\\|")
            out.append(f"| {f.severity.upper()} | {f.check} | {f.ref} | `{f.location}` | {detail} |")
    if report.notes:
        out += ["", "## Notes", ""] + [f"- {n}" for n in report.notes]
    return "\n".join(out) + "\n"


SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def _location_path_line(location: str) -> tuple[str, int]:
    path = location.split(" @ ", 1)[0]
    m = re.search(r":(\d+)$", path)
    if m:
        return path[:m.start()], int(m.group(1))
    return path, 1


def render_sarif(report: Report) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in report.findings:
        rules.setdefault(f.check, {"id": f.check, "name": f.check,
                                   "shortDescription": {"text": f.check},
                                   "properties": {"checklist": f.ref}})
        path, line = _location_path_line(f.location)
        results.append({
            "ruleId": f.check,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.detail},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": line}}}],
            "properties": {"severity": f.severity},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "deploy-security-gate",
                "informationUri": "https://github.com/vitwit/claude-plugins",
                "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------- allowlist
ALLOW_MARKER_RX = re.compile(r"security-gate:\s*(?:allow|ignore)|pragma:\s*allowlist\s+secret", re.I)


def load_ignore_rules(repo: Path) -> list[tuple[str, str | None, str | None]]:
    """Parse .security-gate-ignore. Rules (one per line):
        <check-id>            ignore every finding from this check
        path:<glob>           ignore every finding whose file matches glob
        <check-id> <glob>     ignore that check only within matching paths
    Returns (kind, check, glob) tuples where kind is "check" or "path"."""
    f = repo / ".security-gate-ignore"
    rules: list[tuple[str, str | None, str | None]] = []
    if not f.exists():
        return rules
    for raw in f.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("path:"):
            rules.append(("path", None, line[len("path:"):].strip()))
            continue
        parts = line.split()
        if len(parts) >= 2:
            rules.append(("check", parts[0], parts[1]))
        elif "/" in line or "*" in line:
            rules.append(("path", None, line))
        else:
            rules.append(("check", line, None))
    return rules


def is_ignored(finding: Finding, rules: list[tuple[str, str | None, str | None]]) -> bool:
    path, _ = _location_path_line(finding.location)
    for kind, check, glob in rules:
        if kind == "check" and finding.check == check and (glob is None or fnmatch.fnmatch(path, glob)):
            return True
        if kind == "path" and glob and fnmatch.fnmatch(path, glob):
            return True
    return False


def apply_allowlist(report: Report, repo: Path, rules):
    kept = []
    line_cache: dict[str, list[str]] = {}
    for f in report.findings:
        if is_ignored(f, rules):
            continue
        path, line = _location_path_line(f.location)
        if " @ " not in f.location and re.search(r":\d+$", f.location):
            lines = line_cache.get(path)
            if lines is None:
                try:
                    lines = (repo / path).read_text(errors="replace").splitlines()
                except OSError:
                    lines = []
                line_cache[path] = lines
            if 1 <= line <= len(lines) and ALLOW_MARKER_RX.search(lines[line - 1]):
                continue  # inline `# security-gate: allow` on that line
        kept.append(f)
    report.findings = kept


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--build-dir", action="append", default=[], help="Built frontend/mobile output to scan (repeatable). Auto-detects common dirs if omitted.")
    ap.add_argument("--history", action="store_true", help="Also scan all git history for secrets (slower).")
    ap.add_argument("--entropy", action="store_true", help="Also flag high-entropy strings no named pattern caught (low severity).")
    ap.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high")
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"error: {repo} is not a directory", file=sys.stderr)
        return 2
    report = Report(repo=str(repo))
    files, is_git = list_files(repo)
    if not is_git:
        report.notes.append("Not a git repository: committed-file and history checks were limited.")

    build_dirs = [repo / b for b in args.build_dir] or [repo / b for b in BUILD_DIR_CANDIDATES if (repo / b).is_dir()]
    build_set = {bd.resolve() for bd in build_dirs}

    for f in files:
        if any(str(f.resolve()).startswith(str(bd) + os.sep) for bd in build_set):
            continue  # scanned separately as build output
        text = read_text(f)
        if text is None:
            continue
        report.scanned_files += 1
        scan_secrets(report, repo, f, text)
        check_client_exposure(report, repo, f, text)
        check_webhooks(report, repo, f, text)
        if args.entropy:
            check_entropy(report, repo, f, text)

    check_env_files(report, repo, files, is_git)
    check_build_output(report, repo, build_dirs)
    if not build_dirs:
        report.notes.append("No build output found. Build the frontend/mobile app and rerun with --build-dir to check shipped bundles.")
    check_workflows(report, repo)
    check_dockerfiles(report, repo, files)
    check_agent_config(report, repo, files)
    detect_integrations(report, repo, files)
    if args.history:
        scan_history(report, repo)

    apply_allowlist(report, repo, load_ignore_rules(repo))

    if args.format == "json":
        data = asdict(report)
        data.pop("reported_values", None)
        print(json.dumps(data, indent=2))
    elif args.format == "sarif":
        print(render_sarif(report))
    else:
        print(render_md(report))

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
