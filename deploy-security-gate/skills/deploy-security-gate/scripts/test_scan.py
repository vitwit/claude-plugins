#!/usr/bin/env python3
"""Regression tests for scan.py. Standard library only: run with `python3 -m unittest`
or `python3 test_scan.py`. Each test maps to a bug fixed in the scanner."""
import re
import tempfile
import unittest
from pathlib import Path

import scan


def run(tmp: Path, *extra: str, entropy: bool = False, allowlist: bool = False) -> scan.Report:
    """Build a Report for a directory the same way main() does, minus argparse/exit."""
    report = scan.Report(repo=str(tmp))
    files, is_git = scan.list_files(tmp)
    build_dirs = [tmp / b for b in extra] or [tmp / b for b in scan.BUILD_DIR_CANDIDATES if (tmp / b).is_dir()]
    import os
    build_set = {bd.resolve() for bd in build_dirs}
    for f in files:
        if any(str(f.resolve()).startswith(str(bd) + os.sep) for bd in build_set):
            continue
        text = scan.read_text(f)
        if text is None:
            continue
        report.scanned_files += 1
        scan.scan_secrets(report, tmp, f, text)
        scan.check_client_exposure(report, tmp, f, text)
        if entropy:
            scan.check_entropy(report, tmp, f, text)
    scan.check_env_files(report, tmp, files, is_git)
    scan.check_build_output(report, tmp, build_dirs)
    scan.check_dockerfiles(report, tmp, files)
    scan.check_workflows(report, tmp)
    scan.detect_integrations(report, tmp, files)
    if allowlist:
        scan.apply_allowlist(report, tmp, scan.load_ignore_rules(tmp))
    return report


# Fixture keys are assembled from fragments so this test file itself contains no
# contiguous, format-valid key literal (otherwise the scanner flags its own fixtures).
# The values written into temp files below are contiguous and so remain matchable.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7XZ9QW2P"
FAKE_ANTHROPIC_KEY = "sk-ant-" + "api03-REALKEYMATERIAL1234567890abcdefXY"


def checks(report: scan.Report) -> set[str]:
    return {f.check for f in report.findings}


def find(report: scan.Report, check_prefix: str):
    return [f for f in report.findings if f.check.startswith(check_prefix)]


class PlaceholderTests(unittest.TestCase):
    def test_b1_word_inside_real_value_not_placeholder(self):
        # "latest" contains "test", "yourco" contains "your": must NOT be treated as placeholders.
        self.assertFalse(scan.is_placeholder("latest_deploy_token_a1b2c3d4e5"))
        self.assertFalse(scan.is_placeholder("yourcompany_prod_key_9f8a7b6c5d"))

    def test_b1_standalone_word_is_placeholder(self):
        self.assertTrue(scan.is_placeholder("your_token_value_here"))
        self.assertTrue(scan.is_placeholder("test"))
        self.assertTrue(scan.is_placeholder("changeme_now_please"))

    def test_b1_structural_and_runs_still_caught(self):
        self.assertTrue(scan.is_placeholder("xxxxxxxxxxxxxxxx"))
        self.assertTrue(scan.is_placeholder("${MY_SECRET}"))
        self.assertTrue(scan.is_placeholder("aaaaaaaaaaaa"))

    def test_b1_aws_example_key_still_placeholder(self):
        self.assertTrue(scan.is_placeholder("AKIAIOSFODNN7EXAMPLE", strict=True))


class SecretScanTests(unittest.TestCase):
    def test_c2_live_key_in_tests_stays_high(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "app" / "tests").mkdir(parents=True)
            (tmp / "app" / "tests" / "fixture.py").write_text(f'KEY = "{FAKE_AWS_KEY}"\n')
            aws = find(run(tmp), "secret:aws-access-key")
            self.assertTrue(aws)
            self.assertEqual(aws[0].severity, "high")

    def test_c1_secret_in_large_bundle_found(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "dist").mkdir()
            big = "x" * 2_100_000 + f'\nconst k="{FAKE_ANTHROPIC_KEY}";'
            (tmp / "dist" / "app.js").write_text(big)
            report = run(tmp, "dist")
            self.assertTrue(find(report, "secret:anthropic-key"))

    def test_b2_unquoted_env_assignment_found(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "config.yaml").write_text("password: supersecretvalue123\n")
            (tmp / "service.env").write_text("API_KEY=abcd1234efgh5678ijkl\n")
            report = run(tmp)
            self.assertTrue(find(report, "secret:hardcoded-assignment"))
            self.assertGreaterEqual(len(find(report, "secret:hardcoded-assignment")), 2)

    def test_b2_no_false_positive_on_code_expression(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "app.py").write_text("API_KEY = os.environ.get('API_KEY')\n")
            self.assertFalse(find(run(tmp), "secret:hardcoded-assignment"))


class DockerfileTests(unittest.TestCase):
    def test_b3_alternate_dockerfile_names_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "app.Dockerfile").write_text("FROM node:20\nENV API_TOKEN=supersecretvalue1\n")
            self.assertTrue(find(run(tmp), "docker-secret-arg"))


class GitignoreTests(unittest.TestCase):
    def test_b4_env_local_does_not_cover_env(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / ".env").write_text("X=1\n")
            (tmp / ".gitignore").write_text(".env.local\n.envrc\n")
            self.assertTrue(find(run(tmp), "gitignore-env"))

    def test_b4_env_glob_covers_env(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / ".env").write_text("X=1\n")
            (tmp / ".gitignore").write_text(".env\n")
            self.assertFalse(find(run(tmp), "gitignore-env"))


class IntegrationTests(unittest.TestCase):
    def test_b5_go_module_openai_detected(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "go.mod").write_text(
                "module example.com/app\n\nrequire github.com/sashabaranov/go-openai v1.17.0\n")
            report = run(tmp)
            self.assertIn("OpenAI", report.integrations.get("ai", []))


class NewProviderTests(unittest.TestCase):
    def test_new_provider_patterns(self):
        cases = {
            "digitalocean-token": "dop_v1_" + "a" * 64,
            "new-relic-key": "NRAK-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N",
            "shopify-token": "shpat_" + "0123456789abcdef0123456789abcdef",
            "databricks-token": "dapi" + "0123456789abcdef0123456789abcdef",
            "slack-app-token": "xapp-1-" + "A0123ABCD-1234567890-abcdef",
        }
        for pid, value in cases.items():
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                (tmp / "svc.py").write_text(f'TOKEN = "{value}"\n')
                self.assertTrue(find(run(tmp), f"secret:{pid}"), pid)


class EntropyTests(unittest.TestCase):
    def test_high_entropy_string_flagged_only_with_flag(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "cfg.py").write_text('OPAQUE = "Zx9Kq2Lm7Pw4Rt1Yb6Nc3Vd8Hf5Jg0As"\n')
            self.assertFalse(find(run(tmp), "secret:high-entropy-string"))
            self.assertTrue(find(run(tmp, entropy=True), "secret:high-entropy-string"))

    def test_entropy_ignores_git_sha_and_prose(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            # 40-char lowercase hex (git SHA): no case mix -> not flagged.
            (tmp / "a.py").write_text('REV = "da39a3ee5e6b4b0d3255bfef95601890afd80709"\n')
            # integrity hash line is skipped by context.
            (tmp / "b.txt").write_text('integrity "sha512-Zx9Kq2Lm7Pw4Rt1Yb6Nc3Vd8Hf5Jg0AsBcDeFgHi"\n')
            self.assertFalse(find(run(tmp, entropy=True), "secret:high-entropy-string"))


class CiSecretToFileTests(unittest.TestCase):
    def _wf(self, tmp: Path, body: str):
        wf = tmp / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(body)

    def test_secret_written_to_github_env(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._wf(tmp, "permissions: {}\njobs:\n  a:\n    steps:\n"
                          '      - run: echo "TOKEN=${{ secrets.TOKEN }}" >> $GITHUB_ENV\n')
            # echo+redirect: ci-secret-echo fires; ci-secret-to-file must not double-count.
            report = run(tmp)
            self.assertTrue(find(report, "ci-secret-echo"))

    def test_secret_tee_to_file(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._wf(tmp, "permissions: {}\njobs:\n  a:\n    steps:\n"
                          "      - run: printf '%s' ${{ secrets.TOKEN }} | tee /tmp/t\n")
            # printf is excluded from secret-to-file; this is covered by ci-secret-echo.
            self.assertTrue(find(run(tmp), "ci-secret-echo"))

    def test_secret_redirected_without_echo(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._wf(tmp, "permissions: {}\njobs:\n  a:\n    steps:\n"
                          "      - run: cat ${{ secrets.KUBECONFIG }} >> $GITHUB_ENV\n")
            self.assertTrue(find(run(tmp), "ci-secret-to-file"))


class AllowlistTests(unittest.TestCase):
    def test_inline_marker_suppresses(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "app.py").write_text(
                'KEY = "' + ("AKIA" + "IOSFODNN7XZ9QW2P") + '"  # security-gate: allow\n')
            self.assertFalse(find(run(tmp, allowlist=True), "secret:aws-access-key"))
            self.assertTrue(find(run(tmp, allowlist=False), "secret:aws-access-key"))

    def test_ignore_file_by_check_and_path(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "app.py").write_text('KEY = "' + ("AKIA" + "IOSFODNN7XZ9QW2P") + '"\n')
            (tmp / ".security-gate-ignore").write_text("secret:aws-access-key\n")
            self.assertFalse(find(run(tmp, allowlist=True), "secret:aws-access-key"))

    def test_ignore_file_by_path_glob(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "vendored").mkdir()
            (tmp / "vendored" / "x.py").write_text('KEY = "' + ("AKIA" + "IOSFODNN7XZ9QW2P") + '"\n')
            (tmp / ".security-gate-ignore").write_text("path:vendored/*\n")
            self.assertFalse(find(run(tmp, allowlist=True), "secret:aws-access-key"))


class SarifTests(unittest.TestCase):
    def test_sarif_is_valid_json_with_results(self):
        import json
        report = scan.Report(repo="/x")
        report.add("high", "secret:aws-access-key", "1", "app.py:3", "detail")
        doc = json.loads(scan.render_sarif(report))
        self.assertEqual(doc["version"], "2.1.0")
        res = doc["runs"][0]["results"][0]
        self.assertEqual(res["ruleId"], "secret:aws-access-key")
        self.assertEqual(res["level"], "error")
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "app.py")
        self.assertEqual(loc["region"]["startLine"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
