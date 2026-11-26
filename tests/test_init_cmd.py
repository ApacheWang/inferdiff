"""CLI coverage for the scaffolded CI and pre-commit configurations."""

from __future__ import annotations

import io
import json
import os
import re
import shlex
import shutil
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from inferdiff.cli import main


_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "case1_responses_truncated_tool"


@contextmanager
def _working_directory(path: str):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        rc = main(args)
    return rc, stdout.getvalue(), stderr.getvalue()


class InitCommandTests(unittest.TestCase):
    def test_stdout_does_not_create_files_even_with_output(self):
        with tempfile.TemporaryDirectory() as directory, _working_directory(directory):
            rc, content, error = _cli("init", "--stdout", "--output", "elsewhere/canary.yml")

            self.assertEqual(rc, 0, error)
            self.assertEqual(error, "")
            self.assertIn("ApacheWang/inferdiff@v0", content)
            self.assertEqual(list(Path.cwd().iterdir()), [])

    def test_each_target_writes_its_default_path(self):
        targets = {
            "github-actions": ".github/workflows/inferdiff-canary.yml",
            "gitlab-ci": ".gitlab/inferdiff-canary.yml",
            "pre-commit": ".pre-commit-config.yaml",
        }
        with tempfile.TemporaryDirectory() as directory, _working_directory(directory):
            for target, path in targets.items():
                with self.subTest(target=target):
                    rc, _, error = _cli("init", "--target", target)
                    self.assertEqual(rc, 0, error)
                    self.assertTrue(Path(path).read_text(encoding="utf-8").endswith("\n"))

    def test_custom_output_is_preserved_until_forced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom" / "canary.yml"
            rc, _, error = _cli("init", "--output", str(path))
            self.assertEqual(rc, 0, error)
            self.assertIn("ApacheWang/inferdiff@v0", path.read_text(encoding="utf-8"))

            path.write_text("existing configuration\n", encoding="utf-8")
            rc, _, error = _cli("init", "--output", str(path))
            self.assertEqual(rc, 1)
            self.assertIn("--force", error)
            self.assertEqual(path.read_text(encoding="utf-8"), "existing configuration\n")

            rc, expected, error = _cli("init", "--stdout", "--profile", "full")
            self.assertEqual(rc, 0, error)
            rc, _, error = _cli("init", "--output", str(path), "--force", "--profile", "full")
            self.assertEqual(rc, 0, error)
            self.assertEqual(path.read_bytes(), expected.encode("utf-8"))

    def test_github_workflow_wires_schedule_and_reports(self):
        endpoint = "https://gateway.example.test/v1?api-version=2026-01-01&stream=true"
        model = 'models/check: "π" # label'
        rc, content, error = _cli("init", "--stdout", "--endpoint", endpoint, "--model", model,
                                  "--profile", "relay")
        self.assertEqual(rc, 0, error)
        self.assertRegex(content, r"(?m)^on:\n  schedule:\n    - cron: [^\n]+\n  workflow_dispatch:")
        self.assertRegex(content, r"(?m)^permissions:\n(?:  [^\n]+\n)*  security-events: write$")
        action = re.search(r"(?m)^        uses: ApacheWang/inferdiff@v0\n        with:\n((?:          [^\n]+\n)+)",
                           content)
        self.assertIsNotNone(action)
        inputs = dict(line.strip().split(": ", 1) for line in action.group(1).splitlines())
        self.assertEqual(json.loads(inputs["url"]), endpoint)
        self.assertEqual(json.loads(inputs["model"]), model)
        self.assertEqual(inputs["api-key"], "${{ secrets.LLM_API_KEY }}")
        self.assertEqual(inputs["profile"], "relay")
        self.assertIn("always()", content)
        self.assertRegex(content, rf"(?m)^        uses: github/codeql-action/upload-sarif@v4\n"
                         rf"        with:\n          sarif_file: {re.escape(inputs['sarif-output'])}$")
        self.assertRegex(content, rf"(?m)^        uses: actions/upload-artifact@v4\n"
                         rf"        with:\n          name: [^\n]+\n          path: {re.escape(inputs['junit-output'])}$")

    def test_gitlab_job_uses_literal_variables_and_junit_report(self):
        model = 'models/check: "π" # $MODEL $(printf literal)'
        rc, content, error = _cli("init", "--target", "gitlab-ci", "--stdout", "--model", model,
                                  "--profile", "full")
        self.assertEqual(rc, 0, error)
        self.assertIn("#   - local: /.gitlab/inferdiff-canary.yml", content)
        self.assertRegex(content, r"(?m)^inferdiff-canary:\n  image: [^\n]+\n  variables:")
        value = re.search(r"(?m)^    INFERDIFF_MODEL:\n      value: ([^\n]+)\n      expand: false$", content)
        self.assertIsNotNone(value)
        self.assertEqual(json.loads(value.group(1)), model)
        self.assertRegex(content, r'(?m)^    INFERDIFF_PROFILE: full$')
        self.assertIn('inferdiff doctor "$@"', content)
        self.assertIn('--model="$INFERDIFF_MODEL"', content)
        self.assertIn("'--api-key=$LLM_API_KEY'", content)
        report = re.search(r"(?m)^  artifacts:\n    when: always\n    reports:\n      junit: (.+)$", content)
        self.assertIsNotNone(report)
        self.assertIn(f"--out-junit {report.group(1)}", content)

    def test_pre_commit_hook_replays_matched_fixture_traces(self):
        rc, content, error = _cli("init", "--target", "pre-commit", "--stdout")
        self.assertEqual(rc, 0, error)
        self.assertRegex(content, r"(?m)^repos:\n  - repo: local\n    hooks:\n      - id: [^\n]+$")
        self.assertRegex(content, r"(?m)^        language: system$")
        self.assertRegex(content, r"(?m)^        pass_filenames: false$")
        entry = re.search(r"(?m)^        entry: (.+)$", content)
        self.assertIsNotNone(entry)
        executable, command, current, baseline_flag, baseline = shlex.split(entry.group(1))
        self.assertEqual((executable, command, baseline_flag), ("inferdiff", "replay", "--baseline"))
        with tempfile.TemporaryDirectory() as directory, _working_directory(directory):
            for path in (Path(current), Path(baseline)):
                path.mkdir(parents=True)
                shutil.copyfile(_EXAMPLE / "baseline.trace.jsonl", path / "sample.trace.jsonl")
            rc, _, error = _cli(command, current, baseline_flag, baseline)
            self.assertEqual(rc, 0, error)
            shutil.copyfile(_EXAMPLE / "target.trace.jsonl", Path(current) / "sample.trace.jsonl")
            rc, _, error = _cli(command, current, baseline_flag, baseline)
            self.assertEqual(rc, 2, error)

    def test_never_copies_api_keys_from_the_environment(self):
        fake_keys = {name: f"test-only-{name.lower()}-value" for name in
                     ("LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")}
        with patch.dict(os.environ, fake_keys):
            for target in ("github-actions", "gitlab-ci", "pre-commit"):
                with self.subTest(target=target):
                    rc, content, error = _cli("init", "--target", target, "--stdout")
                    self.assertEqual(rc, 0, error)
                    for key in fake_keys.values():
                        self.assertNotIn(key, content + error)
                    if target == "pre-commit":
                        self.assertNotIn("API_KEY", content)

    def test_rejects_credential_inputs_without_echoing_them(self):
        inputs = [
            ("--endpoint", "https://person:embedded-fixture-secret@gateway.example.test/v1"),
            ("--endpoint", "https://gateway.example.test/v1?key=embedded-fixture-secret"),
            ("--endpoint", "https://gateway.example.test/v1/token/embedded-fixture-secret"),
            ("--model", "sk-example-fixture-test-key-value"),
        ]
        for flag, value in inputs:
            with self.subTest(flag=flag, value=value):
                rc, content, error = _cli("init", "--stdout", flag, value)
                self.assertEqual(rc, 1)
                self.assertEqual(content, "")
                self.assertNotIn(value, error)
                self.assertNotIn("embedded-fixture-secret", error)

    def test_rejects_github_expression_substitutions_in_literal_fields(self):
        expression = "${{ secrets.UNRELATED_SECRET }}"
        for flag, value in (("--model", expression), ("--endpoint", f"https://example.test/{expression}")):
            with self.subTest(flag=flag):
                rc, content, error = _cli("init", "--stdout", flag, value)
                self.assertEqual(rc, 1)
                self.assertEqual(content, "")
                self.assertIn("expression", error)
                self.assertNotIn(expression, error)
