"""Generate local CI configuration without connecting to an endpoint."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from urllib.parse import unquote

from ._urls import RecorderError, validate_url
from .redact import extract_url_secret_values, redact_secret_text


DEFAULT_ENDPOINT = "https://api.openai.com/v1"

_GITHUB_ACTIONS = """# Store the endpoint API key in the LLM_API_KEY repository secret.
name: inferdiff canary

on:
  schedule:
    - cron: '0 3 * * *'
  workflow_dispatch:

permissions:
  actions: read
  contents: read
  security-events: write

jobs:
  canary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run inferdiff canary
        uses: ApacheWang/inferdiff@v0
        with:
          url: %(endpoint)s
          model: %(model)s
          api-key: ${{ secrets.LLM_API_KEY }}
          profile: %(profile)s
          sarif-output: inferdiff.sarif
          junit-output: inferdiff-junit.xml
      - name: Upload SARIF to code scanning
        if: always() && hashFiles('inferdiff.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: inferdiff.sarif
      - name: Upload JUnit report
        if: always() && hashFiles('inferdiff-junit.xml') != ''
        uses: actions/upload-artifact@v4
        with:
          name: inferdiff-junit
          path: inferdiff-junit.xml
"""

_GITLAB_CI = """# Add this to .gitlab-ci.yml (adjust the path if you moved this file):
# include:
#   - local: /.gitlab/inferdiff-canary.yml
# Set LLM_API_KEY as a masked project CI/CD variable for authenticated endpoints.
inferdiff-canary:
  image: python:3.12-slim
  variables:
    INFERDIFF_ENDPOINT:
      value: %(endpoint)s
      expand: false
    INFERDIFF_MODEL:
      value: %(model)s
      expand: false
    INFERDIFF_PROFILE: %(profile)s
  before_script:
    - python -m pip install 'inferdiff>=0.2.0'
  script:
    - |
      set -- --base-url="$INFERDIFF_ENDPOINT" --model="$INFERDIFF_MODEL" \\
        --profile="$INFERDIFF_PROFILE" --no-color --out-junit inferdiff-junit.xml
      if [ -n "${LLM_API_KEY:-}" ]; then
        set -- "$@" '--api-key=$LLM_API_KEY'
      else
        unset OPENAI_API_KEY
      fi
      inferdiff doctor "$@"
  artifacts:
    when: always
    reports:
      junit: inferdiff-junit.xml
"""

_PRE_COMMIT = """# Install inferdiff >= 0.2.0 on PATH and run `pre-commit install`.
# Commit matching .trace.jsonl files under fixtures/inferdiff/current and
# fixtures/inferdiff/baseline, using the same relative paths in each directory.
# If you already have a pre-commit config, merge this hook into its repos list.
repos:
  - repo: local
    hooks:
      - id: inferdiff-replay
        name: inferdiff offline replay
        entry: inferdiff replay fixtures/inferdiff/current --baseline fixtures/inferdiff/baseline
        language: system
        pass_filenames: false
        always_run: true
"""

_TARGETS = {
    "github-actions": (".github/workflows/inferdiff-canary.yml", _GITHUB_ACTIONS),
    "gitlab-ci": (".gitlab/inferdiff-canary.yml", _GITLAB_CI),
    "pre-commit": (".pre-commit-config.yaml", _PRE_COMMIT),
}
INIT_TARGETS = tuple(_TARGETS)


def render_init_config(target: str, *, endpoint: str, model: str, profile: str) -> tuple[str, str]:
    """Return the default relative path and text for a supported target."""
    path, template = _TARGETS[target]
    if target == "pre-commit":
        return path, template

    values = {"endpoint": endpoint, "model": model}
    for name, value in values.items():
        if target == "github-actions" and "${{" in value:
            raise ValueError(f"--{name} must be a literal value without GitHub expressions.")
        if value and not value.isprintable():
            raise ValueError(f"--{name} must contain only printable characters.")
        decoded = unquote(value)
        if redact_secret_text(decoded) != decoded:
            raise ValueError(f"--{name} must not contain credentials. Use the CI secret LLM_API_KEY.")

    try:
        validate_url(endpoint)
    except RecorderError:
        raise ValueError("--endpoint must be a valid HTTP(S) URL without credentials.") from None
    if any(char.isspace() for char in endpoint):
        raise ValueError("--endpoint must not contain whitespace.")
    if extract_url_secret_values(endpoint):
        raise ValueError("--endpoint must not contain credentials. Use the CI secret LLM_API_KEY.")
    if target == "github-actions" and model.startswith("-"):
        raise ValueError("--model must not start with a hyphen for GitHub Actions.")

    # A JSON string is also a quoted YAML scalar. Substitutions stay out of shell scripts.
    scalars = {name: json.dumps(value, ensure_ascii=False) for name, value in values.items()}
    return path, template % {**scalars, "profile": profile}


def write_init_config(path: Path, content: str, *, force: bool) -> None:
    """Write a scaffold, reserving the destination exclusively by default."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not force:
        try:
            with path.open("x", encoding="utf-8", newline="\n") as output:
                output.write(content)
        except FileExistsError:
            raise ValueError(f"Refusing to overwrite {path}. Use --force to replace it.") from None
        return

    output = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent,
                                         prefix=".inferdiff-", suffix=".tmp", delete=False)
    replacement = Path(output.name)
    try:
        with output:
            output.write(content)
        replacement.replace(path)
    finally:
        replacement.unlink(missing_ok=True)
