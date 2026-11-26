# Changelog

## v0.2.0 (unreleased)

- Added `inferdiff proxy --upstream https://api.openai.com --save-dir ./traces --only-breaches` for live SDK traffic. The loopback proxy forwards SSE as it arrives, runs `D1`–`D4`, and redacts credentials in its live `/_inferdiff/` dashboard, logs, and traces. Use `--fallback-url` to retry eligible upstream failures before response headers reach the client.
- Added `C9` for Anthropic `/v1/messages` and `C10` for Google Gemini SSE. The canaries check stream termination, token accounting, and provider-specific wire contracts.
- Added optional, non-invasive LMCache MP, Mooncake Store, and Linux `/proc/<pid>/io` sampling. Storage detectors `D6`–`D8` cover page-cache warming, lookup hits with delivery failures, and fragmented reads or storage-backed TTFT regressions.
- Expanded the offline HTML waterfall with `C9` and `C10` protocol badges and `D6`–`D8` storage metrics and severity badges.
- Added A/B canary mode to `compare` alongside request replay. It compares wire contracts, model fingerprints, and timings.
- Added `watch` for scheduled canaries, redacted JSONL logs, and failure and recovery notifications over webhooks.
- Added offline `replay` for trace files and directories, with `--baseline` to gate new findings by relative path.
- Added SARIF 2.1.0 and JUnit XML exports. The GitHub Action accepts optional `sarif-output` and `junit-output` paths in live and offline modes.
- Added `inferdiff init` to scaffold GitHub Actions and GitLab CI canaries and offline pre-commit baseline checks.
- Hardened credential redaction for protocol-token collisions, handling of malformed traces and relay responses, report serialization, and comparisons with zero-duration samples.

## v0.1.1

- Added bounded canary retries for thinking models and improved `C5`, `C7`, and `C8` accuracy for role and index checks, buffered SSE detection, and backend drift.
- Added a GitHub composite Action for live `doctor` or offline `diff` gates with an HTML waterfall artifact.

## v0.1.0

- Introduced the OpenAI Chat and Responses canaries (`C1`–`C8`) for streaming integrity. Added recording and offline analysis for OpenAI Chat, OpenAI Responses, SGLang native SSE, and Ollama NDJSON.
- Added `record`, `audit`, `diff`, and request-mode `compare`, plus self-contained HTML waterfalls and compact, redacted issue exports.
- Established the `inferdiff.trace.v1` format, deterministic CI exit codes, and a zero-dependency Python 3.10+ CLI.
