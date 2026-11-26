# inferdiff

**Wire-level regression diff, silent-failure forensics, and <=25-line GitHub Issue reproducer for LLM serving upgrades.**

> Catches HTTP 200 OK regressions that slip past standard evals: truncated tool-call JSON claiming `completed`, ghost reasoning tokens swallowing the output budget, fixed-length benchmark short-generation clipping, premature stream EOF, and benchmark prefix-cache / burst illusions.

## Why `inferdiff`?

- **Zero heavy runtime dependencies**: Pure Python 3.11+ standard library (`http.client`, `json`, `hashlib`, `dataclasses`, `time.monotonic_ns`) — fast `uvx inferdiff` cold start (< 80 ms) with zero dependency conflicts in CI.
- **4 native streaming dialects**:
  - `openai-chat` (`/v1/chat/completions` SSE — `llama-server`, `vLLM` incl. `stream_options.include_usage` empty-`choices` tails, `SGLang`, `LiteLLM`)
  - `openai-responses` (`/v1/responses` typed SSE events — tracks `function_call_arguments.delta` / `.done` / `response.completed|incomplete|failed`)
  - `sglang-native` (`/generate` cumulative SSE + textless terminal `meta_info`)
  - `ollama-ndjson` (`/api/chat` & `/api/generate` NDJSON — `thinking`, `eval_count`, `done_reason`, multi-chunk tool calls)
- **Chunk-jitter-proof two-layer diff**: Aligns normalized visible text, reasoning (unifying inline `<think>` and dedicated `reasoning_content`), structural JSON tool arguments, and dialect-aware closure — then maps the exact earliest divergence back to physical frame sequences `before#seq` and `after#seq`.
- **Safe-by-default shareable exports**: Sanitizes auth headers (SHA-256 8-char fingerprints), URL query params, and secrets; omits arbitrary prompt bodies and raw wire excerpts unless explicitly opted in via `--include-body` / `--include-wire`; emits POSIX shell-quoted `curl --globoff --url ...` commands strictly within **25 lines**.

## Quickstart (Zero-GPU Bundled Golden Examples)

```bash
# Install editable locally (Python 3.11+)
pip install -e .

# Case 1 (D1 P0 -> exits 2): llama.cpp #30773 truncated /v1/responses tool call claiming completed
inferdiff diff \
  examples/case1_responses_truncated_tool/baseline.trace.jsonl \
  examples/case1_responses_truncated_tool/target.trace.jsonl

# Export a compact <=25-line GitHub Issue report (safe redacted defaults)
inferdiff export \
  examples/case1_responses_truncated_tool/baseline.trace.jsonl \
  examples/case1_responses_truncated_tool/target.trace.jsonl \
  --format github-issue

# Case 2 (D2 P0 -> exits 2): Ollama #17274 ghost thinking tokens with 0 B visible output
inferdiff diff \
  examples/case2_ollama_ghost_thinking_tokens/baseline.trace.jsonl \
  examples/case2_ollama_ghost_thinking_tokens/target.trace.jsonl

# Case 3 (D3 + D5b P1 -> exits 3 under --fail-on p1): SGLang #53119 8/8000 short generation illusion
inferdiff diff \
  examples/case3_sglang_8_of_8000_short_gen/baseline.trace.jsonl \
  examples/case3_sglang_8_of_8000_short_gen/target.trace.jsonl \
  --fail-on p1
```

## Live Recording & Side-by-Side Comparison

```bash
# Record a single request or multi-line .jsonl request suite (per-frame flush)
inferdiff record \
  --url http://127.0.0.1:8080/v1/responses \
  -d request.json \
  -H "Authorization: Bearer $API_KEY" \
  --label llama-v1.1.0 \
  -o target.trace.jsonl

# Compare two live endpoints sequentially with per-target scoped credentials
inferdiff compare \
  --before-url http://127.0.0.1:8080/v1/chat/completions \
  --after-url  http://127.0.0.1:8081/v1/chat/completions \
  --before-header "Authorization: Bearer $KEY_A" \
  --after-header  "Authorization: Bearer $KEY_B" \
  -d request.json \
  --save-dir ./traces \
  --fail-on p1
```

## Deterministic CI Exit Codes

| Exit Code | Constant | Meaning |
| :--- | :--- | :--- |
| `0` | `EXIT_OK` | Gate passed (no blocking findings at configured `--fail-on` / `--strict` level) |
| `1` | `EXIT_USAGE_OR_IO_ERROR` | Invalid CLI args, malformed trace schema, connection error, or non-200 HTTP status |
| `2` | `EXIT_SILENT_PROTOCOL_BREACH` | P0 silent corruption (`D1` unclosed tool success, `D2` ghost empty output, `D4` premature EOF / framing breach) |
| `3` | `EXIT_SEMANTIC_REGRESSION` | P1 regression (`D3` fixed-length short gen, `D5` benchmark illusion, terminal drift, TTFT regression, or content diff under `--fail-on any-diff`) |

> Note on `--ignore-timing`: suppresses TTFT latency regression checks and D5 timing/benchmark-illusion alerts while preserving all D1–D4 protocol checks and semantic diffs.

## Roadmap (v0.2: Non-Intrusive KV & Storage Probes)

The `inferdiff.trace.v1` schema and `inferdiff.probes.base.BackendProbe` already expose the zero-overhead three-point snapshot lifecycle (`T_pre -> T_ttft -> T_eof`) for v0.2 plugins:

- `LmcacheMpProbe` (`http://<host>:8080/metrics` — token + key-level L1/L2 hit and staging OOM failure deltas)
- `MooncakeStoreProbe` (Master `:9003` + Client `:9300` `/version` & `/metrics` with graceful 503 degradation)
- `LinuxProcIoProbe` (same-UID `/proc/<pid>/io` isolating Prefill `[T_pre, T_ttft]` physical `read_bytes` vs `rchar`)
- Storage × inference detectors: `D6 PAGE_CACHE_WARM_ILLUSION`, `D7 LOOKUP_HIT_PREFETCH_DROP`, `D8 OFFLOAD_SLOWER_THAN_RECOMPUTE`.

## License

MIT
