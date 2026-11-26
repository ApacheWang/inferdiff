# Case 1: Truncated Tool JSON Marked Completed (D1)

Models [`ggml-org/llama.cpp#30773`](https://github.com/ggml-org/llama.cpp/issues/30773): `/v1/chat/completions` honestly reports `finish_reason: "length"` on a budget-truncated tool call, while `/v1/responses` omits `response.function_call_arguments.done` and reports `status: "completed"` on broken JSON.

```bash
inferdiff diff \
  examples/case1_responses_truncated_tool/baseline.trace.jsonl \
  examples/case1_responses_truncated_tool/target.trace.jsonl

inferdiff export \
  examples/case1_responses_truncated_tool/baseline.trace.jsonl \
  examples/case1_responses_truncated_tool/target.trace.jsonl \
  --format github-issue
```
