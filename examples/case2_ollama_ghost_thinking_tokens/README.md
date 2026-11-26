# Case 2: Ghost Budget Empty Output (D2)

Models [`ollama/ollama#17274`](https://github.com/ollama/ollama/issues/17274): HTTP 200 reports `done: true`, `done_reason: "stop"`, and `eval_count: 40`, yet all 40 tokens were consumed inside `thinking` with 0 visible content bytes and 0 tool calls.

```bash
inferdiff audit examples/case2_ollama_ghost_thinking_tokens/target.trace.jsonl

inferdiff diff \
  examples/case2_ollama_ghost_thinking_tokens/baseline.trace.jsonl \
  examples/case2_ollama_ghost_thinking_tokens/target.trace.jsonl
```
