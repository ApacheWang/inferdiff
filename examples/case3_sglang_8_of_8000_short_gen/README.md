# Case 3: Silent Short Generation & Benchmark Illusion (D3 + D5b)

Models [`sgl-project/sglang#53119`](https://github.com/sgl-project/sglang/pull/53119) / `#50443`: a fixed-length request (`ignore_eos: true`, `max_new_tokens: 8000`, `stop: []`) returns HTTP 200 with only `8 / 8000` tokens (terminal metadata arriving in a textless SSE frame), producing an apparent 167x latency speedup that is actually a 99.9% workload collapse.

```bash
inferdiff diff \
  examples/case3_sglang_8_of_8000_short_gen/baseline.trace.jsonl \
  examples/case3_sglang_8_of_8000_short_gen/target.trace.jsonl \
  --fail-on p1
```
