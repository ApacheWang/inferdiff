"""Tests for paired canary evidence and its report formats."""

import json
import unittest

from inferdiff.canary import DoctorReport, ProbeResult
from inferdiff.comparison import (
    compare_reports,
    render_comparison_html,
    render_comparison_markdown,
    render_comparison_terminal,
)
from inferdiff.schema import TraceDocument, TraceFrame, TraceHeader, TraceSummary


def report(*, model="requested", observed="requested", fingerprint="fp_a", ttft=35.0,
           total=100.0, finish="length", status="PASS", thinking=False, extra_sample=False,
           arguments_streamed=False):
    response = {"model": observed, "system_fingerprint": fingerprint}
    doc = TraceDocument(
        TraceHeader("trace", "doctor-C1", "", "openai-chat", {"effective_params": {"model": model}}, {}),
        [TraceFrame(0, 1.0, 1.0, None, "data: " + json.dumps(response), False, None, {"phase": "HANDSHAKE"})],
        TraceSummary(True, 1, {"ttft_effective_ms": ttft, "total_ms": total}, {
            "finish_reason": finish, "reasoning_text": "hidden evidence" if thinking else "",
            "tool_calls": [{"name": "write_config", "json_valid": False, "saw_args_delta": arguments_streamed}],
        }),
    )
    url = "https://example.invalid/v1?key=unsafe-query-value"
    result = ProbeResult("C1", "TOOL_CALL_BUDGET_CLIP", "P0", status, "probe summary", total, 1, 10, "",
                         traces=[doc, doc] if extra_sample else [doc])
    return DoctorReport(url, url, "openai-chat", model, "quick", "A+", 0, 0, 0, 0, 10, None, [result])


class TestCanaryComparison(unittest.TestCase):
    def test_verdict_precedence_and_contract_evidence(self):
        result = compare_reports(report(), report(observed="swapped", fingerprint="fp_b", finish="stop",
                                                  status="FAIL", thinking=True, ttft=80.0, total=250.0))
        self.assertEqual(result.verdict, "SUSPECTED_MODEL_MISMATCH")
        self.assertEqual(result.exit_code, 2)
        payload = result.to_dict()
        self.assertTrue(payload["contract_drift"])
        self.assertTrue(payload["latency_regression"])
        self.assertEqual({d["field"] for d in payload["divergences"]},
                         {"status", "model", "system_fingerprint", "model_rewrite", "finish_reason", "thinking_stream"})
        self.assertEqual(payload["checks"][0]["b"]["status"], "FAIL")

    def test_latency_uses_matched_samples_and_ignores_small_noise(self):
        self.assertEqual(compare_reports(report(ttft=1.0, total=5.0), report(ttft=8.0, total=11.0)).verdict,
                         "IDENTICAL_CONTRACT")
        self.assertEqual(compare_reports(report(), report(ttft=56.0)).verdict, "LATENCY_REGRESSION")
        self.assertEqual(compare_reports(report(), report(ttft=56.0), ignore_timing=True).verdict,
                         "IDENTICAL_CONTRACT")
        result = compare_reports(report(), report(ttft=70.0, total=130.0, extra_sample=True)).to_dict()
        self.assertEqual(result["timing"]["ttft_ratio"], 2.0)
        self.assertEqual(result["timing"]["total_latency_ratio"], 1.3)
        self.assertEqual(result["timing"]["total_pairs"], 1)

    def test_intentionally_distinct_models_and_shared_alias(self):
        distinct = compare_reports(report(), report(model="another", observed="another", fingerprint="fp_b"))
        self.assertEqual(distinct.verdict, "IDENTICAL_CONTRACT")
        self.assertEqual({d["field"] for d in distinct.to_dict()["divergences"]}, {"model", "system_fingerprint"})
        self.assertEqual(compare_reports(report(observed="stable-alias"), report(observed="stable-alias")).verdict,
                         "IDENTICAL_CONTRACT")

    def test_metadata_and_sample_omissions_are_visible(self):
        metadata_only = compare_reports(report(), report(observed=None, fingerprint=None))
        self.assertEqual(metadata_only.verdict, "IDENTICAL_CONTRACT")
        result = compare_reports(report(), report(observed=None, fingerprint=None, extra_sample=True))
        self.assertEqual(result.verdict, "CONTRACT_DRIFT")
        self.assertEqual({item.field for item in result.divergences}, {"model", "system_fingerprint", "sample_availability"})

    def test_tool_argument_streaming_shape_is_compared(self):
        result = compare_reports(report(), report(arguments_streamed=True))
        self.assertEqual(result.verdict, "CONTRACT_DRIFT")
        diff, = result.to_dict()["divergences"]
        self.assertEqual(diff["field"], "tool_calls")
        self.assertFalse(diff["a"][0]["arguments_streamed"])
        self.assertTrue(diff["b"][0]["arguments_streamed"])

    def test_reports_scrub_reflections_and_escape_untrusted_labels(self):
        key = "nonstandard-reflected-key"
        report_a = report(observed="leak-" + key, fingerprint=key)
        result = compare_reports(report_a, report(ttft=float("nan")),
                                 a_label=key + " | [link](https://bad.invalid) <script>\x1b[2J", known_secrets=[key])
        text = render_comparison_terminal(result, no_color=True)
        markdown = render_comparison_markdown(result)
        html = render_comparison_html(result)
        for output in (text, markdown, html, json.dumps(result.to_dict(), allow_nan=False)):
            self.assertNotIn(key, output)
            self.assertNotIn("unsafe-query-value", output)
            self.assertNotIn("hidden evidence", output)
            self.assertNotIn("\x1b", output)
        self.assertIn("&#124;", markdown)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Waterfall", html)
        self.assertIn("<svg", html)
