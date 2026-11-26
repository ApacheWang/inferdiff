"""Gemini SSE capture and offline trace bundle regression tests."""

from __future__ import annotations

import http.server
import io
import json
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from inferdiff.cli import main
from inferdiff.detectors import audit_trace
from inferdiff.recorder import SSEFramer, build_frame_from_chunk
from inferdiff.schema import TraceDocument, TraceHeader, assemble_summary, load_trace, strict_json_loads, write_trace


def _cli(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main([str(arg) for arg in args])
    return code, stdout.getvalue(), stderr.getvalue()


def _sse(*frames):
    return ''.join(f'data: {json.dumps(frame, ensure_ascii=False)}\r\n\r\n' for frame in frames).encode('utf-8')


def _parts(*parts):
    return {'candidates': [{'content': {'role': 'model', 'parts': parts}}]}


def _end(reason, *, candidates, thoughts=0, total=None):
    return {
        'candidates': [{'finishReason': reason}],
        'usageMetadata': {
            'promptTokenCount': 9,
            'candidatesTokenCount': candidates,
            'thoughtsTokenCount': thoughts,
            'totalTokenCount': 9 + candidates + thoughts if total is None else total,
        },
    }


@contextmanager
def _serve(respond, *, models=None):
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            requests.append((self.path, self.headers, None))
            if models is None:
                self._reply(404, 'text/plain', b'')
            else:
                self._reply(200, 'application/json', json.dumps(models).encode())

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append((self.path, self.headers, request))
            status, payload = respond(request)
            self._reply(status, 'text/event-stream; charset=utf-8' if status == 200 else 'text/plain', payload)

        def _reply(self, status, content_type, payload):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            rocket = payload.find(b'\xf0\x9f\x9a\x80')
            if rocket >= 0:
                self.wfile.write(payload[:rocket + 2])
                self.wfile.flush()
                self.wfile.write(payload[rocket + 2:])
            else:
                self.wfile.write(payload)

    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        try:
            yield f'http://127.0.0.1:{server.server_port}', requests
        finally:
            server.shutdown()
            thread.join(timeout=2)


def _recorded_trace(path, *, breach=False, warning=False, legacy_secrets=False, tokens=1, total_ms=12.0):
    endpoint = 'https://offline.invalid/v1/chat/completions'
    headers = {}
    tool_name = 'write_config'
    if legacy_secrets:
        endpoint += '?key=offline%2Fquery%2Dkey'
        headers['x-goog-api-key'] = 'offline-header-key'
        tool_name = 'offline-header-key offline/query-key'

    delta = {'role': 'assistant', 'content': 'hello'}
    if breach:
        delta['tool_calls'] = [{
            'index': 0, 'id': 'call_test', 'type': 'function',
            'function': {'name': tool_name, 'arguments': '{"value":'},
        }]
    payload = _sse(
        {'choices': [{'delta': delta}]},
        {'choices': [{'delta': {}, 'finish_reason': 'tool_calls' if breach else 'stop'}]},
        {'choices': [], 'usage': {'prompt_tokens': 5, 'completion_tokens': tokens}},
    ) + b'data: [DONE]\r\n\r\n'
    framer = SSEFramer()
    chunks = framer.feed(payload, 10_000_000) + framer.finish(11_000_000)
    frames = []
    for seq, chunk in enumerate(chunks):
        frame, _ = build_frame_from_chunk(
            chunk, seq=seq, dialect='openai-chat', prev_rel_ms=frames[-1].t_rel_ms if frames else 0.0,
            t0_ns=0, sglang_prev_text='',
        )
        frames.append(frame)
    header = TraceHeader(
        trace_id='tr_replay_test', label='offline-test', recorded_at_utc='2026-01-01T00:00:00Z',
        dialect='openai-chat', request={
            'url': endpoint, 'headers_redacted': headers,
            'effective_params': {'max_budget_tokens': 8, 'ignore_eos': warning},
        }, response_meta={'status_code': 200, 'content_type': 'text/event-stream'},
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    write_trace(path, TraceDocument(header, frames, assemble_summary(header, frames, total_ms=total_ms)))


class GeminiProbeTests(unittest.TestCase):
    def _probe(self, respond, *, selection=('--only', 'C10')):
        with tempfile.TemporaryDirectory() as directory, _serve(respond) as (host, requests):
            path = Path(directory)
            code, stdout, stderr = _cli(
                'doctor', host, '--model', 'gemini-test', *selection, '--save-dir', path, '--json', '--timeout', '2',
            )
            self.assertEqual(stderr, '')
            report = strict_json_loads(stdout)
            self.assertEqual(report['dialect'], 'gemini-sse')
            (result,) = report['results']
            self.assertEqual((result['probe_id'], result['code']), ('C10', 'gemini_stream_contract'))
            self.assertEqual(len(requests), 1)
            traces = [load_trace(trace) for trace in path.glob('*.trace.jsonl')]
            return code, result, traces

    def test_honest_max_tokens_and_multibyte_sse_pass(self):
        def respond(request):
            cap = request['generationConfig']['maxOutputTokens']
            ending = _end('MAX_TOKENS', candidates=cap)
            return 200, _sse(
                _parts({'text': '🚀 1, 2, 3,'}), {'candidates': ending['candidates']},
                {'usageMetadata': ending['usageMetadata']},
            )

        code, result, traces = self._probe(respond)
        self.assertEqual((code, result['status']), (0, 'PASS'))
        self.assertEqual(result['details']['finish_reason'], 'MAX_TOKENS')
        (trace,) = traces
        self.assertTrue(trace.summary.eof_clean)
        self.assertEqual(trace.summary.assembled['content_text'], '🚀 1, 2, 3,')
        self.assertGreater(trace.summary.assembled['reported_usage']['completion_tokens'], 0)

    def test_stop_with_a_complete_sentence_at_the_token_cap_fails(self):
        def respond(request):
            cap = request['generationConfig']['maxOutputTokens']
            return 200, _sse(_parts({'text': 'The numbers are complete.'}), _end('STOP', candidates=cap))

        code, result, _ = self._probe(respond)
        self.assertEqual((code, result['status']), (2, 'FAIL'))
        self.assertIn('MAX_TOKENS', result['summary'])

    def test_stop_with_incomplete_output_below_the_reported_cap_fails(self):
        code, result, _ = self._probe(lambda _: (
            200, _sse(_parts({'text': 'The next numbers are 1, 2,'}), _end('STOP', candidates=7)),
        ))
        self.assertEqual((code, result['status']), (2, 'FAIL'))

    def test_usage_zero_with_text_or_invalid_total_fails(self):
        for candidates, total in ((0, 9), (7, 15)):
            with self.subTest(candidates=candidates, total=total):
                code, result, _ = self._probe(lambda _: (
                    200, _sse(_parts({'text': 'Multiple words'}), _end('MAX_TOKENS', candidates=candidates, total=total)),
                ))
                self.assertEqual((code, result['status']), (2, 'FAIL'))

    def test_thinking_only_stream_passes_and_counts_frames(self):
        def respond(request):
            cap = request['generationConfig']['maxOutputTokens']
            return 200, _sse(
                _parts({'text': '推理', 'thought': True}, {'text': '中', 'thought': True}),
                _parts({'text': '🚀', 'thought': True}),
                _end('MAX_TOKENS', candidates=0, thoughts=cap),
            )

        code, result, traces = self._probe(respond, selection=('--protocol', 'gemini'))
        self.assertEqual((code, result['status']), (0, 'PASS'))
        self.assertEqual(result['details']['thought_frames'], 2)
        (trace,) = traces
        self.assertEqual(trace.summary.assembled['content_text'], '')
        self.assertEqual(trace.summary.assembled['reasoning_text'], '推理中🚀')
        self.assertEqual(audit_trace(trace), [])

    def test_function_call_parts_are_preserved(self):
        code, result, traces = self._probe(lambda _: (
            200, _sse(_parts({'functionCall': {'name': 'record_numbers', 'args': {'numbers': [1, 2]}}}),
                      _end('MAX_TOKENS', candidates=7)),
        ))
        self.assertEqual((code, result['status']), (0, 'PASS'))
        (trace,) = traces
        (call,) = trace.summary.assembled['tool_calls']
        self.assertEqual(call['name'], 'record_numbers')
        self.assertTrue(call['json_valid'])
        self.assertEqual(strict_json_loads(call['raw_arguments']), {'numbers': [1, 2]})

    def test_utf8_replacement_fails(self):
        payload = _sse(_parts({'text': 'invalid token'}), _end('MAX_TOKENS', candidates=7))
        for corrupted in (b'\xff', '\ufffd'.encode('utf-8')):
            with self.subTest(corrupted=corrupted):
                code, result, _ = self._probe(lambda _: (200, payload.replace(b'invalid', corrupted)))
                self.assertEqual((code, result['status']), (2, 'FAIL'))

    def test_unsupported_gemini_route_skips(self):
        for status in (404, 405, 501):
            with self.subTest(status=status):
                code, result, traces = self._probe(lambda _: (status, b'unsupported'))
                self.assertEqual((code, result['status'], traces), (0, 'SKIP', []))

    def test_model_discovery_uses_header_authentication_from_base_url(self):
        models = {'models': [
            {'name': 'models/embedding-only', 'supportedGenerationMethods': ['embedContent']},
            {'name': 'models/gemini-found', 'supportedGenerationMethods': ['generateContent']},
        ]}
        reply = _sse(_parts({'text': '🚀'}), _end('MAX_TOKENS', candidates=1))
        with tempfile.TemporaryDirectory() as directory, _serve(lambda _: (200, reply), models=models) as (host, requests):
            code, output, stderr = _cli('doctor', '--base-url', host + '/v1beta?key=discovery%2Ftest-token',
                                        '--protocol', 'gemini', '--save-dir', directory, '--timeout', '2', '--json')
            self.assertEqual((code, stderr), (0, ''))
            self.assertEqual(strict_json_loads(output)['model'], 'gemini-found')
            self.assertEqual([target for target, _, _ in requests], [
                '/v1beta/models', '/v1beta/models/gemini-found:streamGenerateContent?alt=sse',
            ])
            self.assertEqual([headers.get('x-goog-api-key') for _, headers, _ in requests], ['discovery/test-token'] * 2)

    def test_credentials_are_header_only_and_redacted_in_traces_and_reports(self):
        header_key = 'gemini-private-header-token'
        encoded_url_key = 'gemini%2Fprivate%2Dquery-token'
        decoded_url_key = 'gemini/private-query-token'
        reflected_url_key = 'separately-reflected-query-token'
        reflected_header_key = 'separately-reflected-header-token'
        nested_header_key = 'nested-json-header-token'

        def respond(request):
            cap = request['generationConfig']['maxOutputTokens']
            reflected = (
                f'{header_key} {encoded_url_key} {decoded_url_key} '
                f'/v1beta/models?key={reflected_url_key} x-goog-api-key: {reflected_header_key} '
                + json.dumps({'x-goog-api-key': nested_header_key})
            )
            return 200, _sse(_parts({'text': reflected}), _end('STOP', candidates=cap))

        with tempfile.TemporaryDirectory() as directory, _serve(respond) as (host, requests):
            root = Path(directory)
            sarif, junit, html = (root / name for name in ('gemini.sarif', 'gemini.xml', 'gemini.html'))
            code, stdout, stderr = _cli(
                'doctor', f'{host}/proxy?key={encoded_url_key}', '--model', 'gemini-test',
                '--protocol', 'gemini', '--api-key', header_key, '--save-dir', root, '--timeout', '2', '--json',
                '--out-sarif', sarif, '--out-junit', junit, '--html', html,
            )
            self.assertEqual((code, stderr), (2, ''))
            ((target, headers, body),) = requests
            parsed = urlsplit(target)
            self.assertEqual(parsed.path, '/proxy/v1beta/models/gemini-test:streamGenerateContent')
            self.assertEqual(parse_qs(parsed.query), {'alt': ['sse']})
            self.assertEqual(headers.get('x-goog-api-key'), header_key)
            self.assertNotIn('Authorization', headers)
            self.assertNotIn('stream', body)
            (trace,) = root.glob('*.trace.jsonl')
            _, markdown, export_error = _cli('export', trace, '--format', 'github-issue', '--include-body', '--include-wire')
            self.assertEqual(export_error, '')
            self.assertIn('inferdiff', markdown)
            report = strict_json_loads(stdout)
            self.assertEqual(report['results'][0]['status'], 'FAIL')
            self.assertEqual(strict_json_loads(sarif.read_text(encoding='utf-8'))['runs'][0]['results'][0]['ruleId'], 'C10')
            self.assertIsNotNone(ET.parse(junit).find('.//failure'))
            for exported in (stdout, markdown, *(path.read_text(encoding='utf-8') for path in root.iterdir())):
                for secret in (header_key, encoded_url_key, decoded_url_key, reflected_url_key, reflected_header_key,
                               nested_header_key):
                    self.assertNotIn(secret, exported)

    def test_short_api_key_is_redacted_from_sse_comments_and_ids(self):
        for key in ('abc', '9'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                payload = (f': received {key}\r\nid: {key}\r\n'.encode() +
                           _sse(_parts({'text': 'numbers'}), _end('MAX_TOKENS', candidates=7)))
                with _serve(lambda _: (200, payload)) as (host, requests):
                    code, output, stderr = _cli('doctor', host, '--model', 'gemini-test', '--only', 'C10',
                                                '--api-key', key, '--save-dir', directory, '--timeout', '2', '--json')
                self.assertEqual((code, stderr), (0, ''))
                self.assertEqual(requests[0][1].get('x-goog-api-key'), key)
                self.assertEqual(strict_json_loads(output)['results'][0]['details']['prompt_tokens'], 9)
                (trace_path,) = Path(directory).glob('*.trace.jsonl')
                raw_wire = ''.join(frame.raw_wire for frame in load_trace(trace_path).frames)
                self.assertNotIn(f': received {key}', raw_wire)
                self.assertNotIn(f'id: {key}', raw_wire)


class ReplayTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        network = patch('socket.socket.connect', side_effect=AssertionError('Replay attempted a network connection'))
        network.start()
        self.addCleanup(network.stop)

    def test_single_trace_runs_detectors_and_exports_reports(self):
        trace = self.root / 'tool.trace.jsonl'
        _recorded_trace(trace, breach=True, legacy_secrets=True)
        report, sarif, junit, html = (self.root / name for name in ('report.json', 'report.sarif', 'report.xml', 'report.html'))
        code, _, stderr = _cli('replay', trace, '--out-json', report, '--out-sarif', sarif,
                              '--out-junit', junit, '--out-html', html)
        self.assertEqual((code, stderr), (2, ''))
        payload = strict_json_loads(report.read_text(encoding='utf-8'))
        (item,) = payload['traces']
        self.assertEqual(item['trace'], trace.name)
        self.assertEqual([(finding['detector_id'], finding['severity']) for finding in item['findings']], [('D1', 'P0')])
        run = strict_json_loads(sarif.read_text(encoding='utf-8'))['runs'][0]
        self.assertEqual([(result['ruleId'], result['level']) for result in run['results']], [('D1', 'error')])
        suite = ET.parse(junit).find('testsuite')
        self.assertEqual(suite.get('failures'), '1')
        self.assertIn('D1', suite.find('testcase[failure]').get('name'))
        self.assertIn('tool.trace.jsonl', html.read_text(encoding='utf-8'))
        for path in (report, sarif, junit, html):
            for secret in ('offline-header-key', 'offline%2Fquery%2Dkey', 'offline/query-key'):
                self.assertNotIn(secret, path.read_text(encoding='utf-8'))

    def test_directory_trace_order_is_deterministic_and_strict_gates_warnings(self):
        path = self.root / 'bundle'
        _recorded_trace(path / 'z.trace.jsonl', warning=True)
        _recorded_trace(path / 'a.trace.jsonl')
        (path / 'doctor_summary.json').write_text('{}', encoding='utf-8')
        code, output, stderr = _cli('replay', path, '--out-json', '-')
        self.assertEqual((code, stderr), (0, ''))
        traces = strict_json_loads(output)['traces']
        self.assertEqual([trace['trace'] for trace in traces], ['a.trace.jsonl', 'z.trace.jsonl'])
        self.assertEqual(traces[0]['findings'], [])
        self.assertEqual([(f['detector_id'], f['severity']) for f in traces[1]['findings']], [('D3', 'P1')])
        code, _, stderr = _cli('replay', path, '--strict')
        self.assertEqual((code, stderr), (3, ''))

    def test_baseline_classifies_new_fixed_and_unchanged_p0_breaches(self):
        before, after = self.root / 'before', self.root / 'after'
        for directory, breach in ((before, False), (after, True)):
            _recorded_trace(directory / 'c1.trace.jsonl', breach=breach)
            _recorded_trace(directory / 'c2.trace.jsonl', breach=True)

        code, text, stderr = _cli('replay', after, '--baseline', before, '--out-json', '-')
        self.assertEqual((code, stderr), (2, ''))
        regression = strict_json_loads(text)['regression']
        self.assertEqual(regression['FIXED_BREACHES'], [])
        self.assertEqual([(f['trace'], f['detector_id'], f['severity']) for f in regression['NEW_BREACHES']],
                         [('c1.trace.jsonl', 'D1', 'P0')])
        self.assertEqual([f['trace'] for f in regression['UNCHANGED']], ['c2.trace.jsonl'])

        junit = self.root / 'fixed.xml'
        code, text, stderr = _cli('replay', before, '--baseline', after, '--out-json', '-', '--out-junit', junit)
        self.assertEqual((code, stderr), (0, ''))
        regression = strict_json_loads(text)['regression']
        self.assertEqual(regression['NEW_BREACHES'], [])
        self.assertEqual([f['trace'] for f in regression['FIXED_BREACHES']], ['c1.trace.jsonl'])
        self.assertEqual([f['trace'] for f in regression['UNCHANGED']], ['c2.trace.jsonl'])
        self.assertEqual(ET.parse(junit).find('testsuite').get('failures'), '0')

    def test_baseline_runs_pair_only_timing_detector_for_matching_traces(self):
        before, after = self.root / 'before', self.root / 'after'
        _recorded_trace(before / 'bench.trace.jsonl', tokens=8, total_ms=120.0)
        _recorded_trace(after / 'bench.trace.jsonl')

        code, text, stderr = _cli('replay', after, '--baseline', before, '--out-json', '-', '--strict')
        self.assertEqual((code, stderr), (3, ''))
        report = strict_json_loads(text)
        (finding,) = report['regression']['NEW_BREACHES']
        self.assertEqual((finding['detector_id'], finding['severity']), ('D5', 'P1'))
