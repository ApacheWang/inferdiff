"""CI report format and CLI coverage with local streaming endpoints."""

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
from urllib.parse import unquote

from inferdiff import __version__
from inferdiff.canary import PROBE_CATALOG, DoctorReport, ProbeResult
from inferdiff.cli import main
from inferdiff.detectors import Finding
from inferdiff.recorder import record_stream
from inferdiff.schema import TraceDocument, TraceHeader, TraceSummary, strict_json_loads, write_trace


@contextmanager
def _serve(respond):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            status, body = respond(self.path, request)
            self.send_response(status)
            self.send_header('Content-Type', 'text/event-stream' if status == 200 else 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        try:
            yield f'http://127.0.0.1:{server.server_port}'
        finally:
            server.shutdown()
            thread.join(timeout=2)


def _sse(*events, done=True):
    text = ''.join(f'data: {json.dumps(event)}\n\n' for event in events)
    return (text + ('data: [DONE]\n\n' if done else '')).encode('utf-8')


def _tool_stream(reason, model='mock-model'):
    return _sse(
        {'model': model, 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': [
            {'index': 0, 'id': 'call_1', 'type': 'function',
             'function': {'name': 'write_config', 'arguments': '{"description":"incomplete'}},
        ]}}]},
        {'choices': [{'index': 0, 'delta': {}, 'finish_reason': reason}]},
    )


def _cli(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        rc = main(tuple(str(arg) for arg in args))
    return rc, stdout.getvalue(), stderr.getvalue()


def _doctor_report():
    specs = [
        ('C1', 'FAIL', 'Malformed call <tool> & arguments\x00\ud800; Authorization: bEaReR xy', 1250.0),
        ('C4', 'WARN', 'Rejected {"X-Auth-Token": "unknown-header-value"} at '
         'https://example.test/v1/token/url-opaque%2Fsecond-half/chat/completions?private=opaque-url-query',
         float('nan')),
        ('C5', 'SKIP', 'No support; Cookie: sid=unknown-cookie-value', 250.0),
        ('C6', 'ERROR', 'Could not connect; reflected acct%2Fquery%2Dvalue', float('inf')),
        ('C9', 'PASS', 'Clean', -1.0),
    ]
    results = []
    for rule_id, status, summary, duration in specs:
        code, severity, reference = PROBE_CATALOG[rule_id]
        results.append(ProbeResult(rule_id, code, severity, status, summary, duration, 0, None, reference))
    return DoctorReport(
        target_url='https://example.test/v1',
        chat_url='https://person:user-credential@example.test/v1/%74oken/opaque-path-secret/chat/completions'
                 '?secret=acct%2Fquery-value#private-fragment',
        dialect='openai-chat', model='mock-model', profile='quick', grade='F', exit_code=2,
        p0_count=1, warning_count=1, error_count=1, total_tokens=None, save_dir=None, results=results,
    )


class ExporterTests(unittest.TestCase):
    def assert_counts(self, xml, *, tests, failures, skipped, errors):
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, 'testsuites')
        suite = root.find('testsuite')
        self.assertIsNotNone(suite)
        for key, expected in dict(name='inferdiff', tests=tests, failures=failures,
                                  skipped=skipped, errors=errors).items():
            self.assertEqual(suite.get(key), str(expected))
        self.assertEqual(len(suite.findall('testcase')), tests)
        self.assertGreaterEqual(float(suite.get('time')), 0.0)
        return suite

    def test_sarif_rule_indices_levels_and_safe_endpoint_location(self):
        from inferdiff.exporters import canary_cases, render_sarif

        rendered = render_sarif(canary_cases(_doctor_report()), known_secrets=('xy', 'acct/query-value'))
        log = strict_json_loads(rendered)
        self.assertIn('2.1.0', log['$schema'])
        self.assertEqual(log['version'], '2.1.0')
        self.assertEqual(len(log['runs']), 1)
        run = log['runs'][0]
        driver = run['tool']['driver']
        self.assertEqual((driver['name'], driver['version']), ('inferdiff', __version__))
        self.assertEqual([rule['id'] for rule in driver['rules']], ['C1', 'C4', 'C5', 'C6', 'C9'])
        self.assertEqual([(row['ruleId'], row['level']) for row in run['results']],
                         [('C1', 'error'), ('C4', 'warning')])
        for item in run['results']:
            self.assertEqual(driver['rules'][item['ruleIndex']]['id'], item['ruleId'])
            self.assertTrue(item['message']['text'])
            (location,) = item['locations']
            artifact = location['physicalLocation']['artifactLocation']
            self.assertIn(artifact['uriBaseId'], run['originalUriBaseIds'])
            uri = artifact['uri']
            self.assertIn('/v1/', uri)
            self.assertIn('/chat/completions/', uri)
            self.assertTrue(uri.endswith('/' + item['ruleId']))
            self.assertEqual(location['logicalLocations'][0]['fullyQualifiedName'], uri)
            self.assertNotIn('?', uri)
            self.assertNotIn('#', uri)
        for secret in ('opaque-path-secret', 'user-credential', 'query-value', 'private-fragment',
                       'bEaReR xy', 'unknown-header-value', 'url-opaque', 'second-half', 'opaque-url-query'):
            self.assertNotIn(secret, unquote(rendered))

    def test_junit_status_counts_xml_escaping_and_finite_timing(self):
        from inferdiff.exporters import canary_cases, render_junit

        xml = render_junit(canary_cases(_doctor_report()), known_secrets=('xy', 'acct/query-value'))
        suite = self.assert_counts(xml, tests=5, failures=1, skipped=1, errors=1)
        self.assertEqual(float(suite.get('time')), 1.5)
        cases = {case.get('name').split()[0]: case for case in suite.findall('testcase')}
        self.assertIn('Malformed call <tool> & arguments', cases['C1'].find('failure').get('message'))
        self.assertIn('WARN', cases['C4'].findtext('system-out'))
        self.assertTrue(cases['C5'].find('skipped').get('message'))
        self.assertTrue(cases['C6'].find('error').get('message'))
        self.assertEqual(len(cases['C9']), 0)
        for secret in ('bEaReR xy', 'unknown-header-value', 'unknown-cookie-value', 'acct%2Fquery%2Dvalue',
                       'acct/query-value', 'url-opaque', 'second-half', 'opaque-url-query'):
            self.assertNotIn(secret, xml)

    def test_multiple_findings_reuse_the_detector_rule_and_testcase(self):
        from inferdiff.exporters import audit_cases, render_junit, render_sarif

        trace = TraceDocument(
            TraceHeader('trace-id', '', '', 'openai-chat', {'url': 'https://example.test/v1'}, {}),
            [], TraceSummary(False, 0, {}, {}),
        )
        findings = [Finding('D1', 'UNCLOSED_TOOL_CALL_SUCCESS', 'P0', message)
                    for message in ('First malformed tool call', 'Second malformed tool call')]
        cases = audit_cases(trace, findings, only={'D1'})
        run = strict_json_loads(render_sarif(cases))['runs'][0]
        self.assertEqual([rule['id'] for rule in run['tool']['driver']['rules']], ['D1'])
        self.assertEqual([item['message']['text'] for item in run['results']],
                         ['First malformed tool call', 'Second malformed tool call'])
        suite = self.assert_counts(render_junit(cases), tests=1, failures=1, skipped=0, errors=0)
        self.assertIn('First malformed tool call', suite.findtext('.//failure'))
        self.assertIn('Second malformed tool call', suite.findtext('.//failure'))

    def test_canary_cli_reports_warning_failure_skip_and_error(self):
        reflected = b'private-auth-key / private%2Fquery%2Dvalue / private-extra-credential'

        def respond(path, request):
            if request['messages'][0]['content'] == 'Reply OK.':
                return 400, reflected
            if request.get('tools'):
                name = request['tools'][0]['function']['name']
                if name == 'write_config':
                    return 200, _tool_stream('tool_calls')
                return 400, reflected
            return 500, reflected

        with tempfile.TemporaryDirectory() as root, _serve(respond) as host:
            sarif, junit = Path(root) / 'report.sarif', Path(root) / 'report.xml'
            rc, stdout, stderr = _cli(
                'canary', host + '/v1?opaque=private%2Fquery-value', '--model', 'mock-model',
                '--api-key', 'private-auth-key', '--header', 'X-Auth-Token: private-extra-credential',
                '--only', 'C1,C4,C5,C6', '--timeout', '2', '--save-dir', root, '--json',
                '--out-sarif', sarif, '--out-junit', junit,
            )
            self.assertEqual((rc, stderr), (2, ''))
            sarif_text, xml = sarif.read_text(encoding='utf-8'), junit.read_text(encoding='utf-8')
            self.assert_counts(xml, tests=4, failures=1, skipped=1, errors=1)
            results = strict_json_loads(sarif_text)['runs'][0]['results']
            self.assertEqual([(item['ruleId'], item['level']) for item in results],
                             [('C1', 'error'), ('C4', 'warning')])
            self.assertEqual(len(strict_json_loads(stdout)['results']), 4)
            for exported in (sarif_text, xml, stdout, (Path(root) / 'doctor_summary.json').read_text(encoding='utf-8')):
                for secret in ('private-auth-key', 'private%2Fquery%2Dvalue', 'private-extra-credential',
                               'private/query-value'):
                    self.assertNotIn(secret, exported)

    def test_audit_and_diff_cli_map_selected_detectors_and_redact_legacy_trace_values(self):
        def respond(path, request):
            text, done = ('after', False) if request.get('ignore_eos') else ('before', True)
            return 200, _sse(
                {'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': text}}]},
                {'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]},
                {'choices': [], 'usage': {'prompt_tokens': 3, 'completion_tokens': 1, 'total_tokens': 4}},
                done=done,
            )

        with tempfile.TemporaryDirectory() as root, _serve(respond) as host:
            root = Path(root)
            before, after = root / 'before.jsonl', root / 'after.jsonl'
            endpoint = host + '/v1/chat/completions'
            request = {'model': 'mock-model', 'stream': True, 'max_tokens': 16}
            record_stream(url=endpoint, request_body=request, out_path=before, timeout=2)
            trace = record_stream(url=endpoint, request_body=dict(request, ignore_eos=True), timeout=2)
            trace.header.request['url'] = endpoint + '?opaque=legacy%2Fquery-value'
            trace.header.request['headers_redacted'] = {'x-api-key': 'legacy-header-value'}
            trace.summary.assembled['finish_reason'] = 'legacy-header-value & legacy%2Fquery%2Dvalue'
            trace.summary.assembled['reported_usage']['authorization'] = {'value': 'opaque-leak-there'}
            write_trace(after, trace)

            sarif, junit = root / 'report.sarif', root / 'report.xml'
            commands = [
                (('audit', after, '--only', 'D3,D4,D7'), ['D3', 'D4', 'D7'], 3, 0),
                (('diff', before, after, '--ignore-timing'), ['D1', 'D2', 'D3', 'D4', 'D6', 'D7', 'D8'], 8, 1),
                (('diff', before, after), ['D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8'], 8, 0),
                (('diff', after, after, '--ignore-timing'), ['D1', 'D2', 'D3', 'D4', 'D6', 'D7', 'D8'], 8, 1),
            ]
            for cmd, rules, tests, skipped in commands:
                with self.subTest(command=cmd[0]):
                    rc, stdout, stderr = _cli(*cmd, '--out-sarif', sarif, '--out-junit', junit, '--json')
                    self.assertEqual((rc, stderr), (2, ''))
                    sarif_text, xml = sarif.read_text(encoding='utf-8'), junit.read_text(encoding='utf-8')
                    self.assert_counts(xml, tests=tests, failures=1, skipped=skipped, errors=0)
                    run = strict_json_loads(sarif_text)['runs'][0]
                    self.assertEqual([rule['id'] for rule in run['tool']['driver']['rules']], rules)
                    self.assertEqual({item['ruleId']: item['level'] for item in run['results']},
                                     {'D3': 'warning', 'D4': 'error'})
                    strict_json_loads(stdout)
                    for exported in (sarif_text, xml, stdout):
                        self.assertNotIn('legacy-header-value', exported)
                        self.assertNotIn('legacy%2Fquery%2Dvalue', exported)
                        self.assertNotIn('legacy%2Fquery-value', exported)
                        self.assertNotIn('opaque-leak-there', exported)

    def test_report_outputs_cannot_replace_input_or_each_other(self):
        with tempfile.TemporaryDirectory() as root:
            trace, report = Path(root) / 'trace.jsonl', Path(root) / 'report.xml'
            trace.write_text('evidence sentinel', encoding='utf-8')
            report.write_text('report sentinel', encoding='utf-8')
            rc, _, stderr = _cli('audit', trace, '--out-junit', trace)
            self.assertEqual(rc, 1)
            self.assertIn('overwrite', stderr)
            self.assertEqual(trace.read_text(encoding='utf-8'), 'evidence sentinel')
            rc, _, stderr = _cli('audit', trace, '--out-junit', report, '--out-sarif', report)
            self.assertEqual(rc, 1)
            self.assertIn('distinct', stderr)
            self.assertEqual(report.read_text(encoding='utf-8'), 'report sentinel')

    def test_compare_canary_cli_preserves_both_targets(self):
        with tempfile.TemporaryDirectory() as root, _serve(
            lambda path, req: (200, _tool_stream('length' if path.startswith('/good/') else 'tool_calls')),
        ) as host:
            junit = Path(root) / 'report.xml'
            rc, _, stderr = _cli(
                'compare', '--a-url', host + '/good/v1', '--b-url', host + '/bad/v1',
                '--a-model', 'mock-model', '--b-model', 'mock-model', '--only', 'C1', '--ignore-timing',
                '--a-key', 'compare-api-key', '--b-label', 'compare-api-key', '--timeout', '2', '--out-junit', junit,
            )
            self.assertEqual((rc, stderr), (2, ''))
            xml = junit.read_text(encoding='utf-8')
            suite = self.assert_counts(xml, tests=2, failures=1, skipped=0, errors=0)
            a, b = suite.findall('testcase')
            self.assertTrue(a.get('classname').endswith('.A'))
            self.assertEqual(len(a), 0)
            self.assertTrue(b.get('classname').endswith('.B'))
            self.assertIsNotNone(b.find('failure'))
            self.assertNotIn('compare-api-key', xml)

    def test_compare_canary_cli_reports_identity_drift_with_passing_checks(self):
        with tempfile.TemporaryDirectory() as root, _serve(
            lambda path, req: (200, _tool_stream('length', 'rewritten' if path.startswith('/b/') else 'mock-model')),
        ) as host:
            junit = Path(root) / 'report.xml'
            rc, _, stderr = _cli(
                'compare', '--a-url', host + '/a/v1', '--b-url', host + '/b/v1',
                '--a-model', 'mock-model', '--b-model', 'mock-model', '--only', 'C1', '--ignore-timing',
                '--timeout', '2', '--out-junit', junit,
            )
            self.assertEqual((rc, stderr), (3, ''))
            suite = self.assert_counts(junit.read_text(encoding='utf-8'), tests=3, failures=1, skipped=0, errors=0)
            self.assertIn('SUSPECTED_MODEL_MISMATCH', suite.find('.//failure').get('message'))

    def test_compare_replay_cli_keeps_detector_results_and_ci_failure_threshold(self):
        def respond(path, request):
            text = 'before' if path.startswith('/a/') else 'after'
            return 200, _sse(
                {'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': text}}]},
                {'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]},
            )

        with tempfile.TemporaryDirectory() as root, _serve(respond) as host:
            junit, request = Path(root) / 'report.xml', Path(root) / 'request.json'
            request.write_text('{"model":"mock-model","stream":true}', encoding='utf-8')
            rc, _, stderr = _cli(
                'compare', '--before-url', host + '/a/v1/chat/completions',
                '--after-url', host + '/b/v1/chat/completions', '--request', request,
                '--ignore-timing', '--timeout', '2', '--out-junit', junit, '--fail-on', 'any-diff',
            )
            self.assertEqual((rc, stderr), (3, ''))
            suite = self.assert_counts(junit.read_text(encoding='utf-8'), tests=9, failures=1, skipped=1, errors=0)
            self.assertIn('semantic', suite.find('.//failure').get('message').lower())
