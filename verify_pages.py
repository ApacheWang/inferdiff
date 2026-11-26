"""Verify the static site with Python and Node. Add --chrome for browser tests."""

import argparse
from collections import Counter
from functools import partial
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from threading import Thread
import time
from urllib.parse import unquote, urlsplit


VOID = set("area base br col embed hr img input link meta param source track wbr".split())
ASSET_ATTRS = {
    "audio": ("src",), "embed": ("src",), "iframe": ("src",), "image": ("href", "xlink:href"),
    "img": ("src", "srcset"), "input": ("src",), "link": ("href",), "object": ("data",),
    "script": ("src",), "source": ("src", "srcset"), "track": ("src",), "use": ("href", "xlink:href"),
    "video": ("src", "poster"),
}
JS_TYPES = {"", "module", "text/javascript", "application/javascript", "text/ecmascript"}
CSS_REFERENCE = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)|@import\s*(['\"])(.*?)\3", re.I | re.S)
SENSITIVE = {
    "possible credential": re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{30,}|"
        r"github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{24,}|"
        r"(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{14,}|"
        r"eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,})\b|"
        r"\bBearer\s+[A-Za-z0-9._-]{20,}|"
        r"\b(?:api[_-]?key|password|secret|access[_-]?token)['\"]?\s*[:=]\s*"
        r"['\"][A-Za-z0-9+/_.@!$-]{16,}['\"]",
        re.I,
    ),
    "machine-local path": re.compile(
        r"\b[A-Z]:[\\/]+|\bfile:/+|\\\\[\w.-]+\\+[\w.-]+|"
        r"(?<![\w/.:])/(?:Users|home|mnt|Volumes|private|var/folders|tmp)/",
        re.I,
    ),
}

STREAM_FIXTURES = r"""
const args = '{"node":"edge';
const fakeKey = 'sk-' + 'syntheticFixtureOnly123456789';
const fakeBearer = 'header.payload.signature';
const prefix = 'Authorization: Bearer ' + fakeBearer + '\n\n';
const events = (...entries) => entries.map(payload => {
  if (payload === '[DONE]') return 'data: [DONE]\n\n';
  return (payload.type ? 'event: ' + payload.type + '\n' : '') +
    'data: ' + JSON.stringify(payload) + '\n\n';
}).join('');
const added = {
  type: 'response.output_item.added', output_index: 0,
  item: { type: 'function_call', name: 'lookup', call_id: 'call_fixture', arguments: '', status: 'in_progress' }
};
const delta = { type: 'response.function_call_arguments.delta', output_index: 0, delta: args };
const argsDone = { type: 'response.function_call_arguments.done', output_index: 0, arguments: args };
const itemDone = status => ({
  type: 'response.output_item.done', output_index: 0,
  item: { ...added.item, arguments: args, status }
});
const completed = { type: 'response.completed', response: { status: 'completed', audit: fakeKey } };
const incomplete = {
  type: 'response.incomplete',
  response: { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } }
};
const breachedSse = prefix + events(added, delta, itemDone('completed'), completed);
const trace = (after = false) => [
  { type: 'header', schema_version: 'inferdiff.trace.v1', dialect: 'openai-responses',
    trace_id: 'tr_case1_fixture', response_meta: { status_code: 200 } },
  ...(after ? [added, delta, argsDone, itemDone('incomplete'), incomplete]
    : [added, delta, itemDone('completed'), completed]).map((payload, seq) => ({
      type: 'frame', seq, t_rel_ms: [43.5, 89.9, 133.1, 151.6, 152.4][seq],
      dt_ms: 42, sse_event: payload.type, raw_wire: events(payload),
      is_done_sentinel: payload.type === 'response.completed' || payload.type === 'response.incomplete',
      parse_error: null,
      norm: { phase: 'TOOL_CALL', text_delta: '', reasoning_delta: '',
        tool_deltas: payload === delta ? [{ index: 0, args_delta: args }] : [],
        closed_events: [], finish_reason: null, terminal_status: payload.response?.status ?? null }
    })),
  { type: 'summary', eof_clean: true, total_frames: after ? 5 : 4, assembled: {
    content_text: '', reasoning_text: '', finish_reason: 'unknown',
    terminal_status: after ? 'incomplete' : 'completed',
    tool_calls: [{ index: 0, id: 'call_fixture', name: 'lookup', raw_arguments: args,
      json_valid: false, saw_args_done_event: after }]
  }}
].map(row => JSON.stringify(row)).join('\n');
"""

PARSER_TESTS = r"""
const assert = require('node:assert/strict');
require(process.argv[1]);
const { inspect, redact } = globalThis.InferdiffStream;

const before = inspect(breachedSse);
assert.equal(before.protocol, 'Responses', 'detect the Responses event stream');
assert.equal(before.frames.length, 4, 'count SSE frames without log headers');
assert.equal(before.verdict, 'breach', 'completed with partial arguments is a breach');
assert.equal(before.missingArgumentsDone, 1, 'identify missing Responses arguments.done');
assert.equal(before.tools[0].valid, false, 'partial JSON is invalid');
assert.equal(before.tools[0].text, args, 'closing snapshot must not duplicate tool deltas');
assert.ok(!JSON.stringify(before).includes(fakeKey), 'redact keys from inspector output');
const sanitized = redact(breachedSse);
assert.equal(sanitized.count, 2, 'redact both credential forms');
assert.ok(!sanitized.text.includes(fakeBearer) && !sanitized.text.includes(fakeKey), 'mask pasted credentials');

const after = inspect(events(added, delta, argsDone, itemDone('incomplete'), incomplete));
assert.equal(after.verdict, 'incomplete', 'an explicit token limit honestly reports truncation');
assert.equal(after.missingArgumentsDone, 0, 'record an arguments.done event');
assert.ok(JSON.stringify(after.endings).includes('max_output_tokens'), 'expose the reason for Responses truncation');

const chatChunk = (delta, finish_reason = null, index = 0) => ({
  object: 'chat.completion.chunk', choices: [{ index, delta, finish_reason }]
});
const chatTool = (index, args) => ({ index, function: { arguments: args } });
const chat = inspect(events(
  chatChunk({ content: '你好 ' }),
  chatChunk({ content: '🌍', tool_calls: [chatTool(0, '{"a":'), chatTool(1, '{"b":')] }),
  chatChunk({ tool_calls: [chatTool(1, '2}'), chatTool(0, '1}')] }),
  chatChunk({}, 'tool_calls'), '[DONE]'
).replaceAll('\n', '\r\n'));
assert.equal(chat.protocol, 'Chat Completions');
assert.equal(chat.verdict, 'pass');
assert.deepEqual(chat.tools.map(tool => tool.text), ['{"a":1}', '{"b":2}'], 'keep interleaved calls separate');
assert.ok(chat.tools.every(tool => tool.valid), 'validate complete JSON');
assert.equal(chat.texts[0].text, '你好 🌍', 'assemble UTF-8 text');
const chatStop = inspect(events(
  chatChunk({ tool_calls: [chatTool(0, args)] }), chatChunk({}, 'stop'), '[DONE]'
).replaceAll('\n\n', '\n'));
assert.equal(chatStop.verdict, 'breach', 'detect a false stop even in a compact SSE paste');
const choices = inspect(events(
  chatChunk({ tool_calls: [chatTool(0, args)] }, 'length', 0),
  chatChunk({ content: 'fine' }, 'stop', 1), '[DONE]'
));
assert.ok(choices.verdict !== 'breach', 'associate each finish reason with its own choice');

const anthropic = reason => inspect(events(
  { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'lookup', input: {} } },
  { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: args } },
  { type: 'content_block_stop', index: 0 },
  { type: 'message_delta', delta: { stop_reason: reason } }, { type: 'message_stop' }
));
assert.equal(anthropic('end_turn').protocol, 'Anthropic Messages');
assert.equal(anthropic('end_turn').verdict, 'breach');
assert.equal(anthropic('tool_use').verdict, 'breach');
assert.equal(anthropic('max_tokens').verdict, 'incomplete');

const gemini = reason => inspect(events(
  { candidates: [{ content: { parts: [{ text: 'ready' }] } }] },
  { candidates: [{ finishReason: reason, content: { parts: [
    { functionCall: { name: 'lookup', ...(reason === 'STOP' ? { args: { node: 'edge' } } : {}) } }
  ] } }] }
));
assert.equal(gemini('STOP').protocol, 'Gemini SSE');
assert.equal(gemini('STOP').verdict, 'pass');
assert.equal(gemini('STOP').tools[0].valid, true);
assert.equal(gemini('MAX_TOKENS').verdict, 'incomplete');

const recorded = inspect(trace());
assert.equal(recorded.protocol, 'inferdiff trace');
assert.equal(recorded.frames.length, 4);
assert.equal(recorded.frames[0].ms, 43.5, 'keep recorded trace timing');
assert.equal(recorded.tools.length, 1, 'do not count summary tools twice');
assert.equal(recorded.verdict, 'breach');
assert.equal(inspect(trace(true)).verdict, 'incomplete');
assert.ok(inspect('data: {malformed}\n\n').issueCount, 'surface malformed event JSON');
const unusualIndex = { toString: null };
const malformedResponses = inspect(events({ ...delta, output_index: unusualIndex },
  { ...argsDone, arguments: { toString: null } }, completed));
assert.equal(malformedResponses.protocol, 'Responses', 'malformed fields should preserve protocol detection');
assert.equal(malformedResponses.frames.length, 3, 'retain malformed payloads for frame inspection');
assert.deepEqual(malformedResponses.frames[0].payload.output_index, unusualIndex, 'retain the malformed frame evidence');
assert.notEqual(malformedResponses.verdict, 'pass', 'malformed tool frames cannot count as a pass');
assert.equal(inspect('').frames.length, 0, 'clear the inspection on empty input');
"""

BROWSER_TESTS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const [debugURL, origin, fileURL, tracePath, screenshotPath] = process.argv.slice(1);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const probe = selector => 'document.querySelector(' + JSON.stringify(selector) + ')';

async function connect() {
  const tabs = await (await fetch(debugURL + '/json/list')).json();
  const target = tabs.find(tab => tab.type === 'page');
  assert.ok(target?.webSocketDebuggerUrl, 'Chrome must open a debuggable page');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('Chrome DevTools connection failed')), { once: true });
  });
  const pending = new Map();
  const observed = [];
  let nextId = 0;
  socket.addEventListener('close', () => {
    for (const call of pending.values()) {
      clearTimeout(call.timer);
      call.reject(new Error('Chrome DevTools disconnected during ' + call.method));
    }
    pending.clear();
  });
  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    if (message.method) observed.push(message);
    const call = pending.get(message.id);
    if (!call) return;
    pending.delete(message.id);
    clearTimeout(call.timer);
    if (message.error) call.reject(new Error(call.method + ': ' + message.error.message));
    else call.resolve(message.result);
  });
  function command(method, params = {}) {
    if (socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('Chrome DevTools disconnected'));
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(method + ' timed out'));
      }, 7000);
      pending.set(id, { method, resolve, reject, timer });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  return { socket, command, observed };
}

async function main() {
  const { socket, command, observed } = await connect();
  async function evaluate(expression) {
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.result?.description || result.exceptionDetails.text);
    return result.result.value;
  }
  async function waitFor(expression, label) {
    for (let attempts = 0; attempts < 60; attempts++) {
      if (await evaluate(expression)) return;
      await delay(50);
    }
    throw new Error('Timed out waiting for ' + label);
  }
  async function click(selector) {
    await evaluate(probe(selector) + '.click()');
  }
  async function navigate(url) {
    const { errorText } = await command('Page.navigate', { url });
    assert.ok(!errorText, errorText);
    await waitFor('location.href === ' + JSON.stringify(url) +
      ' && document.readyState === "complete" && !!' + probe('.replay-tab'), 'showcase to load');
  }
  function requests(checkpoint) {
    return observed.slice(checkpoint).flatMap(({ method, params }) => {
      if (method === 'Network.requestWillBeSent') return [params.request.url];
      if (method === 'Network.webSocketCreated') return [params.url];
      return [];
    }).filter(url => /^(https?|wss?):/i.test(url));
  }

  try {
    for (const domain of ['Page', 'Runtime', 'Network', 'Log', 'DOM']) await command(domain + '.enable');
    await command('Page.bringToFront');
    await command('Emulation.setFocusEmulationEnabled', { enabled: true });
    await command('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
    let screenshot;
    for (const [width, height, mobile] of [[1440, 960, false], [390, 844, true]]) {
      const checkpoint = observed.length;
      await command('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile });
      await command('Emulation.setTouchEmulationEnabled', { enabled: mobile });
      await navigate(origin + '/index.html');
      await click('[data-language="en"]');
      const ready = observed.length;
      assert.equal(await evaluate('innerWidth'), width);
      assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'page overflows at ' + width);
      assert.equal(await evaluate('document.querySelectorAll("#probe-grid .probe-card").length'), 18);
      assert.match(await evaluate(probe('[data-probe-id="C10"]') + '.textContent'), /v0\.2.*Preview/i);
      assert.ok(await evaluate(probe('[data-variant="before"]') + '.getAttribute("aria-pressed") === "true"'));
      assert.equal(await evaluate(probe('#replay-app .inspector-event') + '.textContent'), 'response.completed');
      assert.match(await evaluate(probe('#replay-app .finding-copy') + '.textContent'), /arguments\.done/);
      await click('[data-variant="after"]');
      const terminalFrames = await evaluate(
        'Array.from(document.querySelectorAll("#replay-app .frame-dot"), frame => frame.title.split(" · ")[0])' +
        '.filter(event => /arguments\.done|output_item\.done|response\.incomplete|response\.completed/.test(event))'
      );
      assert.deepEqual(terminalFrames, [
        'response.function_call_arguments.done', 'response.output_item.done', 'response.incomplete',
      ]);
      assert.match(await evaluate(probe('#replay-app .finding-copy') + '.textContent'), /protocol_violations:\s*\[\]/);
      assert.match(await evaluate(probe('#replay-app .inspector-code') + '.textContent'), /max_output_tokens/);
      await click('[data-scenario="C10"]');
      assert.ok(await evaluate(probe('[data-scenario="C10"]') + '.getAttribute("aria-pressed") === "true"'));
      assert.match(await evaluate(probe('#replay-app .finding-copy') + '.textContent'), /STOP|MAX_TOKENS/);
      await click('[data-scenario="C1"]');
      await click('[data-variant="before"]');

      await click('[data-stream-sample="healthy"]');
      await waitFor(probe('.stream-frame'), 'healthy sample frames');
      assert.notEqual(await evaluate(probe('#stream-finding') + '.dataset.tone'), 'crimson');

      if (mobile) {
        const { root } = await command('DOM.getDocument');
        const { nodeId } = await command('DOM.querySelector', { nodeId: root.nodeId, selector: '#stream-file' });
        await command('DOM.setFileInputFiles', { nodeId, files: [tracePath] });
      } else {
        const { x, y } = await evaluate(`(() => {
          const target = document.querySelector('.stream-drop');
          target.scrollIntoView({ block: 'center', behavior: 'instant' });
          const bounds = target.getBoundingClientRect();
          return { x: bounds.x + bounds.width / 2, y: bounds.y + bounds.height / 2 };
        })()`);
        const data = { items: [], files: [tracePath], dragOperationsMask: 1 };
        for (const type of ['dragEnter', 'dragOver', 'drop']) {
          await command('Input.dispatchDragEvent', { type, x, y, data });
        }
      }
      await waitFor(probe('#stream-protocol') + '.textContent.includes("inferdiff trace")', 'trace file inspection');
      assert.match(await evaluate(probe('#stream-count') + '.textContent'), /\b4\b/);

      await evaluate('navigator.clipboard.writeText(' + JSON.stringify(breachedSse) + ')');
      await evaluate(probe('#stream-input') + '.focus(); ' + probe('#stream-input') + '.select()');
      const paste = { modifiers: 2, key: 'v', code: 'KeyV', windowsVirtualKeyCode: 86 };
      await command('Input.dispatchKeyEvent', { type: 'rawKeyDown', ...paste });
      await command('Input.dispatchKeyEvent', { type: 'keyUp', ...paste });
      await waitFor(probe('#stream-protocol') + '.textContent.includes("Responses") && ' +
        probe('#stream-finding') + '.dataset.tone === "crimson"', 'pasted Responses P0 breach');
      assert.match(await evaluate(probe('#stream-finding') + '.textContent'), /P0 BREACH/);
      assert.ok(await evaluate(
        'getComputedStyle(' + probe('#stream-finding') + ').getPropertyValue("--tone").trim() === ' +
        'getComputedStyle(document.documentElement).getPropertyValue("--crimson").trim()' +
        ' && !!getComputedStyle(document.documentElement).getPropertyValue("--crimson").trim()'
      ), 'P0 finding uses the crimson accent');
      assert.ok(await evaluate('![' + JSON.stringify(fakeKey) + ',' + JSON.stringify(fakeBearer) +
        '].some(secret => ' + probe('#stream-input') + '.value.includes(secret))'), 'pasted credentials are masked');
      assert.equal(await evaluate('document.querySelectorAll(".stream-frame").length'), 4);
      await click('.stream-frame:last-child');
      assert.match(await evaluate(probe('#stream-frame-code') + '.textContent'), /completed/);
      assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'inspection overflows at ' + width);

      await click('[data-language="zh"]');
      assert.equal(await evaluate('document.documentElement.lang'), 'zh-CN');
      assert.match(await evaluate(probe('#inspect h2') + '.textContent'), /粘贴日志离线诊断/);
      assert.match(await evaluate(probe('#stream-finding') + '.textContent'), /P0/);
      await click('[data-language="en"]');
      if (!mobile && screenshotPath) {
        await evaluate('document.activeElement.blur(); ' + probe('#stream-input') +
          '.scrollTop = 0; window.scrollTo({ top: 0, behavior: "instant" })');
        const { cssContentSize } = await command('Page.getLayoutMetrics');
        ({ data: screenshot } = await command('Page.captureScreenshot', {
          format: 'png', captureBeyondViewport: true, clip: {
            x: 0, y: 0, width, height: Math.ceil(cssContentSize.height), scale: 1,
          },
        }));
      }
      const external = requests(checkpoint).filter(url => new URL(url).origin !== origin);
      assert.deepEqual(external, [], 'no external requests at ' + width);
      assert.deepEqual(requests(ready), [], 'no network during local interactions at ' + width);
      console.log('PASS: Chrome ' + width + 'px, clipboard-pasted crimson P0, ' +
        (mobile ? 'file picker' : 'file drop') + ', replay, C10, localization, zero external requests.');
    }

    const offlineCheckpoint = observed.length;
    await command('Network.emulateNetworkConditions', {
      offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0,
    });
    await navigate(fileURL);
    await click('[data-stream-sample="breach"]');
    await waitFor(probe('#stream-finding') + '.dataset.tone === "crimson"', 'standalone offline inspection');
    assert.deepEqual(requests(offlineCheckpoint), [], 'standalone page requires no HTTP');
    const faults = observed.filter(({ method, params }) =>
      method === 'Runtime.exceptionThrown' ||
      (method === 'Runtime.consoleAPICalled' && params.type === 'error') ||
      (method === 'Log.entryAdded' && params.entry.level === 'error')
    );
    assert.deepEqual(faults, [], 'Chrome reports zero console or JavaScript errors');
    if (screenshot) fs.writeFileSync(screenshotPath, Buffer.from(screenshot, 'base64'));
    console.log('PASS: Chrome standalone file with networking disabled, zero console or JavaScript errors.');
  } finally {
    await command('Browser.close').catch(() => {});
    socket.close();
  }
}

fs.writeFileSync(tracePath, trace());
main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
"""


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.counts = Counter()
        self.doctypes = 0
        self.ids = set()
        self.dependencies = []
        self.scripts = []
        self.styles = []
        self.errors = []

    def error(self, message):
        self.errors.append(f"index.html:{self.getpos()[0]}: {message}")

    def handle_decl(self, declaration):
        if declaration.strip().lower() == "doctype html" and not self.counts:
            self.doctypes += 1
        else:
            self.error("expected <!doctype html> before the document")

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.counts[tag] += 1
        parent = self.stack[-1][0] if self.stack else None
        if not self.stack and tag != "html":
            self.error(f"<{tag}> is outside the document")
        expected_parent = {"head": "html", "body": "html", "title": "head"}.get(tag)
        if expected_parent and parent != expected_parent:
            self.error(f"<{tag}> is in the wrong part of the document")
        if len(attributes) != len(attrs):
            self.error(f"duplicate attribute on <{tag}>")
        if tag == "html" and not attributes.get("lang"):
            self.error("<html> requires a language")
        if tag == "base":
            self.error("<base> can break relative asset URLs")

        element_id = attributes.get("id")
        if element_id in self.ids:
            self.error("duplicate id attribute")
        if element_id:
            self.ids.add(element_id)

        for asset_attr in ASSET_ATTRS.get(tag, ()):
            if asset_attr not in attributes:
                continue
            reference = attributes[asset_attr] or ""
            if asset_attr == "srcset":
                for candidate in reference.split(","):
                    if candidate.strip():
                        self.dependencies.append((tag, candidate.split()[0]))
            else:
                self.dependencies.append((tag, reference))
        if tag == "meta" and (attributes.get("http-equiv") or "").lower() == "refresh":
            self.error("meta refresh can navigate away from the offline site")
        if attributes.get("style"):
            self.styles.append(attributes["style"])
        if tag not in VOID:
            self.stack.append((tag, attributes, [], self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        if tag not in VOID and tag != "svg" and not any(node[0] == "svg" for node in self.stack):
            self.error(f"<{tag}> requires an explicit closing tag")
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_data(self, data):
        if self.stack and self.stack[-1][0] in {"script", "style"}:
            self.stack[-1][2].append(data)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1][0] != tag:
            self.error(f"unexpected </{tag}>")
            return
        _, attributes, parts, line = self.stack.pop()
        if tag == "style":
            self.styles.append("".join(parts))
        if tag == "script":
            script_type = (attributes.get("type") or "").strip().lower()
            if script_type in JS_TYPES:
                if attributes.get("src"):
                    self.scripts.append((attributes["src"], None, script_type))
                else:
                    self.scripts.append((f"index.html:{line} inline script", "".join(parts), script_type))


def asset_path(root, reference, allow_data, errors, label):
    reference = reference.strip()
    try:
        url = urlsplit(reference)
    except ValueError:
        errors.append(f"{label}: invalid asset URL")
        return None
    if allow_data and (reference.startswith("#") or (
        url.scheme == "data" and url.path.lower().startswith(("image/", "font/"))
    )):
        return None
    if url.scheme or url.netloc or reference.startswith(('/', '\\')):
        errors.append(f"{label}: asset URL must be relative or embedded")
        return None
    path = (root / unquote(url.path)).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        errors.append(f"{label}: missing or out-of-directory asset")
        return None
    return path


def check_javascript(scripts, errors):
    node = shutil.which("node")
    if not node:
        errors.append("Node.js is needed to parse JavaScript during verification")
        return
    for label, source, script_type in scripts:
        command = [node, "--check", "--input-type=module", "-"] if script_type == "module" else [
            node, "-e", "new (require('node:vm').Script)(require('node:fs').readFileSync(0, 'utf8'))",
        ]
        result = subprocess.run(
            command, input=source, capture_output=True, encoding="utf-8", timeout=15, check=False,
        )
        if result.returncode:
            detail = re.search(r"^SyntaxError: .+$", result.stderr, re.MULTILINE)
            errors.append(f"{label}: {detail[0] if detail else 'JavaScript parser failed'}")


def run_node(source, arguments=(), timeout=15):
    node = shutil.which("node")
    if not node:
        raise OSError("Node.js is required")
    return subprocess.run(
        [node, "-e", source, *map(str, arguments)],
        capture_output=True, encoding="utf-8", timeout=timeout, check=False,
    )


def check_stream_inspector(root, errors):
    script = root / "stream-inspector.js"
    if not script.is_file():
        errors.append("stream-inspector.js is missing")
        return
    result = run_node(STREAM_FIXTURES + PARSER_TESTS, [script])
    if result.returncode:
        detail = re.search(r"^\w*Error(?: \[[^\]]+\])?: .+$", result.stderr, re.MULTILINE)
        errors.append(f"stream inspector regression failed: {detail[0] if detail else 'Node test failed'}")


def verify(root):
    page_path = root / "index.html"
    if not page_path.is_file():
        return ["index.html is missing"]
    sources = {
        path: path.read_text(encoding="utf-8-sig")
        for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in {".html", ".css", ".js"}
    }

    page = Page()
    page.feed(sources[page_path])
    page.close()
    errors = page.errors
    if page.stack:
        errors.append(f"index.html: unclosed <{page.stack[-1][0]}>")
    if page.doctypes != 1:
        errors.append("index.html: expected one HTML doctype")
    for tag in ("html", "head", "title", "body", "main"):
        if page.counts[tag] != 1:
            errors.append(f"index.html: expected one <{tag}>")

    for tag, reference in page.dependencies:
        path = asset_path(root, reference, tag != "script", errors, f"index.html <{tag}>")
        if path and path.suffix.lower() in {".css", ".js"} and path not in sources:
            sources[path] = path.read_text(encoding="utf-8-sig")
    for path, source in sources.items():
        for kind, pattern in SENSITIVE.items():
            match = pattern.search(source)
            if match:
                line = source.count("\n", 0, match.start()) + 1
                errors.append(f"{path.name}:{line}: {kind}")
    styles = [(path.parent, path.name, source) for path, source in sources.items() if path.suffix.lower() == ".css"]
    styles.extend((root, "index.html style", style) for style in page.styles)
    for directory, label, source in styles:
        for match in CSS_REFERENCE.finditer(source):
            asset_path(directory, match[2] if match[2] is not None else match[4], True, errors, label)

    copy = "\n".join(source for path, source in sources.items() if path.suffix.lower() != ".css")
    if len(re.findall(r"[\u3400-\u9fff]", copy)) < 20 or not re.search(r"\b(?:en|english)\b", copy, re.I):
        errors.append("English and Chinese UI strings are required")

    scripts = []
    linked_scripts = set()
    for label, source, script_type in page.scripts:
        if source is None:
            path = asset_path(root, label, False, [], "script")
            if not path:
                continue
            linked_scripts.add(path)
            label, source = path.name, path.read_text(encoding="utf-8-sig")
        scripts.append((label, source, script_type))
    scripts.extend((path.name, source, "") for path, source in sources.items()
                   if path.suffix.lower() == ".js" and path not in linked_scripts)
    if not errors:
        check_javascript(scripts, errors)
        check_stream_inspector(root, errors)
    return errors


class PageHandler(BaseHTTPRequestHandler):
    CONTENT_TYPES = {
        ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
        ".png": "image/png", ".woff2": "font/woff2",
    }

    def __init__(self, *args, directory):
        self.directory = directory
        super().__init__(*args)

    def log_message(self, *_):
        pass

    def do_GET(self):
        path = asset_path(self.directory, self.path.lstrip("/"), False, [], "browser asset")
        mime_type = self.CONTENT_TYPES.get(path.suffix.lower()) if path else None
        if not mime_type:
            self.send_error(404)
            return
        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def chrome_endpoint(profile, process):
    port_file = profile / "DevToolsActivePort"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if port_file.is_file():
            lines = port_file.read_text(encoding="utf-8").splitlines()
            if lines and lines[0].isdigit():
                return f"http://127.0.0.1:{lines[0]}"
        if process.poll() is not None:
            raise RuntimeError(f"headless Chrome exited during startup ({process.returncode})")
        time.sleep(0.05)
    raise RuntimeError("headless Chrome did not open its DevTools port")


def verify_browser(root, chrome, screenshot, chrome_no_sandbox=False):
    handler = partial(PageHandler, directory=root)
    with tempfile.TemporaryDirectory(prefix="inferdiff-pages-") as temporary, \
            ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        profile = Path(temporary) / "profile"
        origin = f"http://127.0.0.1:{server.server_port}"
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            chrome_args = [
                str(chrome), "--headless=new", "--disable-gpu", "--disable-software-rasterizer",
                "--disable-background-networking", "--disable-component-update", "--disable-default-apps",
                "--no-first-run", "--no-default-browser-check", "--proxy-server=direct://",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--remote-debugging-port=0",
                f"--user-data-dir={profile}",
            ]
            if chrome_no_sandbox:
                chrome_args.append("--no-sandbox")
            with subprocess.Popen(
                [*chrome_args, "about:blank"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ) as process:
                try:
                    result = run_node(STREAM_FIXTURES + BROWSER_TESTS, [
                        chrome_endpoint(profile, process), origin, (root / "index.html").as_uri(),
                        Path(temporary) / "fixture.trace.jsonl", screenshot or "",
                    ], timeout=45)
                finally:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.terminate()
            return result
        finally:
            server.shutdown()
            thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", type=Path, help="run interactive tests with this Chrome executable")
    parser.add_argument("--chrome-no-sandbox", action="store_true", help="run Chrome inside an existing OS sandbox")
    parser.add_argument("--screenshot", type=Path, help="save a full 1440px preview after the browser checks pass")
    options = parser.parse_args()
    if options.screenshot and not options.chrome:
        parser.error("--screenshot requires --chrome")
    if options.chrome_no_sandbox and not options.chrome:
        parser.error("--chrome-no-sandbox requires --chrome")
    root = Path(__file__).resolve().parent
    try:
        errors = verify(root)
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: verification failed ({type(error).__name__})")
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: HTML structure, local assets, JavaScript syntax, bilingual strings, leak scan, and offline parser fixtures.")
    if options.chrome:
        try:
            result = verify_browser(root, options.chrome.resolve(), options.screenshot, options.chrome_no_sandbox)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            print(f"FAIL: browser verification failed ({error})")
            return 1
        if result.stdout:
            print(result.stdout.strip())
        if result.returncode:
            print(f"FAIL: {result.stderr.strip() or 'Chrome tests failed'}")
            return 1
        if options.screenshot:
            print(f"PASS: saved {options.screenshot.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
