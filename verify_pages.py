"""Verify the static site with Python, Node.js 22+, and headless Chrome or Chromium."""

import argparse
from collections import Counter
from functools import partial
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
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
OFFLINE_CSP = ("connect-src 'none'", "form-action 'none'", "object-src 'none'", "base-uri 'none'")
SENSITIVE = {
    "machine-local account": re.compile(r"\bbc15[5]\b", re.I),
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

CONTROL_FIXTURES = r"""
const quickstarts = [
  ['python', 'Python CLI', 'uvx inferdiff doctor http://127.0.0.1:8080/v1 --html report.html', 'Python 命令行'],
  ['pipe', 'Unix Pipe', 'curl -sN https://api.example/v1/chat/completions ... | inferdiff audit -', 'Unix 管道'],
  ['node', 'Node / TS', 'npx inferdiff-js proxy --upstream https://api.example/v1', 'Node / TS 代理'],
  ['pytest', 'pytest SDK', 'from inferdiff.testing import assert_sse_honest, assert_endpoint_honest', 'pytest 测试'],
  ['actions', 'GitHub Actions', 'uses: ApacheWang/inferdiff@v0', 'GitHub 工作流'],
  ['chaos', 'Local Chaos', 'inferdiff-chaos --scenario c1-responses-lie', '本地故障模拟'],
];
const openaiProbes = Array.from({ length: 8 }, (_, index) => 'C' + (index + 1));
const anthropicGeminiProbes = ['C9', 'C10'];
const proxyStorageProbes = Array.from({ length: 8 }, (_, index) => 'D' + (index + 1));
const filters = [
  ['all', 'All', [...openaiProbes, ...anthropicGeminiProbes, ...proxyStorageProbes], '全部'],
  ['openai', 'OpenAI C1–C8', openaiProbes, 'OpenAI C1–C8'],
  ['anthropic-gemini', 'Anthropic & Gemini C9–C10', anthropicGeminiProbes, 'Anthropic 与 Gemini C9–C10'],
  ['proxy-storage', 'Live Proxy & Storage D1–D8', proxyStorageProbes, '实时代理与存储 D1–D8'],
];
const quickTab = id => `[data-quickstart="${id}"]`;
const probeFilter = id => `[data-probe-filter="${id}"]`;
"""

MOCK_DOM_TESTS = r"""
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const read = name => readFileSync(join(process.argv[1], name), 'utf8');
const html = read('index.html');
const voidTags = new Set('area base br col embed hr img input link meta param source track wbr'.split(' '));
const decode = text => text.replace(/&(amp|quot|apos|lt|gt|#\d+);/g, (_, entity) =>
  entity.startsWith('#') ? String.fromCodePoint(Number(entity.slice(1))) :
    ({ amp: '&', quot: '"', apos: "'", lt: '<', gt: '>' })[entity]
);

// Model the selectors, event bubbling and editing operations used by the page.
// Parse its real static HTML and the replay templates inserted through innerHTML.
class Element {
  constructor(tag = '', text = '') {
    this.tag = tag;
    this.text = text;
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.style = { setProperty() {} };
    this.value = '';
    this.selectionStart = this.selectionEnd = 0;
    this.dataset = new Proxy({}, {
      get: (_, key) => this.getAttribute(Element.dataAttr(key)) ?? undefined,
      set: (_, key, value) => (this.setAttribute(Element.dataAttr(key), value), true),
    });
  }
  static dataAttr(key) { return 'data-' + key.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase()); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  hasAttribute(name) { return this.attributes.has(name); }
  removeAttribute(name) { this.attributes.delete(name); }
  toggleAttribute(name, force) { if (force) this.setAttribute(name, ''); else this.removeAttribute(name); }
  get firstChild() { return this.children[0] ?? null; }
  get textContent() { return this.text + this.children.map(node => node.textContent).join(''); }
  set textContent(text) { this.children = []; this.text = text == null ? '' : String(text); }
  set innerHTML(text) { this.replaceChildren(...parse(text).children); }
  append(...nodes) {
    for (const node of nodes) {
      if (node.tag === '#fragment') { this.append(...node.children); continue; }
      node.parentElement = this;
      this.children.push(node);
    }
  }
  replaceChildren(...nodes) { this.textContent = ''; this.append(...nodes); }
  matches(selector) {
    const attr = selector.match(/^\[([\w-]+)(?:="([^"]*)")?\]$/);
    if (attr) return attr[2] == null ? this.hasAttribute(attr[1]) : this.getAttribute(attr[1]) === attr[2];
    if (selector.startsWith('.')) return this.className.split(/\s+/).includes(selector.slice(1));
    if (selector.startsWith('#')) return this.getAttribute('id') === selector.slice(1);
    return this.tag === selector;
  }
  closest(selector) {
    return this.matches(selector) ? this : this.parentElement?.closest(selector) ?? null;
  }
  querySelectorAll(selector) {
    const terms = selector.split(/\s+/);
    const collect = (node, index) => node.children.flatMap(child => {
      const descendants = collect(child, index);
      if (!child.matches(terms[index])) return descendants;
      return index === terms.length - 1 ? [child, ...descendants] : collect(child, index + 1).concat(descendants);
    });
    return collect(this, 0);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
  emit(type, attributes = {}) {
    const event = { target: this, ...attributes, preventDefault() { this.defaultPrevented = true; } };
    for (let node = this; node; node = node.parentElement) {
      for (const listener of node.listeners.get(type) || []) listener(event);
    }
    return event;
  }
  click() { if (!this.disabled) this.emit('click'); }
  focus() { document.activeElement = this; }
  setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
  setRangeText(text, start, end) {
    this.value = this.value.slice(0, start) + text + this.value.slice(end);
    this.setSelectionRange(start + text.length, start + text.length);
  }
  getBoundingClientRect() { return { left: 0, right: 0, width: 0 }; }
}

for (const [property, attr] of Object.entries({ className: 'class', href: 'href', rel: 'rel', target: 'target' })) {
  Object.defineProperty(Element.prototype, property, {
    get() { return this.getAttribute(attr) ?? ''; }, set(value) { this.setAttribute(attr, value); },
  });
}
for (const attribute of ['hidden', 'disabled', 'open']) {
  Object.defineProperty(Element.prototype, attribute, {
    get() { return this.hasAttribute(attribute); }, set(value) { this.toggleAttribute(attribute, value); },
  });
}

function parse(markup) {
  const root = new Element('#document');
  const parents = [root];
  for (const part of markup.match(/<!--[\s\S]*?-->|<![^>]*>|<\/?[\w-]+(?:[^>"']|"[^"]*"|'[^']*')*>|[^<]+|</g) || []) {
    if (part.startsWith('<!')) continue;
    if (part.startsWith('</')) { parents.pop(); continue; }
    const tag = part.match(/^<([\w-]+)/)?.[1];
    if (!tag) { parents.at(-1).append(new Element('#text', decode(part))); continue; }
    const node = new Element(tag);
    const rawAttrs = part.slice(tag.length + 1);
    for (const [, attr, double, single, bare] of rawAttrs.matchAll(/([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      node.setAttribute(attr, decode(double ?? single ?? bare ?? ''));
    }
    parents.at(-1).append(node);
    if (!voidTags.has(tag) && !part.endsWith('/>')) parents.push(node);
  }
  return root;
}

const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
const document = parse(html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ''));
const query = selector => {
  const element = document.querySelector(selector);
  assert.ok(element, 'missing ' + selector);
  return element;
};
Object.assign(document, {
  documentElement: query('html'), body: query('body'), getElementById: id => document.querySelector('#' + id),
  createElement: tag => new Element(tag), createTextNode: text => new Element('#text', text),
  createDocumentFragment: () => new Element('#fragment'), getSelection: () => null,
});

const requests = [];
function unexpectedRequest(api) {
  return function () { requests.push(api); throw new Error('Unexpected network API: ' + api); };
}
let clipboard = '';
const storage = new Map();
let animation;
const context = vm.createContext({
  document, localStorage: { getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value) },
  navigator: { language: 'en', clipboard: { writeText: async text => { clipboard = text; } }, sendBeacon: unexpectedRequest('sendBeacon') },
  fetch: unexpectedRequest('fetch'), XMLHttpRequest: unexpectedRequest('XMLHttpRequest'),
  WebSocket: unexpectedRequest('WebSocket'), EventSource: unexpectedRequest('EventSource'),
  setTimeout: () => 0, clearTimeout() {}, performance: { now: () => 0 },
  requestAnimationFrame: callback => (animation = callback, 1), cancelAnimationFrame: () => { animation = null; },
});
context.window = context;
for (const [, attributes, inline] of scripts) {
  const name = attributes.match(/\bsrc="([^"]+)"/)?.[1];
  vm.runInContext(name ? read(name) : inline, context, { filename: name || 'index.html inline script' });
}

const click = selector => query(selector).click();
const replay = selector => query('#replay-app ' + selector);
const scenario = id => `[data-scenario="${id}"]`;
const finding = () => replay('.replay-finding').textContent;

async function testControls() {
  const tabs = document.querySelectorAll('[data-quickstart]');
  const chips = () => document.querySelectorAll('[data-probe-filter]');
  const selected = (nodes, attr) => nodes.filter(node => node.getAttribute(attr) === 'true');
  const visibleProbes = () => document.querySelectorAll('#probe-grid [data-probe-id]')
    .filter(node => !node.hidden).map(node => node.dataset.probeId);
  assert.equal(tabs.length, quickstarts.length, 'six quickstart tabs');
  assert.deepEqual(selected(tabs, 'aria-selected'), [query(quickTab('python'))]);
  assert.equal(query('#quick-command').textContent, quickstarts[0][2]);
  for (const [current, key, next] of [['python', 'ArrowLeft', 'chaos'], ['chaos', 'Home', 'python'],
    ['python', 'ArrowRight', 'pipe'], ['pipe', 'End', 'chaos']]) {
    const event = query(quickTab(current)).emit('keydown', { key });
    assert.ok(event.defaultPrevented);
    assert.equal(document.activeElement, query(quickTab(next)));
    assert.deepEqual(selected(tabs, 'aria-selected'), [document.activeElement]);
  }
  for (const [id, label, snippet] of quickstarts) {
    const tab = query(quickTab(id));
    assert.equal(tab.getAttribute('role'), 'tab');
    assert.equal(tab.textContent.trim(), label);
    tab.click();
    assert.deepEqual(selected(tabs, 'aria-selected'), [tab]);
    assert.deepEqual(tabs.filter(node => node.getAttribute('tabindex') === '0'), [tab]);
    assert.equal(query('#quick-panel').getAttribute('aria-labelledby'), tab.getAttribute('id'));
    assert.equal(query('#quick-command').textContent, snippet);
    click('#quick-copy');
    await new Promise(setImmediate);
    assert.equal(clipboard, snippet, 'copied exact ' + label + ' snippet');
    assert.equal(query('#copy-status').textContent, 'Copied');
  }

  assert.equal(chips().length, filters.length, 'four probe filter chips');
  assert.deepEqual(selected(chips(), 'aria-pressed'), [query(probeFilter('all'))]);
  assert.deepEqual(visibleProbes(), filters[0][2]);
  for (const [id, label, ids] of filters) {
    const chip = query(probeFilter(id));
    assert.ok(chip.textContent.trim().startsWith(label), label + ' filter label');
    chip.click();
    assert.deepEqual(selected(chips(), 'aria-pressed'), [chip]);
    assert.deepEqual(visibleProbes(), ids, label + ' probe IDs');
  }

  click('[data-language="zh"]');
  for (const [id, , , label] of quickstarts) assert.equal(query(quickTab(id)).textContent.trim(), label);
  for (const [id, , , label] of filters) assert.ok(query(probeFilter(id)).textContent.trim().startsWith(label));
  assert.deepEqual(selected(tabs, 'aria-selected'), [query(quickTab('chaos'))]);
  assert.deepEqual(selected(chips(), 'aria-pressed'), [query(probeFilter('proxy-storage'))]);
  assert.deepEqual(visibleProbes(), proxyStorageProbes);
  assert.equal(query('#quick-command').textContent, quickstarts.at(-1)[2]);
  click('#quick-copy');
  await new Promise(setImmediate);
  assert.equal(clipboard, quickstarts.at(-1)[2]);
  assert.equal(query('#copy-status').textContent, '已复制');
  click('[data-language="en"]');
  click(probeFilter('all'));
  assert.deepEqual(visibleProbes(), filters[0][2], 'All restores all 18 probes');
}

async function testPage() {
  assert.equal(document.documentElement.lang, 'en');
  await testControls();
  assert.equal(document.querySelectorAll('.replay-tab').length, 6, 'six replay tabs');
  assert.match(replay('[data-variant="before"]').textContent, /Before Fix.*Grade F/);
  assert.match(finding(), /P0 BREACH/);
  assert.equal(replay('.inspector-event').textContent, 'response.completed');
  click('[data-variant="after"]');
  assert.match(finding(), /GRADE A\+ · 8\/8/);
  assert.match(finding(), /protocol_violations: \[\]/);
  assert.equal(replay('.inspector-event').textContent, 'response.incomplete');
  click('[data-variant="before"]');
  assert.match(finding(), /P0 BREACH/);

  for (const [id, event] of [['C5', 'tool_calls[1]'], ['C7', 'delta.content'], ['C9', 'message_delta'], ['C10', 'finishReason']]) {
    click(scenario(id));
    assert.equal(query(scenario(id)).getAttribute('aria-pressed'), 'true');
    assert.equal(replay('.inspector-event').textContent, event);
    replay('.replay-reset').click();
    assert.match(replay('.replay-progress').textContent, /0\//);
    replay('.replay-step').click();
    assert.match(replay('.inspector-meta').textContent, /#01/);
    replay('.replay-play').click();
    assert.equal(typeof animation, 'function');
    animation(100000);
    assert.equal(animation, null);
    assert.match(finding(), /PASS|P1 WARN|P0 BREACH/);
  }

  click(scenario('PROXY'));
  assert.match(query(scenario('PROXY')).textContent, /Proxy Live Wire-Tap/);
  assert.match(query(scenario('PROXY')).textContent, /D1–D4/);
  assert.match(finding(), /P0/);
  assert.match(replay('.inspector-meta').textContent, /#05/);
  const report = replay('.proxy-issue');
  const markdown = replay('.proxy-issue-preview');
  assert.equal(report.hidden, false);
  assert.match(markdown.textContent, /UNCLOSED_TOOL_CALL_SUCCESS/);
  assert.doesNotMatch(markdown.textContent, /lookup_service_status|\[REDACTED\]/, 'report omits tool payloads');
  replay('.proxy-copy').click();
  await new Promise(setImmediate);
  assert.equal(clipboard, markdown.textContent);
  assert.match(query('#replay-app').textContent, /\/_inferdiff\//);
  const proxyLinks = replay('.replay-source').querySelectorAll('a');
  replay('.replay-reset').click();
  assert.equal(report.hidden, true);
  const proxyFrames = document.querySelectorAll('#replay-app .frame-dot');
  assert.equal(proxyFrames.length, 7, 'six SSE frames and the transport EOF');
  for (const frame of proxyFrames) {
    assert.equal(report.hidden, true, 'report is revealed when the stream ends');
    replay('.replay-step').click();
    const label = frame.dataset.event === 'transport EOF' ? 'Transport EOF' : frame.dataset.event;
    assert.equal(replay('.inspector-event').textContent, label);
  }
  assert.equal(replay('.inspector-event').textContent, 'Transport EOF');
  assert.equal(report.hidden, false);
  assert.match(markdown.textContent, /UNCLOSED_TOOL_CALL_SUCCESS/);

  click('[data-language="zh"]');
  assert.equal(document.documentElement.lang, 'zh-CN');
  assert.equal(query('[data-language="zh"]').getAttribute('aria-pressed'), 'true');
  for (const node of document.querySelectorAll('[data-i18n]')) {
    assert.ok(node.textContent.trim(), 'Chinese translation for ' + node.dataset.i18n);
  }
  assert.match(query(scenario('PROXY')).textContent, /[\u3400-\u9fff]/);
  assert.match(finding(), /P0.*违约/s);
  assert.match(replay('.proxy-issue-preview').textContent, /UNCLOSED_TOOL_CALL_SUCCESS/);
  click(scenario('C1'));
  click('[data-variant="after"]');
  assert.match(finding(), /A\+ 评级 · 8\/8/);
  click('[data-language="en"]');
  assert.equal(document.documentElement.lang, 'en');
  assert.match(finding(), /GRADE A\+ · 8\/8/);

  const input = query('#stream-input');
  const pasted = input.emit('paste', { clipboardData: { getData: () => breachedSse } });
  assert.equal(pasted.defaultPrevented, true);
  assert.match(query('#stream-finding').textContent, /P0 BREACH/);
  assert.equal(query('#stream-count').textContent, '4');
  assert.ok(!input.value.includes(fakeKey) && !input.value.includes(fakeBearer), 'paste is redacted');
  const payload = trace(true);
  const file = { name: 'fixture.trace.jsonl', size: Buffer.byteLength(payload), text: async () => payload };
  const drop = query('#stream-editor').emit('drop', { dataTransfer: { files: [file] } });
  assert.equal(drop.defaultPrevented, true);
  await new Promise(setImmediate);
  assert.equal(query('#stream-protocol').textContent, 'inferdiff trace');
  assert.equal(query('#stream-count').textContent, '5');
  assert.match(query('#stream-finding').textContent, /INCOMPLETE/);
  assert.match(query('#stream-timing').textContent, /43\.5/);
  click('[data-language="zh"]');
  assert.equal(query('#stream-verdict').textContent, '如实中断');
  click('#stream-clear');
  assert.equal(query('#stream-results').hidden, true);

  const owner = 'https://github.com/ApacheWang/';
  const repos = ['inferdiff', 'inferdiff-mcp', 'inferdiff-js', 'inferdiff-extension', 'inferdiff-bot', 'inferdiff-bench', 'inferdiff-chaos'];
  const hubLinks = document.querySelectorAll('.product-card a');
  for (const repo of repos) {
    assert.ok(hubLinks.some(link => link.href === owner + repo), repo + ' hub link');
  }
  assert.ok(hubLinks.some(link => link.href === '#quickstart'), 'Cloud links to the local CLI quickstart');
  for (const link of [...document.querySelectorAll('a'), ...proxyLinks]) {
    if (!link.href || link.href.startsWith('#')) continue;
    assert.ok(repos.some(repo => link.href === owner + repo || link.href.startsWith(owner + repo + '/')), link.href);
    assert.equal(link.target, '_blank');
    assert.ok(['noopener', 'noreferrer'].every(token => link.rel.split(/\s+/).includes(token)), link.href);
  }
  assert.deepEqual(requests, [], 'no network API used during local interactions');
}

testPage().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
"""

BROWSER_TESTS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const [debugURL, origin, fileURL, tracePath, screenshotPath] = process.argv.slice(1);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const probe = selector => 'document.querySelector(' + JSON.stringify(selector) + ')';

async function connect() {
  assert.equal(typeof WebSocket, 'function', 'browser verification requires Node.js 22+');
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
  async function evaluate(expression, userGesture = false) {
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true, userGesture });
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
  async function pressKey(key, code, windowsVirtualKeyCode, modifiers = 0) {
    const event = { key, code, windowsVirtualKeyCode, modifiers };
    await command('Input.dispatchKeyEvent', { type: 'rawKeyDown', ...event });
    await command('Input.dispatchKeyEvent', { type: 'keyUp', ...event });
  }
  async function pasteClipboard() {
    await pressKey('v', 'KeyV', 86, process.platform === 'darwin' ? 4 : 2);
  }
  async function readClipboard() {
    await evaluate(`(() => {
      const field = document.createElement('textarea');
      field.id = 'verify-clipboard';
      document.body.append(field);
      field.focus({ preventScroll: true });
    })()`);
    try {
      await pasteClipboard();
      const value = probe('#verify-clipboard') + '.value';
      await waitFor(value + '.length > 0', 'clipboard paste in standalone page');
      return await evaluate(value);
    } finally {
      await evaluate(probe('#verify-clipboard') + '.remove()');
    }
  }
  async function testControls(width, offline) {
    const values = (selector, expression) => evaluate(
      'Array.from(document.querySelectorAll(' + JSON.stringify(selector) + '), node => ' + expression + ')'
    );
    const tabs = '[data-quickstart]';
    const chips = '[data-probe-filter]';
    const selectedTabs = () => values(tabs + '[aria-selected="true"]', 'node.dataset.quickstart');
    const selectedChips = () => values(chips + '[aria-pressed="true"]', 'node.dataset.probeFilter');
    const visibleProbes = () => evaluate(`Array.from(document.querySelectorAll('#probe-grid [data-probe-id]'))
      .filter(node => node.getClientRects().length).map(node => node.dataset.probeId)`);
    const copied = async (snippet, status) => {
      const message = await evaluate(`new Promise(resolve => {
        const status = document.getElementById('copy-status');
        const observer = new MutationObserver(() => {
          observer.disconnect();
          resolve(status.textContent);
        });
        observer.observe(status, { childList: true });
        document.getElementById('quick-copy').click();
      })`, true);
      assert.equal(message, status);
      const actual = offline ? await readClipboard() : await evaluate('navigator.clipboard.readText()');
      assert.equal(actual, snippet);
    };

    assert.deepEqual(await values(tabs, 'node.textContent.trim()'), quickstarts.map(([, label]) => label));
    assert.deepEqual(await selectedTabs(), ['python']);
    assert.equal(await evaluate(probe('#quick-command') + '.textContent'), quickstarts[0][2]);
    await evaluate(probe(quickTab('python')) + '.focus()');
    for (const [key, code, id] of [['ArrowLeft', 37, 'chaos'], ['Home', 36, 'python'],
      ['ArrowRight', 39, 'pipe'], ['End', 35, 'chaos']]) {
      await pressKey(key, key, code);
      assert.equal(await evaluate('document.activeElement.dataset.quickstart'), id);
      assert.deepEqual(await selectedTabs(), [id]);
    }
    for (const [id, , snippet] of quickstarts) {
      await click(quickTab(id));
      assert.deepEqual(await selectedTabs(), [id]);
      assert.equal(await evaluate(probe('#quick-command') + '.textContent'), snippet);
      assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), id + ' quickstart overflows at ' + width);
      await copied(snippet, 'Copied');
    }

    assert.equal((await values(chips, 'node.dataset.probeFilter')).length, filters.length);
    assert.deepEqual(await selectedChips(), ['all']);
    assert.deepEqual(await visibleProbes(), filters[0][2]);
    for (const [id, label, ids] of filters) {
      assert.ok((await evaluate(probe(probeFilter(id)) + '.textContent.trim()')).startsWith(label));
      await click(probeFilter(id));
      assert.deepEqual(await selectedChips(), [id]);
      assert.deepEqual(await visibleProbes(), ids, label + ' probe IDs');
      assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), id + ' filter overflows at ' + width);
    }

    await click('[data-language="zh"]');
    assert.deepEqual(await values(tabs, 'node.textContent.trim()'), quickstarts.map(([, , , label]) => label));
    for (const [id, , , label] of filters) {
      assert.ok((await evaluate(probe(probeFilter(id)) + '.textContent.trim()')).startsWith(label));
    }
    assert.deepEqual(await selectedTabs(), ['chaos']);
    assert.deepEqual(await selectedChips(), ['proxy-storage']);
    assert.deepEqual(await visibleProbes(), proxyStorageProbes);
    assert.equal(await evaluate(probe('#quick-command') + '.textContent'), quickstarts.at(-1)[2]);
    await copied(quickstarts.at(-1)[2], '已复制');
    assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'localized controls overflow at ' + width);
    await click('[data-language="en"]');
    await click(quickTab('python'));
    await click(probeFilter('all'));
    assert.deepEqual(await visibleProbes(), filters[0][2]);
  }
  async function assertPolicyAndPrivacy() {
    const policies = await evaluate(`Array.from(document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]'), node => node.content)`);
    assert.equal(policies.length, 1);
    const directives = policies[0].split(';').map(value => value.trim());
    for (const expected of offlineCsp) {
      assert.deepEqual(directives.filter(value => value.split(/\s+/)[0] === expected.split(' ')[0]), [expected]);
    }
    assert.doesNotMatch(await evaluate('document.body.innerText'), /\b[a-z]:[\\/]+|\bfile:\/+|\\\\[\w.-]+\\+[\w.-]+|\bbc15[5]\b/i, 'no local Windows paths in rendered content');
  }
  async function navigate(url) {
    const { errorText } = await command('Page.navigate', { url });
    assert.ok(!errorText, errorText);
    await waitFor('location.href === ' + JSON.stringify(url) +
      ' && document.readyState === "complete" && !!' + probe('.replay-tab'), 'showcase to load');
  }
  function requests(checkpoint) {
    return observed.slice(checkpoint).flatMap(({ method, params }) => {
      if (method === 'Network.requestWillBeSent') return [{ url: params.request.url, type: params.type }];
      if (method === 'Network.webSocketCreated') return [{ url: params.url, type: 'WebSocket' }];
      return [];
    }).filter(({ url }) => /^(https?|wss?):/i.test(url));
  }

  try {
    for (const domain of ['Page', 'Runtime', 'Network', 'Log', 'DOM']) await command(domain + '.enable');
    await command('Page.addScriptToEvaluateOnNewDocument', {
      source: `document.addEventListener('securitypolicyviolation', event => console.error('CSP violation: ' + event.violatedDirective));`,
    });
    await command('Page.bringToFront');
    await command('Emulation.setFocusEmulationEnabled', { enabled: true });
    await command('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
    let screenshot;
    const viewports = [[1440, 960, false], [390, 844, true]];
    const staticAssets = new Map([
      ['/index.html', 'Document'], ['/styles.css', 'Stylesheet'], ['/app.js', 'Script'],
      ['/stream-inspector.js', 'Script'], ['/inspector-ui.js', 'Script'],
    ]);
    async function viewport(width, height, mobile) {
      await command('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile });
      await command('Emulation.setTouchEmulationEnabled', { enabled: mobile });
    }
    for (const [width, height, mobile] of viewports) {
      const checkpoint = observed.length;
      await viewport(width, height, mobile);
      await navigate(origin + '/index.html');
      await click('[data-language="en"]');
      const ready = observed.length;
      assert.equal(await evaluate('innerWidth'), width);
      assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'page overflows at ' + width);
      await testControls(width, false);
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
      await click('[data-scenario="PROXY"]');
      assert.match(await evaluate(probe('.proxy-issue-preview') + '.textContent'), /UNCLOSED_TOOL_CALL_SUCCESS/);
      assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'proxy replay overflows at ' + width);
      await click('.replay-reset');
      assert.equal(await evaluate(probe('.proxy-issue') + '.hidden'), true);
      await click('.replay-play');
      await waitFor('!' + probe('.proxy-issue') + '.hidden', 'D1 incident at EOF');
      await click('[data-language="zh"]');
      assert.match(await evaluate(probe('#replay-app .finding-copy') + '.textContent'), /违约|结束/);
      await click('[data-language="en"]');
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
      await pasteClipboard();
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
      await assertPolicyAndPrivacy();
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
      const browserRequests = requests(checkpoint);
      const external = browserRequests.filter(({ url }) => new URL(url).origin !== origin);
      assert.deepEqual(external, [], 'no external requests at ' + width);
      assert.deepEqual(browserRequests.filter(({ url, type }) => staticAssets.get(url.slice(origin.length)) !== type),
        [], 'page requests only its static dependencies at ' + width);
      assert.deepEqual(requests(ready), [], 'no network during local interactions at ' + width);
      console.log('PASS: Chrome ' + width + 'px, clipboard-pasted crimson P0, ' +
        (mobile ? 'file picker' : 'file drop') + ', C1 comparison, C10, D1 replay, all quickstart copies and probe filters, EN/中文, strict CSP, no local paths, zero external requests.');
    }

    await command('Network.emulateNetworkConditions', {
      offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0,
    });
    for (const [width, height, mobile] of viewports) {
      const checkpoint = observed.length;
      await viewport(width, height, mobile);
      await navigate(fileURL);
      await click('[data-language="en"]');
      assert.equal(await evaluate('innerWidth'), width);
      assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'standalone page overflows at ' + width);
      await testControls(width, true);
      await click('[data-stream-sample="breach"]');
      await waitFor(probe('#stream-finding') + '.dataset.tone === "crimson"', 'standalone offline inspection');
      await assertPolicyAndPrivacy();
      assert.deepEqual(requests(checkpoint), [], 'standalone page requires no HTTP at ' + width);
      console.log('PASS: Chrome standalone ' + width + 'px with networking disabled, all quickstart copies and probe filters, EN/中文, SSE inspector, strict CSP, no local paths, zero external requests.');
    }
    const faults = observed.filter(({ method, params }) =>
      method === 'Runtime.exceptionThrown' ||
      (method === 'Runtime.consoleAPICalled' && params.type === 'error') ||
      (method === 'Log.entryAdded' && params.entry.level === 'error')
    );
    assert.deepEqual(faults, [], 'Chrome reports zero console or JavaScript errors');
    if (screenshot) fs.writeFileSync(screenshotPath, Buffer.from(screenshot, 'base64'));
    console.log('PASS: Chrome reports zero console or JavaScript errors across all four runs.');
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
        self.csp = []
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
        if tag == "meta" and (attributes.get("http-equiv") or "").lower() == "content-security-policy":
            self.csp.append(attributes.get("content") or "")
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


def check_page_interactions(root, errors):
    result = run_node(STREAM_FIXTURES + CONTROL_FIXTURES + MOCK_DOM_TESTS, [root])
    if result.returncode:
        detail = re.search(r"^\w*Error(?: \[[^\]]+\])?: .+$", result.stderr, re.MULTILINE)
        errors.append(f"mocked DOM test failed: {detail[0] if detail else 'Node test failed'}")


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
    directives = [directive.strip() for policy in page.csp for directive in policy.split(";") if directive.strip()]
    names = [directive.split()[0] for directive in directives]
    if len(page.csp) != 1 or len(set(names)) != len(names) or not set(OFFLINE_CSP).issubset(directives):
        errors.append("index.html: expected the offline Content Security Policy")

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
        check_page_interactions(root, errors)
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


def find_chrome():
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        executable = shutil.which(name)
        if executable:
            return Path(executable)

    if os.name == "nt":
        for directory in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            if root := os.environ.get(directory):
                for brand in (("Google", "Chrome"), ("Chromium",)):
                    executable = Path(root, *brand, "Application", "chrome.exe")
                    if executable.is_file():
                        return executable
    else:
        for directory in (Path("/Applications"), Path.home() / "Applications"):
            for name in ("Google Chrome", "Chromium"):
                executable = directory / f"{name}.app" / "Contents" / "MacOS" / name
                if executable.is_file():
                    return executable
    return None


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
                    browser_fixtures = f"const offlineCsp = {json.dumps(OFFLINE_CSP)};\n"
                    result = run_node(STREAM_FIXTURES + CONTROL_FIXTURES + browser_fixtures + BROWSER_TESTS, [
                        chrome_endpoint(profile, process), origin, (root / "index.html").as_uri(),
                        Path(temporary) / "fixture.trace.jsonl", screenshot or "",
                    ], timeout=60)
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
    parser.add_argument("--chrome", type=Path, help="override the automatically detected Chrome or Chromium executable")
    parser.add_argument("--chrome-no-sandbox", action="store_true", help="run Chrome inside an existing OS sandbox")
    parser.add_argument("--screenshot", type=Path, help="save a full 1440px preview after the browser checks pass")
    options = parser.parse_args()
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
    print("PASS: HTML structure, local assets, CSP, JavaScript syntax, leak scan, and offline parser fixtures.")
    print("PASS: mocked DOM in EN and 中文, all six replays, C1 comparison, D1 report, all quickstart copies and probe filters, SSE paste, trace drop, and outbound link policy.")
    chrome = options.chrome or find_chrome()
    if not chrome:
        print("FAIL: Chrome or Chromium is required. Use --chrome to specify its executable.")
        return 1
    try:
        result = verify_browser(root, chrome.resolve(), options.screenshot, options.chrome_no_sandbox)
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
