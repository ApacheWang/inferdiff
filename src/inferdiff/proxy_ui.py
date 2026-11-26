"""Self-contained dashboard served by the local proxy."""

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>inferdiff · Live Proxy</title>
<style>
:root {
  color-scheme: dark;
  --bg: #0b1020;
  --panel: #11192b;
  --raised: #172237;
  --border: #2b3852;
  --text: #edf2ff;
  --muted: #a9b7cd;
  --emerald: #56e3af;
  --amber: #f7c76e;
  --violet: #beaaff;
  --crimson: #ff859a;
  font: 14px/1.5 system-ui, "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); }
button, input, textarea { font: inherit; }
button {
  background: var(--raised); color: var(--text); border: 1px solid var(--border);
  border-radius: 7px; padding: .45rem .75rem; cursor: pointer;
}
button:hover { border-color: var(--violet); }
button:disabled { opacity: .6; cursor: default; }
:focus-visible { outline: 2px solid var(--violet); outline-offset: 3px; }
input { accent-color: var(--emerald); }
code, .mono, td.metric, dd { font-family: ui-monospace, Consolas, monospace; }
h1, h2, h3, p, dl, dd { margin: 0; }
h1 { font-size: 1.15rem; font-weight: 620; }
h2 { font-size: 1.05rem; font-weight: 650; }
h3 { font-size: .86rem; font-weight: 650; }
h1 code { color: var(--violet); font-size: 1.3rem; margin-right: .5rem; }
header {
  background: var(--panel); border-bottom: 1px solid var(--border);
  padding: 1.1rem clamp(1rem, 4vw, 3rem);
  display: flex; align-items: center; justify-content: space-between; gap: .85rem; flex-wrap: wrap;
}
.toolbar, .filters, .heading { display: flex; align-items: center; flex-wrap: wrap; gap: .6rem; }
.auto { display: inline-flex; align-items: center; gap: .35rem; color: var(--muted); }
#connection { display: flex; align-items: center; gap: .45rem; color: var(--muted); min-height: 1.5rem; }
#connection::before { content: ""; width: .5rem; height: .5rem; border-radius: 50%; background: currentColor; }
#connection[data-state="live"] { color: var(--emerald); }
#connection[data-state="error"] { color: var(--crimson); }
main { max-width: 100rem; margin: auto; padding: clamp(1rem, 3vw, 2.5rem); }
.metrics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: .75rem; margin-bottom: 1.25rem; }
.tile, .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }
.tile { padding: .9rem 1rem; }
.tile dt { color: var(--muted); font-size: .85rem; }
.tile dd { font-size: clamp(1.25rem, 2.6vw, 1.95rem); margin-top: .2rem; overflow-wrap: anywhere; }
.p0 { color: var(--crimson); }
.p1, .failover { color: var(--amber); }
.stream { color: var(--emerald); }
.timing { color: var(--violet); }
.workspace { display: grid; grid-template-columns: minmax(0, 1.5fr) minmax(17rem, 1fr); gap: 1rem; align-items: start; }
.heading { justify-content: space-between; padding: .9rem 1rem; }
.filters button { border-radius: 20px; font-size: .84rem; padding: .3rem .65rem; }
.filters [aria-pressed="true"] { color: var(--violet); border-color: var(--violet); }
.table-scroll { overflow: auto; max-height: 65vh; }
table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: .84rem; }
th, td { padding: .55rem .75rem; border-top: 1px solid var(--border); text-align: left; }
th { position: sticky; top: 0; z-index: 1; background: var(--raised); color: var(--muted); white-space: nowrap; }
tr[data-id] { cursor: pointer; }
tr[data-id]:hover td, tr[data-selected="true"] td { background: var(--raised); }
tr[data-selected="true"] td:first-child { box-shadow: inset 3px 0 var(--violet); }
td.path { width: 100%; }
.path button { display: block; padding: .15rem .2rem; background: none; border: 0; text-align: left; overflow-wrap: anywhere; }
.metric { white-space: nowrap; }
.badge { display: inline-block; white-space: nowrap; padding: .06rem .45rem; border: 1px solid var(--border); border-radius: 5px; }
.failover.badge {
  margin-inline-start: .15rem; font-size: .72rem;
  background: rgba(247, 199, 110, .08); border-color: rgba(247, 199, 110, .28);
}
.muted { color: var(--muted); }
.empty { padding: 1.15rem 1rem; }
.inspector-inner { padding: 0 1rem 1rem; }
.inspector-inner > :not([hidden]) + :not([hidden]), #event-detail > * + * { margin-top: 1rem; }
.details { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .7rem; }
.details dt, .timeline-labels { color: var(--muted); font-size: .8rem; }
.details dd, .request, .finding, #copy-notice { overflow-wrap: anywhere; }
.request { font-size: .86rem; }
.findings { list-style: none; padding: 0; margin: .45rem 0 0; }
.finding { border: 1px solid var(--border); border-radius: 7px; padding: .6rem; margin-top: .4rem; }
.finding p { margin-top: .35rem; font-size: .85rem; }
.timeline { position: relative; margin: .5rem .25rem .2rem; height: 2rem; }
.timeline::before {
  content: ""; position: absolute; left: 0; right: 0; top: calc(50% - 2px); height: 4px;
  border-radius: 4px; background: var(--border);
}
.marker {
  position: absolute; left: var(--arrival); height: .8rem; top: .6rem;
  transform: translateX(-50%); border-left: 2px solid var(--emerald);
}
.marker.terminal { border-color: var(--violet); height: 1.1rem; top: .45rem; }
.marker.invalid { border-color: var(--crimson); }
.timeline-labels { display: flex; justify-content: space-between; }
.frames { margin-top: .5rem; max-height: 17rem; border: 1px solid var(--border); border-radius: 7px; }
#copy-report { color: var(--emerald); }
#manual-report { width: 100%; min-height: 8rem; background: var(--bg); color: var(--text); }
#copy-notice, #clear-notice { font-size: .83rem; }
#clear-notice { margin-bottom: .75rem; }
@media (max-width: 820px) {
  .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .workspace { grid-template-columns: minmax(0, 1fr); }
  .table-scroll { max-height: 45vh; }
}
@media (max-width: 540px) {
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .tile { padding: .55rem .7rem; }
  th, td { padding: .5rem; }
}
</style>
</head>
<body>
<header>
  <div>
    <h1><code>inferdiff</code> <span data-label="title">Live Proxy</span></h1>
    <p id="connection" role="status"></p>
  </div>
  <div class="toolbar">
    <label class="auto"><input id="auto" type="checkbox" checked> <span data-label="auto">Auto-refresh</span></label>
    <button id="refresh" type="button" data-label="refresh">Refresh</button>
    <button id="clear" type="button" data-label="clear">Clear events</button>
    <button id="language" type="button" lang="zh">中文</button>
  </div>
</header>
<main>
  <dl class="metrics">
    <div class="tile"><dt data-label="total">Total Requests</dt><dd id="requests_total">—</dd></div>
    <div class="tile"><dt data-label="stream">Streaming</dt><dd class="stream" id="streaming_requests">—</dd></div>
    <div class="tile"><dt data-label="failovers">Failovers</dt><dd class="failover" id="failovers_total">—</dd></div>
    <div class="tile"><dt data-label="p0">P0 Breaches</dt><dd class="p0" id="p0_breaches">—</dd></div>
    <div class="tile"><dt data-label="p1">P1 Warnings</dt><dd class="p1" id="p1_warnings">—</dd></div>
    <div class="tile"><dt data-label="median">Median TTFT</dt><dd class="timing" id="median_ttft_ms">—</dd></div>
  </dl>
  <p id="clear-notice" class="p0" role="status" hidden></p>
  <div class="workspace">
    <section class="panel" aria-labelledby="requests-heading">
      <div class="heading">
        <h2 id="requests-heading" data-label="requests">Recent Requests</h2>
        <div class="filters">
          <button type="button" data-filter="all" data-label="all" aria-pressed="true">All</button>
          <button type="button" data-filter="breach" data-label="breach" aria-pressed="false">Breaches Only</button>
          <button type="button" data-filter="stream" data-label="stream" aria-pressed="false">Streaming</button>
        </div>
      </div>
      <div class="table-scroll">
        <table aria-labelledby="requests-heading">
          <thead><tr>
            <th scope="col" data-label="method">Method</th><th scope="col" data-label="path">Path</th>
            <th scope="col" data-label="status">Status</th><th scope="col">TTFT</th>
            <th scope="col" data-label="duration">Total</th><th scope="col" data-label="findings">Findings</th>
          </tr></thead>
          <tbody id="requests"></tbody>
        </table>
      </div>
    </section>
    <aside class="panel" aria-labelledby="inspector-heading">
      <div class="heading">
        <h2 id="inspector-heading" tabindex="-1" data-label="inspector">Frame &amp; Finding Inspector</h2>
        <button id="close-inspector" type="button" data-label="close" hidden>Close</button>
      </div>
      <div class="inspector-inner">
        <p id="inspector-message" class="muted" role="status"></p>
        <div id="event-detail" hidden></div>
        <button id="copy-report" type="button" data-label="copy" hidden>Copy Redacted Issue Report</button>
        <p id="copy-notice" class="muted" role="status" hidden></p>
        <textarea id="manual-report" class="mono" readonly hidden></textarea>
      </div>
    </aside>
  </div>
</main>
<script>
"use strict";
const translations = {
  en: {
    title: "Live Proxy", auto: "Auto-refresh", refresh: "Refresh", clear: "Clear events",
    total: "Total Requests", stream: "Streaming", p0: "P0 Breaches", p1: "P1 Warnings", median: "Median TTFT",
    failovers: "Failovers", failover: "FAILOVER",
    requests: "Recent Requests", all: "All", breach: "Breaches Only", method: "Method", path: "Path",
    status: "Status", duration: "Total", findings: "Findings", inspector: "Frame & Finding Inspector", close: "Close",
    copy: "Copy Redacted Issue Report", loading: "Loading…", live: "Live", paused: "Paused",
    connectionError: "Could not load proxy status.", clearError: "Could not clear events.",
    empty: "No requests captured yet.", noMatch: "No requests match this filter.",
    select: "Select a request to inspect its findings and frames.",
    missing: "This event is no longer retained.", detailError: "Could not load this event.",
    pass: "None", dialect: "Dialect", finish: "Finish reason", terminalStatus: "Stream status",
    timeline: "Frame arrivals", frame: "Frame",
    arrival: "Arrival", event: "Event", terminal: "Terminal", parseError: "Parse error", bytes: "Bytes",
    tools: (count) => `${count} tool call ${count === 1 ? "delta" : "deltas"}`,
    shown: (shown, total) => `Showing ${shown} of ${total} frames.`,
    shownFindings: (shown, total) => `Showing ${shown} of ${total} findings.`,
    noFrames: "No stream frames captured.", copied: "Redacted issue report copied.",
    manualCopy: "Select and copy the report below."
  },
  zh: {
    title: "实时代理", auto: "自动刷新", refresh: "刷新", clear: "清除事件",
    total: "请求总数", stream: "流式请求", p0: "P0 违规", p1: "P1 警告", median: "首令牌延迟中位数",
    failovers: "故障切换次数", failover: "故障切换",
    requests: "最近请求", all: "全部", breach: "仅看违规", method: "方法", path: "路径",
    status: "状态", duration: "总耗时", findings: "检测结果", inspector: "帧与检测结果检查器", close: "关闭",
    copy: "复制已脱敏的问题报告", loading: "正在加载…", live: "实时", paused: "已暂停",
    connectionError: "无法加载代理状态。", clearError: "无法清除事件。",
    empty: "尚未捕获请求。", noMatch: "没有符合此筛选条件的请求。",
    select: "选择请求以查看检测结果和帧。",
    missing: "该事件已不在缓冲区中。", detailError: "无法加载此事件。",
    pass: "无", dialect: "协议", finish: "结束原因", terminalStatus: "流状态",
    timeline: "帧到达时间", frame: "帧",
    arrival: "到达时间", event: "事件", terminal: "终止帧", parseError: "解析错误", bytes: "字节",
    tools: (count) => `${count} 个工具调用增量`,
    D1: "流响应报告成功，但工具调用不完整或不一致。",
    D2: "流响应已有生成迹象，但可见输出为空。",
    D3: "流响应生成的令牌数少于固定预算。",
    D4: "流响应结束时，协议或传输未正常终止。",
    shown: (shown, total) => `显示 ${total} 帧中的 ${shown} 帧。`,
    shownFindings: (shown, total) => `显示 ${total} 条检测结果中的 ${shown} 条。`,
    noFrames: "未捕获到流式帧。", copied: "已复制脱敏的问题报告。",
    manualCopy: "请选中并复制下方的报告。"
  }
};
const byId = (id) => document.getElementById(id);
const auto = byId("auto");
const rows = byId("requests");
const filters = [...document.querySelectorAll("[data-filter]")];
const detail = byId("event-detail");
const copyButton = byId("copy-report");
const manualReport = byId("manual-report");
let language = "en";
let filter = "all";
let status = null;
let statusError = false;
let statusRequest = null;
let pollTimer;
let clearing = false;
let clearFailed = false;
let selectedId = null;
let selectedEvent = null;
let eventRequest = null;
let inspectorMessage = "select";
let copyMessage = "";

const label = (key) => translations[language][key];
const ms = (value) => value == null ? "—" : `${value} ms`;
function element(tag, value, className) {
  const node = document.createElement(tag);
  if (value != null) node.textContent = value;
  if (className) node.className = className;
  return node;
}

function showStatus() {
  const connection = byId("connection");
  const state = statusError ? "error" : !status ? "loading" : auto.checked ? "live" : "paused";
  connection.dataset.state = state;
  const message = label(statusError ? "connectionError" : state);
  if (connection.textContent !== message) connection.textContent = message;
  for (const key of ["requests_total", "streaming_requests", "failovers_total", "p0_breaches", "p1_warnings"]) {
    byId(key).textContent = status?.[key] ?? "—";
  }
  byId("median_ttft_ms").textContent = ms(status?.median_ttft_ms);
  byId("clear").disabled = clearing;
  byId("refresh").disabled = clearing;
  const clearNotice = byId("clear-notice");
  clearNotice.textContent = clearFailed ? label("clearError") : "";
  clearNotice.hidden = !clearFailed;
}

function showRows() {
  const activeId = rows.contains(document.activeElement) ? document.activeElement.closest("tr")?.dataset.id : null;
  const events = status?.recent_events || [];
  const visible = events.filter((event) =>
    filter === "all" || (filter === "breach" ? event.p0_breaches > 0 : event.streaming));
  const fragment = document.createDocumentFragment();
  let restoreFocus;
  for (const event of visible) {
    const row = element("tr");
    row.dataset.id = event.id;
    row.dataset.selected = String(event.id === selectedId);
    const button = element("button", event.path, "mono");
    button.type = "button";
    button.setAttribute("aria-controls", "event-detail");
    button.setAttribute("aria-current", row.dataset.selected);
    const path = element("td", null, "path");
    path.append(button);
    const badges = element("td");
    if (event.p0_breaches) badges.append(element("span", `P0 × ${event.p0_breaches}`, "p0 badge"));
    if (event.p1_warnings) badges.append(element("span", `P1 × ${event.p1_warnings}`, "p1 badge"));
    if (!badges.hasChildNodes()) badges.append(element("span", "—", "muted"));
    const upstream = element("td", event.status, event.status >= 400 ? "metric p0" : "metric");
    if (event.failover_used) upstream.append(" ", element("span", label("failover"), "failover badge"));
    row.append(element("td", event.method, "metric"), path, upstream,
      element("td", ms(event.ttft_ms), "metric timing"),
      element("td", ms(event.total_ms), "metric"), badges);
    if (event.id === activeId) restoreFocus = button;
    fragment.append(row);
  }
  if (!visible.length) {
    const message = statusError && !status ? "connectionError" : !status ? "loading" : events.length ? "noMatch" : "empty";
    const cell = element("td", label(message), "empty muted");
    cell.colSpan = 6;
    const row = element("tr");
    row.append(cell);
    fragment.append(row);
  }
  rows.replaceChildren(fragment);
  restoreFocus?.focus({preventScroll: true});
}

function showFindings(event) {
  const findings = event.findings;
  const section = element("section");
  section.append(element("h3", label("findings")));
  if (!findings.length) {
    section.append(element("p", label("pass"), "muted"));
    return section;
  }
  const list = element("ul", null, "findings");
  for (const finding of findings) {
    const item = element("li", null, "finding");
    const badge = element("span", `${finding.severity} · ${finding.detector_id}`,
      finding.severity === "P0" ? "p0 badge" : "p1 badge");
    item.append(badge, element("p", label(finding.detector_id) || finding.message || finding.code),
      element("code", finding.code, "muted"));
    if (finding.frame_seq != null) item.append(element("span", ` · ${label("frame")} #${finding.frame_seq}`, "muted"));
    list.append(item);
  }
  section.append(list);
  if (event.findings_count > findings.length) {
    section.append(element("p", label("shownFindings")(findings.length, event.findings_count), "muted"));
  }
  return section;
}

function showFrames(event) {
  const section = element("section");
  section.append(element("h3", label("timeline")));
  if (!event.frames.length) {
    section.append(element("p", label("noFrames"), "muted"));
    return section;
  }
  const end = Math.max(event.total_ms, 0);
  const timeline = element("div", null, "timeline");
  timeline.setAttribute("aria-hidden", "true");
  const axis = element("div", null, "timeline-labels mono");
  axis.append(element("span", ms(0)), element("span", ms(end)));
  const scroll = element("div", null, "table-scroll frames");
  const table = element("table");
  table.setAttribute("aria-label", label("timeline"));
  const heading = table.createTHead().insertRow();
  for (const key of ["frame", "arrival", "event", "bytes"]) {
    const th = element("th", label(key));
    th.scope = "col";
    heading.append(th);
  }
  const body = table.createTBody();
  for (const frame of event.frames) {
    const markerClass = frame.parse_error ? "marker invalid" : frame.terminal ? "marker terminal" : "marker";
    const marker = element("span", null, markerClass);
    const percent = end ? Math.max(0, Math.min(100, 100 * frame.t_rel_ms / end)) : 0;
    marker.style.setProperty("--arrival", `${percent}%`);
    timeline.append(marker);
    const description = [frame.event, frame.finish_reason, frame.tool_call_count && label("tools")(frame.tool_call_count),
      frame.terminal && frame.event !== "TERMINAL" && label("terminal"),
      frame.parse_error && label("parseError")].filter(Boolean).join(" · ") || "—";
    body.insertRow().append(element("td", frame.seq, "metric"),
      element("td", ms(frame.t_rel_ms), "metric timing"),
      element("td", description), element("td", frame.content_bytes ?? "—", "metric"));
  }
  scroll.append(table);
  section.append(timeline, axis, scroll);
  if (event.frame_count > event.frames.length) {
    section.append(element("p", label("shown")(event.frames.length, event.frame_count), "muted"));
  }
  return section;
}

function showCopyState() {
  const notice = byId("copy-notice");
  notice.hidden = !copyMessage;
  notice.textContent = copyMessage ? label(copyMessage) : "";
  manualReport.hidden = copyMessage !== "manualCopy";
  manualReport.setAttribute("aria-label", label("copy"));
  manualReport.value = manualReport.hidden ? "" : selectedEvent.issue_markdown;
}

function showInspector() {
  const message = byId("inspector-message");
  message.hidden = !inspectorMessage;
  message.textContent = inspectorMessage ? label(inspectorMessage) : "";
  detail.hidden = !selectedEvent;
  copyButton.hidden = !selectedEvent;
  byId("close-inspector").hidden = !selectedId;
  detail.replaceChildren();
  showCopyState();
  if (!selectedEvent) return;
  const event = selectedEvent;
  const info = element("dl", null, "details");
  const fields = [
    ["status", event.status], ["dialect", event.dialect], ["finish", event.finish_reason],
    ["TTFT", ms(event.ttft_ms)], ["duration", ms(event.total_ms)], ["frame", event.frame_count]
  ];
  if (event.terminal_status != null) fields.push(["terminalStatus", event.terminal_status]);
  for (const [key, value] of fields) {
    const item = element("div");
    item.append(element("dt", label(key) || key), element("dd", value ?? "—"));
    info.append(item);
  }
  detail.append(element("p", `${event.method} ${event.path}`, "request mono"), info,
    showFindings(event), showFrames(event));
}

function closeInspector(message = "select") {
  eventRequest?.abort();
  eventRequest = null;
  selectedId = null;
  selectedEvent = null;
  inspectorMessage = message;
  copyMessage = "";
  showInspector();
}

async function openInspector(id, moveFocus) {
  closeInspector("loading");
  selectedId = id;
  for (const row of rows.querySelectorAll("[data-id]")) {
    row.dataset.selected = String(row.dataset.id === id);
    row.querySelector("button").setAttribute("aria-current", row.dataset.selected);
  }
  byId("close-inspector").hidden = false;
  if (moveFocus || window.matchMedia("(max-width: 820px)").matches) byId("inspector-heading").focus();
  const request = new AbortController();
  eventRequest = request;
  try {
    const response = await fetch("/_inferdiff/event/" + encodeURIComponent(id), {signal: request.signal});
    if (request.signal.aborted) return;
    if (response.status === 404) {
      closeInspector("missing");
      showRows();
      return;
    }
    if (!response.ok) throw new Error();
    const event = await response.json();
    if (request.signal.aborted) return;
    selectedEvent = event;
    inspectorMessage = "";
  } catch {
    if (request.signal.aborted) return;
    inspectorMessage = "detailError";
  } finally {
    if (eventRequest === request) eventRequest = null;
  }
  showInspector();
}

function scheduleStatus() {
  clearTimeout(pollTimer);
  if (auto.checked && !document.hidden && !clearing) pollTimer = setTimeout(loadStatus, 1500);
}

function stopStatus() {
  clearTimeout(pollTimer);
  statusRequest?.abort();
  statusRequest = null;
}

async function loadStatus() {
  if (statusRequest || clearing || document.hidden) return;
  clearTimeout(pollTimer);
  const request = new AbortController();
  statusRequest = request;
  try {
    const response = await fetch("/_inferdiff/status", {signal: request.signal});
    if (!response.ok) throw new Error();
    const next = await response.json();
    if (request.signal.aborted) return;
    const changed = !status || next.recent_events[0]?.id !== status.recent_events[0]?.id ||
      next.recent_events.length !== status.recent_events.length;
    status = next;
    statusError = false;
    if (selectedId && !status.recent_events.some((event) => event.id === selectedId)) closeInspector("missing");
    if (changed) showRows();
  } catch {
    if (request.signal.aborted) return;
    statusError = true;
    if (!status) showRows();
  } finally {
    if (statusRequest === request) {
      statusRequest = null;
      showStatus();
      scheduleStatus();
    }
  }
}

async function clearEvents() {
  clearing = true;
  clearFailed = false;
  stopStatus();
  showStatus();
  try {
    const response = await fetch("/_inferdiff/clear", {method: "POST"});
    if (!response.ok) throw new Error();
    closeInspector();
    if (status) status = {...status, recent_events: [], median_ttft_ms: null};
    showRows();
  } catch {
    clearFailed = true;
  } finally {
    clearing = false;
    showStatus();
    loadStatus();
  }
}

async function copyReport() {
  const event = selectedEvent;
  if (!event) return;
  try {
    await navigator.clipboard.writeText(event.issue_markdown);
    if (selectedEvent !== event) return;
    copyMessage = "copied";
    showCopyState();
  } catch {
    if (selectedEvent !== event) return;
    copyMessage = "manualCopy";
    showCopyState();
    manualReport.focus();
    manualReport.select();
  }
}

function setLanguage() {
  document.documentElement.lang = language;
  document.title = "inferdiff · " + label("title");
  for (const node of document.querySelectorAll("[data-label]")) node.textContent = label(node.dataset.label);
  const toggle = byId("language");
  toggle.lang = language === "en" ? "zh" : "en";
  toggle.textContent = language === "en" ? "中文" : "EN";
  toggle.setAttribute("aria-label", language === "en" ? "切换至中文" : "Switch to English");
  showStatus();
  showRows();
  showInspector();
}

rows.addEventListener("click", (click) => {
  const row = click.target.closest("[data-id]");
  if (row) openInspector(row.dataset.id, click.detail === 0);
});
for (const button of filters) button.addEventListener("click", () => {
  filter = button.dataset.filter;
  for (const choice of filters) choice.setAttribute("aria-pressed", String(choice === button));
  showRows();
});
byId("close-inspector").addEventListener("click", () => {
  const id = selectedId;
  closeInspector();
  showRows();
  const row = [...rows.querySelectorAll("[data-id]")].find((row) => row.dataset.id === id);
  (row?.querySelector("button") || filters.find((button) => button.dataset.filter === filter)).focus();
});
byId("refresh").addEventListener("click", loadStatus);
byId("clear").addEventListener("click", clearEvents);
byId("language").addEventListener("click", () => {
  language = language === "en" ? "zh" : "en";
  setLanguage();
});
auto.addEventListener("change", () => {
  showStatus();
  if (auto.checked) loadStatus();
  else clearTimeout(pollTimer);
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) stopStatus();
  else if (auto.checked || !status) loadStatus();
});
copyButton.addEventListener("click", copyReport);
setLanguage();
loadStatus();
</script>
</body>
</html>
""".encode("utf-8")
