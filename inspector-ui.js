// Browser-only UI for the offline stream inspector.
(() => {
  "use strict";

  const copy = {
    en: {
      breach: "P0 BREACH",
      breachNote: "The stream reported success with invalid or inconsistent tool JSON, or without the required Responses arguments.done event.",
      incomplete: "INCOMPLETE",
      incompleteNote: "The stream reported that it ended early. Check the tool-call JSON before using it.",
      pass: "PASS",
      passNote: "The captured finish reason or status matches the assembled output.",
      warning: "CHECK STREAM",
      warningNote: "Some frames could not be read, reported an error, or disagreed with the assembled output.",
      unknown: "UNCONFIRMED",
      unknownNote: "A finish reason or status could not be confirmed from this capture.",
      unreadable: "Paste SSE with data: lines or open an inferdiff trace with captured frames.",
      masked: "API keys or Bearer tokens were masked.",
      size: "This input exceeds 8 MiB. Try a smaller capture.",
      type: "Choose a .trace.jsonl or .jsonl file.",
      read: "The browser could not read this file.",
      none: "None observed",
      undetected: "Unknown",
      noTools: "No tool calls",
      valid: "Valid JSON",
      invalid: "Invalid JSON",
      invalidTools: (bad, total) => bad + " / " + total + " invalid",
      missing: (count) => count + " missing arguments.done",
      issues: (count) => count + (count === 1 ? " stream issue." : " stream issues."),
      order: "Frame order",
      frame: "Frame",
      empty: "The capture has no frames to inspect.",
      noOutput: "No text or tool calls were assembled from this capture.",
      text: "Text",
      tool: "Tool",
      deepPayload: "This frame is too deeply nested for pretty printing. Its original payload is in the input above.",
    },
    zh: {
      breach: "P0 违约",
      breachNote: "流报告成功，但工具调用 JSON 无效或前后不一致，或缺少 Responses 必需的 arguments.done 事件。",
      incomplete: "如实中断",
      incompleteNote: "流报告提前结束。使用工具参数前，请检查 JSON 是否完整。",
      pass: "通过",
      passNote: "记录中的结束原因或状态与拼接结果一致。",
      warning: "请检查日志",
      warningNote: "部分帧无法解析、报告了错误，或与拼接结果不一致。",
      unknown: "无法确认",
      unknownNote: "从这份记录中无法确认结束原因或状态。",
      unreadable: "请粘贴包含 data: 行的 SSE，或打开包含数据帧的 inferdiff 追踪文件。",
      masked: "已遮蔽 API 密钥或 Bearer 令牌。",
      size: "输入超过 8 MiB，请试用较小的记录。",
      type: "请选择 .trace.jsonl 或 .jsonl 文件。",
      read: "浏览器无法读取此文件。",
      none: "未观察到",
      undetected: "未知",
      noTools: "无工具调用",
      valid: "JSON 有效",
      invalid: "JSON 无效",
      invalidTools: (bad, total) => bad + " / " + total + " 项无效",
      missing: (count) => count + " 个调用缺少 arguments.done",
      issues: (count) => "发现 " + count + " 个流问题。",
      order: "按帧排序",
      frame: "帧",
      empty: "这份记录没有可检查的数据帧。",
      noOutput: "未能从记录中拼接出文本或工具调用。",
      text: "文本",
      tool: "工具",
      deepPayload: "此帧嵌套过深，无法格式化。原始载荷可在上方输入框查看。",
    },
  };

  const asSse = (frames) => frames.map((frame) =>
    (frame.type ? "event: " + frame.type + "\n" : "") + "data: " + JSON.stringify(frame)
  ).join("\n\n");
  const samples = {
    breach: asSse([
      { type: "response.output_item.added", output_index: 0, item: { type: "function_call", id: "fc_demo", name: "find_files", arguments: "" } },
      { type: "response.function_call_arguments.delta", output_index: 0, item_id: "fc_demo", delta: '{"pattern":' },
      { type: "response.function_call_arguments.delta", output_index: 0, item_id: "fc_demo", delta: '"src/' },
      { type: "response.output_item.done", output_index: 0, item: { type: "function_call", id: "fc_demo", name: "find_files", arguments: '{"pattern":"src/', status: "completed" } },
      { type: "response.completed", response: { status: "completed", incomplete_details: null } },
    ]),
    healthy: asSse([
      { object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "The stream " } }] },
      { object: "chat.completion.chunk", choices: [{ index: 0, delta: { content: "looks healthy. " } }] },
      { object: "chat.completion.chunk", choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_demo", type: "function", function: { name: "find_files", arguments: '{"pattern":' } }] } }] },
      { object: "chat.completion.chunk", choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '"src/*.js"}' } }] }, finish_reason: "tool_calls" }] },
    ]) + "\n\ndata: [DONE]",
  };

  const pageSize = 60;
  const inputLimit = 8 * 1024 * 1024;
  const get = (name) => document.getElementById("stream-" + name);
  const view = {
    input: get("input"), editor: get("editor"), file: get("file"), clear: get("clear"), message: get("message"),
    results: get("results"), finding: get("finding"), verdict: get("verdict"), note: get("finding-copy"),
    protocol: get("protocol"), count: get("count"), json: get("json"), terminal: get("terminal"),
    timing: get("timing"), timeline: get("timeline"), pages: get("page"), range: get("frame-range"),
    previousPage: get("prev-page"), nextPage: get("next-page"), previous: get("prev"), next: get("next"),
    meta: get("frame-meta"), event: get("frame-event"), code: get("frame-code"), output: get("output"),
  };
  const stream = globalThis.InferdiffStream;
  const state = { words: copy.en, format: new Intl.NumberFormat("en"), result: null, selected: -1, page: -1, masked: false, message: "", revision: 0 };

  function element(tag, text) {
    const node = document.createElement(tag);
    node.textContent = text;
    return node;
  }

  function showMessage() {
    view.message.hidden = !state.message;
    view.message.textContent = state.words[state.message] || "";
    view.message.toggleAttribute("data-error", Boolean(state.message && state.message !== "masked"));
  }

  function frameTime(ms) {
    return Number.isFinite(ms) ? " · +" + state.format.format(ms) + " ms" : "";
  }

  function drawTimeline(page) {
    const { frames } = state.result;
    const start = page * pageSize;
    const end = Math.min(start + pageSize, frames.length);
    const first = frames[start]?.ms;
    const last = frames[end - 1]?.ms;
    const timed = Number.isFinite(first) && Number.isFinite(last);
    const span = timed ? last - first : 0;
    view.timing.textContent = timed
      ? "+" + state.format.format(first) + " → +" + state.format.format(last) + " ms"
      : state.words.order;

    const buttons = frames.slice(start, end).map((frame, offset) => {
      const index = start + offset;
      const button = element("button", state.format.format(index + 1));
      button.type = "button";
      button.className = "stream-frame";
      button.dataset.tone = frame.tone;
      button.dataset.index = index;
      button.title = state.words.frame + " " + (index + 1) + " · " + frame.event + frameTime(frame.ms);
      button.setAttribute("aria-label", button.title);
      button.setAttribute("aria-pressed", "false");
      if (span > 0 && offset > 0 && Number.isFinite(frame.ms) && Number.isFinite(frames[index - 1].ms)) {
        const gap = Math.max(0, (frame.ms - frames[index - 1].ms) / span * 150);
        button.style.setProperty("--gap", gap + "px");
      }
      return button;
    });
    view.timeline.replaceChildren(...buttons);
    view.timeline.scrollLeft = 0;
    view.pages.hidden = frames.length <= pageSize;
    view.range.textContent = (start + 1) + "–" + end + " / " + state.format.format(frames.length);
    view.previousPage.disabled = start === 0;
    view.nextPage.disabled = end === frames.length;
    state.page = page;
  }

  function selectFrame(index) {
    const { frames } = state.result;
    const frame = frames[index];
    state.selected = frame ? index : -1;
    const page = Math.max(0, Math.floor(state.selected / pageSize));
    if (page !== state.page) drawTimeline(page);
    view.previous.disabled = state.selected <= 0;
    view.next.disabled = state.selected < 0 || state.selected >= frames.length - 1;
    view.timeline.querySelector('[aria-pressed="true"]')?.setAttribute("aria-pressed", "false");
    view.meta.textContent = frame ? "#" + state.format.format(index + 1) + frameTime(frame.ms) : "";
    view.event.textContent = frame?.event || "";
    view.event.dataset.tone = frame?.tone || "slate";
    try {
      view.code.textContent = frame
        ? (typeof frame.payload === "string" ? frame.payload : JSON.stringify(frame.payload, null, 2))
        : state.words.empty;
    } catch {
      view.code.textContent = state.words.deepPayload;
    }
    view.code.parentElement.scrollTop = 0;
    const current = view.timeline.querySelector('[data-index="' + index + '"]');
    if (current) {
      current.setAttribute("aria-pressed", "true");
      const bounds = current.getBoundingClientRect();
      const rail = view.timeline.getBoundingClientRect();
      if (bounds.left < rail.left || bounds.right > rail.right) {
        view.timeline.scrollLeft += bounds.left - rail.left - (rail.width - bounds.width) / 2;
      }
    }
  }

  function drawOutput() {
    const { texts, tools } = state.result;
    const entries = document.createDocumentFragment();
    for (const { label, text } of texts) {
      const block = element("div", "");
      block.append(element("strong", state.words.text + (label ? " · " + label : "")), element("pre", text));
      entries.append(block);
    }
    for (const { label, text, valid } of tools) {
      const block = element("div", "");
      const title = element("strong", (label || state.words.tool) + " · " + state.words[valid ? "valid" : "invalid"]);
      title.dataset.tone = valid ? "emerald" : "crimson";
      block.append(title, element("pre", text || "∅"));
      entries.append(block);
    }
    if (!entries.firstChild) entries.append(element("p", state.words.noOutput));
    view.output.replaceChildren(entries);
  }

  function draw() {
    showMessage();
    view.clear.disabled = !view.input.value;
    const result = state.result;
    view.results.hidden = !result;
    if (!result) {
      view.output.replaceChildren();
      view.code.textContent = "";
      view.timeline.replaceChildren();
      return;
    }

    const { protocol, frames, tools, endings, verdict, issueCount, missingArgumentsDone } = result;
    const words = state.words;
    const bad = tools.filter((tool) => !tool.valid).length;
    view.finding.dataset.tone = { breach: "crimson", pass: "emerald", incomplete: "amber", warning: "amber", unknown: "slate" }[verdict];
    view.verdict.textContent = words[verdict];
    view.note.textContent = words[!frames.length && !endings.length ? "unreadable" : verdict + "Note"]
      + (issueCount ? " " + words.issues(issueCount) : "");
    view.protocol.textContent = protocol === "Unknown" ? words.undetected : protocol;
    view.count.textContent = state.format.format(frames.length);
    view.json.textContent = (!tools.length ? words.noTools : bad ? words.invalidTools(bad, tools.length) : words.valid)
      + (missingArgumentsDone ? " · " + words.missing(missingArgumentsDone) : "");
    view.json.dataset.tone = bad || missingArgumentsDone ? "crimson" : tools.length ? "emerald" : "slate";
    view.terminal.textContent = [...new Set(endings.map(({ value }) => value))].join(" · ") || words.none;
    state.page = -1;
    selectFrame(state.selected);
    if (view.output.parentElement.open) drawOutput();
    else view.output.replaceChildren();
  }

  function analyze({ trace = false, newCapture = false, masked = false } = {}) {
    state.revision++;
    const raw = view.input.value;
    if (raw.length > inputLimit) {
      view.input.value = "";
      state.result = null;
      state.masked = false;
      state.message = "size";
      draw();
      return;
    }
    const safe = stream.redact(raw);
    if (safe.count) {
      const caret = stream.redact(raw.slice(0, view.input.selectionStart)).text.length;
      view.input.value = safe.text;
      view.input.setSelectionRange(caret, caret);
    }
    state.masked = Boolean(safe.count || masked ||
      (!newCapture && state.masked && safe.text.includes("[REDACTED]")));
    state.message = state.masked ? "masked" : "";
    state.result = safe.text.trim() ? stream.inspect(safe.text, { trace }) : null;
    const frames = state.result?.frames || [];
    const breach = frames.findLastIndex((frame) => frame.tone === "crimson");
    state.selected = breach >= 0 ? breach : frames.findLastIndex((frame) => frame.event !== "[DONE]");
    if (state.selected < 0 && frames.length) state.selected = 0;
    draw();
  }

  async function readFile(file) {
    const revision = ++state.revision;
    if (!/\.jsonl$/i.test(file.name) || file.size > inputLimit) {
      state.message = file.size > inputLimit ? "size" : "type";
      showMessage();
      return;
    }
    try {
      const content = await file.text();
      if (revision !== state.revision) return;
      const safe = stream.redact(content);
      view.input.value = safe.text;
      analyze({ trace: true, newCapture: true, masked: Boolean(safe.count) });
    } catch {
      if (revision === state.revision) {
        state.message = "read";
        showMessage();
      }
    }
  }

  view.input.addEventListener("input", () => analyze());
  view.input.addEventListener("paste", (event) => {
    const text = event.clipboardData?.getData("text/plain");
    if (!text) return;
    event.preventDefault();
    const start = view.input.selectionStart;
    const end = view.input.selectionEnd;
    const newCapture = start === 0 && end === view.input.value.length;
    if (view.input.value.length - (end - start) + text.length > inputLimit) {
      state.message = "size";
      showMessage();
      return;
    }
    const safe = stream.redact(text);
    view.input.setRangeText(safe.text, start, end, "end");
    analyze({ newCapture, masked: Boolean(safe.count) });
  });
  view.clear.addEventListener("click", () => {
    view.input.value = "";
    analyze({ newCapture: true });
    view.input.focus();
  });
  get("choose").addEventListener("click", () => view.file.click());
  view.file.addEventListener("change", () => {
    const file = view.file.files[0];
    view.file.value = "";
    if (file) readFile(file);
  });
  for (const button of document.querySelectorAll("[data-stream-sample]")) {
    button.addEventListener("click", () => {
      view.input.value = samples[button.dataset.streamSample];
      analyze({ newCapture: true });
    });
  }
  view.editor.addEventListener("dragover", (event) => {
    if (!event.dataTransfer.types.includes("Files")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    view.editor.setAttribute("data-dragging", "");
  });
  view.editor.addEventListener("dragleave", (event) => {
    if (!view.editor.contains(event.relatedTarget)) view.editor.removeAttribute("data-dragging");
  });
  view.editor.addEventListener("drop", (event) => {
    view.editor.removeAttribute("data-dragging");
    const file = event.dataTransfer.files[0];
    if (!file) return;
    event.preventDefault();
    readFile(file);
  });
  view.timeline.addEventListener("click", (event) => {
    const button = event.target.closest("[data-index]");
    if (button) selectFrame(Number(button.dataset.index));
  });
  view.previous.addEventListener("click", () => selectFrame(state.selected - 1));
  view.next.addEventListener("click", () => selectFrame(state.selected + 1));
  view.previousPage.addEventListener("click", () => selectFrame((state.page - 1) * pageSize));
  view.nextPage.addEventListener("click", () => selectFrame((state.page + 1) * pageSize));
  view.output.parentElement.addEventListener("toggle", () => {
    if (state.result && view.output.parentElement.open) drawOutput();
  });

  window.renderStreamInspector = (language) => {
    state.words = copy[language] || copy.en;
    state.format = new Intl.NumberFormat(language, { maximumFractionDigits: 2 });
    draw();
  };
})();
