// Offline SSE replay
(() => {
  "use strict";

  const copy = {
    en: {
      scenarios: "Replay scenarios",
      play: "Play",
      pause: "Pause",
      step: "Step frame",
      reset: "Reset",
      timing: "Arrival timeline",
      inspector: "Frame inspector",
      previous: "Previous arrived frame",
      next: "Next arrived frame",
      frames: "frames",
      waiting: "Awaiting frames",
      empty: "Play or step to inspect an SSE frame.",
      listening: "Listening for terminal frames…",
      sample: "Simulated frames and timing",
      source: "Published example trace modeling the live breach",
      reasoning: "Reasoning / timing",
      tool: "Tool call",
      text: "UTF-8 / pass",
      breach: "P0 breach",
    },
    zh: {
      scenarios: "回放场景",
      play: "播放",
      pause: "暂停",
      step: "单步播放",
      reset: "重置",
      timing: "到达时间轴",
      inspector: "帧检查器",
      previous: "上一帧",
      next: "下一帧",
      frames: "帧",
      waiting: "等待数据帧",
      empty: "播放或单步查看 SSE 数据帧。",
      listening: "等待流的结束事件…",
      sample: "模拟帧与时间",
      source: "项目公开的示例追踪，用于复现实测违约",
      reasoning: "推理 / 计时",
      tool: "工具调用",
      text: "UTF-8 / 通过",
      breach: "P0 违约",
    },
  };

  // Frame payloads and relative arrival times from the published Case 1 example.
  const caseOneFrames = [
    [42.1,1,"slate","delta.role",{"id":"chatcmpl-01","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_glob_01","type":"function","function":{"name":"glob_files","arguments":""}}]},"finish_reason":null}]}],
    [43.5,0,"slate","response.output_item.added",{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_glob_01","name":"glob_files","arguments":"","status":"in_progress"}}],
    [88.45,1,"violet","tool_calls[0]",{"id":"chatcmpl-01","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"pattern\": \"src/**/*.cpp\", "}}]},"finish_reason":null}]}],
    [89.9,0,"violet","response.function_call_arguments.delta",{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"pattern\": \"src/**/*.cpp\", "}],
    [131.2,1,"violet","tool_calls[0]",{"id":"chatcmpl-01","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"exclude\": [\"build/"}}]},"finish_reason":null}]}],
    [133.1,0,"violet","response.function_call_arguments.delta",{"type":"response.function_call_arguments.delta","output_index":0,"delta":"\"exclude\": [\"build/"}],
    [149.8,1,"emerald","finish_reason",{"id":"chatcmpl-01","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}],
    [150.9,1,"slate","usage",{"id":"chatcmpl-01","choices":[],"usage":{"prompt_tokens":68,"completion_tokens":24,"total_tokens":92}}],
    [151.2,1,"slate","[DONE]","[DONE]"],
    [151.6,0,"slate","response.output_item.done",{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_glob_01","name":"glob_files","arguments":"{\"pattern\": \"src/**/*.cpp\", \"exclude\": [\"build/","status":"completed"}}],
    [152.4,0,"crimson","response.completed",{"type":"response.completed","response":{"status":"completed","incomplete_details":null,"usage":{"input_tokens":68,"output_tokens":24}}}],
  ];

  const chatChunk = (id, delta, finishReason = null) => ({
    id,
    object: "chat.completion.chunk",
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  });

  function toolDelta(index, args, id) {
    const entry = { index, function: { arguments: args } };
    if (id) {
      entry.id = id;
      entry.type = "function";
      entry.function.name = "get_node_status";
    }
    return { tool_calls: [entry] };
  }

  const parallel = (ms, track, delta, event, tone = "violet") => [
    ms, track, tone, event, chatChunk("chatcmpl-parallel", delta),
  ];
  const chatDone = (ms, track) => [ms, track, "slate", "[DONE]", "[DONE]"];
  const streamParts = ["01, 02, 03, 04, 05, ", "06, 07, 08, 09, 10, ", "11, 12, 13, 14, 15, ", "16, 17, 18, 19, 20, ", "21, 22, 23, 24, 25"];

  function streamFrames(track, id, times, end) {
    return [
      [24, track, "slate", "delta.role", chatChunk(id, { role: "assistant", content: "" })],
      ...streamParts.map((content, index) => [
        times[index], track, track === 0 ? "amber" : "emerald", "delta.content", chatChunk(id, { content }),
      ]),
      [end - 0.5, track, track === 0 ? "amber" : "emerald", "finish_reason", chatChunk(id, {}, "stop")],
      chatDone(end, track),
    ];
  }

  function messageFrames(track, id, times, reason, tone) {
    const entries = [
      ["message_start", {
        message: { id, type: "message", role: "assistant", content: [], model: "claude-example", stop_reason: null, stop_sequence: null, usage: { input_tokens: 68, output_tokens: 1 } },
      }, "slate"],
      ["content_block_start", {
        index: 0, content_block: { type: "tool_use", id: "toolu_example", name: "get_node_status", input: {} },
      }, "violet"],
      ["content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: '{"node":"node' } }, "violet"],
      ["content_block_stop", { index: 0 }, "slate"],
      ["message_delta", { delta: { stop_reason: reason, stop_sequence: null }, usage: { output_tokens: 12 } }, tone],
      ["message_stop", {}, "slate"],
    ];
    return entries.map(([event, data, kind], index) => [times[index], track, kind, event, { type: event, ...data }]);
  }

  const scenarios = [
    {
      id: "C1",
      title: ["Live Breach", "实测违约"],
      range: 160,
      rate: 0.1,
      tracks: [
        ["/v1/responses", ["P0 breach", "P0 违约"], "crimson", 0.95],
        ["/v1/chat/completions", ["Pass · honest truncation", "通过 · 如实报告截断"], "emerald", 0.932],
      ],
      frames: caseOneFrames,
      inspect: "response.completed",
      verdict: ["P0 BREACH", "P0 违约"],
      finding: [
        'Both streams return HTTP 200. Responses claims status: "completed" with invalid tool JSON and no response.function_call_arguments.done. Chat Completions correctly reports finish_reason: "length".',
        '两个端点都返回 HTTP 200。Responses 的工具参数 JSON 未闭合，缺少 response.function_call_arguments.done，却声称 status: "completed"。Chat Completions 正确报告 finish_reason: "length"。',
      ],
      tone: "crimson",
      source: "https://github.com/ApacheWang/inferdiff/tree/main/examples/case1_responses_truncated_tool",
    },
    {
      id: "C5",
      title: ["Parallel Tool Calls", "并行工具调用"],
      range: 400,
      rate: 0.25,
      tracks: [
        ["tool_calls[0]", ["node-a", "node-a"], "violet", 0.54],
        ["tool_calls[1]", ["node-b", "node-b"], "violet", 0.63],
        ["/v1/chat/completions", ["Pass · indices [0, 1]", "通过 · 索引 [0, 1]"], "emerald", 0.76],
      ],
      frames: [
        parallel(38, 2, { role: "assistant", content: null }, "delta.role", "slate"),
        parallel(76, 0, toolDelta(0, '{"node":"', "call_node_a"), "tool_calls[0]"),
        parallel(115, 1, toolDelta(1, '{"node":"', "call_node_b"), "tool_calls[1]"),
        parallel(169, 0, toolDelta(0, "node-a"), "tool_calls[0]"),
        parallel(201, 1, toolDelta(1, "node-b"), "tool_calls[1]"),
        parallel(216, 0, toolDelta(0, '"}'), "tool_calls[0]"),
        parallel(252, 1, toolDelta(1, '"}'), "tool_calls[1]"),
        [304, 2, "emerald", "finish_reason", chatChunk("chatcmpl-parallel", {}, "tool_calls")],
        chatDone(336, 2),
      ],
      inspect: "tool_calls[1]",
      verdict: ["PASS", "通过"],
      finding: [
        'The initial delta announces role: "assistant". Indices [0, 1] stay distinct while the calls interleave, so each tool gets its own valid JSON arguments.',
        '第一帧带有 role: "assistant"。两个调用的分片交错到达，索引始终保持为 [0, 1]，因此每个工具都能独立拼接出有效的 JSON 参数。',
      ],
      tone: "emerald",
    },
    {
      id: "C7",
      title: ["Fake-Streaming Buffering", "伪流式缓冲"],
      range: 1600,
      rate: 1,
      tracks: [
        ["/v1/chat/completions", ["Buffered relay · 3 ms burst", "缓冲中转 · 3 毫秒内突发"], "amber", 0.908],
        ["/v1/chat/completions", ["Pass · incremental", "通过 · 逐帧交付"], "emerald", 0.85],
      ],
      frames: [
        ...streamFrames(0, "chatcmpl-buffered", [1452, 1452.7, 1453.4, 1454.1, 1455], 1456),
        ...streamFrames(1, "chatcmpl-streamed", [148, 401, 654, 908, 1162], 1360),
      ],
      inspect: "delta.content",
      verdict: ["P1 WARN", "P1 警告"],
      finding: [
        'The buffered relay spends 1,452 of 1,456 ms waiting for the first token, then delivers all five content frames in 3 ms. The incremental comparison sends content throughout the request.',
        '缓冲中转耗时 1,456 毫秒，首个 token 到达就用了 1,452 毫秒，随后 5 个内容帧在 3 毫秒内集中送达。对照流在请求期间持续发送内容。',
      ],
      tone: "amber",
    },
    {
      id: "C9",
      title: ["Anthropic Truncation", "Anthropic 截断"],
      range: 400,
      rate: 0.25,
      tracks: [
        ["/v1/messages", ["P0 breach · false tool_use", "P0 违约 · 误报 tool_use"], "crimson", 0.83],
        ["/v1/messages", ["Pass · honest max_tokens", "通过 · 如实报告 max_tokens"], "emerald", 0.745],
      ],
      frames: [
        ...messageFrames(0, "msg_truncated", [28, 90, 177, 264, 332, 361], "tool_use", "crimson"),
        ...messageFrames(1, "msg_reported", [34, 103, 164, 230, 298, 338], "max_tokens", "emerald"),
      ],
      inspect: "message_delta",
      verdict: ["P0 BREACH", "P0 违约"],
      finding: [
        'An input_json_delta is cut off mid-string. A message_delta with stop_reason: "tool_use" advertises an unusable call. The matching comparison reports stop_reason: "max_tokens".',
        'input_json_delta 在字符串中途截断，message_delta 却用 stop_reason: "tool_use" 宣告了无法执行的调用。对照流如实返回 stop_reason: "max_tokens"。',
      ],
      tone: "crimson",
    },
  ];

  for (const scenario of scenarios) {
    scenario.frames.sort(([first], [second]) => first - second);
  }

  const ticks = [0, 1, 2, 3, 4];
  const state = { scenario: scenarios[0], language: "en", elapsed: 0, count: 0, selected: -1, animation: 0 };
  let view;

  function local(pair) {
    return pair[state.language === "zh" ? 1 : 0];
  }

  function formatMs(ms) {
    return Number(ms.toFixed(2)).toLocaleString(state.language === "zh" ? "zh-CN" : "en", { maximumFractionDigits: 2 });
  }

  function buildTimeline() {
    const { id, frames, tracks, range } = state.scenario;
    const ruler = ticks.map((tick) => `<span class="timeline-tick" style="--position:${tick * 25}%">${formatMs(tick * range / 4)}${tick === 4 ? " ms" : ""}</span>`).join("");
    const rails = tracks.map(([label, detail, tone, end], track) => {
      const trackFrames = frames.map((frame, index) => ({ frame, index })).filter(({ frame }) => frame[1] === track);
      let prevTime = -range;
      let closeCount = 0;
      const points = trackFrames.map(({ frame: [ms, , color, event], index }) => {
        closeCount = ms - prevTime < range * 0.035 ? closeCount + 1 : 0;
        prevTime = ms;
        const offset = Math.ceil(closeCount / 2) * (closeCount % 2 === 0 ? 1 : -1) * 13;
        return `<button type="button" class="frame-dot" data-frame="${index}" data-tone="${color}" data-arrived="false" style="--position:${ms / range * 100}%;--offset:${offset}px" title="${event} · ${formatMs(ms)} ms" aria-label="${label}, ${event}, ${formatMs(ms)} ms" aria-pressed="false" disabled></button>`;
      }).join("");
      return `<div class="timeline-track" data-tone="${tone}">
        <div class="timeline-label"><code>${label}</code><span>${local(detail)}</span></div>
        <div class="timeline-rail"><span class="timeline-fill" style="--track-end:${end * 100}%"></span>${points}</div>
      </div>`;
    }).join("");

    return `<section class="timeline" aria-label="${copy[state.language].timing}">
      <div class="timeline-heading"><strong>${copy[state.language].timing}</strong><span>${state.scenario.rate}×</span></div>
      <div class="timeline-chart" data-timeline="${id}">
        <div class="timeline-ruler" aria-hidden="true">${ruler}</div>
        ${rails}
      </div>
      <div class="timeline-legend">${[
        ["amber", copy[state.language].reasoning], ["violet", copy[state.language].tool],
        ["emerald", copy[state.language].text], ["crimson", copy[state.language].breach],
      ].map(([tone, label]) => `<span data-tone="${tone}">${label}</span>`).join("")}</div>
    </section>`;
  }

  function highlightPayload(target, payload) {
    const logical = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
    const tokens = logical.split(/("(?:[^"\\]|\\.)*"(?=\s*:)|"(?:[^"\\]|\\.)*"|\b(?:true|false|null)\b|-?\b\d+(?:\.\d+)?\b)/g);
    const parts = tokens.map((part, index) => {
      if (index % 2 === 0) return document.createTextNode(part);
      const span = document.createElement("span");
      const isKey = tokens[index + 1]?.trimStart().startsWith(":");
      span.className = isKey ? "json-key" : part.startsWith('"') ? "json-string" : "json-value";
      span.textContent = part;
      return span;
    });
    target.replaceChildren(...parts);
  }

  function paint(elapsed) {
    const { frames, range } = state.scenario;
    state.elapsed = elapsed;
    view.timeline.style.setProperty("--elapsed", `${elapsed / range * 100}%`);
    view.progress.textContent = `${formatMs(elapsed)} ms · ${state.count}/${frames.length} ${copy[state.language].frames}`;
  }

  function updateFrameView() {
    const words = copy[state.language];
    const { frames, tracks, tone, verdict, finding } = state.scenario;
    const done = state.count === frames.length;
    view.dots.forEach((dot) => {
      const index = Number(dot.dataset.frame);
      dot.disabled = index >= state.count;
      dot.dataset.arrived = String(!dot.disabled);
      dot.setAttribute("aria-pressed", String(index === state.selected));
    });
    view.previous.disabled = state.selected <= 0;
    view.next.disabled = state.selected >= state.count - 1;
    view.finding.dataset.tone = done ? tone : "slate";
    view.badge.textContent = done ? local(verdict) : words.waiting;
    view.note.textContent = done ? local(finding) : words.listening;

    if (state.selected < 0) {
      view.meta.textContent = words.waiting;
      view.event.textContent = "SSE";
      view.event.dataset.tone = "slate";
      view.code.textContent = words.empty;
      return;
    }

    const [ms, track, color, event, payload] = frames[state.selected];
    view.meta.textContent = `#${String(state.selected + 1).padStart(2, "0")} · +${formatMs(ms)} ms · ${tracks[track][0]}`;
    view.event.textContent = event;
    view.event.dataset.tone = color;
    highlightPayload(view.code, payload);
    view.code.parentElement.scrollTop = 0;
  }

  function updatePlayButton() {
    view.playLabel.textContent = state.animation ? copy[state.language].pause : copy[state.language].play;
    view.playIcon.textContent = state.animation ? "Ⅱ" : "▶";
  }

  function stop() {
    cancelAnimationFrame(state.animation);
    state.animation = 0;
    updatePlayButton();
  }

  function reset() {
    stop();
    state.count = 0;
    state.selected = -1;
    paint(0);
    updateFrameView();
  }

  function step() {
    stop();
    const { frames } = state.scenario;
    if (state.count === frames.length) reset();
    state.selected = state.count++;
    paint(frames[state.selected][0]);
    updateFrameView();
  }

  function play() {
    if (state.animation) {
      stop();
      return;
    }
    const { frames, rate } = state.scenario;
    if (state.count === frames.length) reset();
    const start = performance.now() - state.elapsed / rate;
    const end = frames.at(-1)[0];

    function advance(now) {
      const elapsed = Math.min(Math.max(0, (now - start) * rate), end);
      const countBefore = state.count;
      while (state.count < frames.length && frames[state.count][0] <= elapsed) state.count++;
      paint(elapsed);
      if (state.count !== countBefore) {
        state.selected = state.count - 1;
        updateFrameView();
      }
      if (state.count < frames.length) {
        state.animation = requestAnimationFrame(advance);
      } else {
        stop();
      }
    }

    state.animation = requestAnimationFrame(advance);
    updatePlayButton();
  }

  function inspect(index) {
    if (index < 0 || index >= state.count) return;
    state.selected = index;
    updateFrameView();
  }

  function loadOverview(scenario) {
    state.scenario = scenario;
    state.count = scenario.frames.length;
    state.elapsed = scenario.frames.at(-1)[0];
    state.selected = scenario.frames.findLastIndex(([, track, , event]) => event === scenario.inspect && track === (scenario.id === "C5" ? 1 : 0));
  }

  function draw() {
    const mount = document.querySelector("#replay-app");
    if (!mount) return;
    const words = copy[state.language];

    mount.innerHTML = `
      <div class="replay-tabs" role="group" aria-label="${words.scenarios}">
        ${scenarios.map(({ id, title }) => `<button type="button" class="replay-tab" data-scenario="${id}" aria-pressed="${id === state.scenario.id}"><span class="replay-tab-id">${id}</span><span class="replay-tab-title">${local(title)}</span></button>`).join("")}
      </div>
      <div class="replay-toolbar">
        <div class="replay-controls">
          <button type="button" class="replay-play"><span class="replay-play-icon" aria-hidden="true">▶</span><span class="replay-play-label">${words.play}</span></button>
          <button type="button" class="replay-step"><span aria-hidden="true">▸|</span> ${words.step}</button>
          <button type="button" class="replay-reset"><span aria-hidden="true">↺</span> ${words.reset}</button>
        </div>
        <span class="replay-progress"></span>
      </div>
      <div class="replay-body">
        ${buildTimeline()}
        <section class="frame-inspector" aria-label="${words.inspector}">
          <div class="inspector-heading"><strong>${words.inspector}</strong>
            <div class="inspector-controls"><button type="button" class="inspector-prev" aria-label="${words.previous}" title="${words.previous}">‹</button><button type="button" class="inspector-next" aria-label="${words.next}" title="${words.next}">›</button></div>
          </div>
          <div class="inspector-meta"></div>
          <div class="inspector-event"></div>
          <pre class="inspector-code" tabindex="0"><code></code></pre>
        </section>
      </div>
      <div class="replay-finding">
        <span class="finding-badge"></span><span class="finding-copy"></span>
      </div>
      <div class="replay-source">${state.scenario.source ? `<a href="${state.scenario.source}">${words.source}</a>` : words.sample}</div>`;

    const find = (selector) => mount.querySelector(selector);
    view = {
      timeline: find(".timeline-chart"), progress: find(".replay-progress"), playLabel: find(".replay-play-label"), playIcon: find(".replay-play-icon"),
      finding: find(".replay-finding"), badge: find(".finding-badge"), note: find(".finding-copy"),
      previous: find(".inspector-prev"), next: find(".inspector-next"), meta: find(".inspector-meta"), event: find(".inspector-event"), code: find(".inspector-code code"),
      dots: mount.querySelectorAll(".frame-dot"),
    };
    find(".replay-play").addEventListener("click", play);
    find(".replay-step").addEventListener("click", step);
    find(".replay-reset").addEventListener("click", reset);
    view.previous.addEventListener("click", () => inspect(state.selected - 1));
    view.next.addEventListener("click", () => inspect(state.selected + 1));
    view.dots.forEach((dot) => dot.addEventListener("click", () => inspect(Number(dot.dataset.frame))));
    mount.querySelectorAll(".replay-tab").forEach((tab) => tab.addEventListener("click", () => {
      window.selectReplayScenario(tab.dataset.scenario);
      find(`[data-scenario="${tab.dataset.scenario}"]`).focus();
    }));

    paint(state.elapsed);
    updateFrameView();
    updatePlayButton();
  }

  window.renderReplay = (language = "en") => {
    state.language = language === "zh" || language.startsWith("zh-") ? "zh" : "en";
    draw();
  };

  window.selectReplayScenario = (id) => {
    const scenario = scenarios.find((entry) => entry.id === String(id).toUpperCase());
    if (!scenario || scenario === state.scenario) return;
    if (view) stop();
    loadOverview(scenario);
    draw();
  };

  loadOverview(scenarios[0]);
})();

// Probe matrix
(() => {
  'use strict';

  const doctor = 'uvx inferdiff doctor http://127.0.0.1:8080/v1';
  const audit = 'uvx inferdiff audit target.trace.jsonl --only';
  const roadmapUrl = 'https://github.com/ApacheWang/inferdiff/blob/v0.1.1/README.md#L144';
  const probes = [
    {
      id: "C1", level: 'P0', profile: 'full', replay: true,
      title: ['Truncated tool arguments', '工具参数截断'],
      detail: ['Catches a stream that reports success with unfinished tool-call JSON or omits the Responses arguments.done event. The full profile checks both OpenAI endpoints.', '检测工具调用 JSON 尚未完整却报告成功，或 Responses 缺少 arguments.done 事件。full 配置会交叉检查两个 OpenAI 端点。'],
    },
    {
      id: "C2", level: 'P0', profile: 'relay',
      title: ['Reasoning starvation', '推理耗尽预算'],
      detail: ['Flags a successful stop when reasoning consumed the token budget and left no visible answer or tool call.', '检测推理耗尽 token 预算后，正文和工具调用均为空却报告成功结束的情况。'],
    },
    {
      id: "C3", level: 'P1', profile: 'full',
      title: ['Fixed budget mismatch', '定长生成不足'],
      detail: ['Checks whether ignore_eos=true delivers the full 96-token probe budget. An endpoint that rejects the option is skipped.', '检查 ignore_eos=true 时是否生成满 96 个探针 token。端点拒绝该选项时会跳过。'],
    },
    {
      id: "C4", level: 'P1', profile: 'quick',
      title: ['Missing usage accounting', '用量统计缺失'],
      detail: ['Finds a missing final usage frame with empty choices or prompt-token counts that omit the tool schema.', '检测空 choices 的结束用量帧是否丢失，以及提示 token 是否漏计工具 schema。'],
    },
    {
      id: "C5", level: 'P1 / P0', profile: 'quick', replay: true,
      title: ['Parallel tool indices', '并行工具索引'],
      detail: ['Checks the opening delta.role and tool indices. Missing or colliding indices can merge the arguments of separate calls.', '检查开头的 delta.role 及工具索引。索引缺失或冲突可能使不同调用的参数被拼在一起。'],
    },
    {
      id: "C6", level: 'P0', profile: 'quick',
      title: ['UTF-8 integrity', 'UTF-8 完整性'],
      detail: ['Detects malformed multibyte characters, U+FFFD replacement characters, and truncated tails that swallow the final emoji.', '检测多字节字符损坏、U+FFFD 替换字符，以及流尾截断吞掉最后一个 emoji 的情况。'],
    },
    {
      id: "C7", level: 'P1', profile: 'quick', replay: true,
      title: ['Fake streaming', '缓冲式假流'],
      detail: ['For streams lasting at least 250 ms with at least 40 B of payload, flags waits over 96% of total time followed by a burst under 5 ms.', '对总耗时至少 250 毫秒、有效载荷至少 40 字节的流，检测首包等待是否超过总耗时的 96%，随后在不到 5 毫秒内集中送达。'],
    },
    {
      id: "C8", level: 'P2', profile: 'relay',
      title: ['Backend pool drift', '后端池漂移'],
      detail: ['Uses a fixed seed and varied prefixes to look for backend fingerprints or token counts that suggest heterogeneous routing.', '使用固定种子与变化的前缀，排查后端指纹或 token 计数差异所反映的异构路由。'],
    },
    {
      id: "C9", kind: 'simulation', replay: true,
      title: ['Anthropic tool truncation', 'Anthropic 工具参数截断'],
      detail: ['The /v1/messages replay compares a relay claiming tool_use with partial tool JSON to an honest max_tokens stop.', '/v1/messages 回放对比两种结束方式：工具 JSON 尚未完整却报告 tool_use，以及如实报告 max_tokens。'],
    },
    {
      id: "D1", level: 'P0',
      title: ['Invalid tool call marked successful', '无效工具调用被标为成功'],
      detail: ['Audits assembled tool arguments for invalid JSON, inconsistent payloads, and missing Responses completion events under a success status.', '在成功终态下检查工具参数能否解析为 JSON、载荷是否一致，以及 Responses 完成事件是否齐全。'],
    },
    {
      id: "D2", level: 'P0',
      title: ['Empty output after reasoning', '推理后正文为空'],
      detail: ['Flags HTTP 200 streams that produce no answer or tool call after consuming tokens, emitting reasoning, or claiming stop.', '检测返回 HTTP 200 且无正文或工具调用的流，核查是否已消耗 token、输出推理内容或报告 stop。'],
    },
    {
      id: "D3", level: 'P1',
      title: ['Silent short generation', '生成长度静默不足'],
      detail: ['Audits fixed-length runs that set ignore_eos=true and finish below the requested token count without an effective stop sequence.', '审计启用 ignore_eos=true 的定长运行，检测未命中有效停止序列却提前结束的情况。'],
    },
    {
      id: "D4", level: 'P0',
      title: ['Premature EOF', '流提前结束'],
      detail: ['Catches a stream that ends without its required terminal frame, sends terminal events out of order, or returns an unsupported 2xx status.', '检测缺少必需终帧、终止事件顺序错误，或返回不支持的 2xx 状态。'],
    },
    {
      id: "D5", level: 'P1', kind: 'diff',
      title: ['Misleading benchmark speedup', '误导性的跑分提速'],
      detail: ['Checks a latency drop of more than 50% for evidence of warmed caches, sharply reduced output, or bursty delivery.', '当延迟降幅超过 50% 时，检查是否伴随缓存预热、输出骤减或集中突发发送。'],
    },
    {
      id: "D6", kind: 'roadmap',
      title: ['KV and storage telemetry', 'KV 与存储遥测'],
      detail: ['The v0.2 roadmap lists LMCache, Mooncake and Linux process I/O probes for D6–D8. Individual detector conditions are pending publication.', 'v0.2 路线图为 D6–D8 列出了 LMCache、Mooncake 和 Linux 进程 I/O 探针。各规则的判定条件有待公布。'],
    },
    {
      id: "D7", kind: 'roadmap',
      title: ['KV and storage telemetry', 'KV 与存储遥测'],
      detail: ['The planned D6–D8 checks share a backend snapshot protocol that takes measurements before dispatch, at the first effective payload and at EOF.', '规划中的 D6–D8 共用后端快照协议，在请求发出前、首个有效载荷到达时以及流结束时采样。'],
    },
    {
      id: "D8", kind: 'roadmap',
      title: ['KV and storage telemetry', 'KV 与存储遥测'],
      detail: ['The D6–D8 roadmap connects inference timing with backend storage and I/O counters. Per-rule failure criteria are pending publication.', 'D6–D8 路线图将推理时序与后端存储和 I/O 计数关联分析。各规则的故障判定标准有待公布。'],
    },
  ];

  const messages = {
    en: {
      filters: { all: 'All', C: 'Canary', D: 'Deep' }, filterLabel: 'Filter probes',
      copy: 'Copy', copyLabel: 'Copy command for', replay: 'View replay', roadmap: 'View roadmap',
      simulation: 'Replay only · v0.1.1 runs C1–C8', planned: 'Roadmap · v0.2',
      profile: 'Runs all probes in the selected profile.', audit: 'Needs a recorded target trace.',
      diff: 'Needs baseline and target traces.',
    },
    zh: {
      filters: { all: '全部', C: '金丝雀探针', D: '深度检测' }, filterLabel: '筛选探针',
      copy: '复制', copyLabel: '复制命令', replay: '查看回放', roadmap: '查看路线图',
      simulation: '仅供回放 · v0.1.1 运行 C1–C8', planned: '路线图 · v0.2',
      profile: '运行所选配置的整套探针。', audit: '需要已录制的目标 trace。',
      diff: '需要基线和目标 trace。',
    },
  };

  let language = 'en';
  let family = 'all';

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function cliExample(probe, t) {
    if (probe.profile) return [`${doctor} --profile ${probe.profile}`, t.profile];
    if (probe.kind === 'diff') return ['uvx inferdiff diff baseline.trace.jsonl target.trace.jsonl', t.diff];
    return [`${audit} ${probe.id}`, t.audit];
  }

  function card(probe) {
    const t = messages[language];
    const lang = language === 'zh' ? 1 : 0;
    const item = element('article', 'probe-card');
    item.dataset.probeId = probe.id;

    const meta = element('div', 'probe-meta');
    meta.append(element('span', 'probe-id', probe.id), element('span', 'probe-family', t.filters[probe.id[0]]));
    if (probe.level) {
      const severity = element('span', 'probe-severity', probe.level);
      severity.dataset.level = probe.level.includes('P0') ? 'p0' : probe.level.toLowerCase();
      meta.append(severity);
    }
    item.append(meta, element('h3', null, probe.title[lang]), element('p', null, probe.detail[lang]));

    const actions = element('div', 'probe-actions');
    if (probe.kind === 'simulation' || probe.kind === 'roadmap') {
      actions.append(element('p', 'probe-scope', probe.kind === 'roadmap' ? t.planned : t.simulation));
    } else {
      const [text, scope] = cliExample(probe, t);
      const command = element('div', 'probe-command');
      const copy = element('button', 'copy-button', t.copy);
      copy.type = 'button';
      copy.setAttribute('aria-label', `${t.copyLabel} ${probe.id}`);
      copy.addEventListener('click', () => window.copyCommand(text, copy));
      command.append(element('code', null, text), copy);
      actions.append(command, element('p', 'probe-scope', scope));
    }

    if (probe.replay || probe.kind === 'roadmap') {
      const link = element('a', 'probe-replay', probe.replay ? t.replay : t.roadmap);
      link.href = probe.replay ? '#replay' : roadmapUrl;
      if (probe.replay) {
        link.dataset.replayLink = probe.id;
        link.setAttribute('aria-label', `${t.replay} ${probe.id}`);
      }
      actions.append(link);
    }
    item.append(actions);
    return item;
  }

  function renderCards() {
    const grid = document.getElementById('probe-grid');
    const shown = probes.filter((probe) => family === 'all' || probe.id.startsWith(family));
    grid.replaceChildren(...shown.map(card));
  }

  window.renderProbeMatrix = (locale = 'en') => {
    language = locale.startsWith('zh') ? 'zh' : 'en';
    const filters = document.getElementById('probe-filters');
    const t = messages[language];
    filters.setAttribute('role', 'group');
    filters.setAttribute('aria-label', t.filterLabel);
    const choices = Object.entries(t.filters);
    filters.replaceChildren(...choices.map(([value, label]) => {
      const count = probes.filter((probe) => value === 'all' || probe.id.startsWith(value)).length;
      const button = element('button', 'filter-button', `${label} ${count}`);
      button.type = 'button';
      button.setAttribute('aria-pressed', String(value === family));
      button.addEventListener('click', () => {
        family = value;
        filters.querySelector('[aria-pressed="true"]').setAttribute('aria-pressed', 'false');
        button.setAttribute('aria-pressed', 'true');
        renderCards();
      });
      return button;
    }));
    renderCards();
  };
})();

// Page controls and localization
(() => {
  'use strict';

  const chinese = {
    skip: '跳到正文',
    navLabel: '主导航',
    navReplay: '瀑布图',
    navProbes: '探针',
    navCloud: '云服务',
    language: '语言',
    github: '在 GitHub 上查看',
    heroLabel: '流式 LLM API 协议校验工具',
    heroLineOne: '逐帧定位',
    heroLineTwo: 'LLM 流式故障。',
    heroDescription: '发现 HTTP 200 背后的工具参数截断、SSE 缓冲等协议故障，定位异常发生的具体帧。',
    projectDetails: '项目信息',
    stars: 'GitHub 星标',
    zeroDeps: '零依赖',
    inspectC1: '查看 C1 瀑布图',
    failureSignature: '实测故障',
    breach: '违约',
    doneMissing: '缺少 arguments.done',
    pass: '通过',
    truncationReported: '如实报告截断',
    openReplay: '打开逐帧回放',
    quickstart: '快速开始',
    copy: '复制',
    replayHeading: '帧级瀑布图',
    replayIntro: '播放记录或逐帧查看。选择已收到的帧，检查它的 SSE 载荷。',
    localReplay: '离线回放',
    liveRun: '实测记录',
    checksRan: '已运行检查',
    elapsed: '耗时',
    skips: '跳过',
    probesHeading: '探针矩阵',
    probesIntro: '按故障类型查找探针，并复制对应的排查命令。',
    cloudHeading: 'CLI 与云端监控',
    cloudIntro: '按需运行检查，或持续监控你的中转服务。',
    cliTitle: '开源 CLI',
    cliDescription: '可在本地和 CI 免费运行 ',
    sentenceEnd: '。',
    cliFeatureOne: '运行金丝雀探针，检查线上端点。',
    cliFeatureTwo: '录制 SSE 流并逐帧对比。',
    cliFeatureThree: '导出离线 HTML 瀑布图，附到回归报告中。',
    hosting: '托管版 / 自托管版',
    cloudDescription: '在浏览器中检查和对比中转服务。',
    free: '免费',
    freeFeatures: '网页即时检查与中转服务并排对比',
    pro: '专业版',
    proFeatures: '全天候监控，支持飞书、Telegram 和微信告警',
    webCheck: '网页检查',
    relayPk: '中转对比',
    watchdog: '持续监控',
    selfHost: '自托管',
    cloudNote: '可在展示站配置中填写云服务链接。',
    footerCopy: '流式 LLM 协议校验',
    license: 'MIT 许可证',
  };

  const preferenceKey = 'inferdiff-pages-language';
  const languageButtons = [...document.querySelectorAll('[data-language]')];
  const translatedText = [...document.querySelectorAll('[data-i18n]')].map((node) => [node, node.textContent]);
  const translatedLabels = [...document.querySelectorAll('[data-i18n-aria]')].map((node) => [node, node.getAttribute('aria-label')]);
  const copyTimers = new WeakMap();
  let language = 'en';

  function preferredLanguage() {
    try {
      const saved = localStorage.getItem(preferenceKey);
      if (saved === 'en' || saved === 'zh') return saved;
    } catch {
      // Browser storage can be disabled for a local file or private session.
    }
    return (navigator.language || '').toLowerCase().startsWith('zh') ? 'zh' : 'en';
  }

  function setLanguage(next) {
    language = next;
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
    document.title = language === 'zh' ? 'inferdiff | 流式 LLM 协议校验工具' : 'inferdiff | Streaming LLM contract verifier';
    for (const [node, english] of translatedText) {
      node.textContent = language === 'zh' ? chinese[node.dataset.i18n] : english;
    }
    for (const [node, english] of translatedLabels) {
      node.setAttribute('aria-label', language === 'zh' ? chinese[node.dataset.i18nAria] : english);
    }
    for (const button of languageButtons) {
      button.setAttribute('aria-pressed', String(button.dataset.language === language));
    }
    window.renderReplay(language);
    window.renderProbeMatrix(language);
  }

  function fallbackCopy(text) {
    const active = document.activeElement;
    const selection = document.getSelection();
    const ranges = selection ? Array.from({ length: selection.rangeCount }, (_, index) => selection.getRangeAt(index).cloneRange()) : [];
    const input = document.createElement('textarea');
    input.className = 'sr-only';
    input.value = text;
    input.readOnly = true;
    document.body.append(input);
    input.select();
    try {
      return document.execCommand('copy');
    } finally {
      input.remove();
      active?.focus({ preventScroll: true });
      if (selection && ranges.length) {
        selection.removeAllRanges();
        for (const range of ranges) selection.addRange(range);
      }
    }
  }

  window.copyCommand = async (text, button) => {
    let copied = false;
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
    } catch {
      try {
        copied = fallbackCopy(text);
      } catch {
        copied = false;
      }
    }

    const label = button.querySelector('[data-copy-label]') || button;
    const message = copied ? (language === 'zh' ? '已复制' : 'Copied') : (language === 'zh' ? '命令已选中，请手动复制' : 'Command selected for manual copy');
    if (!copied) {
      const command = button.parentElement?.querySelector('code');
      const selection = document.getSelection();
      if (command && selection) {
        const range = document.createRange();
        range.selectNodeContents(command);
        selection.removeAllRanges();
        selection.addRange(range);
      }
    }
    const status = document.getElementById('copy-status');
    status.textContent = message;
    label.textContent = copied ? message : (language === 'zh' ? chinese.copy : 'Copy');
    button.toggleAttribute('data-copied', copied);

    clearTimeout(copyTimers.get(button));
    copyTimers.set(button, setTimeout(() => {
      label.textContent = language === 'zh' ? chinese.copy : 'Copy';
      button.removeAttribute('data-copied');
    }, 1600));
  };

  const quickCopy = document.getElementById('quick-copy');
  quickCopy.addEventListener('click', () => window.copyCommand(document.getElementById('quick-command').textContent, quickCopy));

  for (const button of languageButtons) {
    button.addEventListener('click', () => {
      const next = button.dataset.language;
      if (language === next) return;
      setLanguage(next);
      try {
        localStorage.setItem(preferenceKey, next);
      } catch {
        // The language switch still works for this page visit.
      }
    });
  }

  document.addEventListener('click', (event) => {
    const link = event.target.closest('[data-replay-link]');
    if (link) window.selectReplayScenario(link.dataset.replayLink);
  });

  let hasPlaceholder = false;
  for (const link of document.querySelectorAll('[data-cloud]')) {
    const url = SITE_CONFIG[link.dataset.cloud];
    if (url) {
      link.href = url;
      link.removeAttribute('aria-disabled');
    } else {
      hasPlaceholder = true;
    }
  }
  document.getElementById('cloud-note').hidden = !hasPlaceholder;
  document.getElementById('github-stars').textContent = SITE_CONFIG.githubStars;
  setLanguage(preferredLanguage());
})();
