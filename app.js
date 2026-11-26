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
      variants: "C1 patch comparison",
      reasoning: "Reasoning / timing",
      tool: "Tool call",
      text: "UTF-8 / pass",
      breach: "P0 breach",
      proxyEvents: "events",
      proxyDashboard: "Local proxy dashboard",
      proxyForwarding: "Forwards each chunk as it arrives · no buffering",
      proxyEof: "Transport EOF",
      proxyWaiting: "Forwarding the stream. D1–D4 checks run at EOF.",
      proxyIssue: "Redacted Issue Markdown",
      proxyPrivacy: "Request metadata and findings only. Credentials, prompts and tool arguments are omitted.",
      proxyCopy: "Copy",
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
      variants: "C1 修复前后对比",
      reasoning: "推理 / 计时",
      tool: "工具调用",
      text: "UTF-8 / 通过",
      breach: "P0 违约",
      proxyEvents: "个事件",
      proxyDashboard: "本地代理面板",
      proxyForwarding: "收到数据块即转发 · 无缓冲",
      proxyEof: "传输结束（EOF）",
      proxyWaiting: "正在转发数据流。流结束后运行 D1–D4 检查。",
      proxyIssue: "脱敏后的 Issue Markdown",
      proxyPrivacy: "仅包含请求元数据和检测结果，省略凭据、提示词及工具参数。",
      proxyCopy: "复制",
    },
  };

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

  // Both v0.1.1 full-profile captures preserve every C1 frame's relative time
  // and contract fields. The payload view uses aliases for capture identifiers.
  const c1Fragments = ["{", '"', "description", '\":', ' "', "A", " detailed", " service", " configuration", " with", " 4", " endpoint", " URLs", '.\",', ' "', "end"];

  function c1Capture(patched, responseTimes, chatTimes) {
    const [opened, added, ...deltaTimes] = responseTimes;
    const [role, ...toolTimes] = chatTimes;
    const responseEnd = deltaTimes.at(-1);
    const chatEnd = toolTimes.at(-1);
    const suffix = patched ? "patched" : "upstream";
    const responseId = `resp_${suffix}`;
    const itemId = `fc_${suffix}`;
    const callId = `call_${suffix}`;
    const chatId = `chatcmpl_${suffix}`;
    const chatCallId = `call_chat_${suffix}`;
    const args = c1Fragments.join("");
    const status = patched ? "incomplete" : "completed";
    const terminal = `response.${status}`;
    const terminalTone = patched ? "emerald" : "crimson";
    const response = { id: responseId, object: "response", status: "in_progress" };
    const item = { id: itemId, type: "function_call", call_id: callId, name: "write_config", arguments: "", status: "in_progress" };
    const closed = { ...item, arguments: args, status };
    const frame = (ms, tone, event, data) => [ms, 0, tone, event, { type: event, ...data }];
    const chat = (ms, tone, event, delta, reason) => [ms, 1, tone, event, chatChunk(chatId, delta, reason)];

    return [
      frame(opened, "slate", "response.created", { response }),
      frame(opened, "slate", "response.in_progress", { response }),
      frame(added, "violet", "response.output_item.added", { output_index: 0, item }),
      ...c1Fragments.map((delta, index) => frame(deltaTimes[index], "violet", "response.function_call_arguments.delta", {
        delta, item_id: itemId, output_index: 0,
      })),
      ...(patched ? [frame(responseEnd, "violet", "response.function_call_arguments.done", {
        item_id: itemId, output_index: 0, arguments: args,
      })] : []),
      frame(responseEnd, terminalTone, "response.output_item.done", { output_index: 0, item: closed }),
      frame(responseEnd, terminalTone, terminal, { response: {
        ...response, status, ...(patched ? { incomplete_details: { reason: "max_output_tokens" } } : {}),
        output: [closed], usage: { input_tokens: 203, output_tokens: 28, total_tokens: 231, input_tokens_details: { cached_tokens: 200 } },
      } }),
      chat(role, "slate", "delta.role", { role: "assistant", content: null }),
      ...c1Fragments.map((fragment, index) => {
        const call = index === 0
          ? { index: 0, id: chatCallId, type: "function", function: { name: "write_config", arguments: fragment } }
          : { index: 0, function: { arguments: fragment } };
        return chat(toolTimes[index], "violet", "tool_calls[0]", { tool_calls: [call] });
      }),
      chat(chatEnd, "emerald", "finish_reason", {}, "length"),
      chatDone(chatEnd, 1),
    ];
  }

  const beforeC1 = {
    id: "C1",
    title: ["Live Breach", "实测违约"],
    range: 720,
    rate: 0.35,
    tracks: [
      ["/v1/responses", ["P0 breach", "P0 违约"], "crimson", 641 / 720],
      ["/v1/chat/completions", ["Pass · honest truncation", "通过 · 如实报告截断"], "emerald", 609 / 720],
    ],
    frames: c1Capture(false,
      [31, 250, 250, 328, 359, 375, 391, 406, 438, 453, 469, 500, 531, 547, 578, 594, 609, 641],
      [31, 203, 297, 328, 344, 359, 391, 406, 422, 453, 469, 500, 531, 547, 562, 594, 609]),
    inspect: "response.completed",
    verdict: ["P0 BREACH", "P0 违约"],
    finding: [
      'Responses reports status: "completed" with truncated tool JSON and omits response.function_call_arguments.done. Chat Completions reports finish_reason: "length".',
      'Responses 的工具参数 JSON 被截断，缺少 response.function_call_arguments.done，却声称 status: "completed"。Chat Completions 如实报告 finish_reason: "length"。',
    ],
    tone: "crimson",
    sourceLabel: ["Recorded upstream run · llama.cpp #30773", "上游实测记录 · llama.cpp #30773"],
  };

  const afterC1 = {
    ...beforeC1,
    range: 8000,
    rate: 2,
    tracks: [
      ["/v1/responses", ["Pass · honest truncation", "通过 · 如实报告截断"], "emerald", 7344 / 8000],
      ["/v1/chat/completions", ["Pass · honest truncation", "通过 · 如实报告截断"], "emerald", 4890 / 8000],
    ],
    frames: c1Capture(true,
      [344, 1500, 1500, 2547, 2672, 2734, 2813, 2922, 3094, 3375, 3578, 3828, 4203, 5719, 6453, 6563, 6719, 7344],
      [265, 1343, 1547, 1609, 1781, 1937, 2359, 2437, 2562, 2625, 2703, 2968, 3531, 4062, 4468, 4750, 4890]),
    inspect: "response.incomplete",
    verdict: ["GRADE A+ · 8/8", "A+ 评级 · 8/8"],
    finding: [
      'Responses closes arguments.done and the output item before response.incomplete, reporting max_output_tokens and preserving the partial JSON.',
      'Responses 先发送 arguments.done 并结束输出项，再发送 response.incomplete，如实报告 max_output_tokens 并保留截断的 JSON。',
    ],
    tone: "emerald",
    protocolViolations: [],
    sourceLabel: ["Verified local patch run · inferdiff v0.1.1 full profile", "本地补丁实测 · inferdiff v0.1.1 full 配置"],
  };

  const c1Variants = {
    before: { scenario: beforeC1, label: ["Before Fix (Upstream · Grade F)", "修复前（上游 · F 评级）"] },
    after: { scenario: afterC1, label: ["After Patch (Verified · Grade A+ 8/8)", "补丁后（已验证 · A+ 评级 8/8）"] },
  };
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

  function geminiFrames(track, times, finishReason, tone) {
    const parts = [
      [{ text: "Continue the sequence.", thought: true }, "thought", "amber"],
      [{ text: "计数 🚀 1, 2, 3, " }, "text", "emerald"],
      [{ text: "4, 5, 6, " }, "text", "emerald"],
    ];
    return [
      ...parts.map(([part, event, color], index) => [times[index], track, color, event, {
        candidates: [{ index: 0, content: { role: "model", parts: [part] } }],
      }]),
      [times.at(-1), track, tone, "finishReason", {
        candidates: [{ index: 0, finishReason }],
        usageMetadata: { promptTokenCount: 20, candidatesTokenCount: 26, thoughtsTokenCount: 6, totalTokenCount: 52 },
      }],
    ];
  }

  const previewSource = ["v0.2 preview · simulated frames and timing", "v0.2 预览 · 模拟帧与时间"];

  const proxyResponse = { id: "resp_proxy_demo", object: "response", status: "in_progress" };
  const proxyTool = { id: "fc_proxy_demo", type: "function_call", call_id: "call_proxy_demo", name: "lookup_service_status", arguments: "", status: "in_progress" };
  const proxyArgs = ['{"service":"', '[REDACTED]","window":"5'];
  const proxyClosedTool = { ...proxyTool, arguments: proxyArgs.join(""), status: "completed" };
  const proxyTtft = 192;
  const proxyEof = 548;
  const proxyEofEvent = "transport EOF";
  const proxyFinding = "UNCLOSED_TOOL_CALL_SUCCESS";
  const proxyFrame = (ms, tone, event, data) => [ms, 0, tone, event, { type: event, ...data }];
  const proxyFrames = [
    proxyFrame(44, "slate", "response.created", { response: proxyResponse }),
    proxyFrame(108, "violet", "response.output_item.added", { output_index: 0, item: proxyTool }),
    ...proxyArgs.map((delta, index) => proxyFrame(proxyTtft + index * 126, "violet", "response.function_call_arguments.delta", {
      delta, output_index: 0, item_id: proxyTool.id,
    })),
    proxyFrame(428, "violet", "response.output_item.done", { output_index: 0, item: proxyClosedTool }),
    proxyFrame(506, "crimson", "response.completed", { response: { ...proxyResponse, status: "completed", output: [proxyClosedTool] } }),
  ];
  const proxyIssueMarkdown = [
    `## inferdiff proxy incident

### Request and stream

- Request: \`POST /v1/responses\`
- HTTP status: 200
- Dialect: openai-responses
- Finish: completed
- TTFT: ${proxyTtft} ms
- Total time: ${proxyEof} ms
- Frames: ${proxyFrames.length}

### Findings

- **P0 D1** \`${proxyFinding}\` at frame ${proxyFrames.length - 1}. The stream reported success with an incomplete or inconsistent tool call.`,
    `## inferdiff 代理故障

### 请求与数据流

- 请求：\`POST /v1/responses\`
- HTTP 状态：200
- 协议：openai-responses
- 结束状态：completed
- 首 token 耗时：${proxyTtft} ms
- 总耗时：${proxyEof} ms
- SSE 帧数：${proxyFrames.length}

### 检测结果

- **P0 D1** \`${proxyFinding}\`，帧序号 ${proxyFrames.length - 1}。工具调用不完整或前后不一致，流却报告成功。`,
  ];

  const scenarios = [
    beforeC1,
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
      sourceLabel: previewSource,
    },
    {
      id: "C10",
      title: ["Gemini SSE", "Gemini SSE 截断"],
      range: 400,
      rate: 0.25,
      tracks: [
        [":streamGenerateContent", ["P0 breach · false STOP", "P0 违约 · 误报 STOP"], "crimson", 0.85],
        [":streamGenerateContent", ["Pass · honest MAX_TOKENS", "通过 · 如实报告 MAX_TOKENS"], "emerald", 0.9],
      ],
      frames: [
        ...geminiFrames(0, [45, 101, 192, 340], "STOP", "crimson"),
        ...geminiFrames(1, [48, 119, 206, 360], "MAX_TOKENS", "emerald"),
      ],
      inspect: "finishReason",
      verdict: ["P0 BREACH", "P0 违约"],
      finding: [
        'The 32-token probe hits its budget, including thinking tokens. STOP claims a natural stop on truncated output. The comparison correctly reports MAX_TOKENS.',
        '此探针达到 32 个 token 的上限（含思考 token）。截断的输出却被标为自然结束 STOP。对照流如实返回 MAX_TOKENS。',
      ],
      tone: "crimson",
      sourceLabel: previewSource,
    },
    {
      id: "PROXY",
      tabLabel: "D1–D4",
      title: ["Proxy Live Wire-Tap", "代理实时抓流"],
      range: 600,
      rate: 0.35,
      tracks: [["/v1/responses", ["Agent tool call · HTTP 200", "智能体工具调用 · HTTP 200"], "violet", proxyEof / 600]],
      frames: [...proxyFrames, [proxyEof, 0, "slate", proxyEofEvent, { eof_clean: true }]],
      inspect: "response.completed",
      verdict: ["D1 · P0 BREACH", "D1 · P0 违约"],
      finding: [
        'At EOF, D1 flags response.completed: tool arguments were truncated and response.function_call_arguments.done never arrived.',
        '流结束时，D1 标记了 response.completed：工具参数已截断，且一直未收到 response.function_call_arguments.done。',
      ],
      tone: "crimson",
      issue: proxyIssueMarkdown,
      source: "https://github.com/ApacheWang/inferdiff/tree/feat/v02-storage-probes",
      sourceLabel: ["v0.2 branch · simulated capture and timing", "v0.2 分支 · 模拟抓流与时间"],
    },
  ];

  for (const scenario of [...scenarios, afterC1]) {
    scenario.frames.sort(([first], [second]) => first - second);
  }

  const ticks = [0, 1, 2, 3, 4];
  const state = { scenario: scenarios[0], c1Variant: "before", language: "en", elapsed: 0, count: 0, selected: -1, animation: 0 };
  let view;

  function local(pair) {
    return pair[state.language === "zh" ? 1 : 0];
  }

  function formatMs(ms) {
    return Number(ms.toFixed(2)).toLocaleString(state.language === "zh" ? "zh-CN" : "en", { maximumFractionDigits: 2 });
  }

  function buildTimeline() {
    const { id, frames, tracks, range } = state.scenario;
    const words = copy[state.language];
    const ruler = ticks.map((tick) => `<span class="timeline-tick" style="--position:${tick * 25}%">${formatMs(tick * range / 4)}${tick === 4 ? " ms" : ""}</span>`).join("");
    const rails = tracks.map(([label, detail, tone, end], track) => {
      const trackFrames = frames.map((frame, index) => ({ frame, index })).filter(({ frame }) => frame[1] === track);
      const rowTimes = [];
      const points = trackFrames.map(({ frame: [ms, , color, event], index }) => {
        const available = rowTimes.findIndex((last) => ms - last >= range * 0.07);
        const row = available < 0 ? rowTimes.length : available;
        rowTimes[row] = ms;
        const offset = Math.ceil(row / 2) * (row % 2 === 0 ? 1 : -1) * 16;
        const eventLabel = event === proxyEofEvent ? words.proxyEof : event;
        return `<button type="button" class="frame-dot" data-frame="${index}" data-track="${track}" data-event="${event}" data-tone="${color}" data-arrived="false" style="--position:${ms / range * 100}%;--offset:${offset}px" title="${eventLabel} · ${formatMs(ms)} ms" aria-label="${label}, ${eventLabel}, ${formatMs(ms)} ms" aria-pressed="false" disabled></button>`;
      }).join("");
      const height = Math.max(55, 2 * Math.floor(rowTimes.length / 2) * 16 + 20);
      return `<div class="timeline-track" data-tone="${tone}">
        <div class="timeline-label"><code>${label}</code><span>${local(detail)}</span></div>
        <div class="timeline-rail" style="min-height:${height}px"><span class="timeline-fill" style="--track-end:${end * 100}%"></span>${points}</div>
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
    const { frames, range, issue } = state.scenario;
    const words = copy[state.language];
    state.elapsed = elapsed;
    view.timeline.style.setProperty("--elapsed", `${elapsed / range * 100}%`);
    view.progress.textContent = `${formatMs(elapsed)} ms · ${state.count}/${frames.length} ${issue ? words.proxyEvents : words.frames}`;
  }

  function updateFrameView() {
    const words = copy[state.language];
    const { frames, tracks, tone, verdict, finding, protocolViolations, issue } = state.scenario;
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
    view.note.textContent = done ? local(finding) : issue ? words.proxyWaiting : words.listening;
    view.protocol.hidden = !done || !protocolViolations;
    view.protocol.textContent = view.protocol.hidden ? "" : `protocol_violations: ${JSON.stringify(protocolViolations)}`;
    if (issue) {
      view.issue.hidden = !done;
      view.issuePreview.textContent = done ? local(issue) : "";
    }

    if (state.selected < 0) {
      view.meta.textContent = words.waiting;
      view.event.textContent = "SSE";
      view.event.dataset.tone = "slate";
      view.code.textContent = words.empty;
      return;
    }

    const [ms, track, color, event, payload] = frames[state.selected];
    const sequence = state.selected + (issue ? 0 : 1);
    const frameLabel = event === proxyEofEvent ? "" : `#${String(sequence).padStart(2, "0")} · `;
    view.meta.textContent = `${frameLabel}+${formatMs(ms)} ms · ${tracks[track][0]}`;
    view.event.textContent = event === proxyEofEvent ? words.proxyEof : event;
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
    const { id, source, sourceLabel, issue } = state.scenario;

    mount.innerHTML = `
      <div class="replay-tabs" role="group" aria-label="${words.scenarios}">
        ${scenarios.map((scenario) => `<button type="button" class="replay-tab" data-scenario="${scenario.id}" aria-pressed="${scenario.id === id}"><span class="replay-tab-id">${scenario.tabLabel ?? scenario.id}</span><span class="replay-tab-title">${local(scenario.title)}</span></button>`).join("")}
      </div>
      ${id === "C1" ? `<div class="replay-variants" role="group" aria-label="${words.variants}">
        ${Object.entries(c1Variants).map(([variant, { label }]) => `<button type="button" class="replay-variant" data-variant="${variant}" aria-pressed="${state.c1Variant === variant}">${local(label)}</button>`).join("")}
      </div>` : ""}
      ${issue ? `<div class="proxy-dashboard">
        <div><strong>${words.proxyDashboard}</strong><code>/_inferdiff/</code></div>
        <div><code>inferdiff proxy</code><span>${words.proxyForwarding}</span></div>
      </div>` : ""}
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
      <div class="replay-finding"${issue ? ' role="status"' : ""}>
        <span class="finding-badge"></span><div class="finding-copy"><span class="finding-note"></span><code class="finding-protocol" hidden></code></div>
      </div>
      ${issue ? `<section class="proxy-issue" aria-label="${words.proxyIssue}" hidden>
        <div class="inspector-heading"><strong>${words.proxyIssue}</strong>
          <button type="button" class="copy-button proxy-copy"><svg class="icon" aria-hidden="true"><use href="#icon-copy"/></svg><span data-copy-label>${words.proxyCopy}</span></button>
        </div>
        <p>${words.proxyPrivacy}</p>
        <pre tabindex="0"><code class="proxy-issue-preview"></code></pre>
      </section>` : ""}
      <div class="replay-source">${source ? `<a href="${source}" target="_blank" rel="noopener noreferrer">${local(sourceLabel)}</a>` : sourceLabel ? local(sourceLabel) : words.sample}</div>`;

    const find = (selector) => mount.querySelector(selector);
    view = {
      timeline: find(".timeline-chart"), progress: find(".replay-progress"), playLabel: find(".replay-play-label"), playIcon: find(".replay-play-icon"),
      finding: find(".replay-finding"), badge: find(".finding-badge"), note: find(".finding-note"), protocol: find(".finding-protocol"),
      previous: find(".inspector-prev"), next: find(".inspector-next"), meta: find(".inspector-meta"), event: find(".inspector-event"), code: find(".inspector-code code"),
      dots: mount.querySelectorAll(".frame-dot"),
    };
    find(".replay-play").addEventListener("click", play);
    find(".replay-step").addEventListener("click", step);
    find(".replay-reset").addEventListener("click", reset);
    if (issue) {
      view.issue = find(".proxy-issue");
      view.issuePreview = find(".proxy-issue-preview");
      const button = find(".proxy-copy");
      button.addEventListener("click", () => window.copyCommand(view.issuePreview.textContent, button, view.issuePreview));
    }
    view.previous.addEventListener("click", () => inspect(state.selected - 1));
    view.next.addEventListener("click", () => inspect(state.selected + 1));
    view.dots.forEach((dot) => dot.addEventListener("click", () => inspect(Number(dot.dataset.frame))));
    mount.querySelectorAll(".replay-tab").forEach((tab) => tab.addEventListener("click", () => {
      window.selectReplayScenario(tab.dataset.scenario);
      find(`[data-scenario="${tab.dataset.scenario}"]`).focus();
    }));
    mount.querySelectorAll(".replay-variant").forEach((button) => button.addEventListener("click", () => {
      const variant = button.dataset.variant;
      if (variant === state.c1Variant) return;
      state.c1Variant = variant;
      showScenario(c1Variants[variant].scenario);
      find(`[data-variant="${variant}"]`).focus();
    }));

    paint(state.elapsed);
    updateFrameView();
    updatePlayButton();
  }

  window.renderReplay = (language = "en") => {
    state.language = language === "zh" || language.startsWith("zh-") ? "zh" : "en";
    draw();
  };

  function showScenario(scenario) {
    if (scenario === state.scenario) return;
    if (view) stop();
    loadOverview(scenario);
    draw();
  }

  window.selectReplayScenario = (id) => {
    const key = String(id).toUpperCase();
    const scenario = key === "C1" ? c1Variants[state.c1Variant].scenario : scenarios.find((entry) => entry.id === key);
    if (scenario) showScenario(scenario);
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
      id: "C9", level: 'P0', kind: 'preview', replay: true,
      title: ['Anthropic tool truncation', 'Anthropic 工具参数截断'],
      detail: ['The /v1/messages replay compares a relay claiming tool_use with partial tool JSON to an honest max_tokens stop.', '/v1/messages 回放对比两种结束方式：工具 JSON 尚未完整却报告 tool_use，以及如实报告 max_tokens。'],
    },
    {
      id: "C10", level: 'P0', kind: 'preview', replay: true,
      title: ['Gemini SSE truncation', 'Gemini SSE 截断'],
      detail: ['Checks that a capped Gemini stream reports MAX_TOKENS. Also checks token accounting and UTF-8 in visible text and thinking frames.', '检查 Gemini 流达到 token 上限时是否报告 MAX_TOKENS，并校验 token 用量以及正文和思考帧的 UTF-8 完整性。'],
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
      preview: 'v0.2 Preview', planned: 'v0.2 Roadmap', previewScope: 'Simulated replay · v0.1.1 runs C1–C8',
      profile: 'Runs all probes in the selected profile.', audit: 'Needs a recorded target trace.',
      diff: 'Needs baseline and target traces.',
    },
    zh: {
      filters: { all: '全部', C: '金丝雀探针', D: '深度检测' }, filterLabel: '筛选探针',
      copy: '复制', copyLabel: '复制命令', replay: '查看回放', roadmap: '查看路线图',
      preview: 'v0.2 预览', planned: 'v0.2 路线图', previewScope: '模拟回放 · v0.1.1 运行 C1–C8',
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
    if (probe.kind === 'preview' || probe.kind === 'roadmap') {
      meta.append(element('span', 'probe-stage', probe.kind === 'roadmap' ? t.planned : t.preview));
    }
    if (probe.level) {
      const severity = element('span', 'probe-severity', probe.level);
      severity.dataset.level = probe.level.includes('P0') ? 'p0' : probe.level.toLowerCase();
      meta.append(severity);
    }
    item.append(meta, element('h3', null, probe.title[lang]), element('p', null, probe.detail[lang]));

    const actions = element('div', 'probe-actions');
    if (probe.kind === 'preview') {
      actions.append(element('p', 'probe-scope', t.previewScope));
    } else if (probe.kind !== 'roadmap') {
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
      } else {
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
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
    navInspect: '离线诊断',
    navProbes: '探针',
    navCloud: '生态',
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
    liveRun: '上游实测记录',
    checksRan: '已运行检查',
    elapsed: '耗时',
    skips: '跳过',
    streamTitle: '粘贴日志离线诊断',
    streamIntro: '粘贴 SSE 或打开追踪文件，检查端点实际发送的内容。',
    streamPrivacy: '纯本地解析，绝不上传',
    streamPaste: '粘贴 SSE 原始日志',
    streamClear: '清空',
    streamHint: '支持 OpenAI Chat Completions、Responses、Anthropic Messages 和 Gemini SSE。自动遮蔽 API 密钥及 Bearer 令牌。',
    streamDrop: '拖放追踪文件',
    streamChoose: '选择文件',
    streamBreachSample: '载入工具参数截断示例',
    streamHealthySample: '载入正常流示例',
    streamProtocol: '检测到的协议',
    streamFrames: '帧数',
    streamToolJson: '工具调用 JSON',
    streamTerminal: '结束原因 / 状态',
    streamTimeline: '帧级时间轴',
    streamFrameHeading: '帧检查器',
    streamPrev: '上一帧',
    streamNext: '下一帧',
    streamPrevPage: '上一组帧',
    streamNextPage: '下一组帧',
    streamAssembled: '拼接后的文本与工具调用 JSON',
    probesHeading: '探针矩阵',
    probesIntro: '按故障类型查找探针，并复制对应的排查命令。',
    cloudHeading: 'inferdiff 工具生态',
    cloudIntro: '用开源工具检查中转服务、搭建集成或复现流式故障。',
    cliDescription: '零依赖 Python CLI，支持导出 HTML 和 SVG 瀑布图，也可通过 GitHub Action 接入 CI。',
    mcpDescription: '通过 MCP 在 Claude Code、Cursor 或 Codex 中检查端点、对比结果并生成排名。',
    mcpCopy: '复制 MCP 配置',
    jsDescription: '适用于 Node.js 20+ 的零依赖 CLI 与 SDK，支持 ESM 和 TypeScript。',
    extensionDescription: '适用于 Chrome 和 Edge 的 Relay Radar 扩展，支持 Manifest V3。',
    botDescription: '在 Telegram 和飞书中交互式检查中转服务、接收持续监控告警。',
    benchDescription: '可复现的基准测试，验证不同推理引擎和中转服务能否如实报告协议错误。',
    chaosDescription: '可编程的本地模拟服务，用于向 LLM 的 SSE 流注入故障。',
    cloudSoon: '即将推出',
    cloudDescription: '托管版的中转检查与定时监控告警正在开发中。现在即可用 CLI 在本地检查中转服务。',
    cloudQuickstart: 'CLI 快速开始',
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
    window.renderStreamInspector(language);
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

  window.copyCommand = async (text, button, command = button.parentElement?.querySelector('code')) => {
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
    const key = label.dataset.i18n || 'copy';
    const english = translatedText.find(([node]) => node === label)?.[1] || 'Copy';
    const idleLabel = () => language === 'zh' ? chinese[key] : english;
    let message = language === 'zh' ? '无法复制到剪贴板' : 'Could not copy to the clipboard';
    const selection = document.getSelection();
    if (copied) {
      message = language === 'zh' ? '已复制' : 'Copied';
    } else if (command && selection) {
      const range = document.createRange();
      range.selectNodeContents(command);
      selection.removeAllRanges();
      selection.addRange(range);
      message = language === 'zh' ? '已选中文本，请手动复制' : 'Text selected for manual copy';
    }
    const status = document.getElementById('copy-status');
    status.textContent = message;
    label.textContent = copied ? message : idleLabel();
    button.toggleAttribute('data-copied', copied);

    clearTimeout(copyTimers.get(button));
    copyTimers.set(button, setTimeout(() => {
      label.textContent = idleLabel();
      button.removeAttribute('data-copied');
    }, 1600));
  };

  const quickCopy = document.getElementById('quick-copy');
  quickCopy.addEventListener('click', () => window.copyCommand(document.getElementById('quick-command').textContent, quickCopy));
  const mcpCopy = document.getElementById('mcp-copy');
  const mcpConfig = { mcpServers: { 'inferdiff-mcp': { type: 'stdio', command: 'inferdiff-mcp', args: [] } } };
  mcpCopy.addEventListener('click', () => window.copyCommand(JSON.stringify(mcpConfig, null, 2), mcpCopy, null));

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

  setLanguage(preferredLanguage());
})();
