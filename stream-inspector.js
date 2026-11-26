// Offline wire parsing and assembly. The page handles presentation separately.
(() => {
  "use strict";

  const CHAT = "Chat Completions";
  const RESPONSES = "Responses";
  const ANTHROPIC = "Anthropic Messages";
  const GEMINI = "Gemini SSE";
  const TRACE = "inferdiff trace";
  const UNKNOWN = "Unknown";
  const dialects = new Map([
    ["openai-chat", CHAT], ["openai-responses", RESPONSES],
    ["anthropic-messages", ANTHROPIC], ["gemini-sse", GEMINI],
  ]);
  const successes = new Set(["stop", "completed", "end_turn", "stop_sequence", "tool_calls", "tool_use", "function_call"]);
  const truncations = new Set(["length", "max_tokens", "max_output_tokens", "max_completion_tokens", "incomplete", "model_context_window_exceeded", "continuation"]);
  const list = (value) => Array.isArray(value) ? value : [];
  const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const indexOr = (value, fallback = 0) => Number.isSafeInteger(value) && value >= 0 ? value : fallback;
  const stringOr = (value, fallback = "") => typeof value === "string" ? value : fallback;

  function redact(source) {
    let count = 0;
    const text = source.replace(/\bBearer(?:[ \t]|\\t)+[A-Za-z0-9._~+/-]+=*|\bsk-[A-Za-z0-9_-]+/gi, () => {
      count++;
      return "[REDACTED]";
    });
    return { text, count };
  }

  function decode(text) {
    try {
      return {
        ok: true,
        value: JSON.parse(text, (_, value) => {
          if (typeof value === "string") return redact(value).text;
          if (!isObject(value)) return value;
          for (const property of Object.keys(value)) {
            const safe = redact(property).text;
            if (safe === property) continue;
            value[safe] = value[property];
            delete value[property];
          }
          return value;
        }),
      };
    } catch {
      return { ok: false, value: text };
    }
  }

  function wireFrame(event, raw) {
    const done = raw.trim() === "[DONE]";
    const data = done ? { ok: true, value: "[DONE]" } : decode(raw);
    const payload = data.value;
    const named = typeof event === "string" && event && event !== "message" ? event : "";
    return {
      event: named || (done ? "[DONE]" : typeof payload?.type === "string" ? payload.type : ""),
      payload,
      malformed: !data.ok || (!done && !isObject(payload)),
      ms: null,
      tone: "slate",
    };
  }

  function readSse(source) {
    const frames = [];
    let event = "";
    let data = [];

    function flush() {
      if (data.length) frames.push(wireFrame(event, data.join("\n")));
      event = "";
      data = [];
    }

    for (const line of source.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
      if (!line.trim()) {
        flush();
        continue;
      }
      const field = /^(event|data): ?(.*)$/.exec(line);
      if (!field) continue;
      if (field[1] === "event") {
        if (data.length && event) flush();
        event = field[2].trim();
      } else {
        // Some pasted logs omit blank lines between complete data-only frames.
        const value = field[2];
        if (data.length && /^\s*(?:\{|\[)/.test(value) && hasCompleteData(data.join("\n"))) flush();
        data.push(value);
      }
    }
    flush();
    return frames;
  }

  function hasCompleteData(text) {
    if (text.trim() === "[DONE]") return true;
    if (!/[}\]]\s*$/.test(text)) return false;
    try {
      JSON.parse(text);
      return true;
    } catch {
      return false;
    }
  }

  function traceFrame(record) {
    let frame;
    const named = record.sse_event ?? record.event;
    const event = typeof named === "string" ? named : "";
    if (typeof record.raw_wire === "string" && record.raw_wire.trim()) {
      frame = readSse(record.raw_wire)[0] || wireFrame(event, record.raw_wire);
    } else if (record.payload !== undefined || record.data !== undefined) {
      const data = record.payload ?? record.data;
      frame = wireFrame(event, typeof data === "string" ? data : JSON.stringify(data ?? null));
    } else if (record.is_done_sentinel && !event && !record.norm) {
      frame = wireFrame("", "[DONE]");
    } else {
      frame = { event, payload: record.norm ?? record, tone: "slate", normalized: true };
    }
    frame.event ||= event;
    frame.ms = Number.isFinite(record.t_rel_ms) && record.t_rel_ms >= 0 ? record.t_rel_ms : null;
    frame.norm = record.norm;
    frame.malformed ||= Boolean(record.parse_error);
    return frame;
  }

  function readTrace(lines) {
    const frames = [];
    let dialect;
    let summary;
    let issues = 0;
    for (const line of lines) {
      const { value, ok } = decode(line);
      if (!ok || !isObject(value)) {
        issues++;
      } else if (value.type === "header") {
        if (value.schema_version && value.schema_version !== "inferdiff.trace.v1") issues++;
        dialect = value.dialect;
      } else if (value.type === "summary") {
        summary = value;
      } else if (value.type === "frame") {
        frames.push(traceFrame(value));
      } else {
        issues++;
      }
    }
    if (summary?.eof_clean === false) issues++;
    if (Number.isInteger(summary?.total_frames) && summary.total_frames !== frames.length) issues++;
    return { frames, dialect, summary, issues };
  }

  function detect({ event, payload }) {
    if (event.startsWith("response.") || payload?.object === "response") return RESPONSES;
    if (/^(?:message_(?:start|delta|stop)|content_block_(?:start|delta|stop))$/.test(event)) return ANTHROPIC;
    if (Array.isArray(payload?.choices) || payload?.object === "chat.completion.chunk") return CHAT;
    if (Array.isArray(payload?.candidates) || payload?.usageMetadata || payload?.promptFeedback) return GEMINI;
    return UNKNOWN;
  }

  function assembly() {
    const groups = new Map();
    const texts = new Map();
    const tools = new Set();
    const aliases = new Map();
    const pendingGemini = new Set();
    let issues = 0;

    function group(key) {
      if (!groups.has(key)) groups.set(key, { endings: new Map(), terminalFrames: new Set(), success: false });
      return groups.get(key);
    }

    function finish(scope, label, value, frame) {
      if (typeof value !== "string" || !value || ["unknown", "FINISH_REASON_UNSPECIFIED"].includes(value)) return;
      const reported = group(scope);
      reported.endings.set(label, { label, value });
      const successful = successes.has(value.toLowerCase());
      reported.success ||= successful;
      if (frame) {
        reported.terminalFrames.add(frame);
        frame.event ||= label;
        frame.tone = successful ? "emerald" : "amber";
      }
    }

    function text(key, label, value, snapshot = false) {
      if (typeof value !== "string" || !value) return false;
      if (!texts.has(key)) texts.set(key, { label, chunks: [], snapshot: "" });
      const entry = texts.get(key);
      if (snapshot) entry.snapshot = value;
      else entry.chunks.push(value);
      return true;
    }

    function tool(scope, path, id, name, frame, update = {}) {
      id = stringOr(id);
      const idKey = id ? `${scope}:id:${id}` : "";
      const pathKey = `${scope}:path:${path}`;
      const indexed = aliases.get(pathKey);
      let entry = (idKey && aliases.get(idKey)) || (!id || !indexed?.id || id === indexed.id ? indexed : null);
      if (!entry) {
        entry = { scope, path, chunks: [], sawDelta: false, closed: false, id: "", name: "", labelFrame: frame };
        tools.add(entry);
      }
      if (idKey) {
        aliases.set(idKey, entry);
        entry.id = id;
      }
      aliases.set(pathKey, entry);
      if (typeof name === "string" && name) entry.name = name;
      if (typeof update.chunk === "string") {
        entry.sawDelta = true;
        entry.chunks.push(update.chunk);
      }
      for (const field of ["initial", "done", "snapshot", "status", "valid"]) {
        if (update[field] !== undefined) entry[field] = update[field];
      }
      if (update.chunk !== undefined && typeof update.chunk !== "string") entry.valid = false;
      if (update.closed) entry.closed = true;
      if (frame) {
        frame.event ||= "tool call";
        frame.tone = "violet";
      }
    }

    function chat(frame) {
      list(frame.payload?.choices).forEach((choice, choicePosition) => {
        const index = indexOr(choice?.index, choicePosition);
        const scope = `choices[${index}]`;
        const delta = choice?.delta ?? choice?.message;
        if (text(scope, scope, delta?.content)) {
          frame.event ||= "delta.content";
          frame.tone = "emerald";
        }
        list(delta?.tool_calls).forEach((call, position) => {
          const number = indexOr(call?.index, position);
          tool(scope, number, call?.id, call?.function?.name, frame, { chunk: call?.function?.arguments });
        });
        if (delta?.function_call) {
          tool(scope, 0, null, delta.function_call.name, frame, { chunk: delta.function_call.arguments });
        }
        finish(scope, "finish_reason", choice?.finish_reason, frame);
      });
      if (frame.payload?.usage) frame.event ||= "usage";
    }

    function responseItem(item, index, frame, stage) {
      if (item?.type === "function_call") {
        const update = stage === "added" ? { initial: item.arguments } : { snapshot: item.arguments, status: item.status };
        tool("response", index, item.id ?? item.call_id, item.name, frame, update);
      }
      list(item?.content).forEach((part, position) => {
        if (part?.type === "output_text") text(`response:${index}:${position}`, `output[${index}].content[${position}]`, part.text, true);
      });
    }

    function responses(frame) {
      const { event, payload: data } = frame;
      const index = indexOr(data?.output_index);
      const contentIndex = indexOr(data?.content_index);
      if (event === "response.output_text.delta" || event === "response.output_text.done") {
        const snapshot = event.endsWith(".done");
        text(`response:${index}:${contentIndex}`, `output[${index}].content[${contentIndex}]`, snapshot ? data.text : data.delta, snapshot);
        frame.tone = "emerald";
      } else if (event === "response.function_call_arguments.delta" || event === "response.function_call_arguments.done") {
        const update = event.endsWith(".done") ? { done: data.arguments, closed: true } : { chunk: data.delta };
        tool("response", index, data.item_id ?? data.call_id, data.name, frame, update);
      } else if (event === "response.output_item.added" || event === "response.output_item.done") {
        responseItem(data.item, index, frame, event.split(".").at(-1));
      } else if (/^response\.(?:completed|incomplete|failed|cancelled)$/.test(event) ||
        data?.object === "response" && !["in_progress", "queued"].includes(data.status)) {
        const response = data?.response ?? data;
        const eventStatus = event.split(".")[1];
        list(response?.output).forEach((item, position) => responseItem(item, position, frame, "final"));
        if (eventStatus && response?.status && response.status !== eventStatus) {
          finish("response", "event", eventStatus, frame);
          issues++;
        }
        finish("response", "status", response?.status ?? eventStatus, frame);
        finish("response", "incomplete_details.reason", response?.incomplete_details?.reason, frame);
      }
    }

    function anthropic(frame) {
      const { event, payload: data } = frame;
      const index = indexOr(data?.index);
      const label = `content[${index}]`;
      if (event === "content_block_start") {
        const block = data.content_block;
        if (block?.type === "tool_use" || block?.type === "server_tool_use") {
          tool("message", index, block.id, block.name, frame, { initial: JSON.stringify(block.input) });
        }
        if (block?.type === "text" && text(label, label, block.text)) frame.tone = "emerald";
      } else if (event === "content_block_delta") {
        if (data.delta?.type === "input_json_delta") tool("message", index, null, null, frame, { chunk: data.delta.partial_json });
        if (data.delta?.type === "text_delta" && text(label, label, data.delta.text)) frame.tone = "emerald";
        if (data.delta?.type === "thinking_delta") frame.tone = "amber";
      } else if (event === "message_delta" || event === "message_start") {
        finish("message", "stop_reason", data?.delta?.stop_reason ?? data?.message?.stop_reason, frame);
      }
    }

    function gemini(frame, frameIndex) {
      list(frame.payload?.candidates).forEach((candidate, position) => {
        const scope = `candidates[${indexOr(candidate?.index, position)}]`;
        list(candidate?.content?.parts).forEach((part, partIndex) => {
          if (part?.thought) {
            frame.tone = "amber";
            return;
          }
          if (text(scope, scope, part?.text)) {
            frame.event ||= "content.parts.text";
            frame.tone = "emerald";
          }
          const call = part?.functionCall;
          if (!isObject(call)) return;
          frame.event ||= "functionCall";
          const fragments = typeof call.args === "string";
          const path = `${partIndex}:${stringOr(call.name)}`;
          const pending = `${scope}:${path}`;
          if (fragments) {
            pendingGemini.add(pending);
            tool(scope, path, call.id, call.name, frame, { chunk: call.args });
          } else {
            // Ordinary Gemini frames carry whole calls. Preserve separate calls with no ID.
            const identity = pendingGemini.delete(pending) ? path : `${path}:${frameIndex}`;
            tool(scope, identity, call.id, call.name, frame, { snapshot: JSON.stringify(call.args === undefined ? {} : call.args) });
          }
        });
        finish(scope, "finishReason", candidate?.finishReason, frame);
      });
      if (frame.payload?.usageMetadata) frame.event ||= "usageMetadata";
    }

    const byProtocol = new Map([[CHAT, chat], [RESPONSES, responses], [ANTHROPIC, anthropic], [GEMINI, gemini]]);
    const traceScope = (protocol) => protocol === RESPONSES ? "response" : protocol === ANTHROPIC ? "message" :
      protocol === CHAT ? "choices[0]" : protocol === GEMINI ? "candidates[0]" : "trace";

    function normalize(norm, protocol, frame) {
      const scope = traceScope(protocol);
      frame.tone = ({ REASONING: "amber", CONTENT: "emerald", ERROR: "amber" })[stringOr(norm.phase)] || "slate";
      text(scope, scope, norm.text_delta, norm.is_cumulative_text);
      list(norm.tool_deltas).forEach((call, position) => {
        const update = { chunk: call?.arguments_delta || call?.args_delta, closed: call?.is_args_done };
        if (call?.is_args_done) update.done = call.arguments_snapshot ?? undefined;
        else if (call?.is_item_done_snapshot !== false) update.snapshot = call?.arguments_snapshot ?? undefined;
        tool(scope, indexOr(call?.index, position), call?.item_id ?? call?.id, call?.name, frame, update);
      });
      finish(scope, "finish_reason", norm.finish_reason, frame);
      finish(scope, "status", norm.terminal_status, frame);
      if (norm.protocol_error || norm.inband_error) issues++;
    }

    function addFrame(frame, protocol, index) {
      if (frame.malformed) {
        frame.tone = "amber";
        issues++;
      } else if (frame.payload?.error || frame.event === "error" || frame.event === "response.error") {
        frame.tone = "amber";
        issues++;
      } else if (frame.norm && (frame.normalized || !byProtocol.has(protocol))) {
        normalize(frame.norm, protocol, frame);
      } else {
        byProtocol.get(protocol)?.(frame, index);
      }
      frame.event ||= "data";
    }

    function useSummary(summary, protocol, last) {
      const assembled = summary?.assembled;
      if (!isObject(assembled)) return;
      const scope = traceScope(protocol);
      issues += list(assembled.protocol_violations).length;
      if (!texts.size) text(scope, scope, assembled.content_text, true);
      if (!tools.size) {
        list(assembled.tool_calls).forEach((call, position) => {
          tool(scope, indexOr(call?.index, position), call?.item_id ?? call?.id, call?.name, last, {
            chunk: call?.saw_args_delta ? call.raw_arguments : undefined, closed: call?.saw_args_done_event,
            snapshot: call?.raw_arguments, valid: call?.json_valid,
          });
        });
      }
      const endings = group(scope).endings;
      if (![...endings.keys()].some((label) => /reason/i.test(label))) finish(scope, "finish_reason", assembled.finish_reason, last);
      if (!endings.has("status")) finish(scope, "status", assembled.terminal_status, last);
    }

    function report(protocol) {
      let missingArgumentsDone = 0;
      let breach = false;
      let invalid = false;
      const assembledTools = [...tools].map((entry) => {
        const { scope, name, path, labelFrame } = entry;
        const streamed = entry.chunks.join("");
        const raw = entry.sawDelta && streamed ? streamed : entry.done ?? entry.snapshot ?? entry.initial ?? "";
        const parsed = decode(raw);
        const valid = typeof raw === "string" && entry.valid !== false && parsed.ok &&
          (!(protocol === ANTHROPIC || protocol === GEMINI) || isObject(parsed.value));
        const missing = protocol === RESPONSES && entry.sawDelta && !entry.closed;
        const mismatch = (first, second) => first !== undefined && second !== undefined && first !== second &&
          ![first, second].some((value) => stringOr(value).includes("[REDACTED]"));
        const inconsistent = protocol === RESPONSES &&
          ((streamed && (mismatch(streamed, entry.done) || mismatch(streamed, entry.snapshot))) || mismatch(entry.done, entry.snapshot));
        if (missing) missingArgumentsDone++;
        if (inconsistent) issues++;
        invalid ||= !valid;
        const reported = group(scope);
        if ((reported.success || entry.status === "completed") && (!valid || missing || inconsistent)) {
          breach = true;
          reported.terminalFrames.forEach((frame) => { frame.tone = "crimson"; });
          if (!reported.terminalFrames.size && labelFrame) labelFrame.tone = "crimson";
        }
        const display = typeof raw === "string" ? raw : JSON.stringify(raw);
        return { label: name || `#${path}`, text: redact(display).text, valid };
      });
      const endings = [...groups.values()].flatMap((entry) => [...entry.endings.values()]);
      const values = endings.map(({ value }) => value.toLowerCase());
      const verdict = breach ? "breach" : issues ? "warning" : values.some((value) => truncations.has(value)) ? "incomplete" :
        values.some((value) => !successes.has(value)) || invalid ? "warning" : values.length ? "pass" : "unknown";
      return {
        texts: [...texts.values()].map(({ label, chunks, snapshot }) => ({ label, text: redact(chunks.join("") || snapshot).text })),
        tools: assembledTools,
        endings,
        verdict,
        issueCount: issues,
        missingArgumentsDone,
      };
    }

    return { addFrame, useSummary, report };
  }

  function inspect(source, { trace = false } = {}) {
    const safe = redact(source).text;
    const firstLine = safe.trimStart().split(/\r\n|\r|\n/, 1)[0];
    const first = firstLine.startsWith("{") ? decode(firstLine).value : null;
    const isTrace = trace || first?.schema_version === "inferdiff.trace.v1" || first?.type === "header" ||
      (first?.type === "frame" && ("raw_wire" in first || "t_rel_ms" in first));
    const parsed = isTrace ? readTrace(safe.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/).filter((line) => line.trim())) :
      { frames: readSse(safe), issues: 0 };
    const inferred = parsed.frames.find((frame) => detect(frame) !== UNKNOWN);
    const protocol = dialects.get(parsed.dialect) ?? (inferred ? detect(inferred) : UNKNOWN);
    const assembled = assembly();
    parsed.frames.forEach((frame, index) => assembled.addFrame(frame, protocol, index));
    if (isTrace) assembled.useSummary(parsed.summary, protocol, parsed.frames.at(-1));
    const result = assembled.report(protocol);
    result.issueCount += parsed.issues;
    if (parsed.issues && result.verdict !== "breach") result.verdict = "warning";
    return {
      protocol: isTrace ? TRACE : protocol,
      frames: parsed.frames.map(({ event, payload, ms, tone }) => ({ event, payload, ms, tone })),
      ...result,
    };
  }

  globalThis.InferdiffStream = Object.freeze({ redact, inspect });
})();
