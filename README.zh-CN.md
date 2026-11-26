# inferdiff — 流式大模型接口的「协议验钞机」

**HTTP 返回 `200 OK`，不代表你的流式推理真的没坏。**

`inferdiff` 是一款**零第三方运行时依赖**（纯 Python 3.11+ 标准库）的流式线协议体检与回归取证 CLI，原生支持 `llama-server`、`vLLM`、`SGLang`、`Ollama` 及各类 OpenAI 兼容网关与中转 API。

如果把压测工具比作“测水流快慢的水表”，把评测数据集比作“给作文打分的评委”，`inferdiff` 就是抓获底层静默损坏的 **Wireshark + 协议验钞机**。

[English Documentation (README.md)](README.md)

## 为什么需要 `inferdiff`？（专治四类监控全绿的“假正常”痛点）

| 受害角色 | `HTTP 200 OK` 掩盖下的真实线上故障 | 真实上游故障锚点 | `inferdiff` 如何当场抓获 |
| :--- | :--- | :--- | :--- |
| **Agent 与应用开发者** | 升级引擎或换量化模型后，函数调用 JSON 参数被预算截断一半却谎报 `completed` / `stop`；或思维链吃光预算导致正文全空却正常结束；或跨包切分吐出 `U+FFFD` 乱码，引发 Agent 反复重试。 | [`llama.cpp #30773`](https://github.com/ggml-org/llama.cpp/issues/30773)、[`Ollama #17274`](https://github.com/ollama/ollama/issues/17274)、[`vLLM #68324`](https://github.com/vllm-project/vllm/issues/68324) | `D1`、`D2` 与探针 `C1`、`C2`、`C6` 逐帧校验严格 JSON 语法树、多字节 UTF-8 边界与终态诚实性。 |
| **中转 API 与网关用户** | 不规范中转站或配错的 Nginx / LiteLLM 网关把非流式结果缓冲到最后倾泻成假流式脉冲、剥离空 `choices` 尾帧 `usage`、漏算工具 Schema Token、弄丢首帧 `role`、并行工具索引串台，或跨异构池路由。 | [`LiteLLM #5803`](https://github.com/BerriAI/litellm/issues/5803)、[`LiteLLM #16112`](https://github.com/BerriAI/litellm/issues/16112)、[`LiteLLM #24221`](https://github.com/BerriAI/litellm/issues/24221)、[vLLM Streaming Usage](https://docs.vllm.ai/en/latest/serving/online_serving/derenderer/) | `inferdiff doctor --profile relay` 发送轻量确定性探针（`C1–C8`），输出 `A+` 至 `F` 线协议健康评级。 |
| **AI Infra 与压测工程师** | 升级跑分看似“吞吐暴涨、TTFT 大降”，结果是定长 `ignore_eos` 请求提前短生成（如 `8 / 8000`）、前缀缓存未隔离污染基线，或靠提前发空握手帧刷低首帧延迟。 | [`SGLang #53119`](https://github.com/sgl-project/sglang/pull/53119)、[`SGLang #50443`](https://github.com/sgl-project/sglang/issues/50443)、[vLLM Benchmarking CLI](https://docs.vllm.ai/en/stable/benchmarking/cli/) | 严格剥离“空握手 `ttff_ms`”与“真首字 `ttft_effective_ms`”，自动拦截短生成与假加速（`D3`、`D5`）。 |
| **开源贡献者与发版 CI** | 流式输出每次切块位置不同，肉眼滚 `curl` 难以定位分叉帧；贴大段原始日志提 Issue 又常被维护者视为噪音直接关闭。 | [rusefi LLM Policy](https://github.com/rusefi/rusefi/wiki/LLM-policy) | 双层状态机抹平切块抖动，精准锁定**第一处分歧物理帧**，一键导出内网秒开的单文件 `<80 KiB` HTML 瀑布图与 `<=25` 行脱敏复现单。 |

## 快速上手

```bash
# 本地源码安装（Python 3.11+，零第三方运行时依赖）
pip install -e .

# 1. 无需录制历史包，一键体检本地推理引擎并生成单文件 HTML 瀑布图
inferdiff doctor http://127.0.0.1:8080/v1 --html doctor.html

# 2. 专检第三方 OpenAI 兼容中转站（密钥自动脱敏），生成可截图分享的 HTML 评分卡
OPENAI_API_KEY=sk-... inferdiff doctor https://api.your-relay.example/v1 \
  --model qwen3-32b --profile relay --html relay-report.html

# 3. 无需 GPU，直接用内置 3 组真实故障黄金样本体验 diff、HTML 瀑布图与 25 行工单导出
inferdiff diff \
  examples/case1_responses_truncated_tool/baseline.trace.jsonl \
  examples/case1_responses_truncated_tool/target.trace.jsonl \
  --html case1-waterfall.html

inferdiff export \
  examples/case1_responses_truncated_tool/baseline.trace.jsonl \
  examples/case1_responses_truncated_tool/target.trace.jsonl \
  --format github-issue
```

> **鉴权安全提示**：若未显式传入 `--api-key` 或 `-H "Authorization: ..."`，`inferdiff doctor` 会自动读取环境变量 `OPENAI_API_KEY` 发送至目标端点（生产密钥请务必使用 `https://`）。服务端反射回来的已知密钥会自动在终端、落盘轨迹、JSON 与 HTML 报告中脱敏。

## 健康评级与确定性 CI 退出码

- **Doctor 评级**：`A+`（全部探针通过、零跳过零告警）、`A`（无 P0/P1 问题，含 P2 建议告警或未触发/跳过项）、`B`（1 项 P1 告警）、`C`（2 项及以上 P1 告警）、`F`（检出 P0 静默协议违约或传输/HTTP 硬失败）。

| 退出码 | 枚举常量 | CI 语义 |
| :--- | :--- | :--- |
| `0` | `EXIT_OK` | 门禁通过（`doctor` 评为 `A+` / `A` / `B` / `C` 且未加 `--strict`） |
| `1` | `EXIT_USAGE_OR_IO_ERROR` | CLI 参数错误、轨迹格式损坏、目标不可达或非 200 HTTP 硬失败 |
| `2` | `EXIT_SILENT_PROTOCOL_BREACH` | 检出 P0 静默协议违约（`D1` / `D2` / `D4` 或 `doctor` P0 `FAIL`） |
| `3` | `EXIT_SEMANTIC_REGRESSION` | 检出 P1 回归或失真（`D3` / `D5`、终态漂移、TTFT 退化、`--fail-on any-diff` 或 `doctor --strict` P1 告警） |

## 离线安全与默认脱敏契约

- 单文件 `--html` 瀑布图内置零外链哈希锁定 CSP（`default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-...'; img-src data:;`），自适应帧折叠严格控制在 `80 KiB` 以内，断网跳板机直接双击秒开。
- 默认对外导出（`github-issue` / `json` / `html`）不回显任意 Prompt 正文与原始报文，如需附带原始帧请审阅后显式传入 `--include-body` 或 `--include-wire`。

## License

MIT
