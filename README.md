# llm-vuln-agent

一个基于 LLM Agent 的漏洞自动发现与验证系统，面向**授权实验环境、自建靶场和 CTF**。

系统以目标资产（IP / 端口 / 协议 / 服务 / 产品 / 版本 / Banner）为输入，通过 LLM Agent、RAG 和 Tool Calling 将传统人工漏洞分析流程自动化，形成：

```
资产探测 → 资产分析 → 漏洞检索 → 漏洞匹配 → 验证决策 → 工具调用 → 结果分析 → 漏洞判定 → 结构化报告
```

## 设计原则

- **LLM 负责理解、分析与决策**（不是扫描器，不执行任意命令）
- **RAG 负责提供漏洞知识**（CVE 数据清洗、结构化、向量化、混合检索）
- **Tool Calling 负责调用安全工具**（统一接口 + 白名单 + 参数校验 + 超时）
- **Verification Engine 负责实际验证**（独立于 LLM，无破坏性）
- **Result Parser 负责解析客观结果**，最终结论**可追溯证据**

## 关键工程决策

规范要求的技术栈（Milvus / MySQL / MongoDB / FastAPI / Nmap / LLM API）都提供了清晰接口，但**核心默认实现零第三方依赖**，保证 Demo 与测试可离线运行：

| 组件 | 默认实现（离线、无依赖） | 可替换为 |
| --- | --- | --- |
| LLM | `MockLLM`（确定性规则规划器） | `OpenAICompatibleLLM`（`openai` 包 + API key） |
| Embedding | `HashingEmbedder`（特征哈希，确定性） | `OpenAIEmbedder` |
| Vector DB | `InMemoryVectorStore`（余弦相似度） | Milvus（`pymilvus`） |
| 持久化 | SQLite（stdlib `sqlite3`） | MySQL / MongoDB |
| 端口扫描 | 纯 Python `socket` 连接扫描 | Nmap（`python-nmap`） |
| API | CLI（`main.py`） | FastAPI |

Agent 部分是一个显式 `while` 循环，未依赖大型 Agent 框架，符合“渐进式开发”要求。

## 目录结构

```
llm-vuln-agent/
├── agent/          # Agent 循环、状态、记忆、提示词、LLM 客户端、规划器
├── rag/            # 文档加载、Embedding、向量库、混合检索
├── tools/          # 统一 Tool 接口、白名单边界、各安全工具
├── vulnerability/  # CVE 数据、版本比较、漏洞匹配、验证引擎
├── models/         # Asset / Vulnerability / VerificationResult / Report
├── pipeline/       # 组件装配、工作流、报告、持久化
├── config/         # config.yaml + 加载器（环境变量覆盖）
├── data/vulnerabilities/  # 示例 CVE 数据
├── tests/          # 单元 + 集成测试
├── main.py         # CLI 入口
└── requirements.txt
```

## 快速开始

```bash
cd llm-vuln-agent
python -m pytest          # 运行全部测试（离线，无需 API key）
```

分析一个已知资产（离线，确定性 Mock LLM）：

```bash
python main.py --ip 127.0.0.1 --port 8080 --product "Apache Tomcat" --version 9.0.50
```

先探测（受白名单约束）再分析：

```bash
python main.py --ip 127.0.0.1 --scan --ports 80 8080
```

输出 JSON / Markdown 报告：

```bash
python main.py --ip 127.0.0.1 --port 8080 --product "Apache Tomcat" --version 9.0.50 \
    --output-json out.json --output-md out.md
```

## 使用真实 LLM

1. `pip install openai`
2. 设置环境变量：`export LLM_API_KEY=sk-...`（Windows: `set LLM_API_KEY=sk-...`）
3. 切换 provider 并指定模型与地址：

```bash
# 以 DeepSeek 为例（OpenAI 兼容）
python main.py ... --provider openai --model deepseek-v4-flash --base-url https://api.deepseek.com
```

或修改 `config/config.yaml`（已内置 DeepSeek 预设注释）：`llm.provider: "openai"`、`llm.model: "deepseek-v4-flash"`、`llm.base_url: "https://api.deepseek.com"`。

> 注意：DeepSeek 旧模型名 `deepseek-chat` / `deepseek-reasoner` 已于 2026-07-24 停用，请使用 `deepseek-v4-flash`（快/便宜）或 `deepseek-v4-pro`（强推理）。

## 安全边界

- **Target Allowlist**：`config.yaml` 的 `targets.allowlist` 默认仅含 `127.0.0.1` / `::1` / `localhost`，任何网络工具触碰白名单外目标会被拒绝（deny-by-default）。
- **禁止任意命令执行**：LLM 只能调用预定义的 6 个 Tool，每个 Tool 有 `name` / `description` / `input_schema` / `output_schema` / 安全边界。
- **无破坏性验证**：`verification.non_destructive_only: true` 阻止破坏性验证器。
- **超时与执行日志**：所有网络操作有超时，工具调用全量记录。
- **API Key 走环境变量**：配置与代码分离，密钥不落盘。

本项目仅用于自建实验环境 / CTF / 明确授权资产，**未实现**针对任意公网目标的自动化攻击能力。

## 六个 Tool

| Tool | 作用 |
| --- | --- |
| `port_scan` | 受白名单约束的 TCP 端口扫描（纯 Python） |
| `service_detect` | 由 Banner / 端口默认值识别服务与产品 |
| `version_detect` | 从 Banner 提取版本 |
| `vulnerability_search` | RAG 混合检索候选 CVE |
| `vulnerability_verify` | 调用 Verification Engine 验证单个 CVE |
| `result_parser` | 将原始输出解析为结构化结果 |

## 验证引擎

内置**无破坏性**验证器：

- `mock` — 离线确定性验证器（Demo / 测试）；无显式 `mock_result` 时按版本区间给出**明确标注为模拟**的结论。
- `banner_check` — 读取服务 Banner 作为证据。
- `http_path_check` — GET 指定路径并检查状态码 / 正文标记。
- `http_header_check` — 检查响应头标记。

将示例数据的 `verification_id` 改为上述真实验证器即可对接自建靶场做真实验证。

## 结果可信度

最终结论仅有三种状态，且信息不足时宁可 `UNCERTAIN`，不做强行猜测：

```
CONFIRMED / NOT_VULNERABLE / UNCERTAIN
```

每条结论都附带 `confidence`、`evidence`、`verification_method`，保证可追溯。

## 测试覆盖（对应规范 Phase 8）

1. 明确存在漏洞 → `CONFIRMED`
2. 明确不存在漏洞 → `NOT_VULNERABLE`
3. 版本不匹配 → `no_match`
4. 信息不足 → `UNCERTAIN`
5. 工具调用失败 / 参数校验 / 越权拒绝
6. RAG 检索为空 → `UNCERTAIN`
7. Agent 多轮 Tool Calling
8. 验证结果为 `UNCERTAIN`
