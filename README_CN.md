<div align="center">
    <img src="assets/DOG_1.png" alt="Skylos - 面向 Python、TypeScript 和 Go 的死代码检测、安全扫描和 AI 防御" width="300">
    <h1>Skylos：开源 Python SAST、死代码检测和 AI 代码安全</h1>
    <h3>查找 Python、TypeScript 和 Go 中的无用代码、硬编码密钥、可利用流程和 AI 生成的安全回退。支持本地运行或在 CI/CD 中把关拉取请求。</h3>
</div>

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![CI/CD Ready](https://img.shields.io/badge/CI%2FCD-30s%20Setup-brightgreen?style=flat&logo=github-actions&logoColor=white)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
[![PyPI version](https://img.shields.io/pypi/v/skylos)](https://pypi.org/project/skylos/)
[![Downloads/month](https://img.shields.io/pypi/dm/skylos)](https://pypistats.org/packages/skylos)
[![Downloads total](https://static.pepy.tech/badge/skylos)](https://pypistats.org/packages/skylos)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
[![GitHub stars](https://img.shields.io/github/stars/duriantaco/skylos)](https://github.com/duriantaco/skylos/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/duriantaco/skylos)](https://github.com/duriantaco/skylos/network)
![Skylos](https://img.shields.io/badge/Skylos-PR%20Guard-2f80ed?style=flat&logo=github&logoColor=white)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/Ftn9t9tErf)

📖 **[官网](https://skylos.dev)** · **[文档](https://docs.skylos.dev)** · **[博客](https://skylos.dev/blog)** · **[GitHub Action](https://github.com/duriantaco/skylos/blob/main/action.yml)** · **[VS Code 扩展](https://marketplace.visualstudio.com/items?itemName=oha.skylos-vscode-extension)** · **[MCP 服务器](https://github.com/duriantaco/skylos/tree/main/skylos_mcp)**

[English](README.md) | **中文**

---

# 什么是 Skylos？

Skylos 是一款面向 Python、TypeScript 和 Go 的开源静态分析工具和 PR 门控系统。它帮助团队在代码合并到 `main` 之前，检测死代码、硬编码密钥、可利用流程和 AI 生成的安全回退。

如果你使用 Vulture 检测死代码、Bandit 进行安全检查、或者 Semgrep/CodeQL 做 CI 执行，Skylos 将这些工作流整合在一起，并提供框架感知的死代码检测和差异感知的 AI 辅助重构回归检测。

核心用例很简单：在本地运行、添加到 CI、并基于真实发现通过 GitHub 注释和审查评论对拉取请求进行门控。高级功能如 AI 防御、修复 Agent、VS Code 扩展、MCP 和云端上传均可用，但你无需使用它们即可从 Skylos 获得价值。

### 最适合

- 需要比 Vulture 更少误报的 Python 团队
- 使用 Cursor、Copilot、Claude Code 或其他 AI 编码助手的代码仓库
- 带有 GitHub 注释和审查评论的 CI/CD 拉取请求门控
- 需要 OWASP LLM Top 10 检查的 Python LLM 应用

### 可用形式

- CLI 用于本地扫描和 CI/CD 工作流
- GitHub Action 用于拉取请求门控和注释
- VS Code 扩展用于编辑器内发现和 AI 辅助修复
- MCP 服务器用于 AI Agent 和编码助手

### 从这里开始

| 目标 | 命令 | 获得的结果 |
|:---|:---|:---|
| **扫描代码仓库** | `skylos . -a` | 死代码、风险流程、密钥和代码质量发现 |
| **门控拉取请求** | `skylos cicd init` | 带质量门控和内联注释的 GitHub Actions 工作流 |
| **审计 LLM 应用** | `skylos defend .` | 针对 Python LLM 集成的可选 AI 防御检查 |

### 团队采用 Skylos 的原因

1. **在真实框架上提供更好的死代码信号：** Skylos 理解 FastAPI、Django、Flask、pytest、Next.js、React 等框架，因此动态代码产生更少噪音。
2. **差异感知的 AI 回归检测：** Skylos 能捕获在 AI 辅助重构过程中消失的认证装饰器、CSRF、速率限制、验证、日志记录和其他控制。
3. **一个工作流替代三个工具：** 死代码、安全扫描和 PR 门控在同一 CLI 和 CI 流程中。
4. **默认本地优先：** 你可以在本地运行扫描，需要时再添加可选的 AI 或云端功能。
5. **自解释输出：** 每个表格都打印图例说明每列和数字的含义 — 无需额外文档。

### 为什么选择 Skylos 而非 Vulture 检测 Python 死代码？

| | Skylos | Vulture |
|:---|:---|:---|
| **召回率** | **98.1%** (51/52) | 84.6% (44/52) |
| **误报** | **220** | 644 |
| **框架感知**（FastAPI、Django、pytest） | 是 | 否 |
| **安全扫描**（密钥、SQLi、SSRF） | 是 | 否 |
| **AI 驱动分析** | 是 | 否 |
| **CI/CD 质量门控** | 是 | 否 |
| **TypeScript + Go 支持** | 是 | 否 |

> 在 9 个热门 Python 代码仓库（合计 350k+ stars）+ TypeScript（[consola](https://github.com/unjs/consola)）上进行基准测试。每个发现均人工验证。[完整案例研究 →](#skylos-vs-vulture-基准测试)

### 🚀 **Skylos 新手？从 CI/CD 集成开始**

```bash
# 30 秒生成 GitHub Actions 工作流
skylos cicd init

# 提交并推送以激活
git add .github/workflows/skylos.yml && git push
```

**你将获得：**
- 每个 PR 自动检测死代码
- 安全漏洞扫描（SQLi、密钥、危险模式）
- 在关键问题上使构建失败的质量门控
- 带 file:line 链接的内联 PR 审查评论
- 在 "Files Changed" 标签页可见的 GitHub 注释

**无需配置** — 开箱即用，提供合理默认值。参见 [CI/CD 章节](#cicd) 了解自定义选项。

---

## 目录

- [什么是 Skylos？](#什么是-skylos)
- [快速开始](#快速开始)
- [技术债务热点](#技术债务热点)
- [核心功能](#核心功能)
- [安装](#安装)
- [Skylos vs Vulture 基准测试](#skylos-vs-vulture-基准测试)
- [使用 Skylos 的项目](#使用-skylos-的项目)
- [工作原理](#工作原理)
- [高级工作流](#高级工作流)
- [CI/CD](#cicd)
- [MCP 服务器](#mcp-服务器)
- [基线追踪](#基线追踪)
- [门控](#门控)
- [VS Code 扩展](#vs-code-扩展)
- [集成与生态系统](#集成与生态系统)
- [审计与精度](#审计与精度)
- [覆盖率集成](#覆盖率集成)
- [过滤](#过滤)
- [CLI 选项](#cli-选项)
- [常见问题](#常见问题)
- [限制与故障排除](#限制与故障排除)
- [贡献](#贡献)
- [路线图](#路线图)
- [许可证](#许可证)
- [联系方式](#联系方式)

## 快速开始

如果你正在评估 Skylos，请从下面的核心工作流开始。LLM 和 AI 防御命令是可选的。

### 核心工作流

| 目标 | 命令 | 结果 |
| :--- | :--- | :--- |
| **首次扫描** | `skylos .` | 带置信度评分的死代码发现 |
| **审计风险和质量** | `skylos . -a` | 死代码、风险流程、密钥、质量和 SCA 发现 |
| **更高置信度的死代码** | `skylos . --trace` | 将静态发现与运行时活动交叉验证 |
| **仅审查变更行** | `skylos . --diff origin/main` | 将发现聚焦于活跃开发而非历史债务 |
| **本地门控** | `skylos --gate` | 代码离开你的机器前在发现项上失败 |
| **设置 CI/CD** | `skylos cicd init` | 30 秒生成 GitHub Actions 工作流 |
| **CI 中门控** | `skylos cicd gate --input results.json` | 当问题超过阈值时使构建失败 |

### 可选工作流

| 目标 | 命令 | 结果 |
| :--- | :--- | :--- |
| **检测未使用的 Pytest Fixtures** | `skylos . --pytest-fixtures` | 在测试 + conftest 中查找未使用的 `@pytest.fixture` |
| **AI 驱动分析** | `skylos agent scan . --model gpt-4.1` | 静态优先分析加上 judge-all LLM 死代码验证 |
| **死代码验证** | `skylos agent verify . --model gpt-4.1` | 仅死代码的二次验证：静态发现由 LLM 审查 |
| **安全审计** | `skylos agent scan . --security` | 深度 LLM 安全审查，支持交互式文件选择 |
| **自动修复** | `skylos agent remediate . --auto-pr` | 扫描、修复、测试并开启 PR — 端到端 |
| **代码清理** | `skylos agent remediate . --standards` | LLM 引导的代码质量清理，对照编码规范 |
| **PR 审查** | `skylos agent scan . --changed` | 仅分析 git 变更文件 |
| **PR 审查（JSON）** | `skylos agent scan . --changed --format json -o results.json` | 带代码级修复建议的 LLM 审查 |
| **本地 LLM** | `skylos agent scan . --base-url http://localhost:11434/v1 --model codellama` | 使用 Ollama/LM Studio（无需 API 密钥） |
| **PR 审查（CI）** | `skylos cicd review -i results.json` | 在 PR 上发布内联评论 |
| **AI 防御：发现** | `skylos discover .` | 映射代码库中所有 LLM 集成 |
| **AI 防御：防御** | `skylos defend .` | 检查 LLM 集成是否缺少防护措施 |
| **AI 防御：CI 门控** | `skylos defend . --fail-on critical --min-score 70` | 阻止存在严重 AI 防御缺口的 PR |
| **白名单** | `skylos whitelist 'handle_*'` | 抑制已知的动态模式 |

## 技术债务热点

使用 `skylos debt <path>` 对结构性债务热点进行排名，不会把所有东西压缩成单一的紧急度数字。

- `score` 是项目级别的结构性债务评分。
- `priority` 是用于排序修复候选项的热点分类评分。
- `--changed` 将可见的热点列表限制为变更文件，但保持结构性债务评分锚定到整个项目。

```bash
# 完整项目债务扫描
skylos debt .

# 仅查看变更的热点，不扭曲项目评分
skylos debt . --changed

# 将当前项目与保存的债务基线进行比较
skylos debt . --baseline

# 保存代码仓库级别的债务基线
skylos debt . --save-baseline
```

债务策略文件如 `skylos-debt.yaml` 从扫描目标向上发现，显式 CLI 标志如 `--top` 会覆盖策略默认值。

### 演示
[![Skylos 演示](https://img.youtube.com/vi/BjMdSP2zZl8/0.jpg)](https://www.youtube.com/watch?v=BjMdSP2zZl8)

备份（GitHub）：https://github.com/duriantaco/skylos/discussions/82

## 核心功能

核心产品是死代码检测、安全扫描和 PR 门控。以下 AI 相关功能是在基线工作流之上的可选层。

### 安全扫描（SAST）
* **污点分析：** 追踪从 API 端点到数据库的不受信任输入，防止 SQL 注入和 XSS。
* **密钥检测：** 在提交之前搜索硬编码的 API 密钥（AWS、Stripe、OpenAI）和私有凭证。
* **漏洞检查：** 标记危险模式如 `eval()`、不安全的 `pickle` 和弱加密。

### AI 生成代码防护

Skylos 还可以标记常见的 AI 生成代码错误。每个发现包含 `vibe_category` 和 `ai_likelihood`（high/medium/low）元数据，你可以按需单独过滤。

* **幻觉调用检测：** 捕获对安全函数（`sanitize_input`、`validate_token`、`check_permission` 等）的调用，这些函数从未定义或导入 — AI 经常虚构这些。`hallucinated_reference, high`
* **幻觉装饰器检测：** 捕获安全装饰器（`@require_auth`、`@rate_limit`、`@authenticate` 等），这些装饰器从未定义或导入。`hallucinated_reference, high`
* **未完成生成：** 检测仅包含 `pass`、`...` 或 `raise NotImplementedError` 的函数 — AI 生成的桩代码在生产环境中静默无操作。`incomplete_generation, medium`
* **未定义配置：** 标记引用从未在项目中定义的特性标志的 `os.getenv("ENABLE_X")`。`ghost_config, medium`
* **过时 Mock 检测：** 捕获 `mock.patch("app.email.send_email")`，其中 `send_email` 已不存在 — AI 重命名了函数但测试仍指向旧名称。`stale_reference, medium`
* **安全 TODO 扫描器：** 标记 AI 留下的 `# TODO: add auth` 占位符，且无人完成。
* **禁用的安全控制：** 检测 `verify=False`、`@csrf_exempt`、`DEBUG=True` 和 `ALLOWED_HOSTS=["*"]`。
* **凭证与随机性检查：** 捕获硬编码密码和用于安全敏感值（如令牌和 OTP）的 `random.choice()`。

### 提示注入和内容扫描

这些检查在 `--danger` 下运行，查找代码仓库内容中的提示注入模式或混淆指令。

* **多文件提示注入扫描器：** 扫描 Python、Markdown、YAML、JSON、TOML 和 `.env` 文件中的隐藏指令载荷 — 指令覆盖（"ignore previous instructions"）、角色劫持（"you are now"）、AI 定向抑制（"do not flag"、"skip security"）、数据窃取提示和 AI 定向短语。
* **文本规范化引擎：** NFKC 正规化、空白折叠和混淆替换在模式匹配前中和混淆。
* **零宽和不可见 Unicode：** 检测零宽空格、连接符、BOM 和双向覆盖（U+200B–U+202E），这些可向人工审查者隐藏载荷。
* **Base64 混淆检测：** 自动解码 base64 编码字符串并重新扫描注入内容。
* **同形字 / 混合脚本检测：** 标记与拉丁文本混合的西里尔和希腊字符（如 `password` 中的西里尔字母 'а'），这些可绕过目视审查。
* **位置感知严重性：** README 文件、HTML 注释和 YAML prompt 字段中的发现会提升严重性。测试文件自动跳过。

### 高级：LLM 应用的 AI 防御

面向 AI 应用安全的静态分析，映射 Python 代码库中的每个 LLM 调用并检查缺失的防护措施。**仅限 Python**（TypeScript/Go 支持已规划）。

```bash
# 发现所有 LLM 集成
skylos discover .

# 检查防御措施并获取评分报告
skylos defend .

# CI 门控：在严重缺口上失败，要求 70% 防御评分
skylos defend . --fail-on critical --min-score 70

# JSON 输出用于仪表盘和流水线
skylos defend . --json -o defense-report.json

# 按 OWASP LLM Top 10 类别过滤
skylos defend . --owasp LLM01,LLM04
```

**13 项防御和运维检查：**

| 检查 | 严重性 | OWASP | 检测内容 |
|:---|:---|:---|:---|
| `no-dangerous-sink` | Critical | LLM02 | LLM 输出流向 eval/exec/subprocess |
| `untrusted-input-to-prompt` | Critical | LLM01 | 原始用户输入在 prompt 中未经处理 |
| `tool-scope` | Critical | LLM04 | Agent 工具含有危险系统调用 |
| `tool-schema-present` | Critical | LLM04 | Agent 工具缺少类型化 schema |
| `output-validation` | High | LLM02 | LLM 输出使用时未经结构化验证 |
| `prompt-delimiter` | High | LLM01 | prompt 中的用户输入缺少分隔符 |
| `rag-context-isolation` | High | LLM01 | RAG 上下文注入时未隔离 |
| `output-pii-filter` | High | LLM06 | 面向用户的 LLM 输出无 PII 过滤 |
| `model-pinned` | Medium | LLM03 | 模型版本未固定（使用浮动别名） |
| `input-length-limit` | Low | LLM01 | LLM 调用前无输入长度检查 |
| `logging-present` | Medium | Ops | LLM 调用周围无日志记录 |
| `cost-controls` | Medium | Ops | LLM 调用未设置 max_tokens |
| `rate-limiting` | Medium | Ops | LLM 端点无速率限制 |

**防御评分和运维评分分开追踪** — 添加日志不会膨胀你的安全评分。

**通过 `skylos-defend.yaml` 自定义策略：**
```yaml
rules:
  model-pinned:
    severity: critical    # 升级严重性
  input-length-limit:
    enabled: false        # 禁用检查
gate:
  min_score: 70
  fail_on: high
```

支持 OpenAI、Anthropic、Google Gemini、Cohere、Mistral、Ollama、Together AI、Groq、Fireworks、Replicate、LiteLLM、LangChain、LlamaIndex、CrewAI 和 AutoGen。

### 死代码检测与清理
* **查找未使用代码：** 识别不可达函数、孤立类和未使用导入，带置信度评分。
* **智能追踪：** 区分真正的死代码和动态框架（Flask/Django 路由、Pytest fixtures）。
* **安全修剪：** 使用 LibCST 安全移除死代码而不破坏语法。

### 高级：Agent、审查和修复
* **上下文感知审计：** 结合静态分析速度和 LLM 推理来验证发现并过滤噪音。
* **修复工作流：** `skylos agent remediate` 可扫描、生成修复、运行测试，并可选择开启 PR。
* **本地模型支持：** 支持 Ollama 和其他 OpenAI 兼容的本地端点，代码可留在你的机器上。

### CI/CD 和 PR 门控

* **30 秒工作流设置：** `skylos cicd init` 生成带合理默认值的 GitHub Actions 工作流。
* **差异感知执行：** 仅门控变更的行，在严重性阈值上失败，通过基线保持历史债务可管理。
* **PR 原生反馈：** GitHub 注释、内联审查评论和可选仪表盘上传，将发现放在团队已有的工作区。

### 安全清理和工作流控制

* **CST 安全移除：** 使用 LibCST 移除选定的导入或函数（处理多行导入、别名、装饰器、async 等）。
* **逻辑感知：** 深度集成 Python 框架（Django、Flask、FastAPI）和 TypeScript（Tree-sitter）以识别活跃路由和依赖。
* **细粒度过滤：** 跳过标记了 `# pragma: no skylos`、`# pragma: no cover` 或 `# noqa` 的行。

### 运维治理与运行时

* **覆盖率集成：** 自动检测 `.skylos-trace` 文件，用运行时数据验证死代码。
* **质量门控：** 通过 `pyproject.toml` 强制执行复杂度、嵌套和安全风险的硬阈值，阻止不合规的 PR。
* **交互式 CLI：** 通过基于 `inquirer` 的终端界面手动验证和移除/注释掉发现项。
* **安全审计模式：** 利用独立推理循环识别安全漏洞。

### Pytest 卫生

* **未使用 Fixture 检测：** 在 `test_*.py` 和 `conftest.py` 中查找未使用的 `@pytest.fixture` 定义。
* **跨文件解析：** 追踪跨模块使用的 fixtures，不仅限于同一文件内。

### 多语言支持

| 语言 | 解析器 | 死代码 | 安全 | 质量 |
|----------|--------|-----------|----------|---------|
| Python | AST | ✅ | ✅ | ✅ |
| TypeScript/TSX | Tree-sitter | ✅ | ✅ | ✅ |
| Java | Tree-sitter | ✅ | ✅ | ✅ |
| Go | 独立二进制文件 | ✅ | - | - |

语言通过文件扩展名自动检测。混合语言代码仓库开箱即用。不需要 Node.js 或 JDK — 所有解析器通过 Tree-sitter 内置。

#### TypeScript 规则

| 规则 | ID | 检测内容 |
|------|-----|-----------------|
| **死代码** | | |
| 函数 | - | 未使用的函数、箭头函数和重载 |
| 类 | - | 未使用的类、接口、枚举和类型别名 |
| 导入 | - | 未使用的命名导入、默认导入和命名空间导入 |
| 方法 | - | 未使用的方法（生命周期方法除外） |
| **安全** | | |
| eval() | SKY-D201 | `eval()` 使用 |
| 动态执行 | SKY-D202 | `exec()`、`new Function()`、字符串参数的 `setTimeout` |
| XSS | SKY-D226 | `innerHTML`、`outerHTML`、`document.write()`、`dangerouslySetInnerHTML` |
| SQL 注入 | SKY-D211 | SQL 查询中的模板字面量 / f-string |
| 命令注入 | SKY-D212 | `child_process.exec()`、`os.system()` |
| SSRF | SKY-D216 | 变量 URL 的 `fetch()`/`axios` |
| 开放重定向 | SKY-D230 | 变量参数的 `res.redirect()` |
| 弱哈希 | SKY-D207/D208 | MD5 / SHA1 使用 |
| 原型污染 | SKY-D510 | `__proto__` 访问 |
| 动态 require | SKY-D245 | 变量参数的 `require()` |
| JWT 绕过 | SKY-D246 | 无验证的 `jwt.decode()` |
| CORS 通配符 | SKY-D247 | `cors({ origin: '*' })` |
| 内部 URL | SKY-D248 | 硬编码的 `localhost`/`127.0.0.1` URL |
| 不安全随机 | SKY-D250 | 安全敏感操作中使用 `Math.random()` |
| 敏感日志 | SKY-D251 | 密码/令牌传递给 `console.log()` |
| 不安全 cookie | SKY-D252 | 缺少 `httpOnly`/`secure` 标志 |
| 计时攻击 | SKY-D253 | 密钥的 `===`/`==` 比较 |
| 存储令牌 | SKY-D270 | `localStorage`/`sessionStorage` 中的敏感数据 |
| 错误泄露 | SKY-D271 | HTTP 响应中发送 `error.stack`/`.sql` |
| 密钥 | SKY-S101 | 硬编码 API 密钥 + 高熵字符串 |
| **质量** | | |
| 复杂度 | SKY-Q301 | 圈复杂度超过阈值 |
| 嵌套深度 | SKY-Q302 | 嵌套层级过多 |
| 函数长度 | SKY-C304 | 函数超过行数限制 |
| 参数过多 | SKY-C303 | 函数参数过多 |
| 重复条件 | SKY-Q305 | if-else-if 链中的相同条件 |
| 循环中的 await | SKY-Q402 | for/while 循环内的 `await` |
| 不可达代码 | SKY-UC002 | return/throw/break/continue 之后的代码 |

**框架感知：** Next.js 约定导出（`page.tsx`、`layout.tsx`、`route.ts`、`middleware.ts`）、配置导出（`getServerSideProps`、`generateMetadata`、`revalidate`）、React 模式（`memo`、`forwardRef`）和导出的自定义 hooks（`use*`）自动排除在死代码报告之外。

TypeScript 死代码检测追踪：回调、类型注解、泛型、装饰器、继承（`extends`）、对象简写、展开、重导出和 `typeof` 引用。在活跃代码上以 95% 召回率和 0 误报进行基准测试。

## 安装

### 基本安装

```bash
## 从 pypi 安装
pip install skylos

## 包含 LLM 驱动功能（agent verify、agent remediate 等）
pip install skylos[llm]

## 包含 Rust 加速分析（最高 63 倍加速）
pip install skylos[fast]

## 两者都包含
pip install skylos[llm,fast]

## 或从源码安装
git clone https://github.com/duriantaco/skylos.git
cd skylos

pip install .
```

> **`skylos[fast]`** 安装可选的 Rust 后端，加速克隆检测（63 倍）、文件发现（5 倍）、耦合分析和循环检测。结果相同，只是更快。纯 Python 不安装也能正常工作 — Rust 模块在运行时自动检测。
>
> **`skylos[llm]`** 安装 `litellm` 用于 LLM 驱动功能（`skylos agent verify`、`skylos agent remediate`、`--llm`）。核心静态分析无需此依赖。

### 🎯 下一步？

安装后，我们建议：

1. **设置 CI/CD（30 秒）：**
   ```bash
   skylos cicd init
   git add .github/workflows/skylos.yml && git push
   ```
   这将在每个 PR 上自动扫描死代码和安全问题。

2. **运行你的首次扫描：**
   ```bash
   skylos .                              # 仅死代码
   skylos . --danger --secrets           # 包含安全检查
   ```

3. **将扫描聚焦于活跃工作：**
   ```bash
   skylos . --diff origin/main
   ```

4. **仅在需要时尝试高级工作流：**
   ```bash
   skylos agent review . --model gpt-4.1
   skylos defend .
   ```

[在快速开始表格中查看所有命令](#快速开始)

---

## Skylos vs Vulture 基准测试

我们在 **GitHub 上 9 个最热门的 Python 代码仓库**上对 Skylos 和 Vulture 进行了基准测试 — 合计 350k+ stars，涵盖 HTTP 客户端、Web 框架、CLI 工具、数据验证、终端 UI 和进度条。每一个发现都经过**人工验证**。没有自动标记，没有挑选结果。

### 为什么选择这 9 个代码仓库？

我们特意选择了以不同方式对死代码检测进行压力测试的项目：

| 代码仓库 | Stars | 测试内容 |
|:---|---:|:---|
| [psf/requests](https://github.com/psf/requests) | 53k | `__init__.py` 重导出、Sphinx conf、pytest 类 |
| [pallets/click](https://github.com/pallets/click) | 17k | IO 协议方法（`io.RawIOBase` 子类）、nonlocal 闭包 |
| [encode/starlette](https://github.com/encode/starlette) | 10k | ASGI 接口参数、多态分发、公共 API 方法 |
| [Textualize/rich](https://github.com/Textualize/rich) | 51k | `__rich_console__` 协议、通过 `f_locals` 的哨兵变量、元类 |
| [encode/httpx](https://github.com/encode/httpx) | 14k | 传输/认证协议方法、零死代码（纯误报测试） |
| [pallets/flask](https://github.com/pallets/flask) | 69k | Jinja2 模板全局变量、Werkzeug 协议方法、扩展钩子 |
| [pydantic/pydantic](https://github.com/pydantic/pydantic) | 23k | Mypy 插件钩子、hypothesis `@resolves`、`__getattr__` 配置 |
| [fastapi/fastapi](https://github.com/fastapi/fastapi) | 82k | 100+ OpenAPI 规范模型字段、Starlette 基类覆盖 |
| [tqdm/tqdm](https://github.com/tqdm/tqdm) | 30k | Keras/Dask 回调、Rich 列渲染、pandas 猴子补丁 |

没有因为结果不利而排除任何代码仓库。我们包含了 Vulture 胜过 Skylos 的代码仓库（click、starlette、tqdm）。

### 结果

| 代码仓库 | 死代码项 | Skylos TP | Skylos FP | Vulture TP | Vulture FP |
|:---|---:|---:|---:|---:|---:|
| psf/requests | 6 | 6 | 35 | 6 | 58 |
| pallets/click | 7 | 7 | 8 | 6 | 6 |
| encode/starlette | 1 | 1 | 4 | 1 | 2 |
| Textualize/rich | 13 | 13 | 14 | 10 | 8 |
| encode/httpx | 0 | 0 | 6 | 0 | 59 |
| pallets/flask | 7 | 7 | 12 | 6 | 260 |
| pydantic/pydantic | 11 | 11 | 93 | 10 | 112 |
| fastapi/fastapi | 6 | 6 | 30 | 4 | 102 |
| tqdm/tqdm | 1 | 0 | 18 | 1 | 37 |
| **总计** | **52** | **51** | **220** | **44** | **644** |

| 指标 | Skylos | Vulture |
|:---|:---|:---|
| **召回率** | **98.1%** (51/52) | 84.6% (44/52) |
| **误报** | **220** | 644 |
| **发现的死代码项** | **51** | 44 |

Skylos 比 Vulture **多发现 7 个死代码项**，同时**误报少 3 倍**。

### 为什么 Skylos 产生更少的误报

Vulture 使用扁平名称匹配 — 如果裸名 `X` 作为字符串或标识符出现在任何地方，所有名为 `X` 的定义都被认为是已使用的。这对简单情况有效，但在重度使用框架的代码库上会淹没在噪音中：

- **Flask**（260 Vulture FP）：Vulture 标记每个 Jinja2 模板全局变量、Werkzeug 协议方法和 Flask 扩展钩子。Skylos 能识别 Flask/Werkzeug 模式。
- **Pydantic**（112 Vulture FP）：Vulture 标记所有配置类注解、`TYPE_CHECKING` 导入和 mypy 插件钩子。Skylos 理解 Pydantic 模型字段和 `__getattr__` 动态访问。
- **FastAPI**（102 Vulture FP）：Vulture 标记 100+ OpenAPI 规范模型字段（Pydantic `BaseModel` 属性如 `maxLength`、`exclusiveMinimum`）。Skylos 将这些识别为 schema 定义。
- **httpx**（59 Vulture FP）：Vulture 标记每个传输和认证协议方法。Skylos 抑制接口实现。

### Skylos 仍然不足的地方（如实说明）

- **click**（8 vs 6 FP）：`io.RawIOBase` 子类上的 IO 协议方法（`readable`、`readinto`）— 由 Python IO 栈调用，而非直接调用点。
- **starlette**（4 vs 2 FP）：跨文件的实例方法调用（`obj.method()`）未解析回类定义。
- **tqdm**（18 vs 37 FP，0 vs 1 TP）：Skylos 遗漏了 `__init__.py` 中的 1 个死函数，因为它将 `__init__.py` 定义作为潜在重导出进行抑制。

> *复现任何基准测试：`cd real_life_examples/{repo} && python3 ../benchmark_{repo}.py`*
>
> *完整方法论和每个代码仓库的详细分析在 [skylos-demo](https://github.com/duriantaco/skylos-demo) 代码仓库中。*

### Skylos vs Knip（TypeScript）

我们还在一个真实的 TypeScript 库上对 Skylos 和 [Knip](https://knip.dev) 进行了基准测试：

| | [unjs/consola](https://github.com/unjs/consola)（7k stars，21 个文件，~2,050 LOC） |
|:---|:---|
| **死代码项** | 4（整个孤立的 `src/utils/format.ts` 模块） |

| 指标 | Skylos | Knip |
|:---|:---|:---|
| **召回率** | **100%** (4/4) | **100%** (4/4) |
| **精确率** | **36.4%** | 7.5% |
| **F1 分数** | **53.3%** | 14.0% |
| **速度** | **6.83s** | 11.08s |

两个工具都找到了所有死代码。Skylos 的**精确率约为 5 倍** — Knip 错误地将包入口点标记为死文件（其 `package.json` exports 指向 `dist/` 而非 `src/`），并将公共 API 重导出报告为未使用。

> *复现：`cd real_life_examples/consola && python3 ../benchmark_consola.py`*

---

## 使用 Skylos 的项目

如果你在公开代码仓库中使用 Skylos，请开一个 issue 并将其添加到这里。此列表基于自我提交，因此在更多团队公开加入之前会保持较小。

[![Analyzed with Skylos](https://img.shields.io/badge/Analyzed%20with-Skylos-2f80ed?style=flat&logo=python&logoColor=white)](https://github.com/duriantaco/skylos)

| 项目 | 描述 |
|---------|-------------|
| [Skylos](https://github.com/duriantaco/skylos) | 在自身上使用 Skylos 进行死代码、安全和 CI 门控 |
| *你的项目* | [添加你的项目](https://github.com/duriantaco/skylos/issues/new?title=Add%20my%20project%20to%20showcase&body=Project:%20%0AURL:%20%0ADescription:%20) |

[添加你的项目 →](https://github.com/duriantaco/skylos/issues/new?title=Add%20my%20project%20to%20showcase&body=Project:%20%0AURL:%20%0ADescription:%20)

---

## 工作原理

Skylos 构建整个代码库的引用图 — 谁定义了什么、谁调用了什么、跨所有文件。

```
解析所有文件 -> 构建定义映射 -> 追踪引用 -> 查找孤立项（零引用 = 死代码）
```

### 高精度与置信度评分
静态分析经常难以应对 Python 的动态特性（如 `getattr`、`pytest.fixture`）。Skylos 通过以下方式最小化误报：

1. **置信度评分：** 对发现进行分级（High/Medium/Low），让你只看到重要的内容。
2. **混合验证：** 使用 LLM 推理在报告前对静态发现进行二次检查。
3. **运行时追踪：** 可选的 `--trace` 模式根据实际运行时执行验证"死"代码。

| 置信度 | 含义 | 操作 |
|------------|---------|--------|
| 100 | 确定未使用 | 可安全删除 |
| 60 | 可能未使用（默认阈值） | 先审查 |
| 40 | 或许未使用（框架辅助函数） | 可能是误报 |
| 20 | 可能未使用（装饰器/路由） | 几乎肯定在使用 |
| 0 | 显示所有 | 调试模式 |

```bash
skylos . -c 60  # 默认：仅高置信度发现
skylos . -c 30  # 包含框架辅助函数
skylos . -c 0   # 所有内容
```

### 框架检测

当 Skylos 检测到 Flask、Django、FastAPI、Next.js 或 React 导入时，会自动调整评分：

| 模式 | 处理方式 |
|---------|----------|
| `@app.route`、`@router.get` | 入口点 → 标记为已使用 |
| `app.add_url_rule(...)`、`app.add_api_route(...)`、`app.add_route(...)`、`app.register_listener(...)`、`app.register_middleware(...)` | 命令式路由或生命周期注册 → 标记为已使用 |
| `@pytest.fixture` | 视为 pytest 入口点，但如果从未引用可报告为未使用 |
| `@pytest.hookimpl`、`@hookimpl` | 插件钩子实现 → 标记为已使用 |
| `@celery.task` | 入口点 → 标记为已使用 |
| `getattr(mod, "func")` | 追踪动态引用 |
| `getattr(mod, f"handle_{x}")` | 追踪模式 `handle_*` |
| Next.js `page.tsx`、`layout.tsx`、`route.ts` | 默认/命名导出 → 标记为已使用 |
| Next.js `getServerSideProps`、`generateMetadata` | 配置导出 → 标记为已使用 |
| `React.memo()`、`forwardRef()` | 包装组件 → 标记为已使用 |
| 导出的 `use*` hooks | 自定义 hooks → 标记为已使用 |

### 测试文件排除

测试以看起来像死代码的奇怪方式调用代码。默认情况下，Skylos 排除：

| 检测方式 | 示例 |
|-------------|----------|
| 路径 | `/tests/`、`/test/`、`*_test.py` |
| 导入 | `pytest`、`unittest`、`mock` |
| 装饰器 | `@pytest.fixture`、`@patch` |

```bash
# 这些自动排除（置信度设为 0）
/project/tests/test_user.py
/project/test/helper.py

# 这些正常分析
/project/user.py
/project/test_data.py  # 不以 _test.py 结尾
```

想包含测试文件？使用 `--include-folder tests`。

### 设计理念

> 当存在歧义时，我们宁可遗漏死代码，也不愿将活跃代码错误标记为死代码。

框架端点通过外部方式调用（HTTP、信号）。名称解析处理别名。当情况不明确时，我们倾向于保守处理。

## 未使用的 Pytest Fixtures

Skylos 可以检测已定义但从未使用的 pytest fixtures。

```bash
skylos . --pytest-fixtures
```

这包括 conftest.py 中的 fixtures，因为 conftest.py 是存储共享测试 fixtures 的标准位置。


## 高级工作流

以下命令为可选项。当你希望在核心扫描器和 CI 门控之上进行 LLM 辅助审查、修复或 AI 防御时使用。

Skylos 采用**混合架构**，将静态分析与 LLM 推理相结合：

### 为何选择混合架构？

| 方案 | 召回率 | 精确率 | 逻辑漏洞 |
|----------|--------|-----------|------------|
| 仅静态分析 | 低 | 高 | ❌ |
| 仅 LLM | 高 | 中 | ✅ |
| **混合** | **最高** | **高** | ✅ |

研究表明，LLM 能发现静态分析遗漏的漏洞，而静态分析可验证 LLM 的建议。然而，若要求 LLM 仅凭原始源代码生成死代码发现，则容易产生误报。

对于死代码检测，Skylos 现采用更严格的约定：
- 静态分析生成候选列表
- 围绕每个候选项收集代码仓库事实和图谱证据
- `skylos agent scan` 和 `skylos agent verify` 在 `judge_all` 模式下，将几乎所有 `references == 0` 的候选项发送给 LLM 进行判断
- 确定性抑制器仍然存在，但在 `judge_all` 模式下作为证据附加，而非静默决定结果

如需使用更经济的确定性优先路径而非默认的 judge-all 审查，请使用 `--verification-mode production`。

### Agent 命令

| 命令 | 描述 |
|---------|-------------|
| `skylos agent scan PATH` | 完整混合流水线，包含修复建议和 judge-all 死代码验证 |
| `skylos agent scan PATH --no-fixes` | 相同流水线，跳过修复建议（更快） |
| `skylos agent scan PATH --changed` | 仅分析 git 变更文件 |
| `skylos agent scan PATH --security` | 仅限安全的 LLM 审计，支持交互式文件选择 |
| `skylos agent verify PATH` | 对静态分析结果进行仅死代码验证 |
| `skylos agent verify PATH --fix --pr` | 验证、生成删除补丁、创建分支并提交 |
| `skylos agent remediate PATH` | 端到端：扫描、修复、测试并创建 PR |
| `skylos agent remediate PATH --standards` | LLM 引导的代码清理，内置规范（或 `--standards custom.md`） |
| `skylos agent triage suggest` | 显示从已学模式中自动筛选的候选项 |
| `skylos agent triage dismiss ID` | 从队列中忽略某个发现 |

### 提供商配置

Skylos 支持云端和本地 LLM 提供商：

```bash
# 云端 - OpenAI（从模型名称自动检测）
skylos agent scan . --model gpt-4.1

# 云端 - Anthropic（从模型名称自动检测）
skylos agent scan . --model claude-sonnet-4-20250514

# 本地 - Ollama
skylos agent scan . \
  --provider openai \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:7b

# 更经济的死代码验证路径
skylos agent verify . \
  --model claude-sonnet-4-20250514 \
  --verification-mode production
```

**注意**：你可以使用 `--model` 标志指定所需模型。我们支持 Gemini、Groq、Anthropic、ChatGPT 和 Mistral。

### 密钥与配置

Skylos 可从以下方式获取 API 密钥：**(1) `skylos key`**，或 **(2) 环境变量**。

#### 推荐方式（交互式）
```bash
skylos key
# 打开菜单：
# - 列出密钥
# - 添加密钥（openai / anthropic / google / groq / mistral / ...）
# - 删除密钥
```

### 环境变量

设置默认值以避免重复输入标志：

```bash
# API 密钥
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# 默认使用本地 Ollama
export SKYLOS_LLM_PROVIDER=openai
export SKYLOS_LLM_BASE_URL=http://localhost:11434/v1
```

### LLM PR 审查

`skylos agent scan --changed` 分析 git 变更文件，运行静态分析，然后使用 LLM 为每个发现（安全、质量和死代码）生成代码级修复建议。

```bash
# 运行 LLM 审查并输出 JSON
skylos agent scan . --changed --model claude-sonnet-4-20250514 --format json -o llm-results.json

# 配合 cicd review 在 PR 上发布内联评论
skylos cicd review --input results.json --llm-input llm-results.json
```

混合流水线分阶段运行：
1. **静态分析** — 发现安全、质量和死代码问题
2. **死代码验证** — LLM 使用图谱证据、代码仓库事实和上下文对静态死代码候选项进行判断
3. **附加 LLM 分析** — 扫描静态分析可能遗漏的逻辑/安全问题
4. **代码修复生成** — 针对每个已报告的发现，生成问题代码片段和修正版本

每条 PR 评论均显示确切的漏洞行和可直接替换的修复方案。

### LLM 分析可检测的内容

| 类别 | 示例 |
|----------|----------|
| **幻觉** | 调用不存在的函数 |
| **逻辑漏洞** | 差一错误、错误条件、缺少边界情况 |
| **业务逻辑** | 认证绕过、访问控制缺陷 |
| **上下文问题** | 需要理解意图才能发现的问题 |

### 本地 LLM 部署（Ollama）

```bash
# 安装 Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 拉取代码模型
ollama pull qwen2.5-coder:7b

# 配合 Skylos 使用
skylos agent scan ./src \
  --provider openai \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:7b
```

### 修复 Agent

修复 Agent 自动化完整的修复生命周期。它扫描你的项目，对发现项进行优先级排序，通过 LLM 生成修复方案，通过运行测试套件验证每个修复，并可选择开启 PR。

```bash
# 预览将要修复的内容（安全，不做任何更改）
skylos agent remediate . --dry-run

# 修复最多 5 个严重/高危问题，并通过测试验证
skylos agent remediate . --max-fixes 5 --severity high

# 全自动：修复、测试、创建 PR
skylos agent remediate . --auto-pr --model gpt-4.1

# 使用自定义测试命令
skylos agent remediate . --test-cmd "pytest test/ -x"
```

**安全防护措施：**
- 默认为预演模式 — 使用 `--dry-run` 预览而不修改文件
- 导致测试失败的修复将自动回滚
- 低置信度修复将被跳过
- 应用修复后，Skylos 重新扫描以确认发现项已消除
- `--auto-pr` 始终在新分支上操作，绝不触碰 main 分支
- `--max-fixes` 防止失控更改（默认值为 10）

### 推荐模型

| 模型 | 提供商 | 适用场景 |
|-------|----------|----------|
| `gpt-4.1` | OpenAI | 最佳准确率 |
| `claude-sonnet-4-20250514` | Anthropic | 最佳推理能力 |
| `qwen2.5-coder:7b` | Ollama | 快速本地分析 |
| `codellama:13b` | Ollama | 更高本地准确率 |

# CI/CD

在 CI 流水线中运行 Skylos，支持质量门控、GitHub 注释和 PR 审查评论。

## 快速开始（30 秒）

```bash
# 自动生成 GitHub Actions 工作流
skylos cicd init

# 提交并激活
git add .github/workflows/skylos.yml && git push
```

完成！你的下一个 PR 将包含：
- 死代码检测
- 安全扫描（SQLi、SSRF、密钥）
- 质量检查
- 带可点击 file:line 链接的内联 PR 评论
- 在关键问题上使构建失败的质量门控

**想要在 PR 上获得 AI 驱动的代码修复？**

```bash
skylos cicd init --llm --model claude-sonnet-4-20250514
```

这将添加一个 LLM 步骤，生成代码级修复建议 — 在你的 PR 上内联显示漏洞代码和修正版本。

**可选 GitHub Secrets**

对于默认的 `skylos cicd init` 工作流，你不需要任何 Skylos 特定的 secrets。仅当你在 GitHub Actions 中启用相应功能时才需添加（**Settings > Secrets and variables > Actions**）：

| Secret | 使用时机 | 描述 |
|--------|-------------|-------------|
| `ANTHROPIC_API_KEY` | 使用 Claude 模型时 | 你的 Anthropic API 密钥 |
| `OPENAI_API_KEY` | 使用 GPT 模型时 | 你的 OpenAI API 密钥 |
| `SKYLOS_API_KEY` | 使用 Skylos Cloud 功能时 | 从 [skylos.dev](https://skylos.dev) 获取 |
| `SKYLOS_TOKEN` | 使用 `--upload` 时 | 从 [skylos.dev/dashboard/settings](https://skylos.dev/dashboard/settings) 获取上传令牌 |

`GH_TOKEN` 由 GitHub Actions 自动提供 — PR 评论无需任何设置。

## 命令参考

### 核心分析

| 命令 | 描述 |
|---------|-------------|
| `skylos <path>` | 死代码、安全和质量分析 |
| `skylos debt <path>` | 基于基线感知优先级的技术债务热点分析 |
| `skylos discover <path>` | 映射代码库中的 LLM/AI 集成 |
| `skylos defend <path>` | 检查 LLM 集成是否缺少防御措施 |
| `skylos city <path>` | 将代码库可视化为 Code City 拓扑图 |

### AI Agent

| 命令 | 描述 |
|---------|-------------|
| `skylos agent scan <path>` | 静态 + LLM 混合分析 |
| `skylos agent verify <path>` | LLM 验证死代码（100% 准确率） |
| `skylos agent remediate <path>` | 自动修复问题并创建 PR |
| `skylos agent watch <path>` | 持续代码仓库监控，可选分类模式学习 |
| `skylos agent pre-commit <path>` | 分析已暂存文件（git hook） |
| `skylos agent triage` | 管理发现项分类（忽略/暂缓） |

### CI/CD

| 命令 | 描述 |
|---------|-------------|
| `skylos cicd init` | 生成 GitHub Actions 工作流 |
| `skylos cicd gate` | 质量门控（CI 退出码） |
| `skylos cicd annotate` | 发送 GitHub Actions 注释 |
| `skylos cicd review` | 发布内联 PR 审查评论 |

### 账户

| 命令 | 描述 |
|---------|-------------|
| `skylos login` | 连接到 Skylos Cloud |
| `skylos whoami` | 显示已连接的账户信息 |
| `skylos key` | 管理 API 密钥 |
| `skylos credits` | 查看积分余额 |

### 工具

| 命令 | 描述 |
|---------|-------------|
| `skylos init` | 在 pyproject.toml 中初始化配置 |
| `skylos baseline <path>` | 将当前发现项保存为基线 |
| `skylos whitelist <pattern>` | 管理白名单符号 |
| `skylos badge` | 获取 README 徽章 markdown |
| `skylos rules` | 安装/管理社区规则包 |
| `skylos doctor` | 检查安装健康状态 |
| `skylos clean` | 删除缓存和状态文件 |
| `skylos tour` | 功能引导游览 |
| `skylos commands` | 列出所有命令（扁平视图） |

运行 `skylos <command> --help` 获取任意命令的详细用法。

## 命令（详细说明）

### `skylos cicd init`

生成可直接使用的 GitHub Actions 工作流。

```bash
skylos cicd init
skylos cicd init --triggers pull_request schedule
skylos cicd init --analysis security quality
skylos cicd init --python-version 3.11
skylos cicd init --llm --model gpt-4.1
skylos cicd init --upload                        # 包含 --upload 步骤 + SKYLOS_TOKEN 环境变量
skylos cicd init --upload --llm --model claude-sonnet-4-20250514  # 上传 + LLM
skylos cicd init --defend                        # 添加 AI 防御检查步骤
skylos cicd init --defend --upload               # 防御 + 将结果上传至云端
skylos cicd init --no-baseline
skylos cicd init -o .github/workflows/security.yml
```

### `skylos cicd gate`

根据质量门控检查发现项。退出码为 `0`（通过）或 `1`（失败）。使用与 `skylos . --gate` 相同的 `check_gate()`。

```bash
skylos . --danger --quality --secrets --json > results.json 2>/dev/null
skylos cicd gate --input results.json
skylos cicd gate --input results.json --strict
skylos cicd gate --input results.json --summary
```

你也可以直接使用主 CLI：

```bash
skylos . --gate --summary
```

在 `pyproject.toml` 中配置阈值：

```toml
[tool.skylos.gate]
fail_on_critical = true
max_critical = 0
max_high = 5
max_security = 10
max_quality = 10
```

### `skylos cicd annotate`

发送 GitHub Actions 注释（`::error`、`::warning`、`::notice`）。使用与 `skylos . --github` 相同的 `_emit_github_annotations()`，支持排序和 50 条注释上限。

```bash
skylos cicd annotate --input results.json
skylos cicd annotate --input results.json --severity high
skylos cicd annotate --input results.json --max 30

skylos . --github
```

### `skylos cicd review`

通过 `gh` CLI 发布内联 PR 审查评论和摘要。仅对 PR 中变更的行进行评论。

```bash
skylos cicd review --input results.json
skylos cicd review --input results.json --pr 20
skylos cicd review --input results.json --summary-only
skylos cicd review --input results.json --max-comments 10
skylos cicd review --input results.json --diff-base origin/develop

# 配合 LLM 生成的代码修复（漏洞代码 → 修复代码）
skylos cicd review --input results.json --llm-input llm-results.json
```

提供 `--llm-input` 时，每条内联评论将显示问题代码和修正版本：

```
🔴 CRITICAL SKY-D211

Possible SQL injection: tainted or string-built query.

Why: User input is concatenated directly into the SQL query string.

Vulnerable code:
  results = conn.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'").fetchall()

Fixed code:
  results = conn.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{q}%",)).fetchall()
```

在 GitHub Actions 中，PR 编号和代码仓库会自动检测。需要 `GH_TOKEN`。

## 整体架构

门控和注释逻辑位于 Skylos 核心模块中（`gatekeeper.py` 和 `cli.py`）。`cicd` 命令是便捷封装，从 JSON 文件读取并调用相同函数：

| `skylos cicd` 命令 | 调用 |
|-----------------------|-------|
| `gate` | `gatekeeper.run_gate_interaction(summary=True)` |
| `annotate` | `cli._emit_github_annotations(max_annotations=50)` |
| `review` | 新增 — `cicd/review.py`（通过 `gh api` 发布 PR 评论） |
| `init` | 新增 — `cicd/workflow.py`（YAML 生成） |

## 使用技巧

- **一次分析，多次使用** — 使用 `--json > results.json 2>/dev/null`，然后将 `--input results.json` 传递给每个子命令。
- **基线** — 运行 `skylos baseline .` 快照现有发现项，然后在 CI 中使用 `--baseline` 仅标记新问题。
- **本地测试** — 所有命令均可在本地运行。`gate` 和 `annotate` 输出到 stdout。`review` 需要 `gh` CLI。

## MCP 服务器

mcp-name: io.github.duriantaco/skylos

Skylos 将其分析能力作为 MCP（Model Context Protocol）服务器对外暴露，允许 Claude Desktop 等 AI 助手直接扫描你的代码库。

### 配置

```bash
pip install skylos
```

添加到你的 Claude Desktop 配置文件（Linux 上为 `~/.config/claude/claude_desktop_config.json`，macOS 上为 `~/Library/Application Support/Claude/claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "skylos": {
      "command": "python",
      "args": ["-m", "skylos_mcp.server"]
    }
  }
}
```

### 可用工具

| 工具 | 描述 |
|------|-------------|
| `analyze` | 死代码检测（未使用的函数、导入、类、变量） |
| `security_scan` | 安全漏洞扫描（等同于 `--danger`） |
| `quality_check` | 代码质量和复杂度分析（等同于 `--quality`） |
| `secrets_scan` | 硬编码密钥检测（等同于 `--secrets`） |
| `remediate` | 端到端：扫描、生成 LLM 修复方案、通过测试验证 |
| `generate_fix` | 为已确认的死代码生成删除补丁 |
| `verify_dead_code` | LLM 验证死代码发现项（减少误报） |
| `learn_triage` | 记录分类决策以供模式学习 |
| `get_triage_suggestions` | 从已学模式中获取自动分类候选项 |

### 可用资源

| 资源 | URI | 描述 |
|----------|-----|-------------|
| 最新结果 | `skylos://results/latest` | 最近一次分析运行结果 |
| 按 ID 查询结果 | `skylos://results/{run_id}` | 特定分析运行结果 |
| 列出所有结果 | `skylos://results` | 所有已存储的分析运行结果 |

### 在 Claude Desktop 中使用

配置完成后，你可以向 Claude 提问：

- "扫描我的项目是否存在安全问题" → 调用 `security_scan`
- "检查 src/ 中的代码质量" → 调用 `quality_check`
- "查找硬编码密钥" → 调用 `secrets_scan`
- "修复我项目中的安全问题" → 调用 `remediate`

## 基线追踪

基线追踪让你可以快照现有发现项，使 CI 仅标记 PR 引入的**新**问题。

```bash
# 从当前状态创建基线
skylos baseline .

# 运行分析，仅显示不在基线中的发现项
skylos . --danger --secrets --quality --baseline

# 在 CI 中：与基线进行对比
skylos . --danger --baseline --gate
```

基线存储在 `.skylos/baseline.json` 中。将此文件提交到你的代码仓库，以便 CI 使用。

## VS Code 扩展

在编辑器中直接进行实时 AI 驱动的代码分析。

<img src="editors/vscode/media/vsce.gif" alt="Skylos VS Code 扩展 — 内联死代码检测、安全扫描和 CodeLens 操作" width="700" />

### 安装

1. 在 VS Code 市场中搜索 "Skylos" 或运行：
```bash
   ext install oha.skylos-vscode-extension
```

2. 确保已安装 CLI：
```bash
   pip install skylos
```

3. （可选）在 VS Code 设置中添加 API 密钥以启用 AI 功能 → `skylos.openaiApiKey` 或 `skylos.anthropicApiKey`

### 工作原理

| 层级 | 触发时机 | 功能 |
|-------|---------|--------------|
| **静态分析** | 保存时 | 运行 Skylos CLI 检测死代码、密钥和危险模式 |
| **AI 监控** | 空闲时（2 秒） | 将变更函数发送给 GPT-4/Claude 进行漏洞检测 |

### 功能特性

- **实时分析**：输入时即检测漏洞 — 无需保存
- **CodeLens 按钮**：在错误行内联显示 "Fix with AI" 和 "Dismiss"
- **流式修复**：实时查看修复进度
- **智能缓存**：仅重新分析实际发生变更的函数
- **多提供商支持**：在 OpenAI 和 Anthropic 之间选择

#### 新功能
- **MCP 服务器支持**：将 Skylos 直接连接到 Claude Desktop 或任意 MCP 客户端，与你的代码库对话。
- **CI/CD Agents**：在流水线中自动扫描、修复、测试并开启 PR 的自主机器人。
- **混合验证**：通过 LLM 推理验证静态发现项，消除误报。

### 扩展设置

| 设置 | 默认值 | 描述 |
|---------|---------|-------------|
| `skylos.aiProvider` | `"openai"` | `"openai"` 或 `"anthropic"` |
| `skylos.openaiApiKey` | `""` | 你的 OpenAI API 密钥 |
| `skylos.anthropicApiKey` | `""` | 你的 Anthropic API 密钥 |
| `skylos.idleMs` | `2000` | AI 分析前的等待时间（毫秒） |
| `skylos.runOnSave` | `true` | 保存时运行 Skylos CLI |
| `skylos.enableSecrets` | `true` | 扫描硬编码密钥 |
| `skylos.enableDanger` | `true` | 标记危险模式 |

### 使用方式

| 操作 | 结果 |
|--------|--------|
| 保存 Python 文件 | Skylos CLI 扫描工作区 |
| 输入并暂停 | AI 分析变更函数 |
| 点击 "Fix with AI" | 生成带差异预览的修复方案 |
| `Cmd+Shift+P` -> "Skylos: Scan Workspace" | 完整项目扫描 |

### 隐私

- 静态分析 100% 在本地运行
- AI 功能仅将变更的函数代码发送给你配置的提供商
- 我们不收集任何遥测数据或用户数据

**[从 VS Code 市场安装](https://marketplace.visualstudio.com/items?itemName=oha.skylos-vscode-extension)**


## 门控

在合并前阻止不良代码。配置阈值，在本地运行，然后在 CI 中自动化。

### 初始化配置
```bash
skylos init
```

在你的 `pyproject.toml` 中创建 `[tool.skylos]`：
```toml
[tool.skylos]
# 质量阈值
complexity = 10
nesting = 3
max_args = 5
max_lines = 50
duplicate_strings = 3
ignore = []
model = "gpt-4.1"

# 语言覆盖（可选）
[tool.skylos.languages.typescript]
complexity = 15
nesting = 4

# 门控策略
[tool.skylos.gate]
fail_on_critical = true
max_security = 0      # 零容忍
max_quality = 10      # 允许最多 10 条警告
strict = false
```

### 免费版

使用退出码在本地运行扫描：

```bash
skylos . --danger --gate
```

- 退出码 `0` = 通过
- 退出码 `1` = 失败

可用于任意 CI 系统：

```yaml
name: Skylos Quality Gate

on:
  pull_request:
    branches: [main, master]

jobs:
  skylos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install skylos
      - run: skylos . --danger --gate
```

> **限制：** 任何有代码仓库访问权限的人均可删除或修改此工作流。

---

### 专业版

由服务器控制的 GitHub 检查，**开发者无法绕过**。

### 快速设置

```bash
pip install skylos
skylos sync setup
```

### 工作原理

1. 开发者开启 PR → GitHub App 创建必要检查（"Queued"）
2. 扫描运行 → 结果上传至 Skylos 服务器
3. 服务器更新检查 → 通过 ✅ 或失败 ❌
4. 开发者在检查通过之前**无法合并**

### 免费版 vs 专业版

| 功能 | 免费版 | 专业版 |
|---------|------|-----|
| 本地扫描 | ✅ | ✅ |
| `--gate` 退出码 | ✅ | ✅ |
| GitHub Actions | ✅（DIY） | ✅（自动） |
| 开发者可绕过？ | 是 | **否** |
| 服务器控制检查 | ❌ | ✅ |
| Slack/Discord 告警 | ❌ | ✅ |

### GitHub App 设置

1. **Dashboard -> Settings -> Install GitHub App**
2. 选择你的代码仓库
3. 在 GitHub 代码仓库设置中：
   - Settings -> Branches -> Add rule -> `main`
   - 要求状态检查
   - 选择 "Skylos Quality Gate"

### 将令牌添加到 GitHub

代码仓库 **Settings → Secrets → Actions → New secret**
- 名称：`SKYLOS_TOKEN`
- 值：*（从 Dashboard → Settings 获取）*

## 集成与生态系统

Skylos 旨在融入你代码所在的每一个环节 — 从 IDE 到部署流水线。

### 1. 集成环境

| 环境 | 工具 | 用例 |
|-------------|------|----------|
| VS Code | Skylos 扩展 | 实时防护。保存时高亮代码腐化和风险。 |
| Web UI | `skylos run` | 启动本地仪表盘进行可视化审计。默认使用 `localhost:5090`，可通过 `--port` 或 `SKYLOS_PORT` 配置。 |
| CI/CD | GitHub Actions / Pre-commit | 在每个 PR 合并前进行审计的自动化门控。 |
| 质量门控 | `skylos --gate` | 在安全或复杂度阈值被超越时阻止部署。 |

### 2. 输出格式

控制你消费发现项的方式。

| 标志 | 格式 | 主要用途 |
|------|--------|-------------|
| `--tui` | TUI 仪表盘 | 启动交互式 TUI 仪表盘。 |
| `--tree` | 逻辑树 | 可视化代码层次结构和结构依赖。 |
| `--json` | 机器原始格式 | 将结果传递给 `jq`、自定义脚本或日志聚合器。 |
| `--sarif` | SARIF | GitHub Code Scanning、IDE 集成。包含 CWE 分类和每条规则的 CWE 关系 |
| `--llm` | LLM 报告 | 带代码上下文的结构化发现，用于 Claude Code、Codex 或任何 AI Agent。 |
| `-o, --output` | 文件导出 | 将审计报告直接保存到文件而非 `stdout`。 |


## 审计与精度

默认情况下，Skylos 查找死代码。使用标志启用额外扫描。

### 死代码（默认）

```bash
skylos .
```

**解读输出：**

| 列 | 含义 |
|--------|---------|
| **Name** | 未使用的函数、导入、类或变量 |
| **Location** | 定义位置 `file:line` |
| **Conf** | 置信度分数（0–100%）— Skylos 多确信此代码确实未使用。越高越安全删除 |

### 安全（`--danger`）

追踪从用户输入到危险汇点的污点数据。

```bash
skylos . --danger
```

**解读输出：**

| 列 | 含义 |
|--------|---------|
| **Issue** | 漏洞类型（如 SQL injection、eval）及其规则 ID |
| **Severity** | 风险等级：Critical > High > Medium > Low |
| **Message** | 发现了什么以及为什么危险 |
| **Location** | 问题发生的位置 `file:line` |
| **Symbol** | 包含漏洞代码的函数或作用域 |

| 规则 | ID | 检测内容 |
|------|-----|-----------------|
| **注入** | | |
| SQL 注入 | SKY-D211 | `cur.execute(f"SELECT * FROM users WHERE name='{name}'")` |
| SQL 原始查询 | SKY-D217 | 带污点输入的 `sqlalchemy.text()`、`pandas.read_sql()`、Django `.raw()` |
| 命令注入 | SKY-D212 | 带污点输入的 `os.system()`、`subprocess(shell=True)` |
| SSRF | SKY-D216 | `requests.get(request.args["url"])` |
| 路径遍历 | SKY-D215 | `open(request.args.get("p"))` |
| XSS (mark_safe) | SKY-D226 | 不受信任的内容传递给 `mark_safe()` / `Markup()` |
| XSS（模板） | SKY-D227 | 禁用自动转义的内联模板 |
| XSS（HTML 构建） | SKY-D228 | 从未转义用户输入构建 HTML |
| 开放重定向 | SKY-D230 | 用户控制的 URL 传递给 `redirect()` |
| **危险调用** | | |
| eval() | SKY-D201 | 通过 `eval()` 的动态代码执行 |
| exec() | SKY-D202 | 通过 `exec()` 的动态代码执行 |
| os.system() | SKY-D203 | OS 命令执行 |
| pickle.load | SKY-D204 | 不安全反序列化 |
| yaml.load | SKY-D206 | 不带 SafeLoader 的 `yaml.load()` |
| 弱哈希（MD5） | SKY-D207 | `hashlib.md5()` |
| 弱哈希（SHA1） | SKY-D208 | `hashlib.sha1()` |
| shell=True | SKY-D209 | 带 `shell=True` 的 `subprocess` |
| TLS 禁用 | SKY-D210 | 带 `verify=False` 的 `requests` |
| 不安全反序列化 | SKY-D233 | `marshal.loads`、`shelve.open`、`jsonpickle.decode`、`dill` |
| **Web 安全** | | |
| CORS 错误配置 | SKY-D231 | 通配符 origin、凭证泄漏、过度宽松的 headers |
| JWT 漏洞 | SKY-D232 | `algorithms=['none']`、缺少验证、弱密钥 |
| 批量赋值 | SKY-D234 | Django `Meta.fields = '__all__'` 暴露所有模型字段 |
| **供应链** | | |
| 幻觉依赖 | SKY-D222 | 导入的包在 PyPI 上不存在（CRITICAL） |
| 未声明依赖 | SKY-D223 | 导入未在 requirements.txt / pyproject.toml 中声明 |
| **MCP 安全** | | |
| 工具描述投毒 | SKY-D240 | MCP 工具元数据中的提示注入 |
| 未认证传输 | SKY-D241 | 无认证中间件的 SSE/HTTP MCP 服务器 |
| 宽松资源 URI | SKY-D242 | 通过 MCP 资源 URI 模板的路径遍历 |
| 网络暴露 MCP | SKY-D243 | 绑定到 `0.0.0.0` 且无认证的 MCP 服务器 |
| MCP 中硬编码密钥 | SKY-D244 | MCP 工具参数默认值中的密钥 |

完整列表在 `DANGEROUS_CODE.md` 中。

### 密钥（`--secrets`）

检测硬编码凭证。
```bash
skylos . --secrets
```

**解读输出：**

| 列 | 含义 |
|--------|---------|
| **Provider** | 密钥所属的服务（如 AWS、Stripe、GitHub）或通用高熵字符串的 "generic" |
| **Message** | 检测到的凭证描述 |
| **Preview** | 密钥的掩码片段（如 `sk_live_****`） |
| **Location** | 发现密钥的位置 `file:line` |

提供商：GitHub、GitLab、AWS、Stripe、Slack、Google、SendGrid、Twilio、私钥。

### 依赖漏洞（`--sca`）

扫描已安装的依赖，对照 OSV.dev 漏洞数据库。

```bash
skylos . --sca
```

**解读输出：**

| 列 | 含义 |
|--------|---------|
| **Package** | 依赖及其安装版本（如 `requests@2.28.0`） |
| **Vuln ID** | CVE 或安全公告标识符 |
| **Severity** | 风险等级：Critical > High > Medium > Low |
| **Reachability** | 你的代码是否实际调用了漏洞代码路径：Reachable（确认风险）、Unreachable（安全）或 Inconclusive |
| **Fix** | 要升级到的修复版本 |

### 质量（`--quality`）

标记难以维护的函数。
```bash
skylos . --quality
```

**解读输出：**

| 列 | 含义 |
|--------|---------|
| **Type** | 类别：Complexity、Nesting、Structure、Quality（重复字面量、耦合、内聚） |
| **Name** | 触发发现的函数、类或字符串字面量 |
| **Detail** | 测量值和阈值 — 如 `Complexity: 14 (max 10)` 表示发现 14 个分支但限制为 10；`repeated 5× (max 3)` 表示字符串字面量出现 5 次但最多应出现 3 次 |
| **Location** | 发现开始的位置 `file:line` |

| 规则 | ID | 检测内容 |
|------|-----|-----------------|
| **复杂度** | | |
| 圈复杂度 | SKY-Q301 | 分支/循环过多（默认：>10） |
| 深嵌套 | SKY-Q302 | 嵌套层级过多（默认：>3） |
| 异步阻塞 | SKY-Q401 | 检测 async 函数中的阻塞调用，会降低服务器吞吐量 |
| 上帝类 | SKY-Q501 | 类拥有过多方法/属性 |
| 耦合（CBO） | SKY-Q701 | 高类间耦合（7 种依赖类型：继承、类型提示、实例化、属性访问、导入、装饰器、protocol/ABC） |
| 内聚（LCOM） | SKY-Q702 | 低类内聚 — 应该拆分的断开方法组（LCOM1/4/5 指标配合 Union-Find） |
| **架构** | | |
| 到主序列的距离 | SKY-Q802 | 模块远离抽象性与不稳定性的理想平衡 |
| 区域警告 | SKY-Q803 | 模块处于痛苦区（僵化）或无用区（一次性） |
| DIP 违规 | SKY-Q804 | 稳定模块依赖不稳定模块（依赖倒置原则） |
| **结构** | | |
| 参数过多 | SKY-C303 | 参数 >5 的函数 |
| 函数过长 | SKY-C304 | >50 行的函数 |
| **逻辑** | | |
| 可变默认值 | SKY-L001 | `def foo(x=[])` - 导致状态泄漏 |
| 裸 except | SKY-L002 | `except:` 会吞掉 SystemExit |
| 危险比较 | SKY-L003 | `x == None` 而非 `x is None` |
| 反模式 try 块 | SKY-L004 | 嵌套 try，或 try 包装过多逻辑 |
| 未使用异常变量 | SKY-L005 | `except Error as e:` 其中 `e` 从未引用 |
| 不一致返回 | SKY-L006 | 函数既返回值又返回 `None` |
| 重复字符串字面量 | SKY-L027 | 相同字符串重复 3+ 次（参见[抑制重复字符串发现](#抑制重复字符串发现)） |
| 返回过多 | SKY-L028 | 函数有 5+ 个 return 语句 |
| 布尔陷阱 | SKY-L029 | 布尔位置参数损害调用点可读性 |
| **性能** | | |
| 内存负载 | SKY-P401 | `.read()` / `.readlines()` 加载整个文件 |
| Pandas 无分块 | SKY-P402 | 不带 `chunksize` 的 `read_csv()` |
| 嵌套循环 | SKY-P403 | O(N²) 复杂度 |
| **不可达** | | |
| 不可达代码 | SKY-UC001 | `if False:` 或永真条件后的 `else` |
| **空文件** | | |
| 空文件 | SKY-E002 | 空文件 |

忽略特定规则：
```toml
# pyproject.toml
[tool.skylos]
ignore = ["SKY-P403"]  # 允许嵌套循环
```

在 `pyproject.toml` 中调整阈值和禁用规则：
```toml
[tool.skylos]
# 调整阈值
complexity = 15        # 默认：10
nesting = 4            # 默认：3
max_args = 7           # 默认：5
max_lines = 80
```

### 抑制重复字符串发现

Skylos 标记出现 3+ 次的字符串字面量（规则 `SKY-L027`）。如果重复字符串是有意的（如在多处检查的状态值），你有三个选择：

**选项 1：提高阈值** — 仅标记重复超过 N 次的字符串：
```toml
# pyproject.toml
[tool.skylos]
duplicate_strings = 10   # 默认：3。设为 999 可有效禁用。
```

**选项 2：完全禁用规则：**
```toml
# pyproject.toml
[tool.skylos]
ignore = ["SKY-L027"]
```

**选项 3：内联抑制** — 在特定行上：
```python
if somevar == "lokal":  # skylos: ignore
    do_something()
```

### 技术债务（`skylos debt`）

使用现有的质量、架构和死代码分析的静态发现来排名结构性债务热点。

```bash
skylos debt .
skylos debt . --changed
skylos debt . --baseline
skylos debt . --save-baseline
skylos debt . --history
skylos debt . --json
```

**债务输出工作方式：**

| 字段 | 含义 |
|------|---------|
| **score** | 热点自身的结构性债务评分 |
| **priority** | 下一步修复的分类优先级。变更文件和基线偏移会提高此值而不改变结构性债务评分 |
| **project score** | 代码仓库级别的结构性债务评分。即使使用 `--changed` 也保持项目范围 |
| **baseline status** | 热点与保存的债务基线相比是 `new`、`worsened`、`improved` 还是 `unchanged` |

`--changed` 是过滤/视图模式，不是不同的评分模型。它将可见的热点列表限制为 git 变更文件，但代码仓库债务评分仍反映完整项目。

债务基线和债务历史是项目级别的工件。`--save-baseline` 和 `--history` 仅在扫描项目根目录时有效。

### 默认 CLI 选项（`addopts`）

在 `pyproject.toml` 中设置默认标志，无需每次输入 — 就像 pytest 的 `addopts`：

```toml
[tool.skylos]
addopts = ["--quality", "--danger", "--secrets"]
```

字符串格式也有效：

```toml
[tool.skylos]
addopts = "--quality --danger --confidence=80"
```

CLI 标志会覆盖 `addopts`，因此你可以随时收窄或扩展扫描而无需编辑配置。

Skylos 在 CLI 扫描期间还会遵循 `[tool.skylos].exclude`，这是保存团队特定路径（如自定义 venv 名称或 `.claude/worktrees/`）的最佳位置。

### 遗留 AI 标志

```bash
# LLM 驱动审计（单文件）
skylos . --audit

# 指定模型
skylos . --audit --model claude-haiku-4-5-20251001
```

> **注意：** 要获得完整项目上下文和更好的结果，请改用 `skylos agent scan`。要自动修复，请使用 `skylos agent remediate`。

### 组合所有功能
```bash
skylos . -a                           # 所有静态扫描（danger + secrets + quality + sca）
skylos agent remediate . --dry-run    # 预览 AI 辅助修复
```

## 智能追踪

静态分析无法看到所有内容。Python 的动态特性意味着像 `getattr()`、插件注册表和基于字符串的分发这样的模式看起来像死代码 — 但实际并非如此。

**智能追踪解决了这个问题。** 通过使用 `sys.settrace()` 运行测试，Skylos 记录每个实际被调用的函数。

### 快速开始
```bash
# 运行带调用追踪的测试，然后分析
skylos . --trace

# 追踪数据保存到 .skylos_trace
skylos .
```

### 工作原理

| 分析类型 | 准确率 | 检测内容 |
|---------------|----------|-----------------|
| 仅静态 | 70-85% | 直接调用、导入、装饰器 |
| + 框架规则 | 85-95% | Django/Flask 路由、pytest fixtures |
| + `--trace` | 95-99% | 动态分发、插件、注册表 |

### 示例
```python
# 静态分析会认为这是死代码，因为没有可见的直接调用
def handle_login():
    return "Login handler"

# 但它实际上在运行时被动态调用
action = request.args.get("action")
func = getattr(module, f"handle_{action}")
func()  # 在这里
```

| 无追踪 | 有 `--trace` |
|-----------------|----------------|
| `handle_login` 被标记为死代码 | `handle_login` 被标记为已使用 |

### 使用时机

| 场景 | 命令 |
|-----------|---------|
| 有 pytest/unittest 测试 | `skylos . --trace` |
| 无测试 | `skylos .`（仅静态；重复运行会复用 `.skylos/cache/grep_results.json` 进行 grep 验证） |
| CI 中有缓存追踪 | `skylos .`（复用 `.skylos_trace`） |

### 追踪能捕获什么

这些模式对静态分析不可见，但可通过 `--trace` 捕获：
```python

# 1. 动态分发
func = getattr(module, f"handle_{action}")
func()

# 2. 插件或注册表模式
PLUGINS = []
def register(f):
  PLUGINS.append(f)
return f

@register
def my_plugin(): ...

# 3. 访问者模式
class MyVisitor(ast.NodeVisitor):
    def visit_FunctionDef(self, node): ...  # 通过 getattr 调用

# 4. 基于字符串的访问
globals()["my_" + "func"]()
locals()[func_name]()
```

### 重要说明

- **追踪只添加信息。** 低测试覆盖率不会产生误报。它只意味着某些动态模式**可能**仍被标记。
- **提交 `.skylos_trace`** 以在 CI 中复用追踪数据而无需重新运行测试。
- **测试不需要通过。** 追踪记录执行了什么，无论通过/失败状态。

## 过滤

控制 Skylos 分析什么和忽略什么。

### 内联抑制

使用注释静默特定发现：
```python
# 忽略此行的死代码检测
def internal_hook():  # pragma: no skylos
    pass

# 这也有效
def another():  # pragma: no cover
    pass

def yet_another():  # noqa
    pass
```

### 文件夹排除

默认情况下，Skylos 排除：`__pycache__`、`.git`、`.pytest_cache`、`.mypy_cache`、`.tox`、`htmlcov`、`.coverage`、`build`、`dist`、`*.egg-info`、`venv`、`.venv`
```bash
# 查看默认排除的内容
skylos --list-default-excludes

# 添加更多排除项
skylos . --exclude-folder vendor --exclude-folder generated

# Skylos 在文件发现期间也遵循项目 `.gitignore` 条目
# 因此被忽略的文件夹（如自定义 venv 和 worktree）会自动跳过

# 强制包含被排除的文件夹
skylos . --include-folder venv

# 扫描所有内容（无排除）
skylos . --no-default-excludes
```

使用 `pyproject.toml` 中的 `[tool.skylos].exclude` 设置团队范围的自定义排除项，即使在 `.gitignore` 之外也应生效。

### 规则抑制

在 `pyproject.toml` 中全局禁用规则：
```toml
[tool.skylos]
ignore = [
    "SKY-P403",   # 允许嵌套循环
    "SKY-L003",   # 允许 == None
    "SKY-S101",   # 允许硬编码密钥（不推荐）
]
```

### 总结

| 想要... | 这样做 |
|------------|---------|
| 跳过一行 | `# pragma: no skylos` |
| 跳过一个密钥 | `# skylos: ignore[SKY-S101]` |
| 跳过一个文件夹 | `--exclude-folder NAME` |
| 全局跳过一条规则 | pyproject.toml 中 `ignore = ["SKY-XXX"]` |
| 包含已排除的文件夹 | `--include-folder NAME` |
| 跳过团队特定文件夹 | pyproject.toml 中 `exclude = ["customenv", ".claude/worktrees"]` |
| 运行所有检查 | `-a` 或 pyproject.toml 中的 `addopts` |
| 扫描所有内容 | `--no-default-excludes` |

## 白名单配置

永久抑制误报而无需内联注释干扰你的代码。

### CLI 命令
```bash
# 添加模式
skylos whitelist 'handle_*'

# 添加并附带原因
skylos whitelist dark_logic --reason "Called via globals() in dispatcher"

# 查看当前白名单
skylos whitelist --show
```

### 内联忽略
```python
# 单行
def dynamic_handler():  # skylos: ignore
    pass

# 也有效
def another():  # noqa: skylos
    pass

# 块忽略
# skylos: ignore-start
def block_one():
    pass
def block_two():
    pass
# skylos: ignore-end
```

### 配置文件（`pyproject.toml`）
```toml
[tool.skylos.whitelist]
# Glob 模式
names = [
    "handle_*",
    "visit_*",
    "*Plugin",
]

# 带原因（在 --show 输出中显示）
[tool.skylos.whitelist.documented]
"dark_logic" = "Called via globals() string manipulation"
"BasePlugin" = "Discovered via __subclasses__()"

# 临时的（过期时发出警告）
[tool.skylos.whitelist.temporary]
"legacy_handler" = { reason = "Migration - JIRA-123", expires = "2026-03-01" }

# 按路径覆盖
[tool.skylos.overrides."src/plugins/*"]
whitelist = ["*Plugin", "*Handler"]
```

### 总结

| 想要... | 这样做 |
|------------|---------|
| 白名单一个函数 | `skylos whitelist func_name` |
| 白名单一个模式 | `skylos whitelist 'handle_*'` |
| 记录原因 | `skylos whitelist x --reason "why"` |
| 临时白名单 | 在 `[tool.skylos.whitelist.temporary]` 中添加并带 `expires` |
| 按文件夹规则 | 添加 `[tool.skylos.overrides."path/*"]` |
| 查看白名单 | `skylos whitelist --show` |
| 内联忽略 | `# skylos: ignore` 或 `# noqa: skylos` |
| 块忽略 | `# skylos: ignore-start` ... `# skylos: ignore-end` |

## CLI 选项

### 主命令标志
```
用法：skylos [OPTIONS] PATH

参数：
  PATH  要分析的 Python 项目路径

选项：
  -h, --help                   显示帮助信息并退出
  --json                       输出原始 JSON 而非格式化文本
  --tree                       以树形格式输出结果
  --tui                        启动交互式 TUI 仪表盘
  --sarif                      输出 SARIF 格式，用于 GitHub/IDE 集成
  --llm                        输出带代码上下文的 LLM 优化报告，用于 AI Agent
  -c, --confidence LEVEL       置信度阈值 0-100（默认：60）
  --comment-out                注释掉代码而非删除
  -o, --output FILE            将输出写入文件而非 stdout
  -v, --verbose                启用详细输出
  --version                    检查版本
  -i, --interactive            交互式选择要移除的项目
  --dry-run                    显示将要移除的内容而不修改文件
  --exclude-folder FOLDER      从分析中排除文件夹（可多次使用）
  --include-folder FOLDER      强制包含否则会被排除的文件夹
  --no-default-excludes        不排除默认文件夹（__pycache__、.git、venv 等）
  --list-default-excludes      列出默认排除的文件夹
  --secrets                    扫描 API 密钥/密钥
  --danger                     扫描危险代码
  --quality                    代码复杂度和可维护性
  --sca                        扫描依赖中的已知 CVE（OSV.dev）
  -a, --all                    启用所有检查：--danger --secrets --quality --sca
  --trace                      先运行带覆盖率的测试
  --audit                      LLM 驱动的逻辑审查（遗留）
  --model MODEL                LLM 模型（默认：gpt-4.1）
  --gate                       在阈值突破时失败（用于 CI）
  --force                      绕过质量门控（紧急覆盖）
```

### Agent 命令标志
```
用法：skylos agent <command> [OPTIONS] PATH

命令：
  scan                静态 + LLM 混合分析（替代 analyze/audit/review/security-audit）
  verify              LLM 验证死代码发现
  remediate           扫描、修复、测试并创建 PR（端到端）
  watch               持续代码仓库监控
  pre-commit          仅暂存文件分析，用于 git hooks
  triage              管理发现项分类（suggest/dismiss/snooze/restore）
  status              显示活跃 agent 摘要
  serve               用于编辑器集成的本地 HTTP API

Agent scan 选项：
  --model MODEL                使用的 LLM 模型（默认：gpt-4.1）
  --provider PROVIDER          强制提供商：openai 或 anthropic
  --base-url URL               本地 LLM 的自定义端点
  --format FORMAT              输出：table、tree、json、sarif
  -o, --output FILE            将输出写入文件
  --min-confidence LEVEL       过滤：high、medium、low
  --no-fixes                   跳过修复建议（更快）
  --changed                    仅分析 git 变更文件
  --security                   仅安全 LLM 审计模式
  -i, --interactive            交互式文件选择（配合 --security）

Agent remediate 选项：
  --dry-run                    显示计划而不应用修复（安全预览）
  --max-fixes N                每次运行的最大修复数（默认：10）
  --auto-pr                    创建分支、提交、推送并开启 PR
  --branch-prefix PREFIX       Git 分支前缀（默认：skylos/fix）
  --test-cmd CMD               自定义测试命令（默认：自动检测）
  --severity LEVEL             最低严重性过滤：critical、high、medium、low
  --standards [FILE]           启用 LLM 清理模式（使用内置规范，或传入自定义 .md）

Agent watch 选项：
  --once                       运行一个刷新周期并退出
  --interval SECONDS           持续监控模式的轮询间隔
  --cycles N                   N 个刷新周期后停止（0 = 持续监控）
  --learn                      在监控模式中启用分类模式学习
  --format FORMAT              输出：table、json
```

### AI 防御命令标志
```
用法：skylos discover [OPTIONS] PATH
  映射 Python 代码库中所有 LLM 集成。

选项：
  --json                       以 JSON 输出
  -o, --output FILE            将输出写入文件
  --exclude FOLDER [FOLDER...] 额外排除的文件夹

用法：skylos defend [OPTIONS] PATH
  检查 LLM 集成是否缺少防御措施。

选项：
  --json                       以 JSON 输出
  -o, --output FILE            将输出写入文件
  --min-severity LEVEL         包含的最低严重性（critical/high/medium/low）
  --fail-on LEVEL              如果有此严重性或以上的防御发现则退出 1
  --min-score N                如果防御评分低于此百分比（0-100）则退出 1
  --policy FILE                skylos-defend.yaml 策略文件路径
  --owasp IDS                  逗号分隔的 OWASP LLM ID（如 LLM01,LLM04）
  --exclude FOLDER [FOLDER...] 额外排除的文件夹
  --upload                     将防御结果上传到 Skylos Cloud 仪表盘
```

### 命令列表
```
命令：
  skylos PATH                  分析项目（静态分析）
  skylos debt PATH             分析技术债务热点
  skylos discover PATH         映射代码库中的 LLM 集成
  skylos defend PATH           检查 LLM 集成是否缺少防御措施
  skylos agent scan PATH       静态 + LLM 混合分析
  skylos agent verify PATH     LLM 验证死代码发现
  skylos agent remediate PATH  端到端扫描、修复、测试并创建 PR
  skylos agent triage CMD      管理发现项分类
  skylos baseline PATH         快照当前发现项用于 CI 基线
  skylos cicd init             生成 GitHub Actions 工作流
  skylos cicd gate             根据质量门控检查发现项
  skylos cicd annotate         发送 GitHub Actions 注释
  skylos cicd review           发布内联 PR 审查评论（支持 --llm-input）
  skylos init                  初始化 pyproject.toml 配置
  skylos key                   管理 API 密钥（添加/删除/列出）
  skylos whitelist PATTERN     添加模式到白名单
  skylos whitelist --show      显示当前白名单
  skylos run                   在 localhost:5090 启动 Web UI（默认值；可通过 --port 或 SKYLOS_PORT 覆盖）

白名单选项：
  skylos whitelist PATTERN           添加 glob 模式（如 'handle_*'）
  skylos whitelist NAME --reason X   添加并附带文档说明
  skylos whitelist --show            显示所有白名单条目
```

### CLI 输出

Skylos 为每个发现显示置信度：
```
────────────────── Unused Functions ──────────────────
#   Name              Location        Conf
1   handle_secret     app.py:16       70%
2   totally_dead      app.py:50       90%
```

置信度越高 = 越确信是死代码。

### 交互模式

交互模式让你选择要移除的特定函数和导入：

1. **选择项目**：使用方向键和 `空格键` 选择/取消选择
2. **确认更改**：应用前审查选中的项目
3. **自动清理**：文件自动更新

## 常见问题

**问：为什么 Skylos 不能找到 100% 的死代码？**
答：Python 的动态特性（getattr、globals 等）无法被完美地静态分析。没有工具能达到 100% 准确率。如果他们说能，那是在骗人。

**问：这些基准测试可靠吗？**
答：它们测试了常见场景但无法覆盖每个边界情况。把它们作为参考，而非教条。

**问：为什么 Skylos 不检测我未使用的 Flask 路由？**
答：Web 框架路由被赋予低置信度（20），因为它们可能被外部 HTTP 请求调用。使用 `--confidence 20` 来查看它们。我们承认这种方法目前有局限性，请谨慎使用。

**问：我应该使用什么置信度级别？**
答：从 60（默认）开始进行安全清理。使用 30 用于框架应用。使用 20 进行更全面的审计。

**问：`--trace` 做什么？**
答：它在分析前带覆盖率追踪运行 `pytest`（或 `unittest`）。实际执行的函数被标记为已使用，置信度 100%，消除动态分发模式的误报。

**问：`--trace` 需要 100% 测试覆盖率才有用吗？**
答：不需要。但是，我们**强烈**鼓励你拥有测试。任何覆盖率都有帮助。如果你有 30% 测试覆盖率，那就是 30% 的代码经过验证。另外 70% 仍使用静态分析。覆盖率只会消除误报，不会增加它们。

**问：为什么 `conftest.py` 中的 fixtures 显示为未使用？**
答：`conftest.py` 是共享 fixtures 的标准位置。如果一个 fixture 在那里定义但从未被任何测试引用，Skylos 会将其报告为未使用。这是正常的，可安全审查。

**问：我的测试失败了。我还能使用 `--trace` 吗？**
答：可以。覆盖率追踪执行情况，不管通过/失败。即使失败的测试也提供覆盖率数据。

**问：质量表格中的数字是什么意思？**
答：每个质量发现都有一个**测量值**和一个**阈值**（配置的最大值）。例如，`Complexity: 14 (max 10)` 表示函数有 14 个分支但限制为 10。对于重复字符串字面量，`repeated 5× (max 3)` 表示相同字符串出现 5 次 — 将其提取为命名常量。你可以在 `pyproject.toml` 的 `[tool.skylos]` 下调整阈值。

**问：`skylos . --audit` 和 `skylos agent scan` 有什么区别？**
答：`skylos agent scan` 运行完整的混合流水线 — 静态分析、judge-all LLM 死代码验证、以及带修复建议的 LLM 安全/质量分析。使用 `--no-fixes` 跳过修复生成。基础命令上的 `--audit` 标志是遗留的仅静态模式。

**问：`--verification-mode` 做什么？**
答：它控制 Skylos 将死代码候选项发送给 LLM 的积极程度。`judge_all` 是 `agent scan` 和 `agent verify` 的默认值；它将几乎所有 `references == 0` 的静态候选项发送给 LLM，并将确定性抑制器作为证据。`production` 更经济，让更多明显活跃的情况在 LLM 看到之前被抑制。

**问：我可以使用本地 LLM 替代 OpenAI/Anthropic 吗？**
答：可以！使用 `--base-url` 指向 Ollama、LM Studio 或任何 OpenAI 兼容端点。localhost 无需 API 密钥。

## 限制与故障排除

### 限制

- **动态代码**：`getattr()`、`globals()`、运行时导入难以检测
- **框架**：Django 模型、Flask、FastAPI 路由可能看起来未使用但实际在使用
- **测试数据**：有限的场景，你的情况可能不同
- **误报**：删除代码前请务必手动审查
- **密钥 PoC**：可能对同一令牌同时发出提供商命中和通用高熵命中。支持的文件类型：`.py`、`.pyi`、`.pyw`、`.env`、`.yaml`、`.yml`、`.json`、`.toml`、`.ini`、`.cfg`、`.conf`、`.ts`、`.tsx`、`.js`、`.jsx`、`.go`
- **质量限制**：质量阈值（`complexity`、`nesting`、`max_args`、`max_lines`、`duplicate_strings`）可在 `pyproject.toml` 的 `[tool.skylos]` 下配置。
- **覆盖率需要执行**：`--trace` 标志仅在你有测试或可以运行应用时有效。纯静态分析在没有它的情况下仍可用。
- **LLM 限制**：AI 分析需要 API 访问（云端）或本地设置（Ollama）。结果取决于模型质量。

### 故障排除

1. **权限错误**
   ```
   Error: Permission denied when removing function
   ```
   在交互模式运行前检查文件权限。

2. **缺少依赖**
   ```
   Interactive mode requires 'inquirer' package
   ```
   安装：`pip install skylos[interactive]`

3. **未找到 API 密钥**
   ```bash
   # 云端提供商
   export OPENAI_API_KEY="sk-..."
   export ANTHROPIC_API_KEY="sk-ant-..."

   # 本地 LLM（无需密钥）
   skylos agent scan . --base-url http://localhost:11434/v1 --model codellama
   ```

4. **本地 LLM 连接被拒绝**
   ```bash
   # 验证 Ollama 是否运行
   curl http://localhost:11434/v1/models

   # 检查 LM Studio
   curl http://localhost:1234/v1/models
   ```

## 贡献

我们欢迎贡献！请在提交拉取请求前阅读我们的 [贡献指南](CONTRIBUTING.md)。

### 快速贡献指南

1. Fork 代码仓库
2. 创建功能分支（`git checkout -b feature/amazing-feature`）
3. 提交更改（`git commit -m 'Add amazing feature'`）
4. 推送到分支（`git push origin feature/amazing-feature`）
5. 开启拉取请求

## 路线图
- [x] 扩展测试用例
- [x] 配置文件支持
- [x] Git hooks 集成
- [x] CI/CD 集成示例
- [x] 部署守门人
- [ ] 进一步优化
- [ ] 添加新规则
- [ ] 扩展 `dangerous.py` 列表
- [x] 迁移到 uv
- [x] 小型 TypeScript 集成
- [x] 扩展 TypeScript 死代码检测（接口、枚举、类型别名、95% 召回率）
- [ ] 扩展和改进 Skylos 在其他语言中的能力
- [x] AI 防御引擎：discover + defend 命令，13 项检查，OWASP LLM Top 10 映射，运维评分
- [x] AI 防御云仪表盘：上传、趋势图、OWASP 网格、每个集成卡片、专用项目页面
- [x] AI 防御 CI/CD：`skylos cicd init --defend`、pre-commit hook
- [x] 扩展 LLM 提供商（OpenAI、Anthropic、Ollama、LM Studio、vLLM）
- [x] 扩展 LLM 检测死代码/危险代码部分（混合架构）
- [x] 覆盖率集成用于运行时验证
- [x] 隐式引用检测（f-string 模式、框架装饰器）

更多功能即将推出！

## 许可证

本项目基于 Apache 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 联系方式

- **作者**：oha
- **邮箱**：aaronoh2015@gmail.com
- **GitHub**：[@duriantaco](https://github.com/duriantaco)
- **Discord**：https://discord.gg/Ftn9t9tErf

<!-- mcp-name: io.github.duriantaco/skylos -->
