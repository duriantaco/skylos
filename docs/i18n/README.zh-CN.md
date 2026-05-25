<div align="center">
    <img src="../../assets/DOG_1.png" alt="Skylos" width="260">
    <h1>Skylos</h1>
    <h3>开源、本地优先，在代码合并前检查死代码、安全问题、密钥、质量回归和 AI 代码错误。</h3>
</div>

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
[![PyPI version](https://img.shields.io/pypi/v/skylos)](https://pypi.org/project/skylos/)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
[![Astronomer Trust](https://img.shields.io/badge/Astronomer%20Trust-A-brightgreen?style=flat&logo=github&logoColor=white)](#star-authenticity-audit)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/Ftn9t9tErf)

[官网](https://skylos.dev) |
[文档](https://docs.skylos.dev) |
[快速开始](https://docs.skylos.dev/quick-start) |
[GitHub Action](../../action.yml) |
[VS Code 扩展](../../editors/vscode/README.md) |
[基准测试](../../BENCHMARK.md) |
[贡献指南](../../CONTRIBUTING.md)

[English](../../README.md) | [Deutsch](./README.de.md) | **简体中文** | [其他翻译](./README.md)

## Skylos 是什么？

Skylos 是一款面向 Python、TypeScript、JavaScript、Java、Go、PHP、Rust、Dart 和 C# 仓库的开源静态分析 CLI。它默认在本地运行，也可以作为 CI/CD PR 门控使用。

如果你使用 Vulture 检测死代码、Bandit 做安全检查，或使用 Semgrep、CodeQL、GitHub Advanced Security 做 CI 门控，Skylos 可以作为补充：它更关注框架感知的死代码检测、差异感知的回归检查，以及适合 PR 审查的反馈。

## 60 秒开始

```bash
pip install skylos
skylos .
```

加入安全、密钥、质量和依赖检查：

```bash
skylos . -a
```

生成 GitHub Actions PR 门控：

```bash
skylos cicd init
git add .github/workflows/skylos.yml
git commit -m "Add Skylos CI gate"
git push
```

需要更多命令？阅读 [CLI Reference](https://docs.skylos.dev/cli-reference)。

## 选择你的工作流

| 目标 | 命令 | 你会得到什么 | 详细文档 |
|:---|:---|:---|:---|
| 第一次死代码扫描 | `skylos .` | 发现未使用的函数、类、导入、文件和框架入口点问题 | [死代码文档](https://docs.skylos.dev/dead-code-detection) |
| 安全与质量审计 | `skylos . -a` | 增加危险数据流、密钥、依赖和质量检查 | [安全文档](https://docs.skylos.dev/security-analysis) |
| PR 门控 | `skylos cicd init` | 生成带注释和失败阈值的 GitHub Actions 工作流 | [CI/CD 指南](https://docs.skylos.dev/ci-cd) |
| 更易读的终端报告 | `skylos . --format pretty` | 按文件分组展示发现，包含严重级别标记、代码片段和可复制的 `file:line` 位置 | [CLI Output Modes](../cli-output.md) |
| 可选择的终端界面 | `skylos . --tui` | 打开键盘驱动的分类列表、发现列表和详情面板 | [CLI Output Modes](../cli-output.md) |
| 只审查变更行 | `skylos . -a --diff origin/main` | 聚焦当前 PR，避免被历史债务淹没 | [质量门控](https://docs.skylos.dev/quality-gate) |
| 运行时辅助死代码检测 | `skylos . --trace` | 用测试运行轨迹降低动态代码误报 | [Smart Tracing](https://docs.skylos.dev/smart-tracing) |
| AI 辅助审查 | `skylos agent scan .` | 静态分析加可选 LLM 审查和修复建议 | [AI Features](https://docs.skylos.dev/ai-features) |
| LLM 应用防护 | `skylos defend .` | 查找缺失的 AI 应用防护措施并映射到 OWASP LLM 风险 | [AI Defense](https://docs.skylos.dev/ai-defense) |
| 技术债务梳理 | `skylos debt .` | 排序热点和债务趋势 | [Technical Debt](https://docs.skylos.dev/technical-debt) |

## Skylos 能发现什么？

| 类别 | 示例 | 为什么重要 |
|:---|:---|:---|
| 死代码 | 未使用的函数、类、导入、包入口点、路由处理器 | 降低维护成本，同时避免误删动态框架代码 |
| 安全缺陷 | SQL 注入、XSS、SSRF、路径穿越、命令注入、不安全反序列化 | 在代码进入 main 前发现可利用路径 |
| 密钥 | API key、token、私有凭据、高熵字符串 | 防止凭据通过提交和 PR 泄露 |
| 质量回归 | 复杂度、深层嵌套、重复分支、长函数、不一致返回 | 防止 AI 辅助重构引入脆弱代码 |
| AI 代码错误 | 幻觉安全调用、缺失装饰器、未完成桩代码、禁用的安全控制 | 捕获常见的 AI 生成或不完整代码路径 |
| LLM 应用风险 | 不安全工具调用、提示注入暴露、缺失输出校验、缺失限流 | 帮助团队在发布 AI 功能时保留防护栏 |

查看完整 [Rules Reference](https://docs.skylos.dev/rules-reference)。

## 团队为什么使用 Skylos？

- **框架感知的死代码检测：** 理解 FastAPI、Django、Flask、pytest、SQLAlchemy、Next.js、React、包入口点和常见插件模式。
- **面向 CI/CD 的工作流：** 本地运行、PR 门控、GitHub diff 注释，并通过基线控制历史问题。
- **默认本地优先：** 核心静态分析不需要云端上传，也不需要 LLM 调用。
- **面向 AI 时代的回归检查：** 捕获 AI 辅助编辑中被移除的验证、认证、日志、CSRF、限流等控制。
- **统一命令入口：** 死代码、安全、密钥、质量、技术债务、Agent 审查和 AI 防御都在同一个 CLI 下。

## 安装选项

```bash
# 核心静态分析
pip install skylos

# LLM Agent 工作流
pip install "skylos[llm]"

# 所有已发布的可选 extras
pip install "skylos[all]"
```

容器镜像：

```bash
docker pull ghcr.io/duriantaco/skylos:latest
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest . --json --no-provenance
```

源码安装、容器使用和可选依赖请看 [Installation](https://docs.skylos.dev/installation)。

## 语言支持

| 语言 | 死代码 | 安全 | 质量 | 说明 |
|:---|:---:|:---:|:---:|:---|
| Python | 是 | 是 | 是 | 覆盖最强，支持框架感知静态分析和可选运行时追踪 |
| TypeScript / JavaScript | 是 | 是 | 是 | Tree-sitter 解析、包图可达性、框架约定 |
| Java | 是 | 是 | 是 | Tree-sitter 解析和结构化安全流分析 |
| Go | 是 | 部分 | 部分 | 死代码和部分安全基准覆盖 |
| PHP | 是 | 是 | 部分 | PHP parser 覆盖，加上污点式安全 sinks 和 sources |
| Rust | 是 | 是 | 部分 | Rust parser 覆盖，加上安全 sinks 和 sources |
| Dart | 是 | 是 | 部分 | Dart parser 覆盖，加上部分安全 sinks 和 sources |
| C# | 是 | 是 | 部分 | C# 符号覆盖，加上部分 ASP.NET、process、SQL、HTTP 和文件 sinks |

规则族和扫描范围请看 [Rules Reference](https://docs.skylos.dev/rules-reference)。

## 基准测试快照

Skylos 有已提交的死代码、安全、质量和 Agent 审查回归基准。这些是严格的回归门控，不代表任何工具在所有场景下都是绝对 SOTA。

| 套件 | 当前 Skylos 结果 | 基线 |
|:---|:---|:---|
| 死代码回归 | 16 cases, TP=36 FP=0 FN=0 TN=59, score 100.0 | Ruff score 62.67；最新本地重跑未安装 Vulture |
| 安全回归 | 49 cases, TP=30 FP=0 FN=0 TN=21, score 100.0 | Bandit 在 Python 适用 cases 上 score 47.14 |
| 质量回归 | 13 cases, score 100.0 | 仅作为回归门控 |
| Agent 审查 | 25 cases, score 100.0 | 仅作为回归门控 |

冻结的 `golden-v0.2` 重点结果：

| 冻结套件 | Skylos 结果 | 注意事项 |
|:---|:---|:---|
| Dead code seeded dev | overall score 96.28；TS/JS/Go/Java score 100.0；Python score 93.33 | Python 剩余项属于标签复核问题 |
| Security seeded dev | overall score 96.52；完整召回，剩一个 Python `urljoin` false positive | 标签应复核 |
| OWASP Java security dev | TP=105 FP=0 FN=15 TN=120, score 94.37 | request-wrapper、LDAP、XPath、property weak-hash 仍有缺口 |
| Quality seeded dev | TP=1 FP=0 FN=0 TN=1, score 100.0 | 目前只有一个 seeded case |

方法论、命令、竞品行和 caveats 请看 [BENCHMARK.md](../../BENCHMARK.md)。

## 项目证据

Skylos 辅助的死代码清理 PR 已被
[Black](https://github.com/psf/black/pull/5041)、
[NetworkX](https://github.com/networkx/networkx/pull/8572)、
[Optuna](https://github.com/optuna/optuna/pull/6547)、
[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136)、
[pypdf](https://github.com/py-pdf/pypdf/pull/3685)、
[beets](https://github.com/beetbox/beets/pull/6473) 和
[Flagsmith](https://github.com/Flagsmith/flagsmith/pull/6953) 合并。这些是已被接受的清理 PR，不代表相关项目背书。详见
[Real-World Results](../../REAL_WORLD_RESULTS.md)。

<a id="star-authenticity-audit"></a>

2026 年 4 月 26 日，本地 Astronomer 扫描统计 420 个 stargazer，返回
**overall trust: A**。StarGuard 同时报告 **low fake-star risk**。

## 集成

| 集成 | 链接 | 用途 |
|:---|:---|:---|
| GitHub Action | [GitHub Action](../../action.yml) | PR 门控、注释和 CI 执行 |
| VS Code 扩展 | [VS Code extension](../../editors/vscode/README.md) | 编辑器内发现和 AI 辅助修复 |
| MCP server | [MCP setup](https://docs.skylos.dev/mcp-server) | 将 Skylos 扫描暴露给 AI Agent 和编码助手 |
| Docker image | [Installation](https://docs.skylos.dev/installation) | 无需本地 Python 安装即可运行 Skylos |
| Skylos Cloud | [Cloud workflow](https://docs.skylos.dev/cloud-workflow) | 可选上传和仪表盘工作流 |

## 文档地图

| 你需要 | 阅读 |
|:---|:---|
| 安装、源码安装和 Docker | [Installation](https://docs.skylos.dev/installation) |
| 第一次扫描和核心工作流 | [Quick Start](https://docs.skylos.dev/quick-start) |
| CLI 命令、flags 和示例 | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| CLI 输出模式、pretty 报告和 TUI 快捷键 | [CLI Output Modes](../cli-output.md) |
| CI 设置、PR 门控、注释和分支保护 | [CI/CD](https://docs.skylos.dev/ci-cd) |
| 死代码行为和框架感知 | [Dead Code Detection](https://docs.skylos.dev/dead-code-detection) |
| 安全扫描和污点分析 | [Security Analysis](https://docs.skylos.dev/security-analysis) |
| Rule ID 前缀和产品术语 | [Rule Dictionary](../../dictionary.md) |
| Agent 扫描、验证、修复和模型设置 | [AI Features](https://docs.skylos.dev/ai-features) |
| AI 防御和 LLM guardrails | [AI Defense](https://docs.skylos.dev/ai-defense) |
| MCP server 设置 | [MCP Server](https://docs.skylos.dev/mcp-server) |
| 基线、过滤、抑制和白名单 | [Configuration](https://docs.skylos.dev/configuration) |
| 智能追踪 | [Smart Tracing](https://docs.skylos.dev/smart-tracing) |
| 规则族和语言支持 | [Rules Reference](https://docs.skylos.dev/rules-reference) |
| 云端上传和仪表盘流程 | [CLI to Dashboard](https://docs.skylos.dev/cloud-workflow) |
| VS Code 扩展 | [VS Code Extension](https://docs.skylos.dev/vscode) |
| 基准测试和方法论 | [BENCHMARK.md](../../BENCHMARK.md) |
| 安全政策 | [SECURITY.md](../../SECURITY.md) |
| 发布流程 | [RELEASE_WORKFLOW.md](../../RELEASE_WORKFLOW.md) |
| 贡献 | [CONTRIBUTING.md](../../CONTRIBUTING.md) |

## 常见问题

**Skylos 会替代 Bandit、Semgrep、CodeQL 或 Vulture 吗？**

不会。Skylos 可以和它们一起使用。Skylos 更关注框架感知的死代码信号、PR 门控、AI 时代的回归检查，以及把死代码、安全、密钥和质量整合到一个工作流。

**Skylos 需要 LLM 吗？**

不需要。核心静态分析在本地运行，不需要 API key。LLM 功能是可选的，通过 `skylos[llm]` 和 agent 命令使用。

**可以只扫描变更代码吗？**

可以。本地使用 `skylos . -a --diff origin/main`，或者在 CI 中配置只关注新发现。

**如何处理有意的动态代码？**

使用基线、白名单、内联抑制或运行时追踪。参见 [configuration docs](https://docs.skylos.dev/configuration) 和 [smart tracing docs](https://docs.skylos.dev/smart-tracing)。

## 贡献与支持

- 安全问题请通过 [SECURITY.md](../../SECURITY.md) 报告。
- Bug 和误报请附带最小复现。
- 发送 PR 前请阅读 [CONTRIBUTING.md](../../CONTRIBUTING.md)。
- 项目质量和门控要求请看 [QUALITY.md](../../QUALITY.md)。
- 社区支持请加入 [Discord](https://discord.gg/Ftn9t9tErf)。

## 许可证

Skylos 使用 [Apache License 2.0](../../LICENSE)。

<!-- mcp-name: io.github.duriantaco/skylos -->
