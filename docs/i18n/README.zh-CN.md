<div align="center">
    <img src="../../assets/DOG_1.png" alt="Skylos" width="160">
    <h1>Skylos</h1>
    <p><strong>拿出证据的代码检查。</strong></p>

[![PyPI version](https://img.shields.io/pypi/v/skylos)](https://pypi.org/project/skylos/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)

[文档](https://docs.skylos.dev) · [快速开始](#quick-start) · [官网](https://skylos.dev) · [VS Code](../../editors/vscode/README.md) · [Discord](https://discord.gg/Ftn9t9tErf)

[English](../../README.md) | [Deutsch](./README.de.md) | **简体中文**

</div>

## Skylos 是什么？

Skylos 是一个免费、开源（Apache-2.0）的代码检查工具，检查你和你的编码智能体写的代码。它在你的机器上运行，也可以运行在智能体的工作循环中，或作为 Pull Request 门控。无需账号、API 密钥或 LLM。

Claude Code、Codex 和 Cursor 等编码智能体写代码的速度远超任何人的审查速度，而且会反复犯同样的错误。它们删除或跳过失败的测试后就说“完成了”；安装不存在的包，导入没人写过的函数；留下注入漏洞和硬编码的密钥。Linter 和安全扫描器各自只能在事后发现其中一部分。Skylos 在一个工具里检查全部问题，并且在还来得及阻止的环节介入。

适用于：

- **让智能体写代码的开发者**：希望在智能体工作时就检查它，而不是事后。
- **维护者**：希望每个 Pull Request 都有一道免费检查。
- **已有代码库**：用一次扫描得到安全、密钥、依赖、质量和死代码问题，支持 Python、TypeScript、Java、Go 和[更多语言](#language-support)。

## 工作方式

Skylos 在四个环节介入：

| 时机 | 命令 | 拦截什么 |
|:---|:---|:---|
| 智能体工作时 | `skylos agent install-hooks` | 编造的包安装、读取含密钥的文件、绕过 Git 钩子；检查每次编辑 |
| 智能体说“完成”时 | `skylos done --base main` | 删除或跳过的测试、放宽的 CI 步骤、被关闭的 lint 或类型检查、只为测试写的特殊分支；运行你的测试 |
| 每个 Pull Request | `skylos cicd init` | 严重安全问题、密钥和严重 AI 代码错误，以及超出你设定上限的问题 |
| 任何时候，整个仓库 | `skylos . -a` | 安全漏洞、密钥、有漏洞的依赖、质量回归、AI 代码错误、死代码 |

## 示例

用全部检查扫描一个 20 行的 Flask 应用（节选）：

```text
$ skylos . -a --format concise
app.py:15  SKY-D211  Possible SQL injection: tainted or string-built query.
app.py:5  SKY-L012  Import from local module 'billing' requests 'issue_refund', but that name is not defined or re-exported there.
app.py:8  SKY-S101  Potential stripe secret detected
requirements.txt:1  SKY-SCA-GHSA-68rp-wp8r-4726  flask@3.1.2: Flask session does not add `Vary: Cookie` header when accessed in some ways
billing.py:1  SKY-U001  unused function: charge_card
```

每条结果都给出文件、行号和规则。安全问题在有记录时会显示从来源到危险调用的路径；`--format json` 保留全部证据。

<a id="quick-start"></a>

## 快速开始

```bash
pip install skylos
skylos . -a               # 对当前仓库运行全部检查
skylos done --base main   # 智能体真的完成了吗？运行你的测试并与 main 比较
skylos cicd init          # 为每个 Pull Request 添加 Skylos 检查
```

在用编码智能体？两个命令：

```bash
skylos setup   # 每个仓库一次：连接 Claude Code 和 Codex，安装它们的钩子，让 Done 运行你的测试，写入 PR 检查
skylos open    # 每天：代码结构图、用大白话说明改了什么、每次检查的结果
```

[教程](../workflow.md)演示了一次真实会话：智能体修改代码、被拦截，然后根据 Skylos 的修复说明完成修复。

单独运行 `skylos .` 会执行快速的死代码扫描。`skylos cloud` 会上传结果，在 Skylos Cloud 上跟踪每个分支；这是可选的。

## 检查智能体的每次编辑

安装钩子，在智能体工作时就进行检查：

```bash
skylos agent install-hooks            # Claude Code
skylos agent install-hooks --codex    # Codex
skylos agent install-hooks --cursor   # Cursor
```

- **每次编辑后：** 检查改动的行是否有安全问题、密钥和 AI 代码错误，并告诉智能体要修什么。
- **读取文件前：** 阻止读取含硬编码密钥的文件。
- **安装包之前**（`pip`、`uv`、`npm`、`pnpm`、`bun`、`go` 等）：阻止编造的或仿冒的包，无法验证的安装会先询问。
- **执行 Git 命令前：** 阻止 `--no-verify` 等绕过 Git 钩子的方式。
- **停止时：** 只要智能体引入的问题还没解决，就不允许它说“完成”。

如果 Skylos 自身出错，该操作会被放行，同时你和智能体都会被告知它未经检查。参见[智能体钩子](../agent-hooks.md)。

## 智能体真的完成了吗？

```bash
skylos done --base main
```

`skylos done` 将分支与 `main` 比较并运行你的测试。它会指出：

- 删除、跳过或削弱的测试
- 放宽的测试设置和 CI 测试步骤
- 被关闭的 lint 或类型检查
- 专门为测试写的特殊分支
- 分支留下的、已无调用者的代码（仅提示，不拦截）

测试失败时，它会在 `main` 上重跑该测试，并把失败标记为“新引入”或“原本就失败”。它会把凭据写入 `.skylos/receipts/`。pytest 会自动运行；其他测试工具只需一行配置：

```toml
[tool.skylos.done]
test_command = "npm test"
```

它从 `main` 读取设置，因此分支无法放宽对自己的检查。退出码：`0` 通过，`1` 被拦截，`2` 无法运行。参见 [Done 门控](../done-gate.md)以及它[漏掉的情况](../done-gate-benchmark.md)。

<a id="cicd"></a>

## 门控 Pull Request

无需账号或令牌：

```bash
git checkout -b add-skylos-gate
skylos cicd init --no-upload
git add .github/workflows/skylos.yml
git commit -m "Add Skylos pull request gate"
git push -u origin add-skylos-gate
```

该工作流会检查每个 Pull Request 改动的行，并在找到测试时运行 `skylos done`。`skylos cicd init` 也支持 GitLab CI、Jenkins、Bitbucket Pipelines、Azure Pipelines 和 CircleCI（[任意 CI](../ci-platforms.md)）。

出现严重安全问题、密钥或严重 AI 代码问题（例如导入一个不存在的包）时，门控一定失败。其他问题只有超出你设定的上限才会失败：

```toml
[tool.skylos.gate]
max_high = 5          # 允许的高危安全问题数
max_quality = 10      # 允许的质量问题数
max_ai_defects = 10   # 允许的 AI 代码问题数
```

策略从基础分支读取，因此 Pull Request 无法放宽自己的门控。每次运行最后会输出 `Quality Gate: PASSED`、`FAILED`（退出码 1）或 `INCOMPLETE`（退出码 2）及原因。演练：[你的第一个门控 Pull Request](../first-gated-pr.md)。

需要人工审批有风险的改动？`skylos cicd init --risk-review` 会添加一项检查：当 Pull Request 删除测试、移除鉴权检查、改动依赖或削弱 CI 时，等待人工批准。参见 [Risk review](../risk-review.md)。

## 扫描仓库

```bash
skylos .                         # 死代码（快速，默认）
skylos . -a                      # 全部检查
skylos . -a --diff origin/main   # 只看改动行上的问题
skylos . --format pretty         # 按文件分组并附代码片段的报告
skylos . --tui                   # 键盘操作的分诊界面
skylos . -a --format json        # 供脚本和智能体使用的完整证据
skylos . --format sarif          # GitHub 代码扫描
skylos cleanup . --top 5         # 按优先级排序的修复清单
```

Skylos 可以替你删除 Python 死代码：`skylos clean . --dry-run` 显示计划，`--apply` 修改文件。输出模式和退出码：[CLI 输出](../cli-output.md)。

## Skylos 能发现什么

| 类别 | 示例 |
|:---|:---|
| AI 代码错误 | 导入不存在的函数、编造的包 API、不存在的包、不可能的版本号、未完成的桩代码、被关闭的安全控制 |
| 安全漏洞 | SQL 注入、XSS、SSRF、路径穿越、命令注入、不安全的反序列化、ReDoS |
| 密钥 | API 密钥、令牌、私有凭据、高熵字符串 |
| 依赖 | 已知 CVE、恶意包、许可证策略、离线 SBOM（CycloneDX、SPDX） |
| 质量 | 复杂度、深层嵌套、重复分支、过长函数、不一致的返回 |
| 死代码 | 未使用的函数、类、导入、文件和依赖，能识别框架约定（FastAPI、Django、Flask、Next.js、React、Laravel 等） |
| CI/CD 与部署 | 有风险的 GitHub Actions 和 GitLab CI、Dockerfile、Docker Compose、systemd、Kubernetes |
| LLM 应用 | 不安全的工具调用、提示注入暴露面、缺少输出校验 |

全部规则：[Rules Reference](https://docs.skylos.dev/rules-reference) 和[规则词典](../../dictionary.md)。

## 验证你构建的 AI 应用

如果你的代码调用 LLM，Skylos 会检查其周围的防护措施，整个过程不调用模型：

```bash
skylos discover .                    # 列出 LLM 调用、智能体工具和提示词位置
skylos defend .                      # 为这些位置的防护措施打分
skylos defend . --fail-on critical   # CI 门控
skylos defend . --format md -o evidence.md   # 含 OWASP LLM Top 10 覆盖情况的证据报告
```

它支持 Python 和 TypeScript/JavaScript；`--owasp-framework agentic` 按 OWASP Agentic Top 10 报告。要用预期回答和工具调用测试一个运行中的智能体，请使用 `skylos agent test`。参见[智能体验证](../agent-verification.md)和[智能体行为测试](../agent-behavior-testing.md)。

<a id="language-support"></a>

## 语言支持

| 语言 | 死代码 | 安全 | 质量 |
|:---|:---:|:---:|:---:|
| Python | 是 | 是 | 是 |
| TypeScript / JavaScript | 是 | 是 | 是 |
| Java | 是 | 是 | 是 |
| Go | 是 | 部分 | 部分 |
| PHP | 是 | 是 | 否 |
| Rust | 实验性 | 部分 | 部分 |
| Ruby | 部分 | 部分 | 否 |
| Dart | 是 | 部分 | 否 |
| C# | 部分 | 部分 | 部分 |
| C++ | 部分 | 否 | 否 |
| Kotlin | 部分 | 部分 | 否 |
| Swift | 部分 | 否 | 否 |
| Shell | 否 | 部分 | 否 |

- Python 的覆盖最深。
- Go 需要原生引擎 `skylos-go`。Linux、macOS 和 Windows 的 PyPI wheel 已包含它；其他平台上 `skylos doctor` 会打印构建命令。
- Dart 需要 `pip install "skylos[dart]"`。
- Rust 死代码默认隐藏；`--confidence 40` 可显示。

完整矩阵和各语言限制：[Language support](https://docs.skylos.dev/language-support)。

## 配置

`skylos init` 会在 `pyproject.toml` 中加入初始配置。没有该文件的项目可以使用 `skylos.toml`，键相同，写在顶层：

```toml
# skylos.toml
exclude = ["generated", "dist"]

[gate]
max_high = 5

[done]
test_command = "npm test"
```

在 monorepo 中，每个包都可以有自己的配置文件；按键取离得最近的那个。`skylos doctor` 会显示正在使用哪些文件。

带理由地忽略单条结果：

```python
query = build_query(user_id)  # skylos: ignore[SKY-D211] user_id is an int from the router
```

如果要接受现有问题、只拦截新问题，运行 `skylos baseline .`，然后用 `--baseline` 扫描。更多：[配置](https://docs.skylos.dev/configuration)。

## 集成

| 集成 | 作用 |
|:---|:---|
| [GitHub Action](../../action.yml) | Pull Request 门控，可选的容器镜像门控 |
| [GitLab、Bitbucket、Azure、Jenkins、CircleCI](../ci-platforms.md) | 对应 CI 的 Pull Request 门控 |
| [智能体钩子](../agent-hooks.md) | Claude Code、Codex 和 Cursor 的每次编辑都会被检查 |
| [MCP 服务器](https://docs.skylos.dev/mcp-server) | 把 Skylos 扫描作为 AI 助手的工具 |
| [VS Code 扩展](../../editors/vscode/README.md) | 在编辑器中查看结果 |
| [Skylos Cloud](../skylos-cloud.md) | 可选：按分支跟踪结果和门控，长期可见 |

## 安装选项

```bash
pip install skylos              # 核心检查
pip install "skylos[llm]"       # 使用 LLM 的智能体命令
pip install "skylos[all]"       # 全部可选扩展
```

或运行容器镜像：

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest . -a
```

其他扩展（`lint`、`verdict`、`dart`）、按 Python 版本区分的镜像标签和源码安装：[安装](https://docs.skylos.dev/installation)。

## 哪些数据会离开你的机器

只有当你运行明确会上传的命令（如 `skylos cloud` 或 `--upload`）时，你的代码和结果才会发送到 Skylos Cloud。仅保存登录状态不会上传任何内容。没有分析统计。

依赖和包检查只把包名和版本发送给 OSV 和公共注册表，从不发送源代码。LLM 命令会把代码发送给你配置的模型提供商。每个请求、触发条件以及如何关闭：[Privacy and network](../privacy-and-network.md)。

## 成果

10 个借助 Skylos 完成的死代码清理 PR 已合并到 9 个开源项目，包括 [Black](https://github.com/psf/black/pull/5041)、[NetworkX](https://github.com/networkx/networkx/pull/8572)、[Optuna](https://github.com/optuna/optuna/pull/6547)、[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136) 和 [pypdf](https://github.com/py-pdf/pypdf/pull/3685)。[Real-World Results](../../REAL_WORLD_RESULTS.md) 列出了我们记录的全部 26 个 PR，包括被关闭或回滚的。这些是被接受的清理 PR，不代表背书。

方法、带日期的结果和与其他工具的对比：[BENCHMARK.md](../../BENCHMARK.md)。

## 常见问题

**Skylos 能替代 Semgrep、CodeQL、Bandit 或 Vulture 吗？**
不能。它与这些工具并行使用，补充智能体检查、能识别框架的死代码检测，以及覆盖安全、密钥、依赖和质量的统一门控。

**需要 LLM 吗？**
不需要。核心检查在本地运行，不调用模型。LLM 功能是可选的（`skylos[llm]`）。

**免费吗？**
CLI 免费且开源。Skylos Cloud 是可选的，提供免费方案；参见[价格](https://skylos.dev/pricing)。

**可以只检查我的改动吗？**
可以：`skylos . -a --diff origin/main`。被移除的安全检查（例如删掉的鉴权装饰器）仍会被报告。

**只被动态调用的代码怎么办？**
使用行内忽略、基线，或用 `--trace` 记录实际运行的代码。参见 [Smart tracing](https://docs.skylos.dev/smart-tracing)。

更多：[FAQ](https://docs.skylos.dev/faq)。

## 文档

| 需求 | 阅读 |
|:---|:---|
| 所有命令和参数 | [CLI 参考](https://docs.skylos.dev/cli-reference) |
| 安装、扩展、Docker | [安装](https://docs.skylos.dev/installation) |
| 配置文件、忽略、基线 | [配置](https://docs.skylos.dev/configuration) |
| 输出格式和退出码 | [CLI 输出](../cli-output.md) |
| 智能体钩子 | [智能体钩子](../agent-hooks.md) |
| `skylos done` | [Done 门控](../done-gate.md) |
| Pull Request 门控 | [第一个门控 PR](../first-gated-pr.md)、[任意 CI](../ci-platforms.md) |
| 安全与污点分析 | [Security](https://docs.skylos.dev/security-analysis) |
| 依赖、SBOM、许可证 | [Dependency scanning](../dependency-scanning.md)、[许可证](../license-compliance.md) |
| AI 代码检查 | [AI code verification](../ai-code-verification.md) |
| 网络请求 | [Privacy and network](../privacy-and-network.md) |
| 规则 ID | [规则词典](../../dictionary.md) |

## 参与贡献

- 提交 Pull Request 前请阅读 [CONTRIBUTING.md](../../CONTRIBUTING.md)。
- 用 `skylos feedback` 报告问题（无需账号），或附上最小复现提交 issue。
- 安全问题请通过 [SECURITY.md](../../SECURITY.md) 报告。
- 分析器改动会用 [liveness_primer](https://github.com/mcdigman/liveness_primer) 在真实项目上测试，该工具由 [Matthew Digman](https://github.com/mcdigman) 构建。参见[指南](../liveness-primer.md)。
- 可以参与的方向：[ROADMAP.md](../../ROADMAP.md)。交流：[Discord](https://discord.gg/Ftn9t9tErf)。

## 许可证

Apache License 2.0。参见 [LICENSE](../../LICENSE)。
