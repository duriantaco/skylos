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

Skylos 是一款面向 Python、TypeScript、JavaScript、Java、Go、PHP、Rust、Ruby、Dart、C#、C++、Kotlin 和 Shell 仓库的开源静态分析 CLI。它默认在本地运行，也可以作为 CI/CD PR 门控使用。Python、TypeScript/JavaScript 和 Java 的覆盖最深，其他语言的支持范围见“语言支持”表。

如果你使用 Vulture 检测死代码、Bandit 做安全检查，或使用 Semgrep、CodeQL、GitHub Advanced Security 做 CI 门控，Skylos 可以作为补充：它更关注框架感知的死代码检测、差异感知的回归检查，以及适合 PR 审查的反馈。

## 60 秒开始

```bash
pip install skylos
skylos .            # 查找问题；代码和发现的问题都留在本机
skylos cloud        # 可选：在 Skylos Cloud 上按分支跟踪结果
skylos cicd init    # 为每个拉取请求添加 Skylos 检查
```

使用编码代理时，只需要两个命令：

```bash
skylos setup   # 每个仓库一次：连接 Claude Code 和 Codex，安装它们的钩子，让 Done 运行测试，写入 PR 检查，生成代码地图
skylos open    # 每天：代码图、用简单语言说明的改动、每一次检查
```

检查由你的代理自己运行。[教程](../workflow.md)记录了一次真实会话：代理描述代码、
修改代码、被拦下，然后按照 Skylos 的修复说明修好。

`skylos cloud` 运行全部检查，显示发现的问题并上传，然后打印当前分支的质量门结果和一个链接：

```text
✗ Quality gate on feat/login: FAILED (was PASSED on 24 Oct 15:38 UTC, 1ba9895) · 1 critical security issue
  Open: https://skylos.dev/dashboard/projects/<project>?branch=feat%2Flogin
  Sent: findings and the Done receipt (fail) · laptop upload, unverified until CI runs the workflow
  Next: fix the issues behind the failed gate, then run skylos cloud again.
```

第一次运行会打开浏览器登录并为此仓库选择项目。它发送的是发现的问题：文件路径、最多
7 行的代码片段（密钥类问题不带片段）、分支、提交、每个被标记行的 git 作者邮箱，以及函数和类的
概览（名称、文件、行号、大小、调用关系）。不会发送你的仓库。当仓库已提交 `[tool.skylos.done]`
表（`skylos setup` 会写入）且工作区干净时，它还会一并发送本次提交的 Done 回执（没有回执时先运行
`skylos done`）；`Sent:` 行说明哪些内容到达了 Skylos Cloud。来自笔记本的上传在 CI 运行工作流之前
视为未验证。即使 Skylos Cloud 质量门失败，退出码
也是 `0`；加上 `--gate` 时退出码为 `1`（用于 CI）。通过质量门永远不需要密钥：修复导致失败的问题即可。详见
[Skylos Cloud](../skylos-cloud.md)。

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

加 `--upload` 时（本机已用 `skylos login` 登录 Skylos Cloud 时这是默认值；未登录时默认不加上传作业），
工作流还会通过 GitHub OIDC 上传到 Skylos Cloud：默认分支的推送，以及指向默认分支的 PR。PR 在没有任何凭据的作业中作为不可信数据扫描，再由一个从不检出其文件的作业上传。

使用 GitLab CI、Jenkins、Bitbucket Pipelines、Azure Pipelines 或 CircleCI？同一条
`skylos cicd init` 会为该 CI 设置 PR 门控，详见 [Skylos on any CI](../ci-platforms.md)。

需要更多命令？阅读 [CLI Reference](https://docs.skylos.dev/cli-reference)。

## 选择你的工作流

| 目标 | 命令 | 你会得到什么 | 详细文档 |
|:---|:---|:---|:---|
| 第一次死代码扫描 | `skylos .` | 发现未使用的函数、类、导入、文件和框架入口点问题 | [死代码文档](https://docs.skylos.dev/dead-code-detection) |
| 安全与质量审计 | `skylos . -a` | 增加危险数据流、密钥、依赖和质量检查 | [安全文档](https://docs.skylos.dev/security-analysis) |
| 可分享的一页报告 | `skylos report .` | 生成 `skylos-report.html`：结论（“Not ready: 1 blocking issue”）、最先要修的五个风险及修复建议和文档链接、按类别的问题数、被抑制的数量和未覆盖的检查；不会上传任何内容 | [CLI Output Modes](../cli-output.md) |
| AI 复核问题 | `skylos . -a --ai-review` | 各语言的未使用代码问题和 Python 文件中的安全问题都会得到 AI 判断：确认、AI 不同意或不确定。不会隐藏任何问题，门禁结果不变；使用 `skylos cloud --ai-review` 时判断会显示在 Skylos Cloud | [AI review](../ai-review.md) |
| 可选 Python lint | `pip install "skylos[lint]" && skylos lint .` | 通过 Skylos CLI 运行 Ruff，并保留其原生配置、输出、修复和退出码 | [Python linting](../python-linting.md) |
| PR 门控 | `skylos cicd init` | 为你的 CI 设置 PR 门控：生成带注释和失败阈值的 GitHub Actions 工作流，或为 GitLab CI、Jenkins、Bitbucket Pipelines、Azure Pipelines 和 CircleCI 生成门控配置 | [CI/CD 指南](https://docs.skylos.dev/ci-cd) |
| 更易读的终端报告 | `skylos . --format pretty` | 按文件分组展示发现，包含严重级别标记、代码片段和可复制的 `file:line` 位置 | [CLI Output Modes](../cli-output.md) |
| 可选择的终端界面 | `skylos . --tui` | 打开键盘驱动的分类列表、发现列表和详情面板 | [CLI Output Modes](../cli-output.md) |
| 审查用的变更地图 | `skylos done map --base origin/main` | 列出每个改动的 Python 或 TypeScript/JavaScript 函数：新旧代码、新增和删除的调用、调用者、被删除的安全检查，以及应该先读哪些改动；由代码计算得出，不是模型生成 | [Change map](../change-map.md) |
| 代码库图谱 | `skylos graph open` | 在本地浏览器中展示每个 Python 和 TypeScript/JavaScript 函数和类（Go、Java、Rust 和 PHP 为初步支持，调用按名称匹配），按区域分组，谁调用谁、测试及其期望输出；标出改动的代码，并说明逻辑是否保持不变（只有能证明时才这样说）。通俗英文说明由你的编码代理、你自己的模型密钥或 Skylos（消耗额度）生成；Skylos Cloud 可以在每个拉取请求上发布逻辑变更评论。`skylos done map` 把每处改动分为“先读”“要读”“略读”和“可跳过”（只有能证明逻辑不变时才可跳过）；相应的 MCP 工具不需要密钥 | [Codebase graph](../graph.md) |
| 只审查变更行 | `skylos . -a --diff origin/main` | 聚焦当前 PR，避免被历史债务淹没 | [质量门控](https://docs.skylos.dev/quality-gate) |
| 运行时辅助死代码检测 | `skylos . --trace` | 用测试运行轨迹降低动态代码误报 | [Smart Tracing](https://docs.skylos.dev/smart-tracing) |
| AI 辅助审查 | `skylos agent scan .` | 静态分析加可选 LLM 审查和修复建议 | [AI Features](https://docs.skylos.dev/ai-features) |
| LLM 应用防护 | `skylos defend .` | 查找缺失的 AI 应用防护措施并映射到 OWASP LLM 风险 | [AI app safety](https://docs.skylos.dev/ai-defense) |
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

# 通过 `skylos lint` 使用 Ruff Python lint
pip install "skylos[lint]"

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
| Go | 是¹ | 部分¹ | 部分 | 死代码和部分安全基准覆盖 |
| PHP | 是 | 是 | 否 | PHP parser 覆盖；安全检查在单个函数或文件内追踪请求数据（超全局变量、Laravel/Symfony/PSR-7/CodeIgniter 请求、Drupal Form API），覆盖命令与代码执行、`include` 文件包含、`echo`/`<?= ?>`/Blade `{!! !!}` XSS、SQL、SSRF、`unserialize` 和文件路径；不跨函数或文件，也不检查 Twig 模板 |
| Rust | 实验性⁴ | 部分 | 部分 | Rust 解析；命令注入、路径穿越、直接不可达语句及重复分支检查 |
| Ruby | 部分 | 部分 | 否 | Tree-sitter 解析；私有辅助方法、明确所属类的方法调用和名称为字面量的 Rails 控制器回调；有限的显式 `Kernel` 调用和反引号命令注入检查 |
| Dart | 是³ | 部分³ | 否 | Dart parser 覆盖；安全检查覆盖命令注入、路径穿越和 SSRF |
| C# | 部分 | 部分 | 部分 | C# 符号、直接代码块中的不可达语句、感知 ASP.NET 的安全检查（请求来源、按接收者类型识别的汇入点、不安全反序列化、XSS）及 NuGet 依赖清单（`.csproj` 和 `packages.lock.json`） |
| C++ | 部分 | 否 | 否 | 仅报告 `.cpp`、`.cc`、`.cxx` 中看似未使用的文件内函数；会读取 C++ 头文件中的引用 |
| Kotlin | 部分² | 部分² | 否 | 词法符号提取；只报告 private 声明和导入；Spring、Ktor、Servlet 和 Android WebView 安全检查 |
| Swift | 部分 | 否 | 否 | 根据语法分析 private/fileprivate 声明的可达性，识别所属类型、局部绑定、回调和调用环；对未知运行时上下文保持保守处理 |
| Shell | 否 | 部分 | 否 | shell 脚本安全检查，覆盖命令注入、SSRF 和路径穿越 |

¹ Go 的死代码和安全检查需要原生 `skylos-go` 引擎。从 4.50 起，Linux、macOS 和 Windows（x86_64 和 arm64）的 PyPI wheel 以及容器镜像都包含该引擎，官方 GitHub Action 会自动构建。其他平台上 `skylos doctor` 会给出构建命令。没有该引擎时只运行 Go 质量检查，Go 文件会被报告为未分析。

² Kotlin 死代码只报告 `private` 类型和函数以及未使用的导入；所有非 private 声明都视为已使用。代码中的任何使用都算引用：类型位置、`::foo`、尾随 lambda 和中缀调用、字符串模板以及 KDoc 链接；运算符约定导入（`getValue`、`plus`、`component1`）从不报告。Kotlin 安全分析是词法级的（没有 Kotlin 解析器），复用 Java 的来源和汇入点：输入来自 Spring 处理方法参数、`HttpServletRequest`、Ktor `call.parameters`、`call.receive<T>()` 和 WebFlux `ServerRequest`；检查覆盖命令注入（SKY-D212、SKY-D203）、包括字符串模板的 SQL 注入（SKY-D211）、路径穿越（SKY-D215）、SSRF（SKY-D216）、开放重定向（SKY-D230）、HTML 响应 XSS（SKY-D226）、`ObjectInputStream`/`XMLDecoder`（SKY-D204、SKY-D233）、XXE（SKY-D236）、SpEL/JNDI（SKY-D237），以及 Android WebView JavaScript 桥（SKY-D257）和 `file://` URL 文件访问（SKY-D258）。数据流只在单个函数或路由 lambda 内跟踪。密钥扫描覆盖 `.kt` 和 `.kts` 文件。

³ Dart 检查需要可选依赖 `skylos[dart]`（`pip install "skylos[dart]"`，安装时需要 C 编译器）。未安装时，包含 `.dart` 文件的扫描会把它们报告为未分析（`SKY-ANALYSIS-INCOMPLETE`）。

⁴ Rust 死代码是实验性功能：trait 方法调用、跨 crate 使用的 `pub` 项、重新导出和宏都不会被解析。Rust 候选项的置信度最高为 40，低于默认阈值 60，因此只有加上 `--confidence 40` 才会列出。

上表所有语言的内联抑制用法相同：在问题所在行的注释里写 `skylos: ignore[SKY-D211] 原因`（只抑制列出的规则）、`skylos: ignore`（抑制所有规则），或用 `skylos: ignore-start` … `skylos: ignore-end` 包住一段代码（Python、Shell、PHP 和 Ruby 用 `#`，其他语言用 `//` 或单行 `/* */`）。它适用于死代码、安全、质量和密钥检查；字符串字面量里的文字不算数，其他工具的标记（`#nosec`、`//nolint`、`NOSONAR`、`@SuppressWarnings`）不会隐藏 Skylos 的问题。

`--secrets` 还会读取 shell 脚本（包括以 shell `#!` 行开头、没有扩展名的脚本）、C 和 C++ 源文件与头文件、Dockerfile、Terraform `.tf`/`.tfvars`/`.hcl`、`.properties`、XML、Gradle、`.npmrc` 和 `.pypirc`。

C# 死代码检查采用保守策略：完整扫描可执行或 Web 应用时，未被引用的 public
类型和方法会作为低置信度候选项；库的公开 API、protected 成员及已知的框架或
配置入口仍视为可被外部使用。构造函数只有在私有、带参数且没有任何调用时才会
报告为未使用函数（与 Roslyn IDE0051 规则一致）；控制器和依赖注入的构造函数由
框架调用。暂不分析 C# 源文件的可达性；质量检查可识别直接代码块中无条件 `return`、`throw`、
`break` 或 `continue` 后的语句，但并非完整控制流分析。安全检查（`--danger`）把
ASP.NET 请求数据视为输入：控制器 Action、Razor Page 处理程序、Minimal API 和
`[From*]` 参数以及 `Request.*`，不包括构造函数参数或普通服务参数，并会跟踪到
同一文件中的辅助方法。它报告 SQL 注入（ADO.NET、EF 原始 SQL、Dapper）、命令注入、
路径遍历、SSRF（`HttpClient`、`WebClient`、`WebRequest`、RestSharp）、开放重定向
（`LocalRedirect` 或 `Url.IsLocalUrl` 检查除外）、不安全反序列化（`BinaryFormatter`
系列、Json.NET `TypeNameHandling`、`SimpleTypeResolver`）以及通过
`HtmlString`/`Html.Raw`/`MarkupString` 和 HTML 响应产生的 XSS，每条都带 CWE。
与汇入点同名的方法（如仓储的 `GetAsync`）只有在接收者类型匹配时才计入。使用
`--secrets` 或 `-a` 时，也会对 `.cs` 文件运行通用密钥扫描。C# 污点分析暂不跟踪
`.cshtml`/`.razor` 标记、跨文件数据流以及插值原始字符串中的表达式。SCA 会收集
`.csproj` 中直接声明的 NuGet `PackageReference`；
只有无条件的精确 `Version`（`[version]`）且没有本地 `Update`/`Remove` 修改时
才会查询漏洞；`VersionOverride` 和集中管理的版本不在此范围内。普通版本号只是最低版本约束；没有已解析的
锁文件时，实际安装版本及漏洞状态仍未知。有 `packages.lock.json`（`RestorePackagesWithLockFile`）时，
会按每个目标框架检查所有已解析的包，包括传递依赖。

规则族和扫描范围请看 [Rules Reference](https://docs.skylos.dev/rules-reference)。

## 依赖文件

依赖漏洞扫描（`--sca`，`-a` 已包含）把下列文件当作数据读取，并按其中记录的精确版本查询 OSV：

| 生态 | 锁文件（全部已记录的包） | 清单文件（只用精确版本；版本范围记为未解析） | 会列出但不读取 |
|:---|:---|:---|:---|
| PyPI | `uv.lock`、`poetry.lock`、`Pipfile.lock` | `requirements.txt`、`pyproject.toml`、`setup.cfg`、`setup.py` | 没有锁文件的 `Pipfile` |
| npm | `package-lock.json`、`npm-shrinkwrap.json`、`pnpm-lock.yaml`、`yarn.lock`、`bun.lock` | `package.json` | `bun.lockb` |
| Go | | `go.mod` | Go 1.17 之前的 `go.sum` |
| Maven / Gradle | `gradle.lockfile` | `pom.xml`（properties、本地父 POM 和 `<dependencyManagement>`） | 没有 `gradle.lockfile` 的 `build.gradle(.kts)` |
| crates.io | `Cargo.lock` | `Cargo.toml`（`=x.y.z`） | |
| Packagist | `composer.lock` | `composer.json` | |
| RubyGems | `Gemfile.lock` | | 没有锁文件的 `Gemfile` |
| Pub | `pubspec.lock` | `pubspec.yaml` | |
| NuGet | `packages.lock.json` | `*.csproj`（`[x.y.z]`） | |

Git、本地路径、SDK、私有仓库和分支（`dev-*`）条目会列为未检查，从不当作公共包查询。详见 [Dependency scanning](../dependency-scanning.md)。

恶意软件公告（`MAL-*`、CWE-506，例如被劫持的 `chalk`、`debug` 和 `xrpl` 版本）报告为 `CRITICAL` 并带有 `metadata.malicious`，不会因为只是开发依赖而降级，并提示你删除该包、轮换安装过程可能读取到的所有凭据。同一次扫描还会通过 ca9 引擎做供应链检查：针对你配置的 `internal_packages` 的依赖混淆（`SKY-SCA-SRC001`）、未固定到提交的 Git 依赖和没有哈希的 URL 依赖（`SKY-SCA-SRC003`）、Pull Request 中把包指向仓库此前未使用的来源（`SKY-SCA-SRC004`）、没有完整性哈希的锁文件条目（`SKY-SCA-INT001`），以及设置了 `min_release_age_hours` 时比该时间窗口更新的版本（`SKY-SCA-AGE001`）。JSON 还会包含包清单和供应链状况（锁文件已提交、CI 冻结安装、禁用安装脚本、发布冷却期、Action 已固定、没有 `pull_request_target` 检出）。详见 [Supply-chain checks](../dependency-scanning.md#supply-chain-checks)。

在 Pull Request 中（`--diff` 或 `--diff-base`），如果改动削弱了安装加固设置，`--sca` 也会让门禁失败：删除或缩短发布冷却期、重新开启安装脚本、向 pnpm `allowBuilds` 或 npm `allowScripts` 添加包、把 Action 从 SHA 改成标签（`SKY-SCA-HRD001`）。按包审核过的例外写在基础分支上。使用 `--review-upgrades`（`skylos cicd init` 生成的工作流默认开启）时，每个 npm 或 PyPI 升级都会下载新旧两个版本并作为数据比较：新增安装钩子、`.pth` 或 `sitecustomize` 代码、解码后执行会让门禁失败（`SKY-SCA-UPG001`）；新增导入时网络调用或二进制文件会列出供审查（`SKY-SCA-UPG002`）。`--danger` 会报告提交到仓库的 Agent 和编辑器钩子（`SKY-D365`、`SKY-D366`：`.claude/settings.json` 的 `SessionStart`、`.vscode/tasks.json` 的 `folderOpen`）、未固定版本、来自隐藏路径或冒充厂商的 MCP 服务器（`SKY-D367`-`SKY-D369`）、覆盖 Agent API 基础地址（`SKY-D370`）、因重复键而隐藏实际执行内容的配置（`SKY-D377`）以及有风险的发布作业（`SKY-D371`-`SKY-D376`）。全仓库扫描或在这些规则出现前保存的基线只列出它们；新增或修改钩子的 Pull Request 会失败，在缺少 ca9 时修改这些文件的 Pull Request 也会失败。详见 [Agent configuration and publish-job rules](../agent-config-and-publish-rules.md)。

Agent 钩子（`skylos agent install-hooks`）在安装前还会拦截被报告为恶意软件的版本、发布不足 48 小时的版本（并给出可改用的较旧版本），以及丢失了此前版本 provenance 的 npm 版本；`npm ci`、`uv sync` 等锁文件安装会对每个锁定的包做恶意软件检查。用 `[tool.skylos.supply_chain] min_release_age_hours` 调整等待时间（设为 0 即关闭）。

MCP 服务器和 Agent 钩子：Agent 钩子会拦截未固定版本或恶意的 MCP 服务器（`claude mcp add`、编辑 `.mcp.json`），并给出应使用的精确固定版本命令；在新增 SessionStart 或 folderOpen 钩子前先询问；并在每次会话中重新检查已配置的服务器。`skylos agent harden` 会输出每个 Agent 自身的凭据禁止访问设置和固定版本的 MCP 设置（用于策略和审计，不是沙箱）。

## 基准测试快照

Skylos 有已提交的死代码、安全、质量、Agent 审查和 AI 代码错误回归套件。
这些是回归门控，不是独立的准确率基准。用例数量会随套件更新；请以各套件的 manifest 为准。

方法论、注明日期的结果、对比数据和限制请看 [BENCHMARK.md](../../BENCHMARK.md)。

## 项目证据

Skylos 辅助的死代码清理 PR 已被
[Black](https://github.com/psf/black/pull/5041)、
[NetworkX](https://github.com/networkx/networkx/pull/8572)、
[Optuna](https://github.com/optuna/optuna/pull/6547)、
[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136)、
[pypdf](https://github.com/py-pdf/pypdf/pull/3685)
和 [beets](https://github.com/beetbox/beets/pull/6473) 合并。这些是已被接受的清理 PR，不代表相关项目背书。详见
[Real-World Results](../../REAL_WORLD_RESULTS.md)。

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
| 通过 Skylos CLI 使用可选 Ruff lint | [Python Linting](../python-linting.md) |
| CI 设置、PR 门控、注释和分支保护 | [CI/CD](https://docs.skylos.dev/ci-cd) |
| 死代码行为和框架感知 | [Dead Code Detection](https://docs.skylos.dev/dead-code-detection) |
| 安全扫描和污点分析 | [Security Analysis](https://docs.skylos.dev/security-analysis) |
| Rule ID 前缀和产品术语 | [Rule Dictionary](../../dictionary.md) |
| Agent 扫描、验证、修复和模型设置 | [AI Features](https://docs.skylos.dev/ai-features) |
| AI 防御和 LLM guardrails | [AI app safety](https://docs.skylos.dev/ai-defense) |
| 一次改动影响了什么、先读什么（`skylos done map`） | [Change map](../change-map.md) |
| 教程：`skylos setup`、`skylos open`、Pipeline 视图和 PR 检查，来自一次真实的代理会话 | [教程](../workflow.md) |
| 谁调用谁、通俗说明，以及改动后的逻辑是否不变（`skylos graph`） | [Codebase graph](../graph.md) |
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

**Skylos 会替代 Ruff 吗？**

不会。`skylos lint` 是一个委托给 Ruff 的可选命令入口。使用
`pip install "skylos[lint]"` 安装；普通 Skylos 扫描不会运行 Ruff。

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
