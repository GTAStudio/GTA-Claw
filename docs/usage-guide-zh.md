# GTA-Claw 使用指南

本指南介绍本仓库中的 Rust 可执行程序：`gta-claw-cli`、`gta-claw-tui`、`gta-claw-daemon`、
`gta-claw-updater`，以及原生桌面客户端 `gta-claw-desktop`。

文中每一条命令、参数、路径和环境变量都来自源码。凡是尚未实现的能力，本指南直接说明，不做描述。

English version: [docs/usage-guide-en.md](usage-guide-en.md)

---

## 目录

- [0. 当前实际可用的功能](#0-当前实际可用的功能)
- [1. 环境要求](#1-环境要求)
- [2. 从源码构建](#2-从源码构建)
- [3. `gta-claw-cli`](#3-gta-claw-cli)
- [4. `gta-claw-tui`](#4-gta-claw-tui)
- [5. `gta-claw-daemon`](#5-gta-claw-daemon)
- [6. `gta-claw-desktop`](#6-gta-claw-desktop)
- [7. `gta-claw-updater`](#7-gta-claw-updater)
- [8. 配置](#8-配置)
- [9. 故障排查](#9-故障排查)
- [10. 尚未提供的功能](#10-尚未提供的功能)

---

## 0. 当前实际可用的功能

请先读这一节，可以省下不少时间。

Rust 工作空间**尚未**提供与遗留实现完全等价的 Agent 服务，但 `gta-claw-daemon` 已经是真实、但仍不完整的
生产组装。当前真正能做的事情是：

- **连接到已有的 OpenClaw Gateway**——CLI 作为受限的诊断工具，TUI 作为交互式客户端，桌面客户端作为
  原生连接界面。
- **通过 Rust 守护进程提供真实传输**：主 HTTP API、遗留 HTTP 门面、Gateway 和仅限回环地址的 MCP；
  可使用已配置的 GitHub Copilot 提供方，或显式启用 smoke 提供方。
- **运行已配置的 Teams、Telegram、Discord 和 WhatsApp 路径**，并支持信号处理、配置重载和可验证的关停
  排空过程。
- **执行一次签名更新**，使用独立的更新器。

CLI 仍没有聊天命令，守护进程也尚未达到完整等价：会话与轮次状态不持久化，没有交互式审批，也没有装配
`claw-tools`，技能执行同样未被分派。`src/` 下的遗留 Node 服务会继续保留，直到这些缺口和冻结的兼容性证据
义务被关闭——详见 [legacy-node-port-obligations.md](legacy-node-port-obligations.md)。

---

## 1. 环境要求

| 项目 | 说明 |
|---|---|
| Rust 工具链 | 由 `rust-toolchain.toml` 固定为 `1.97.1`，在仓库目录内 `rustup` 会自动选用。最低支持版本为 `1.94.0`。 |
| 平台 | 根工作空间可在 Linux、macOS 和 Windows 上构建。桌面客户端**仅支持 Windows 和 macOS**——在 Linux 上构建会被有意拒绝。 |
| 一个 Gateway | CLI、TUI 和桌面客户端都是客户端程序。要做实际的事情，需要一个可达的 OpenClaw Gateway v4 端点（`ws://` 或 `wss://`）。 |

不需要 Node.js、npm 或任何 JavaScript 运行时，也不允许引入——仓库策略会以测试失败的形式拒绝。

---

## 2. 从源码构建

```sh
git clone https://github.com/GTAStudio/GTA-Claw.git
cd GTA-Claw

# 根工作空间：31 个库 crate 和 6 个可执行程序
cargo build --workspace
cargo test  --workspace
```

执行下面的命令后，release 产物位于 `target/release/`：

```sh
cargo build --workspace --release
```

只需要其中某一个程序时，可以单独构建：

```sh
cargo build -p gta-claw-cli --release
cargo build -p gta-claw-tui --release
cargo build -p gta-claw-daemon --release
```

桌面客户端位于**独立的工作空间**，必须显式指定清单路径：

```sh
cargo build --manifest-path desktop/Cargo.toml --workspace --release
cargo test  --manifest-path desktop/Cargo.toml --workspace
```

在 Linux 上执行上述命令预期会失败：桌面工作空间有意拒绝该平台。

运行与 CI 相同的检查：

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test -p claw-repo-policy        # JavaScript / TypeScript 棘轮策略
```

---

## 3. `gta-claw-cli`

无界面的命令行程序。完整的参数面如下：

```text
usage:
  gta-claw-cli --version
  gta-claw-cli health
  gta-claw-cli send <session-id> <message>
  gta-claw-cli gateway health --endpoint <ws-or-wss-url> --ephemeral-device
      [--token-stdin] [--timeout-ms <250..120000>]
      [--allow-insecure-remote-ws] [--json]
```

`--help` 和 `-h` 会打印上面这段用法说明。除此之外没有其他子命令，也没有其他参数。

### 3.1 `health`——本地运行时健康状态

```sh
gta-claw-cli health
```

输出一行以 `healthy runtime=` 开头的文本，描述本机的操作系统与架构。该命令不访问网络，退出码为 `0`。

未知命令退出码为 `2`，并在标准错误输出 `error: unknown command`。

### 3.2 `send`——有意保留为不可用

```sh
gta-claw-cli send session-9 "hello"
```

该命令以退出码 `8` 结束，并输出 `error: unsupported operation: message transport is not configured`。
这是当前的正确行为，不是缺陷：消息传输适配器尚未装配，CLI 拒绝让人误以为消息已被接受。

### 3.3 `gateway health`——真实的 Gateway 诊断

这是唯一会执行真实网络操作的命令。它建立一条 `ws://` 或 `wss://` 连接，完成已认证的 Gateway v4
challenge / connect / hello 流程，发送一次 `operator.read` 的 `health` RPC，然后在限定时间内干净地关闭。

```sh
gta-claw-cli gateway health \
  --endpoint wss://gateway.example.test \
  --ephemeral-device
```

`--ephemeral-device` 是**必填项**。它会生成一次性的内存内 Ed25519 身份，该身份以及 Gateway 返回的任何
设备令牌都不会被持久化。不过这次连接仍可能在 Gateway 一侧创建配对或设备记录。Windows 和 macOS 上基于
安全存储的持久身份尚未实现。

#### 安全地传入令牌

共享令牌是可选的。确实需要时，请使用 `--token-stdin`，它最多从标准输入读取 4096 字节。
**命令行不接受任何令牌参数，也不会隐式读取环境变量。**

POSIX shell——关闭终端回显，并在正常退出或收到信号时恢复：

```sh
restore_tty() { stty echo; }
trap 'restore_tty' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15
stty -echo
IFS= read -r GTA_CLAW_TOKEN
stty echo
trap - 0 1 2 3 15
gta-claw-cli gateway health \
  --endpoint wss://gateway.example.test \
  --ephemeral-device \
  --token-stdin \
  --json <<EOF
$GTA_CLAW_TOKEN
EOF
unset GTA_CLAW_TOKEN
```

PowerShell：

```powershell
$secret = Read-Host "Gateway token" -AsSecureString
$credential = [pscredential]::new("token", $secret)
$credential.GetNetworkCredential().Password | gta-claw-cli gateway health `
  --endpoint wss://gateway.example.test `
  --ephemeral-device `
  --token-stdin
Remove-Variable credential, secret
```

令牌必须是合法的 UTF-8，且为不含空白字符的、非空的一行；结尾的单个 LF 或 CRLF 会被去掉。

`--token-file` 虽然可以解析，但在**所有平台上都会直接失败**。当前实现不敢声称能在所有受支持的文件系统上
同时证明 Unix 的属主与链接安全性、以及 Windows 的属主 / DACL / FileId 安全性，因此选择拒绝而不是假装支持。

#### 端点规则

端点会在读取标准输入之前完成校验。以下情况一律拒绝：

- 空白字符，以及不可见的格式控制字符或双向排版字符；
- 内嵌的用户名密码、查询字符串和片段标识；
- 非规范的 ASCII 主机名大小写；
- 非 ASCII 的主机名文本——国际化域名必须使用小写的 punycode A-label 形式；
- 补零或为零的端口号；端口必须是大于零的十进制数且不带前导零；
- 未压缩或未加方括号的 IPv6 写法；
- 含有点号段（dot-segment）或百分号编码归一化歧义的路径。

非回环地址的明文 `ws://` 会被拒绝，除非显式传入 `--allow-insecure-remote-ws`。`wss://` 使用客户端的
rustls 传输层。

#### 其他选项

| 选项 | 作用 |
|---|---|
| `--timeout-ms <250..120000>` | 整条命令的截止时间，默认 10 000 毫秒。超出范围属于用法错误。 |
| `--allow-insecure-remote-ws` | 允许对非回环主机使用明文 `ws://`。 |
| `--json` | 输出一个确定性的 JSON 对象，而不是人类可读文本。 |

每个选项最多出现一次；重复或未知的选项属于用法错误。

#### 输出

成功时的人类可读输出：

```text
Gateway health: healthy
endpoint: wss://gateway.example.test
protocol: 4
role: operator
scopes: operator.read
server_version: [redacted peer value]
server_version_status: redacted_peer_value
health_ok: true
health_timestamp_ms: 1753000000000
health_duration_ms: 3
elapsed_ms: 128
identity: ephemeral (may create a pairing/device entry; not persisted)
```

服务端的版本字符串属于对端可控文本，**永远不会**被打印。`--json` 输出 schema 版本 2，采用同样的脱敏
策略，字段为：`schema_version`、`command`、`status`、`category`、`message`、`endpoint`、`protocol`、
`role`、排序去重后的 `scopes`、`server`、`health`、`elapsed_ms`、`identity` 和 `pairing_entry_possible`。

失败时，人类可读输出写入标准错误，格式为
`Gateway health failed: <message> (<category>)`。

#### 退出码

| 退出码 | 类别 | 含义 |
| ---: | --- | --- |
| 0 | 成功 | 已认证的 health RPC 返回了肯定的类型化结果 |
| 2 | 用法 / 配置 | 参数、端点或密钥输入非法 |
| 3 | 传输 / 瞬时故障 | 连接失败或出现瞬时传输故障 |
| 4 | 认证 / 配对 | 认证被拒绝，或需要先完成配对 |
| 5 | 协议 | 版本、分帧或类型化载荷校验失败 |
| 6 | 健康为负 | health 响应或其载荷为否定结果 |
| 7 | 超时 / 取消 | 命令超时、被中断，或未能在限定时间内关停 |
| 8 | 内部错误 | 本地运行时或客户端状态故障 |

Ctrl-C 和超时都会走受限的拆解流程，因此某个无法取消的平台解析器或标准输入工作线程不会让进程无限期存活。

#### 这条命令不是什么

它是一个诊断工具。它不是完整的 CLI，不是管理或聊天界面，不是模型提供方接口，不是持久化的钥匙串身份，
不是 GUI，不是 Gateway 服务端，也不构成任何功能账本（feature ledger）状态的声明。

---

## 4. `gta-claw-tui`

终端客户端。它通过与 CLI 相同的客户端 crate 连接 Gateway。

```text
Usage: gta-claw-tui [--gateway ws://HOST:PORT] [--no-color] [--plain]
Set GTA_CLAW_GATEWAY_TOKEN for authenticated Gateways.
```

`--help` 和 `-h` 打印上面这段文本并以 `0` 退出。未知参数以 `2` 退出。

### 4.1 启动

```sh
# 默认端点：ws://127.0.0.1:18789
gta-claw-tui

# 指定端点
gta-claw-tui --gateway wss://gateway.example.test

# 带认证
GTA_CLAW_GATEWAY_TOKEN='…' gta-claw-tui --gateway wss://gateway.example.test
```

| 变量 | 作用 |
|---|---|
| `GTA_CLAW_GATEWAY_URL` | 默认端点，`--gateway` 优先级更高。 |
| `GTA_CLAW_GATEWAY_TOKEN` | 共享的 Gateway 令牌。没有对应的命令行参数。 |
| `NO_COLOR` | 单色渲染，等同于 `--no-color`。 |
| `TERM=dumb` | 视为非交互终端。 |

### 4.2 界面

| 界面 | 内容 |
|---|---|
| Sessions | 会话导航。 |
| Workspace | 所选会话的对话记录与工具。 |
| Runs | 跨会话的运行状态。 |
| Diff | 工作区差异查看器。 |
| Artifacts | 会话产物查看器。 |
| Help | 键盘操作参考。 |

### 4.3 按键

```text
Tab / Shift-Tab   切换界面
Up/Down 或 j/k    选择与滚动
Enter             打开会话 / 提交回答
y / n             批准 / 拒绝
r                 从 Gateway 刷新
Ctrl-P 或 :       命令面板
1..6              跳转到指定界面
Esc               关闭命令面板
?                 键盘帮助
q / Ctrl-C        安全退出
```

### 4.4 命令面板

按 `:` 或 `Ctrl-P` 打开，输入命令后回车。可识别的命令（不区分大小写）：

`sessions`、`workspace`、`runs`、`diff`、`artifacts`、`help`、`refresh`、`quit`（或 `q`）。

其他输入会在提示行显示 `Unknown command: …`。`Esc` 关闭命令面板。

### 4.5 非交互模式

传入 `--plain`，或标准输出不是交互式终端时，程序不会进入全屏循环，而是只做一次快照：连接 Gateway，
最多等待五秒获取会话列表，打印一帧渲染结果后退出。若 Gateway 未在时限内响应，提示行会显示
`Gateway snapshot timed out`。脚本和 CI 场景应使用这个模式。

---

## 5. `gta-claw-daemon`

```text
usage: gta-claw-daemon [--probe | --check-config] [--config PATH] [--listen ADDRESS] [--legacy-listen ADDRESS] [--gateway-listen ADDRESS] [--mcp-listen ADDRESS] [--state-dir PATH] [--log-file PATH] [--tls-terminated-by-frontend] [--smoke]
```

另外也接受 `--help` 和 `-h`。帮助参数是全局的：只要任一写法出现在任何位置，守护进程就会在创建 Tokio
运行时之前打印用法并成功退出，即使同时存在未知参数或缺少参数值。没有帮助参数时，未知、不完整、非 Unicode
或相互冲突的参数都会被拒绝。

### 5.1 健康探针

```sh
gta-claw-daemon --probe
```

输出一行健康状态后退出。

`--probe` 不能与 `--check-config` 或仅用于服务模式的选项组合。解析器允许在 `--probe` 旁传入
`--config` 和 `--state-dir`，但探针模式不会加载或使用这两个值。

### 5.2 检查配置

```sh
gta-claw-daemon --check-config --config /etc/gta-claw/config.json5
```

加载配置，并执行启动前相同的静态配置、密钥引用、通道覆盖、状态目录和暴露策略检查，但不会打开监听器。
`--check-config` 可与 `--config`、`--state-dir` 一起使用；不能与 `--probe` 或任何监听、日志、TLS 断言及
smoke 选项组合。

### 5.3 提供服务

```sh
gta-claw-daemon
```

服务模式会调用 `serve_production`。它会解析配置，打开持久化的 Gateway 配对、安全审计和目标存储，激活
已签名插件，按条件激活 smoke 提供方或 GitHub Copilot，启动已配置的通道传输，并绑定四类入口：

- 主 18 路由 HTTP API；
- 与遗留 Node 服务兼容的 HTTP 门面；
- Gateway v4 服务；
- 仅限回环地址的 MCP 路由。

四条通道路径都按配置启用：Teams 和 WhatsApp 接入遗留 HTTP 门面，Telegram 和 Discord 则作为受监管的
出站客户端运行。配置 GitHub 令牌后，GitHub Copilot 会在启动时激活；否则提供方保持等待 Device Flow 的
状态。`--smoke` 会显式替换为本地安装诊断提供方。

完整选项如下：

| 选项 | 服务模式行为 |
|---|---|
| `--config PATH` | 从 `PATH` 加载严格 JSON5；未指定时依次使用 `GTA_CLAW_CONFIG` 和经过审计的遗留环境变量迁移。 |
| `--listen ADDRESS` | 主 HTTP 监听地址。默认 `127.0.0.1:0`，即由操作系统分配端口。 |
| `--legacy-listen ADDRESS` | 遗留 HTTP 监听地址。默认在回环地址上使用 `core.server.port`。 |
| `--gateway-listen ADDRESS` | Gateway 监听地址。默认 `127.0.0.1:0`。 |
| `--mcp-listen ADDRESS` | MCP 监听地址。默认 `127.0.0.1:0`；任何非回环地址都会被拒绝。 |
| `--state-dir PATH` | 状态根目录；未指定时依次使用 `GTA_CLAW_STATE_DIR` 和 `$HOME/.gta-claw`。配对、安全审计和目标会持久化到这里，但会话与轮次不会。 |
| `--log-file PATH` | 把普通遥测写入文件，而不是标准错误。 |
| `--tls-terminated-by-frontend` | 断言可信前端负责终止 TLS。它不会让守护进程自行启用 TLS，只允许主 HTTP、遗留 HTTP 或 Gateway 绑定到可路由地址。 |
| `--smoke` | 使用确定性的本地安装诊断提供方。所有显式指定的监听地址都必须保持为回环地址。 |

启动时，它会先安装停止信号处理器，再进行组装——这样即使监管进程在启动过程中要求停止，也能被观察到。
所有必需依赖均就绪后会打印：

```text
ready protocol=1
healthy runtime=<os>-<arch>
service http=<address> legacy=<address> gateway=<address> mcp=<address> provider=<name> config_generation=<n>
```

之后持续提供服务，直到出现下列情况之一：

- 监管进程发出的停止信号——Unix 上的 `SIGTERM`（`systemd`、`docker stop`、`kubectl delete` 发送的正是
  它），或 Windows 上的控制台关闭 / 系统关机；
- 中断信号——Unix 上的 `SIGINT`，Windows 上的 Ctrl-C 或 Ctrl-Break；
- 控制通道（标准输入）上收到 `shutdown` 一行文本。

标准输入到达末尾**不是**停止条件：以关闭的 stdin 启动的守护进程会继续提供服务。
同一控制通道还接受 `status` 和 `reload`；重载会报告已应用的代次及变化域，或报告拒绝原因并让上一代配置
继续服务。

停止时打印一行汇总：

```text
stopped reason=<terminate|interrupt|control> clean=<bool> drained=<n> completed=<n> abandoned=<n> tasks=<terminated>/<spawned>
```

如果仍有未完成的工作，进程会以错误退出，并说明有多少任务被放弃。任务计数是真实的：终止计数由守卫对象的
`Drop` 累加，因此中途被取消的任务同样计入，这让 `tasks=t/s` 成为一次真正的泄漏检查，而不是"关停函数返回了"。

手动停止：

```sh
printf 'shutdown\n' | gta-claw-daemon
```

### 5.4 当前限制

- **会话与轮次只存在于进程内存。** `RuntimeStateStore` 把两者保存在 `Mutex<HashMap>` 中，守护进程重启后
  会全部丢失；单独持久化的 Gateway 配对、安全审计和目标存储不受此限制。
- **没有交互式审批界面。** 运行时使用 `SilentApprovalPort`，它会丢弃审批展示通知；当前装配的插件工具描述
  均标记为不需要审批。
- **没有装配 `claw-tools`。** 并非完全不能执行工具：已签名插件注册的工具和持久化目标工具可通过运行时及
  HTTP/MCP 表面执行。缺失的是 `claw-tools` 的工具目录及其模式校验、授权、路径限制和目标网络校验。
- **技能执行和迁移证据接入均未被分派。** 启动时只读取 `claw_skills::registry()` 作为库存计数；生产路径
  没有调用 `WasmSkillHost` 桥接，因此不会执行任何内置技能。应用层同样没有调用
  `validate_migration_evidence`；该函数只做结构校验，制品的密码学验证仍属于独立的插件信任职责。
- **兼容性证据仍缺失。** `apps/` 下没有测试针对已绑定的守护进程重放 `compat/legacy`。这是等价性证据缺口，
  并不表示安全审计证据不存在：服务路径会打开持久化的安全审计日志。

`packaging/linux/systemd/gta-claw-daemon.service` 提供了一份经过评审的 `systemd` 单元文件，Debian 与 RPM
打包原型会使用它。

---

## 6. `gta-claw-desktop`

基于 Slint 1.17.1 的原生客户端。**仅支持 Windows 和 macOS。**

```sh
cargo run --manifest-path desktop/Cargo.toml -p gta-claw-desktop --release
```

### 6.1 首次运行流程

窗口打开后是三步首次运行流程——**Welcome（欢迎）→ Authorize（授权）→ Trust（信任）**——之后进入
Gateway 连接界面。

需要清楚哪些部分是真实的：欢迎、设备授权和工作区信任这三步是**展示性**的引导流程。这些界面上显示的
设备码和工作区路径是占位内容，点击通过并不会真的执行账号授权。真正执行实际操作的是 Gateway 连接面板。

### 6.2 建立连接

连接面板对自己的范围有明确说明：*"Connect performs the real challenge, connect, hello, and safe health
flow."*（连接会执行真实的 challenge、connect、hello 与安全的 health 流程。）它需要填写：

| 字段 | 说明 |
|---|---|
| Gateway 端点 | 校验规则与 CLI 相同。 |
| 令牌 | 仅本次会话有效。提交的瞬间输入框即被清空，且永不持久化。 |
| 临时身份同意项 | 一个必须显式勾选的复选框：*"I consent to a new ephemeral device identity for this diagnostic session."* |

按钮：**Connect**、**Retry**、**Cancel**、**Disconnect**。

连接成功后，摘要面板只展示有界的非敏感字段——端点、协商的协议版本、角色、生效的 scope、健康状态和身份
模式。可能需要先完成配对；该身份以及签发的任何设备令牌都只存在于有界内存中，断开连接或退出应用时即被丢弃。

界面本身也写明了边界：*"This diagnostic does not enroll a persistent device, store credentials, or enable
chat and account features."*（本诊断不会注册持久设备、不存储凭据，也不启用聊天与账号功能。）

### 6.3 为什么没有 Linux 构建，也没有移动端界面

桌面客户端之所以是独立的 Cargo 工作空间，是因为仓库的可信供应链策略拒绝在根工作空间成员可触及的任何位置
引入 Slint 依赖。同一条策略也决定了 `gta-claw-android` 和 `gta-claw-ios` 只是与界面无关的客户端内核，
本仓库中不包含任何用户界面。CI 会对这两条边界做断言，其中包括断言 Linux 桌面构建必须失败。

---

## 7. `gta-claw-updater`

```text
Usage: gta-claw-updater --manifest URL --current VERSION --target PATH
```

三个参数均为必填。

```sh
gta-claw-updater \
  --manifest https://releases.example.test/gta-claw/manifest.json \
  --current 0.1.0 \
  --target /Applications/GTA\ Claw.app
```

可能的结果：

| 结果 | 输出 |
|---|---|
| 已是最新 | `GTA Claw <version> is current.` |
| 安装完成 | `GTA Claw <version> installed successfully.` |
| 已验证但程序仍在运行 | `GTA Claw <version> is verified at <path>. Close the running application and run the updater again; elevation was not attempted.` |
| Linux | `GTA Claw updates are managed by the system package manager.`——更新器直接以 `0` 退出，不做任何操作。 |

更新过程是签名的、可断点续传的，并且支持回滚。通过包管理器或管道安装脚本进行自我改写的方式被设计性地禁止。

---

## 8. 配置

### 8.1 Rust 侧的配置模型

`claw-config` 是 Rust 工作空间的配置边界。它把 UTF-8 的 **JSON5** 读入不可变的类型化快照，覆盖 47 个冻结的
顶层配置域，拒绝未知的信封字段和固定字段名，以原子方式写入并保留可回滚的持久备份，同时发布类型化的重载
通知。分层解析顺序为：

```text
内置 → 系统 → 用户 → 工作区 → 冻结的遗留环境变量 → 命令行
```

嵌套对象递归合并；数组和标量则整体覆盖下层取值。密钥只以经过校验的环境变量引用或平台存储引用形式持久化，
绝不写入明文；密钥类型在 `Debug`、`Display` 和 Serde 输出中都会自我脱敏。

版本 1 的运行时信封要求提供 `schema_version`，以及下列 `core` 配置域：`auth`、`role`、`channels`、
`server`、`logging`、`sessions`、`copilot`、`legacy`、`updates`、`admin`、`network`。

`gta-claw-daemon` 会通过 `--config PATH` 或 `GTA_CLAW_CONFIG` 加载该模型；两者都未设置时，使用经过审计的
遗留环境变量迁移。`--check-config` 可在不提供服务的情况下校验非网络组装。

### 8.2 部分常用环境变量

| 变量 | 读取方 | 含义 |
|---|---|---|
| `GTA_CLAW_GATEWAY_URL` | `gta-claw-tui` | 默认 Gateway 端点（`ws://127.0.0.1:18789`）。 |
| `GTA_CLAW_GATEWAY_TOKEN` | `gta-claw-tui`、`gta-claw-daemon` | 共享的 Gateway 令牌；设置后守护进程把它作为 Gateway 凭据。 |
| `GTA_CLAW_CONFIG` | `gta-claw-daemon` | 未指定 `--config` 时的配置文件回退值。 |
| `GTA_CLAW_STATE_DIR` | `gta-claw-daemon` | 未指定 `--state-dir` 时的状态根目录回退值。 |
| `GTA_CLAW_ADMIN_TOKEN` | `gta-claw-daemon` | 使用 Bearer 认证启用受保护的 HTTP 路由。 |
| `NO_COLOR` | `gta-claw-tui` | 单色输出。 |
| `TERM` | `gta-claw-tui` | 取值为 `dumb` 时视为非交互。 |
| `GTA_CLAW_CREDENTIALS_DIR` | `claw-provider-sdk` 文件密钥存储 | 覆盖凭据根目录。否则依次为 `$XDG_DATA_HOME/gta-claw/credentials`，再否则 `$HOME`（或 `%USERPROFILE%`）`/.local/share/gta-claw/credentials`。 |
| `CREDENTIALS_DIRECTORY` | `claw-provider-sdk` 文件密钥存储 | systemd 的凭据目录。 |
| `GTA_CLAW_ACPX_LEASE_ID`、`GTA_CLAW_ACPX_SESSION_KEY` | `claw-acp` | ACP 扩展的租约与会话密钥。 |
| `CODEX_HOME`、`XDG_CONFIG_HOME`、`XDG_DATA_HOME`、`APPDATA`、`LOCALAPPDATA`、`HOME`、`USERPROFILE` | `claw-migrate`、`gta-claw-updater` | 源目录与状态目录的发现。 |
| `GTA_CLAW_LOG`、`GTA_CLAW_LOG_FORMAT` | `gta-claw-daemon` | 服务模式遥测的 tracing 过滤器及 `human`/`json` 格式。 |

`.env.example`、`deploy/run.sh` 和 `deploy/conf/` 是**遗留 Node 服务**的产物，不是 Rust 配置的权威
入口。守护进程可以通过经过审计的迁移路径转换冻结范围内的遗留进程环境变量；新部署应使用类型化 JSON5。

---

## 9. 故障排查

**`error: unknown command`，退出码 2。** CLI 只接受 `--version`、`--help`/`-h`、`health`、`send` 和
`gateway health`。

**`explicit --ephemeral-device opt-in is required`。** 不带该参数时 `gateway health` 不会运行。目前还没有
持久身份模式。

**退出码 2 且提示端点问题。** 端点校验器是有意严格的。请检查是否存在尾随空白、大写主机名、查询字符串或
片段标识、补零端口、未转换为 punycode 的国际化域名，或未压缩的 IPv6 字面量。对应提示为
`Gateway endpoint spelling is not canonical (usage_config)`。

**`remote plaintext ws requires explicit diagnostic opt-in (usage_config)`，退出码 2。** 非回环地址的
明文连接需要 `--allow-insecure-remote-ws`。更推荐的做法是把端点改成 `wss://`。

**退出码 3，`Gateway transport failed`。** 端点已通过校验，但连接未建立成功。请检查网络可达性和端口。

**退出码 4。** 认证被拒绝，或 Gateway 要求先完成配对。由于 `--ephemeral-device` 每次运行都会生成全新身份，
要求设备审批的 Gateway 会持续要求配对，直到该设备被批准。

**退出码 7。** 调大 `--timeout-ms`（上限 120 000），或检查网络可达性。

**`token-file input is disabled because secure permissions cannot be proven portably`。** 请改用
`--token-stdin`。

**TUI 只打印一帧就退出。** 说明标准输出不是交互式终端，或 `TERM` 为 `dumb`，或传入了 `--plain`。

**`Gateway snapshot timed out`。** 在快照模式下，Gateway 未能在五秒内返回会话列表。

**守护进程以 "shutdown left work behind" 退出。** 排空过程中有任务被放弃。停止汇总行里的
`tasks=<terminated>/<spawned>` 计数会显示差额。

**桌面客户端在 Linux 上构建失败。** 这是预期行为，请在 Windows 或 macOS 上构建。

---

## 10. 尚未提供的功能

这里明确列出，免得有人去找并不存在的参数：

- **没有 Rust 聊天命令。** `gta-claw-cli send` 是有意失败的。
- **没有达到完整等价的 Rust 生产服务。** 守护进程会提供真实传输、提供方和四条已配置的通道路径，但仍有
  5.4 节列出的限制。
- **其他已注册通道没有传输实现。** Teams、Telegram、Discord 和 WhatsApp 会按配置装配；其余通道库存不是
  可提供服务的传输。
- **没有技能执行、并发远程技能拉取或技能迁移证据接入。** 角色加载已经装配，包括有界的远程获取路径；
  这些技能路径尚未装配。
- **没有 JavaScript 技能。** 技能执行只有三种形式：原生 Rust、声明式 HTTP 端口，或 WebAssembly 组件。
  永远不会引入内嵌的 JavaScript 引擎。
- **CLI 和桌面客户端都没有持久设备身份**，目前只支持临时身份。
- **本仓库不包含 Android 或 iOS 应用**，也没有 Linux 桌面构建。

各 crate 与可执行程序的当前状态见 [PROGRESS.md](PROGRESS.md)；架构与这些边界背后的取舍见
[PROJECT_PLAN.md](PROJECT_PLAN.md)。
