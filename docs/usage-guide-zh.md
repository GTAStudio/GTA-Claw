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
- **通过 Rust 守护进程提供可用传输**：17 路由的主 HTTP API、遗留 HTTP 门面和 Gateway；可使用已配置的
  GitHub Copilot 提供方，或显式启用 smoke 提供方。守护进程还会绑定仅限回环地址的 MCP 监听器，但当前
  生产组装无法认证任何 MCP 调用方。
- **运行已配置的 Teams、Telegram、Discord 和 WhatsApp 路径**，并支持信号处理、配置重载和可验证的关停
  排空过程。
- **执行一次签名更新**，使用独立的更新器。

CLI 已有原生发送、历史、取消和审批命令；守护进程已用 redb 持久化会话、轮次和上下文检查点，
但完整事务恢复、调用者绑定、`claw-tools` 和技能执行仍未完成。`src/` 下的遗留 Node 服务会继续保留，直到这些缺口和冻结的兼容性证据
义务被关闭——详见 [legacy-node-port-obligations.md](legacy-node-port-obligations.md)。

---

## 1. 环境要求

| 项目 | 说明 |
|---|---|
| Rust 工具链 | 开发固定为 `1.98.1`，MSRV 声明仍为 `1.94.0`，本增量尚未重新验证 MSRV。受保护发布策略仍固定 `1.97.1`，发布前需独立审查升级。 |
| 平台 | 根工作空间可在 Linux、macOS 和 Windows 上构建。桌面客户端**仅支持 Windows 和 macOS**——在 Linux 上构建会被有意拒绝。 |
| 一个 Gateway | CLI、TUI 和桌面客户端都是客户端程序。要做实际的事情，需要一个可达的 OpenClaw Gateway v4 端点（`ws://` 或 `wss://`）。 |

不需要 Node.js、npm 或任何 JavaScript 运行时，也不允许引入——仓库策略会以测试失败的形式拒绝。

---

## 2. 从源码构建

```sh
git clone https://github.com/GTAStudio/GTA-Claw.git
cd GTA-Claw

# 根工作空间：32 个库 crate 和 6 个应用成员
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

`--help` 和 `-h` 会打印当前用法，其中也列出原生业务命令。

### 3.1 `health`——本地运行时健康状态

```sh
gta-claw-cli health
```

输出一行以 `healthy runtime=` 开头的文本，描述本机的操作系统与架构。该命令不访问网络，退出码为 `0`。

未知命令退出码为 `2`，并在标准错误输出 `error: unknown command`。

### 3.2 原生 Gateway 业务命令

```sh
gta-claw-cli send session-9 "hello" --idempotency-key message-1 --endpoint ws://127.0.0.1:18789 --ephemeral-device
```

需要共享凭据时使用 `--token-stdin`，不能将凭据放入 argv，也不能用 token 绕过设备配对。
还有 `gateway sessions`、`history`、`abort`、`approvals`、`approval`、`approve` 和 `deny`。
业务命令请求最小精确 scope，使用独立 schema-v1 JSON；发送返回接收回执，不代表模型已完成，
当前 daemon 明确报告 `durable: false`，幂等记录仅在进程内。CLI 持久身份和手动配对工作流仍未完成。
完整语法、凭据输入和输出上限见 [CLI 指南](../apps/gta-claw-cli/README.md)。

### 3.3 `gateway health`——真实的 Gateway 诊断

这个诊断命令建立一条 `ws://` 或 `wss://` 连接，完成已认证的 Gateway v4
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

连接原生 daemon 时可显式指定 `--device-profile work`，在 Windows/macOS 系统保护存储中
保留设备身份，不保存共享令牌，也不会在存储失败时退回临时身份。不指定则每次重建连接可换身份。
设备和所需 scopes 仍须由管理员配对批准；身份持久化不等于自动取得信任。

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
| Models | 原生 provider 缓存目录与显式目录刷新。 |

### 4.3 按键

```text
Tab / Shift-Tab   切换界面
Up/Down 或 j/k    选择与滚动
Enter             打开会话 / 提交回答
c / i             新建会话 / 编写消息
Shift-Enter       编写消息时换行
x                 取消精确观察到的原生 run
y / n             批准 / 拒绝
r                 从 Gateway 刷新
Ctrl-P 或 :       命令面板
1..7              跳转到指定界面
Esc               关闭命令面板
?                 键盘帮助
q / Ctrl-C        安全退出
```

### 4.4 命令面板

按 `:` 或 `Ctrl-P` 打开，输入命令后回车。可识别的命令（不区分大小写）：

`sessions`、`workspace`、`runs`、`diff`、`artifacts`、`help`、`refresh`、`quit`（或 `q`），
以及 `new`、`message`、`send`、`run`、`partial`、`partial-next`、`accounting`、`accounting-next`、
`cancel`、`retry-send`、`models`、`models-next`、`refresh-models`、`config-provider <JSON>`。

`discard-draft` 明确丢弃未提交草稿。`discard-send` 只允许丢弃所有尝试都确定未发送的输入；
已排队或曾可能送达的输入不能这样丢弃。下面的记忆动作在重试时仍保留类型，不转为普通聊天。

独立的 Models 视图显示当前连接的缓存目录、已选模型与实例代次、观察时间、可选上限和 SDK
声明能力。`models`（或该视图中的 `r`）只读缓存，`models-next` 固定原摘要续读下一组八项。
`refresh-models` 明确读取 provider 目录，不选模型、不推理。最多一个目录请求在途，失败保留
上一页；刷新成功后旧页失效，需再用 `models` 读取。连接或请求序号变化会拒绝旧响应。
目录不进入聊天历史、不取得 ACK 资格；实号能力与完整在线配置应用仍未验证。
证据见[终端目录追加记录](ledger/native-model-catalogue-20260916.json)。

本地模型候选使用 `config-provider` 后跟一个封闭 JSON 对象：

```text
config-provider {"action":"inspect","source":"D:/Configs/claw.json5"}
config-provider {"action":"prepare","source":"D:/Configs/claw.json5","destination":"D:/Configs/claw.model.json5","model":"exact-model-id"}
```

检查源文件不需要 Gateway 就绪；生成候选要求当前已验证的 Models 页、没有目录请求在途、
同一已检查源路径，以及该页内的精确模型 ID。源 provider 和当前模型必须对应目录；配置
`copilot` 映射到实际 SDK 标识 `github-copilot`。匹配不证明本地文件就是远端 Gateway 配置。
服务会复核源 SHA，独占新建候选、同步并读回；不改源文件、凭据或在线模型，应用需另走
[离线 CLI 流程](../apps/gta-claw-cli/README.md#offline-application-and-recovery)，不推导实号就绪。

JSON 最多16KiB，路径最多4096字节，模型ID最多256字节；路径空格作为数据，使用JSON转义
或正斜杠。重复/未知字段、未支持动作、相对路径、缺失或已选模型、provider不符均拒绝。
命令面板支持有界粘贴，普通命令仍保持较小长度限制；最多一个本地文件任务在途。Gateway
断线不会丢弃该任务或回执，正常退出会等已开始的文件任务结束。结果只显示在Models视图，
不进入聊天历史或ACK队列。I/O故障或进程中断可能留下候选，禁止自动覆盖/删除重试；
这不是客户端崩溃日志或文件系统I/O硬超时。

原生消息在收到持久回执前保留随机幂等键。投递未知时不接受另一个新发送；`retry-send` 是显式
使用原会话、原文本和原键重试，不自动重放。重连会拒绝旧连接的发送、取消、审批、ACK 和回答。
选中原生会话会读取保留历史，并分别分页恢复待显示结果和活动 run。完整结果只在工作区绘制后
按精确 revision 确认；Outcome unknown 独立显示，重复有副作用的操作前须先核对结果。
Diff/Artifacts 是否可用仍取决于服务器实现。

选中原生终态 run 后，`partial` 显式读取第一段保留的可见文本，`partial-next` 读取下一页；
尚未观察到终态 revision 时先使用 `run`。每页最多 2048 UTF-8 字节，总量最多 4MiB；请求固定当前连接、
session、run、turn、revision 和终态，续页同时固定原长度和摘要。选择或 revision 改变会使旧游标失效。

文本以带原字节范围的未确认 partial 数据显示，不冒充完整助手回答；查看页不新增 ACK、不赋予执行或
重放许可，原有完整终态回执的绘制后 ACK 行为保持不变。先校验原字节，再净化控制字符供显示。
空保留文本可查看，缺失则拒绝。完整单页会核对全文 SHA256；后续单页只固定全文摘要，不能独立证明全文，
且 transcript 仍是有界视图而非完整归档。完整收集与摘要校验使用
[CLI export-partial](../apps/gta-claw-cli/README.md#retained-partial-text)，验证边界见
[TUI 记录](ledger/native-tui-partial-20260915.json)。

`accounting` 读取选中且已观察终态的 run 的第一组模型轮次，`accounting-next` 显式续页。
每页最多 16 轮、总量最多 1024 轮，显示 provider/model/response 标识、主计数完整程度、
缓存/推理子集和 finish reason。缺失报告保持 unknown，明确完整的零值仍显示零。
请求固定连接、会话、run、turn、revision、终态、数量、摘要与汇总来源；连接或 run 改变
会清除游标，旧响应不能覆盖当前视图。查看用量不新增 ACK 或重放权限。完整单页核对全文
摘要，后续单页只固定快照；完整独立校验的明文 JSON 文件使用
[CLI export-accounting](../apps/gta-claw-cli/README.md)。费用仍未计算，账单仍未核对。

其他输入会在提示行显示 `Unknown command: …`。`Esc` 关闭命令面板。

### 4.5 非交互模式

传入 `--plain`，或标准输出不是交互式终端时，程序不会进入全屏循环，而是只做一次快照：连接 Gateway，
最多等待五秒获取会话列表，打印一帧渲染结果后退出。若 Gateway 未在时限内响应，提示行会显示
`Gateway snapshot timed out`。脚本和 CI 场景应使用这个模式。

### 4.6 显式记忆

使用 `gta-claw-tui --device-profile work` 连接原生 daemon，服务端显式设置
`GTA_CLAW_MEMORY_POLICY` 为 `{"schemaVersion":1,"enabled":true}`。记忆动作拒绝临时设备身份；
worker 在同一 ready 连接上确认原生无模型记忆能力后才发 `chat.send`，不支持的服务不会收到
记忆提交。普通聊天中直接包含 `!tool` 指令行也会被拒绝，包括大写写法。

先选会话，也可让首个记忆动作创建草稿会话，再在命令面板输入：

```text
memory list [limit [after-id notebook-revision]]
memory get note-id [note-revision offset]
memory search [limit]
memory save note-id fact|preference|procedure expected-notebook-revision
memory delete note-id expected-notebook-revision
memory export notebook-revision [offset]
memory import expected-notebook-revision [overwrite]
```

动作名不区分大小写；笔记 ID 和输入内容保留原始大小写，类型值及 `overwrite` 使用小写字面值。
save 打开笔记编辑框，search 打开查询输入，import 打开归档 JSON 输入。Enter 提交，
Shift-Enter 换行。支持 bracketed paste 的终端会将多行粘贴作为一次纯数据输入，不因换行
自行提交；超限或含禁止控制字符时整段拒绝，不截断后继续。Esc 暂停编辑，回到原会话后
按 `i` 继续；切换会话不能把同一记忆草稿提交到另一个会话。

所有动作，包括读取，仍需要查看完整绑定审批预览并明确批准。结果显示在 Workspace，复用
原生 run 的持久结果、恢复和精确 ACK。预检拒绝显示“未发送”，但重试被拒不能抹掉更早的
未知投递；`retry-send` 保留原动作、会话和幂等键，不自动批准。草稿和未确认键目前只保存在
运行中的 TUI 进程内，还没有客户端崩溃恢复日志。

列表默认16条、最多32条，续页 ID 必须配笔记本 revision；正文页最多2048 UTF-8字节，
非零 offset 必须配该笔记 revision。查询最多4096 UTF-8字节、8个结果；正文最多8192
UTF-8字节；包含 JSON 转义后的完整直接命令仍须小于等于16 KiB。初始笔记本可用 revision 0，
纠正、删除和导入须使用当前笔记本 revision，它不等于 run-result ACK revision。

export 返回一个固定 revision 的明文归档页及完整摘要，不自动收集全部页，也不写加密文件。
import 接受[便携笔记归档](../apps/gta-claw-cli/README.md#explicit-memory-commands)的闭合
schemaVersion 1 JSON；重复或未知字段、无效笔记/来源/revision、超限编码在提交前拒绝。
重名默认冲突；明确 `overwrite` 后仍须通过 CAS 与审批。内容和来源标签都是不可信数据，
不能授予权限；不代表语义/自动召回或完整历史遗忘。服务端既有全库256笔记本、每本256条限制继续生效。

---

## 5. `gta-claw-daemon`

```text
usage: gta-claw-daemon [--probe | --check-config] [--config PATH] [--listen ADDRESS] [--legacy-listen ADDRESS] [--gateway-listen ADDRESS] [--mcp-listen ADDRESS] [--state-dir PATH] [--log-file PATH] [--tls-terminated-by-frontend] [--smoke]
```

另外也接受 `--help` 和 `-h`。帮助参数是全局的：只要任一写法出现在任何位置，守护进程就会在创建 Tokio
运行时之前打印用法并成功退出，即使同时存在未知参数或缺少参数值。没有帮助参数时，每个顶层选项记号都必须
是 Unicode，并与受支持的参数完全匹配。地址参数会取下一个实参，并要求它是可解析为 `SocketAddr` 的 Unicode
字符串。路径参数 `--config`、`--state-dir` 和 `--log-file` 则把下一个原始 `OsString` 直接作为路径，因此
解析器会接受非 Unicode 路径和形似参数的值。取值参数只有在后面完全没有实参时才会因缺值被拒绝。只有进入
顶层选项匹配的记号才会因不受支持而被拒绝，被禁止的模式/服务参数组合也会被拒绝；已经作为路径被吞入的
记号不会再进入该匹配步骤。解析器不识别 `--`。例如 `--config --smoke` 会选择一个字面名称为 `--smoke`
的文件，而不会启用 smoke 模式。

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

加载分层配置，并执行当前的非网络检查子集：针对检查模式所允许选项的暴露策略、状态目录路径解析、代理策略
构造、管理令牌解析、更新及遗留/通道设置、通道覆盖，以及提供方认证配置和密钥解析。它不会打开监听器。
它只计算状态目录路径，不会创建该目录、测试其可用性或权限，也不会打开配对、审计或目标存储；同样不会
初始化遥测或测试其输出、获取角色、发现或激活插件，也不会认证/激活提供方。
原生 API 客户端及传输会被构造以验证静态设置，但不会连接其端点。
`--check-config` 可与 `--config`、`--state-dir` 一起使用；不能与 `--probe` 或任何监听、日志、TLS 断言及
smoke 选项组合。因此，尽管检查过程会调用暴露策略，它无法预检拟议的监听覆盖值或可路由部署。

可选的 `core.provider` 显式选择 `openai`、`anthropic`、`copilot` 或 `disabled`，不再依赖
旧 `core.copilot` 默认值来选择原生后端。例如下面是需要与其余角色、渠道等配置合并的文件片段：

```json5
{
  core: {
    provider: {
      kind: "openai",
      model: "exact-provider-model-id",
      model_aliases: [{ alias: "work", model: "exact-provider-model-id" }],
      api_key: "env:PROVIDER_API_KEY",
      base_url: "https://api.openai.com/v1/",
      credential_origin: "https://api.openai.com",
      completion_api: "responses",
      request_timeout_ms: 30000,
    },
  },
}
```

模型 ID 必须替换为账号真实可用的精确值，非空且不含空白，最多 256 字节。OpenAI/Anthropic
要求 SecretRef，不能填写明文密钥；引用最多 1024 字节，URL 最多 2048 字节，超时为
1000..120000 毫秒、默认 120000。URL 允许 HTTPS 或字面量 loopback HTTP，拒绝 userinfo、
查询、片段、空白及歧义点路径。origin 必须与端点一致且无路径；省略时从已验证端点计算。
默认使用相应官方端点，自定义 origin 仍须通过独立 `GTA_CLAW_PROVIDER_ORIGINS` 登记，
配置里声明 origin 不等于获准发送凭据。`completion_api` 仅 OpenAI 可用，默认
`chat_completions`；`responses` 必须显式选择且保持 stateless。

Copilot 使用 `kind:"copilot"`、精确 `model` 和可选超时，认证继续取自 `core.auth.github`，
不接受原生 API key 或 endpoint 字段。OpenAI/Anthropic 与 disabled 不要求无用的 GitHub 凭据。
`kind:"disabled"` 不接受活动 provider 字段，不启动模型或 Device Flow；管理查询仍可用，
模型就绪状态明确为 false。可选 `max_observed_turn_tokens` 是每回合已观察用量阈值，
不代表货币预算或单次请求硬限额。

可选 `model_aliases` 同样支持 Copilot 和 Anthropic，是区分大小写、只解析一跳的显式
别名到精确 ID 表；最多 128 项，名称与目标总计最多 4096 UTF-8 字节，每个名称遵循
256 字节模型 ID 规则。拒绝重复、别名链、与任何精确 ID 碰撞，以及保留的 `openclaw`
和整个 `openclaw/` 命名空间。文件编辑先验证语法，启动和刷新再对完整目录验证全部目标
与碰撞；无效刷新保留旧目录。主 `model` 始终保存精确 ID，别名先解析再经过固定模型和
能力准入，因此指向另一模型的别名仍不能覆盖已选模型。它不切换账号、端点或提供方，
不推断凭据或 fallback。原生 HTTP 只额外接受明确配置的别名，通用 HTTP 端口不会开始
接受任意名称；别名修改仍需独立审阅后重启。

省略 `core.provider` 时保留旧路径。显式选择不能与 `GTA_CLAW_PROVIDER_POLICY` 并存，
即使旧变量为空也拒绝混用；同样不能被 smoke 覆盖。角色模型或 reload 不能暗中替换固定模型。
provider 修改需重启，拒绝的 reload 保留正在运行的配置和 provider 代次。跨层改变 kind 时
整体替换 provider 对象，避免继承另一家的密钥；同 kind 的局部覆盖保留其他字段。
JSON5 层里的重复对象字段在合并前拒绝。管理状态会报告配置来源和声明的 origin，不输出凭据引用。

[CLI provider inspect/prepare](../apps/gta-claw-cli/README.md#provider-configuration) 可查看保存的选择，
按源文件 SHA 验证后将 stdin 严格 JSON 选择写成新配置文件；不会覆盖源/目标或应用到运行中服务，
也不会合并环境覆盖、解析秘密或联网。候选文件生成后仍需独立检查与受控重启。
验证范围和未完成项见[配置记录](ledger/native-provider-config-20260916.json)。

`config provider prepare --model <精确ID>` 只改模型，保留 provider、凭据引用、端点、方言、
超时和预算。Windows `apply` 还要求源/候选两个摘要、全新备份和
`--confirm-apply --confirm-offline`；先同步并验读原始备份，再用原源文件句柄写入。
这是非原子的离线保存，不是在线应用；失败可能留下未知源内容。独立确认的 `restore`
会先保留这些残留，再恢复完整已审阅配置，且不自动重启。操作步骤与恢复限制见
[离线应用和恢复](../apps/gta-claw-cli/README.md#offline-application-and-recovery)。

原生 `gateway models` 每页最多只读八个缓存模型，保留精确 ID、声明能力、可选上下文/输出
上限、显式别名、当前选择和观察时间，不联网刷新。别名来自本地配置并纳入目录摘要，不是
实号能力声明；编码页最多 16 KiB，因此可少于八项。新客户端仍接受无别名的旧页，旧严格
客户端可能拒绝含别名的页，使用前需升级。TUI/Slint 分开展示别名，候选编辑仍保存精确 ID。
`gateway refresh-models --sha256 <已观察摘要>` 是单独的
读写权限动作，只发起目录读取，最多一个在途刷新、十秒等待预算，不执行推理或切换模型。
无效目录、当前模型缺失、取消、超时或并发 provider 变化都会保留旧缓存。
SDK 声明能力不等于已验证真实账号的每模型能力。完整说明见
[CLI 模型目录](../apps/gta-claw-cli/README.md#model-catalogue)及
[目录验收记录](ledger/native-model-catalogue-20260916.json)。

`gateway models --availability` 显式读取 `disabled`、`authentication_pending`、`not_initialized`
或 `retired` 生命周期状态。TUI 对应 `models-status`，桌面 Models 提供独立状态按钮。它们只读
本地事实，不证明真实账号或推理就绪；普通目录请求保留旧格式，旧服务拒绝时保留上一有效页，
未知原因不作为任意远端文字显示，见[状态记录](ledger/native-model-status-20260916.json)。

`gateway export-models --destination <全新绝对路径>` 通过同一已认证只读连接读取完整缓存目录，
固定每页身份、代次、选择、观察时间和摘要，独立核验全量摘要及跨页 ID/别名唯一性后才新建
文件。不刷新、不推理、不切换模型或发送 ACK。输出为有界明文元数据，不是账号证明或可导入
配置；读取中断不产生文件，文件写入不确定时须保留检查，禁止覆盖已有目标。完整步骤与限制见
[目录导出](../apps/gta-claw-cli/README.md#complete-catalogue-export)和
[验收记录](ledger/native-model-export-20260916.json)。

daemon 在完成、流式和嵌入请求调用 provider 前检查精确模型仍在当前目录，提供方能力与
明确逐模型声明均满足要求，显式输出上限不为零且不超过已知输出/上下文上限。目录未声明
逐模型能力时保留未知，只使用原有提供方级支持检查，不伪造实号能力。用户明确提交的工具、
强制工具选择、图像及类型化工具历史不会被偷偷丢弃；仅对已知文本模型省略可选宿主/运行时
工具声明，使普通文本仍可用。不回落别的模型、不推断未知上下文大小或额外联网，见
[能力准入记录](ledger/native-model-admission-20260916.json)。

### 5.3 提供服务

```sh
gta-claw-daemon
```

服务模式先在 `main` 中解析配置并初始化遥测，然后调用 `serve_production`。`ProductionService` 启动过程
会打开持久化的 Gateway 配对、安全审计和目标存储，激活已签名插件，按条件激活 smoke 提供方或
GitHub Copilot 或显式原生 OpenAI/Anthropic 选择，启动已配置的通道传输，并绑定四个监听器：

- 主 17 路由 HTTP API；
- 与遗留 Node 服务兼容的 HTTP 门面；
- Gateway v4 服务；
- 单独承载 `/mcp` 路由、仅限回环地址的监听器。

第四个监听器使用独立的 `GTA_CLAW_MCP_OWNER_TOKEN` 和 `GTA_CLAW_MCP_TOKEN`；未配置时拒绝访问，
不会复用主 HTTP 凭据。只读 MCP 凭据不能执行写工具，插件 owner 调用仍需运行时审批。

四条通道路径都按配置启用：Teams 和 WhatsApp 接入遗留 HTTP 门面，Telegram 和 Discord 则作为受监管的
出站客户端运行。配置 GitHub 令牌后，GitHub Copilot 会在启动时激活；否则提供方保持等待 Device Flow 的
状态。`--smoke` 会显式替换为本地安装诊断提供方。

完整选项如下：

| 选项 | 服务模式行为 |
|---|---|
| `--config PATH` | 从 `PATH` 加载严格 JSON5；未指定时依次使用 `GTA_CLAW_CONFIG` 和经过审计的遗留环境变量迁移。 |
| `--listen ADDRESS` | 主 HTTP 监听地址。默认 `127.0.0.1:0`，即由操作系统分配端口。 |
| `--legacy-listen ADDRESS` | 遗留 HTTP 监听地址。默认在回环地址上使用 `core.server.port`。绑定到可路由地址时，既要有可信 TLS 前端，也必须由代理执行调用方认证并采用严格的路由白名单；只有守护进程的 TLS 断言并不充分。 |
| `--gateway-listen ADDRESS` | Gateway 监听地址。默认 `127.0.0.1:0`。 |
| `--mcp-listen ADDRESS` | MCP 监听地址。默认 `127.0.0.1:0`；任何非回环地址都会被拒绝。该参数只改变绑定的套接字；由于生产组装没有 MCP 令牌/JWT 认证器，所有请求仍会被拒绝。 |
| `--state-dir PATH` | 状态根目录；未指定时依次使用 `GTA_CLAW_STATE_DIR` 和 `$HOME/.gta-claw`。配对、安全审计、目标及 `runtime.redb` 会话/轮次/上下文检查点保存在这里；完整跨对象事务恢复仍未完成。 |
| `--log-file PATH` | 把普通遥测写入文件，而不是标准错误。 |
| `--tls-terminated-by-frontend` | 断言可信前端负责终止 TLS。它不会让守护进程自行启用 TLS，也不会添加调用方认证；它只让主 HTTP、遗留 HTTP 或 Gateway 的可路由地址通过守护进程的绑定策略。 |
| `--smoke` | 使用确定性的本地安装诊断提供方。所有显式指定的监听地址都必须保持为回环地址。 |

不要仅添加 `--tls-terminated-by-frontend` 就暴露遗留监听器。遗留 `/chat` 没有应用层调用方认证。设置
`GTA_CLAW_ADMIN_TOKEN` 也不会改变这一点。它会配置一个操作员身份且授予全部 scope 的令牌，用于认证以下
六条受保护的主 API 路由：`GET /v1/models`、`GET /v1/models/{id}`、`POST /v1/embeddings`、
`POST /v1/chat/completions`、`POST /v1/responses` 和 `POST /tools/invoke`；同一凭据也认证
`POST /api/v1/admin/rpc`。该令牌存在时还会注册遗留 `/admin/reload`、`/admin/system` 和
`/admin/exec`。reload 路由要求令牌完全匹配，但 system 和 exec 路由接受令牌或回环对端。该令牌不会写入
MCP 专用认证器，也没有接入 JWT 替代认证器，因此不能让 `/mcp` 可访问。同主机反向代理在 system 和 exec
处理器看来就是回环来源。可路由的遗留监听器必须由前端自行认证调用方，并只转发明确允许的路由；除非代理
实施等价授权，否则应阻断 `/admin/*`，也不要在没有单独调用方认证策略时转发 `/chat`。

信号处理并不覆盖服务模式的整个启动过程。`main` 会先加载配置并初始化遥测，然后才调用
`serve_production`；这些较早阶段仍采用操作系统的默认信号行为。进入 `serve_production` 后，它会在启动
`ProductionService` 组装前安装停止处理器。从此时起，组装期间的监管停止会被观察到，并取消启动或执行排空；
而配置加载或遥测初始化期间收到信号时，进程可能直接终止，不会产生守护进程排空汇总。组装完成监听器的绑定
和启动后，会打印：

```text
ready protocol=1
healthy runtime=<os>-<arch>
service http=<address> legacy=<address> gateway=<address> mcp=<address> provider=<name> config_generation=<n>
```

`ready protocol=1` 和 `healthy runtime=...` 是进程协议/健康公告，`service ...` 行是监听器/启动公告；
它们都不表示依赖已经就绪。`/ready`、`/readyz` 和 `status` 控制响应报告依赖及服务状态的就绪性。监听公告
中的提供方可能是 `device-flow-pending`；在 Device Flow 激活提供方之前，提供方依赖为 false，整体就绪
状态也为 false。`mcp` 依赖只表示监听任务已经启动；即使所有 MCP 调用方仍被拒绝，该依赖也可以为 true。

之后持续提供服务，直到出现下列情况之一：

- 监管进程发出的停止信号——Unix 上的 `SIGTERM`（`systemd`、`docker stop`、`kubectl delete` 发送的正是
  它），或 Windows 上的控制台关闭 / 系统关机；
- 中断信号——Unix 上的 `SIGINT`，Windows 上的 Ctrl-C 或 Ctrl-Break；
- 控制通道（标准输入）上收到 `shutdown` 一行文本；
- 发生受监管的运行时/入口故障：主 HTTP、MCP 或遗留 HTTP 任务意外失败、返回或消失；
- 启动后向监管输出写入 reload、status 或其他控制响应失败。

标准输入到达末尾**不是**停止条件：以关闭的 stdin 启动的守护进程会继续提供服务。
同一控制通道还接受 `status` 和 `reload`；重载会报告已应用的代次及变化域，或报告拒绝原因并让上一代配置
继续服务。

停止时打印一行汇总：

```text
stopped reason=<terminate|interrupt|control|runtime> clean=<bool> drained=<n> completed=<n> abandoned=<n> tasks=<terminated>/<spawned>
```

`reason=runtime` 表示启动后发生了受监管故障：入口任务失败、返回或消失，或者向监管方写入 reload、status
或其他控制响应失败。入口故障发生后，守护进程会排空、输出停止汇总，并因该故障使汇总不再 clean 而以错误
退出。输出故障发生后仍会排空并尝试写入同一汇总，但由于输出已经损坏，不能保证 `stopped ...` 行真正发出。
如果最初的启动公告写入失败，守护进程同样会排空并返回 I/O 错误，但此时尚未进入事件循环，不会产生
`reason=runtime` 停止行。仍有工作遗留时也会以错误退出。`tasks=t/s` 是生产停止账本中范围受限的服务任务
计数，只涵盖明确纳入账本的入口、Gateway、插件、通道、Device Flow 和更新器任务。部分已纳入的适配器会用
drop guard 记录终止，但这些数字并非所有 Tokio、阻塞或进程任务的总数，两者相等也不是通用的进程泄漏证明。

手动停止：

```sh
printf 'shutdown\n' | gta-claw-daemon
```

### 5.4 当前限制

- **恢复能力仍不完整。** redb 已保存会话、轮次和保留的上下文检查点，重启/reload/LRU 不会删除历史；
  run/context/goal/outbox 尚未组成一个原子事务，没有完整归档及三平台故障恢复验收。
- **审批策略仍不完整。** Gateway、CLI 和 Slint 已支持完整脱敏预览与一次性批准/拒绝；插件工具要求审批，
  但主体、资源、工具版本和参数摘要绑定仍需完善。
- **MCP 需要独立凭据。** 显式设置 `GTA_CLAW_MCP_OWNER_TOKEN` / `GTA_CLAW_MCP_TOKEN`，两者不能相同，
  长度为 1..4096 ASCII bearer 字节且不含空白或控制字符；缺失时拒绝访问，不复用主 HTTP token。
- **没有装配 `claw-tools`。** 并非完全不能执行工具：已签名插件注册的工具和持久化目标工具可通过运行时及
  已认证的主 HTTP 表面执行，MCP owner 插件调用也使用同一审批执行器。缺失的是 `claw-tools` 的工具目录及其模式校验、
  授权、路径限制和目标网络校验。
- **技能执行和迁移证据接入均未被分派。** 启动时只读取 `claw_skills::registry()` 作为库存计数；生产路径
  没有调用 `WasmSkillHost` 桥接，因此不会执行任何内置技能。应用层同样没有调用
  `validate_migration_evidence`；该函数只做结构校验，制品的密码学验证仍属于独立的插件信任职责。
- **兼容性证据仍缺失。** `apps/` 下没有测试针对已绑定的守护进程重放 `compat/legacy`。这是等价性证据缺口，
  并不表示安全审计证据不存在：服务路径会打开持久化的安全审计日志。

**打包阻塞项：** Debian 与 RPM 原型使用的当前
`packaging/linux/systemd/gta-claw-daemon.service` 与生产服务不兼容，不能原样部署。
`RestrictAddressFamilies=AF_UNIX` 会阻止创建必需的 `AF_INET`/`AF_INET6` TCP 监听器，
`IPAddressDeny=any` 还会阻断必需的 IP 入站和出站流量；此问题仍有待打包修复。

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
| 临时身份同意项 | 显式同意仅本次会话使用设备身份，并申请聊天和审批访问权限。 |
| 保存设备身份 | 显式使用 Windows/macOS 系统保护的 `desktop` profile，按端点隔离；不保存令牌、不自动授予信任。记忆操作需要此选项。 |

按钮：**Connect**、**Retry**、**Cancel**、**Disconnect**。

连接成功后，摘要面板只展示有界的非敏感字段——端点、协商的协议版本、角色、生效的 scope、健康状态和身份
模式。可能需要先完成配对；未明确选择保存则使用临时身份，选择保存后按端点使用系统保护的 profile，
加载失败不会退回临时身份。签发的设备令牌仍只保存在有界进程内存中。

产品模式精确申请 `operator.read`、`operator.write` 和 `operator.approvals`，不会申请 admin。
原生聊天/历史/审批已有真实传输，生产模型初始为空；重连后查询待审批，完整有界预览到达前不能批准。
请求和事件绑定连接 epoch；流式输出、历史/事件合并、工作区信任和完整凭据生命周期仍未完成。

原生终态 run 的 Session Usage 区显示已保存用量；刷新图标从第一轮读取，右箭头在有下一页
时续读。读取期间或当前连接/run 无法对应时按钮禁用。可滚动只读区区分缺失报告、明确零值、
部分计数、持久来源和未计算费用。读取失败保留上一张有效页，不改变 run 终态、不确认结果；
会话、epoch 或 revision 变化会拒绝旧响应。这是有界查看，不是完整导出或发票结算，见
[用量工作流记录](ledger/native-accounting-workflow-20260915.json)。

Settings > Models 现在显示原生缓存目录，不再使用自动路由占位内容。向下箭头读取第一张
缓存页，右箭头固定摘要续页，刷新图标明确从 provider 读取目录。控件使用现有认证连接，
请求在途时禁用，不选择或配置模型。失败/坏响应保留上一张有效页，刷新成功后旧页失效，
需再读取缓存；断线或 epoch 改变会清空视图并拒绝旧响应。缺失上限保持未知，SDK 能力声明
明确标为未验证。可滚动只读区不产生聊天结果或 ACK，这些按钮不代表已经实现模型选择/
应用配置流程，见[桌面目录追加记录](ledger/native-model-catalogue-20260916.json)。

铅笔图标打开独立的**本地**模型候选表单：填写绝对源路径，点击向下箭头检查源文件，
从当前目录页选择精确模型，再填写全新绝对候选路径并点击加号生成。本地 provider 类型和
已保存模型必须对应当前目录，但这不能证明该文件就是所连接 Gateway 的配置；端点与凭据
绑定仍需独立审阅。目录页、连接或实例变化会使旧选择失效，不自动推断别名、fallback 或凭据。

共用平台服务会复核源 SHA，独占新建候选并读回校验；只改变模型字段，不改源文件或在线服务。
回执显示源/候选摘要，不显示凭据引用；断线后仍保留已生成文件的回执，避免误认为没有执行。
本地 I/O 失败可能留下候选文件，必须保留检查。任务在 UI 线程外执行，最多一个在途，正常关闭
控制器会等待任务收尾。审阅后的应用与恢复使用
[离线 CLI 流程](../apps/gta-claw-cli/README.md#offline-application-and-recovery)，表单不执行
在线切换、自动重启或付费模型请求。

### 6.3 平台边界

桌面客户端之所以是独立的 Cargo 工作空间，是因为仓库的可信供应链策略拒绝在根工作空间成员可触及的任何位置
引入 Slint 依赖。根目录 Android/iOS crate 是独立客户端内核，另外的 `android/`、`ios/` 工作空间
已经包含 Slint 连接壳，但平台桥接和完整产品工作流仍未完成。根工作空间排除 Slint、Linux GUI 拒绝
仍是现有政策，不因本轮原生开发而取消。

### 6.4 显式记忆

选择保存设备身份，连接已显式启用记忆的原生 daemon，再进入 Session 并点击 Memory 工具。
动作菜单提供 List、Read、Search、Save、Delete、Export、Import；ID、类型、revision、
字节 offset 和正文分开输入，只有当前动作需要的字段可编辑。List 的可选 ID 是续页 after，
Read 使用笔记 revision，保存/删除/导入使用当前笔记本 revision；导入重名默认冲突，必须
明确勾选覆盖才允许尝试覆盖。这些数值不等于 run-result ACK revision，所有动作仍须经过
原有完整绑定审批预览和明确批准。

controller 在同一 ready epoch 上确认原生无模型能力后才提交，临时身份或不支持的服务会被
拒绝；普通聊天直接写 `!tool` 不能绕过。归档使用已有 Gateway 严格 codec，重复键、错误字段/
revision、超限或过深 JSON、未知版本在提交前拒绝；合法多行 JSON 安全压成一条直接命令。
正文是数据，不是额外指令。正文/查询与最终编码上限和 TUI 指南相同。

表单绑定屏幕上显示的会话和连接；绑定改变会关闭表单并丢弃未提交的本地字段。确认后的完整
记忆结果显示在独立的可滚动、可选择只读区域，不受普通聊天摘要截断；连接失效时清空该视图。
发送未知保留原键，在当前尝试结束后可明确重试原请求；重试前被拒不会抹掉此前未知状态。
只有完整持久收据把原键关联到精确 run 后，结果才可释放原请求，提前到达的事件不能代替收据。
继续复用审批、持久结果查询和精确 ACK，不自动批准或重放。

桌面使用相应端点的系统保护 `desktop` profile；其他 profile 名称对应不同设备身份，笔记不会
自动合并。表单草稿、未确认键及最近结果视图目前是进程内状态，没有客户端崩溃日志。
导出仍是带 revision/摘要的明文页，不自动收集或加密落盘；大归档分阶段导入、完整来源/遗忘流程
和 Windows/macOS 交互实机验收仍开放，无窗口软件渲染测试不能代替这些验收。

CLI 已有独立的[加密记忆文件流程](../apps/gta-claw-cli/README.md#encrypted-memory-files)，
不代表桌面表单已自动传输文件，也不取消每页导出的审批要求。

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
遗留环境变量迁移。`--check-config` 可在不提供服务的情况下校验 5.2 节所列的静态子集；它不是存储、遥测、
角色、插件或提供方启动探针。

### 8.2 部分常用环境变量

| 变量 | 读取方 | 含义 |
|---|---|---|
| `GTA_CLAW_GATEWAY_URL` | `gta-claw-tui` | 默认 Gateway 端点（`ws://127.0.0.1:18789`）。 |
| `GTA_CLAW_GATEWAY_TOKEN` | `gta-claw-tui`、`gta-claw-daemon` | 共享的 Gateway 令牌；设置后守护进程把它作为 Gateway 凭据。 |
| `GTA_CLAW_CONFIG` | `gta-claw-daemon` | 未指定 `--config` 时的配置文件回退值。 |
| `GTA_CLAW_STATE_DIR` | `gta-claw-daemon` | 未指定 `--state-dir` 时的状态根目录回退值。 |
| `GTA_CLAW_ADMIN_TOKEN` | `gta-claw-daemon` | 覆盖配置中的管理令牌；认证主 API 的六条受保护模型/工具路由和 `POST /api/v1/admin/rpc`，并注册遗留 `/admin/*`。它不认证 `/mcp` 或遗留 `/chat`；遗留 system/exec 还会信任回环对端。 |
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

**守护进程以 "shutdown left work behind" 退出。** 汇总中的 `abandoned` 值、截止期限状态及范围受限的
`tasks=<terminated>/<spawned>` 账本会描述已记录的故障。只有明确纳入统计的服务任务才会造成任务计数差额；
其他被放弃的工作可能让这两个数字仍然相等。

**桌面客户端在 Linux 上构建失败。** 这是预期行为，请在 Windows 或 macOS 上构建。

---

## 10. 尚未提供的功能

这里明确列出，免得有人去找并不存在的参数：

- **CLI 对话工作流尚不完整。** 已有发送/历史/取消/审批，持久身份、配对 onboarding、流式输出和持久 run 查询仍未完成。
- **没有达到完整等价的 Rust 生产服务。** 守护进程会提供真实传输、提供方和四条已配置的通道路径，但仍有
  5.4 节列出的限制。
- **其他已注册通道没有传输实现。** Teams、Telegram、Discord 和 WhatsApp 会按配置装配；其余通道库存不是
  可提供服务的传输。
- **没有技能执行、并发远程技能拉取或技能迁移证据接入。** 角色加载已经装配，包括有界的远程获取路径；
  这些技能路径尚未装配。
- **没有 JavaScript 技能。** 技能执行只有三种形式：原生 Rust、声明式 HTTP 端口，或 WebAssembly 组件。
  永远不会引入内嵌的 JavaScript 引擎。
- **CLI 和桌面客户端都没有持久设备身份**，目前只支持临时身份。
- **移动产品尚不完整。** Android/iOS 各有 Slint 连接壳，平台桥接、凭据存储和完整对话仍待实现；Linux GUI 未支持。

各 crate 与可执行程序的当前状态见 [PROGRESS.md](PROGRESS.md)；架构与这些边界背后的取舍见
[PROJECT_PLAN.md](PROJECT_PLAN.md)。
