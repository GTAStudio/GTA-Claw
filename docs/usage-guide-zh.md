# GTA-Claw 使用指南

GTA-Claw 只使用 Rust 工具链构建和运行。根工作区提供命令行工具和无界面守护进程；
独立的 `desktop/` 工作区为 Windows 与 macOS 提供 Slint 桌面应用。

## 无界面健康检查

```text
cargo run --bin gta-claw-cli -- health
cargo run --bin gta-claw-daemon -- --probe
```

常驻守护进程监听 `GTA_CLAW_BIND`（默认 `127.0.0.1:3978`），并提供：

| 端点 | 方法 | 说明 |
|---|---|---|
| `/health` | `GET` | 原生进程健康状态与目标操作系统/架构 |

```text
cargo run --bin gta-claw-daemon
curl http://127.0.0.1:3978/health
cargo run --bin gta-claw-daemon -- --probe-http
```

未知路由统一返回 `404`。

## Gateway 诊断

可使用 CLI 检查单独部署的 OpenClaw Gateway：

```text
cargo run --bin gta-claw-cli -- gateway health \
  --endpoint ws://127.0.0.1:18789 \
  --ephemeral-device
```

凭据和输出参数请运行 `cargo run --bin gta-claw-cli -- --help` 查看。

## 桌面应用

在 Windows 或 macOS 上运行：

```text
cargo run --manifest-path desktop/Cargo.toml --package gta-claw-desktop
```

桌面应用有意不支持 Linux。

## 容器

```text
docker build -t gta-claw .
docker run --rm -p 3978:3978 gta-claw
curl http://127.0.0.1:3978/health
```

镜像以非特权用户运行原生守护进程。健康检查调用
`gta-claw-daemon --probe-http`，会检查实际在线端点，而不只是确认二进制可启动。

## 兼容性数据

`compat/legacy/` 与 `compat/upstream/` 是供验证器和 Rust 测试读取的静态契约数据，
不是运行时代码。旧脚本技能必须显式迁移为签名的 Rust/WASI 组件；GTA-Claw
不会执行其中的脚本文本。
