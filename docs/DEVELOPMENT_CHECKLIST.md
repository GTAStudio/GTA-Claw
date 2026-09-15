# GTA-Claw 开发与迁移 Checklist

规划日期: 2026-09-14。对应 [PROJECT_PLAN.md](PROJECT_PLAN.md)。
上游目标: `v2026.9.4`，源码 `3a9d69db306cd7f081e06254cb89c4bcc14a7107`。
能力对标补充: NousResearch Hermes Agent `v2026.9.11`，仅作为产品工作流参考；
来源、实现边界和差距映射见方案第 2.4 节，不改变 OpenClaw 协议基线或纯 Rust 政策。

本轮由主助手独立开发和核查，不使用子 agent。已完成的窄工作项依据代码与测试勾选，
部分完成的大项保持 `[ ]`，不把局部通过当成整个里程碑完成。具体代码归属见主方案第 4 节。

## 使用规则

- `[ ]` 表示尚未达到验收门槛；blocked 必须注明原因，不能勾选。
- 完成必须同时有实现、真实生产装配、正常及负向测试、版本化证据；不适用项走明确
  的范围/差异审批，不能假装测试通过。
- 每项证据记录: ID、source SHA、upstream SHA、测试名/命令、平台、配置、输入/制品
  指纹、结果、限制、恢复方法。复用 `docs/ledger/`，不改旧封存 ledger 来填完成状态。
- 逐项推进、验证后更新。本清单中的“owner”指代码归属，不授权委派给子 agent。
- 本次已运行 Windows 原生构建、选定核心/CLI/Slint 测试及严格 lint；没有进行真实模型、
  渠道、移动设备、用户状态迁移、部署或发布。已验证 Windows 测试专用本机凭据和隔离设备配对。
  当前证据见 [原生增量记录](ledger/native-followup-20260914.md)，旧执行/基础记录保留为历史。

## 详细执行规则

- 保留 98 个一级 ID；94 个未关闭主项按 `.01` 到 `.04` 拆分可执行子项，分别覆盖具体产物、生产使用、负例及恢复/交付。
- 每个主项记录归属/入口、前置、当前基础、验收、失败处置和证据；“当前”不覆盖并行开发中后续新增的事实，执行前核对最新源码。
- 子项初始未勾选表示尚未按细化范围核证，并非其中所有代码都不存在；满足要求时引用真实证据，不重复实现。
- 四个已完成主项保持原窄范围，不追加未经验证的新完成声明；新版/平台/产品回归由对应未完成主项承接。
- 一级任务行不缩进，子项缩进两格；统计工具分别识别 `M0-01` 与 `M0-01.01`，不能重复计数或把两个层级相加当完成率。
- 依赖表示实现或验收所需合同，不要求停掉所有独立开发等待整个里程碑；发布仍必须满足其全部前置门槛。
- 详细规格、共用证据字段和失败语义见 [PROJECT_PLAN.md](PROJECT_PLAN.md) 第 11 节；实际外部操作仍须适用授权。

## 导航与数量

先读当前工程进度和能力差距，再按 M0-M7 展开任务。每个主项紧邻自己的详细子项，
无需跳到另一份 backlog。方案第 12 节给执行波次，第 13 节给命令/E01-E16 场景，
第 14 节给风险/估算/交接模板。下表只统计任务结构，不是代码完成率。

| 阶段 | 一级任务 | 既有完成 | 开放主项 | 未核证子项 |
|---|---:|---:|---:|---:|
| M0 基线/设计 | 10 | 0 | 10 | 40 |
| M1 安全执行 | 11 | 2 | 9 | 36 |
| M2 持久恢复 | 11 | 0 | 11 | 44 |
| M3 协议/模型/接入 | 15 | 2 | 13 | 52 |
| M4 Agent 能力 | 10 | 0 | 10 | 40 |
| M5 客户端 | 10 | 0 | 10 | 40 |
| M6 迁移/交付 | 20 | 0 | 20 | 80 |
| M7 扩展/兼容 | 11 | 0 | 11 | 44 |
| 合计 | 98 | 4 | 94 | 376 |

## 当前工程进度

| 项目 | 已实现及验证 | 仍未关闭 |
|---|---|---|
| M0-01 / M0-04 | 九月候选 release/tag/commit/tree、API 验签事实、双基线；8个源码见证及6类离线请求schema；CLI/TUI实际RPC参数检查 | 本地验签、完整请求/响应/事件合同与外部互操作；局部证据见[会话协议记录](ledger/native-session-contract-20260914.json) |
| M0-06 / M2-01 / M2-02 | redb 4.2.0、schema、CAS、回合高水位、会话/回合/检查点及进程恢复 | 完整事务端口、archive、跨对象一致恢复和三平台验收 |
| M1-01 | 插件风险默认值已保守设置，实际 bridge 允许/拒绝/取消/超时测试 | 该窄任务完成，不代表身份与策略门槛完成 |
| M1-02 / M1-03 / M1-05 / M1-06 / M1-07 | 认证主体与绑定审批；原生文件/目标/固定程序工具、显式固定IP网络读取；进程摘要在执行句柄上校验；真实批准/拒绝/取消/回收；插件离线schema和持久审计；未知效果不重试 | 渠道多租户、完整插件能力同意、通用DNS/代理网络、Unix竞争保证和全矩阵 |
| M1-04 | Gateway 完整审批端口、CLI 复核指纹、TUI 全文滚动审核、Slint 同一预览合同 | 窄任务完成，不代表完整客户端产品验收 |
| M2-07 / M2-11 | 有界内存 LRU 不删历史、检查点恢复、tracked shutdown | 配额/归档/索引全历史与完整故障恢复 |
| M2-05 / M2-09 / M2-11 | 明确OutcomeUnknown端口类别；提交/工作线程未知后数据库写入栅栏、可读核对、丢弃等待者仍记录失败；关闭不报clean | 物理存储故障注入/断电、跨对象恢复、独立完整恢复流程 |
| M2-10 | 单redb读事务流式快照、严格数量/摘要、空库原子恢复；CLI age加密、stdin口令、错误口令/篡改/截断/已有目标拒绝；相关五包446测试及严格lint通过 | 外部goal/附件等一致备份、全平台ACL/断电、完整运行时兼容和恢复工作流；见[加密快照记录](ledger/native-encrypted-snapshot-20260914.json) |
| M1-02 / M3-12 / M3-13 | Telegram/Discord入站绑定非owner账号/发送者权限与独立持久会话；真实本地分发验证历史/reset隔离 | Teams/WhatsApp同等身份传播、完整恢复与真实账号；后续持久接收/投递增量见下一行 |
| M2-04 / M2-05 / M2-08 / M3-12 / M3-13 | Telegram/Discord消息ID/完整输入持久接收、执行去重、独立回复领取/确认/unknown；七个真实进程退出边界；原生Telegram持久接收后推进offset；管理员只读查询 | provider cursor/resume持久化、休眠队列批准重放、完整分片回执导出、真实账号与外部exactly-once不承诺 |
| M2-04 / M2-08 / M3-12 | Telegram延迟批次处理后确认，按凭据/账号/来源保存单调CAS游标；启动恢复、每轮复核、空闲/时钟回退失效但不清claim；实际runtime重启/并发变化/未知投递只发一次，三包313通过/4忽略及严格lint | Discord持久resume、provider保留期外休眠队列恢复、完整分片回执和真实账号仍开放；见[Telegram恢复记录](ledger/native-telegram-cursor-20260914.json) |
| M2-04 / M2-08 / M3-13 | Discord持久接收后sequence、后台连续结算checkpoint、凭据/配置绑定CAS恢复与失效清理；实际worker重启RESUME/dispatcher成功前缀与未知拒重发、100条回放排空，三包319通过/4忽略及严格lint | provider保留期外休眠恢复、完整分片回执、真实WSS/账号与跨平台仍开放；见[Discord恢复记录](ledger/native-discord-resume-20260914.json) |
| M2-05 / M2-08 / M3-12 / M3-13 | Telegram/Discord远端确认后逐片持久ID/UTF-8摘要、原claim事务校验和只读32项分页；部分发送/存储关闭停发/重启拒重发、8个进程退出边界；三包321通过/4忽略及严格lint | 无回执仍可能已发送；完整远端核对、批量导出、休眠恢复与真实账号仍开放；见[分片回执记录](ledger/native-channel-receipts-20260914.json) |
| M1-02 / M2-04 / M3-12 / M3-13 | 生产账号按渠道/凭据分区，不再共享default；同消息ID换账号历史/reset隔离，实际规范化/收发/回执重启通过，错误账号零发送；daemon197通过/4忽略及严格lint | 同bot轮换token也隔离，旧数据保留；稳定机器人身份验证、审批迁移与真实账号仍开放；见[账号分区记录](ledger/native-channel-accounts-20260914.json) |
| M1-02 / M2-04 / M3-11 / M3-14 | Teams/WhatsApp账号/发送者/消息ID进入非owner authority与持久入站；Teams app/tenant隔离及无显示名回退、重复消息/reset与重启验证；HTTP/daemon312通过/4忽略、严格lint和根check | 两者完整出站投递/回执、活动编辑策略、实号/外部JWT与跨平台仍开放；见[认证渠道身份记录](ledger/native-verified-channel-identity-20260914.json) |
| M2-05 / M2-08 / M3-14 | 原生WhatsApp webhook独占投递claim、逐片严格Cloud回执/持久wamid；5种投递/重启及丢弃请求停后续消息验证，三包328通过/4忽略、严格lint | API确认不等于用户送达/已读；模板/状态回调、远端核对与真实Cloud账号仍开放；见[WhatsApp投递记录](ledger/native-whatsapp-delivery-20260914.json) |
| M2-05 / M2-08 / M3-11 | Teams消息/命令/欢迎回复持久claim、规范化输入结果配对、严格资源回执及逐片保存；实际处理器与6种投递/重启情况，三包331通过/4忽略及严格lint | 实际OAuth/JWT服务/租户收发、活动编辑和远端核对仍开放；见[Teams投递记录](ledger/native-teams-delivery-20260914.json) |
| M2-05 / M2-08 / M3-14 | WhatsApp回调按已知phone/recipient/wamid回执保存四类时间及数字错误码；CAS乱序/重复/并发合并、冲突标记，纯状态通知不执行旧队列；四包445通过/4忽略及严格lint | 不解除unknown、不补录未知/无索引回执；模板/服务窗口、远端核对和Cloud实号仍开放；见[WhatsApp状态记录](ledger/native-whatsapp-status-20260914.json) |
| M2-05 / M3-14 | 原生文本整批时间戳预检、执行/认领/逐片发送前24小时窗口复核；首片后到期保留回执且重启拒重发；三包335通过/4忽略及严格lint | 无模板自动兜底；旧兼容发送、模板审批/全局最近消息窗口和真实Cloud仍开放；见[WhatsApp窗口记录](ledger/native-whatsapp-window-20260914.json) |
| M2-04 / M2-05 / M3-14 | 规范化原生输入保留提供方时间并绑定不可变入站；同ID替换/移除时间在执行与投递认领前拒绝，真实重启回归；daemon205通过/4忽略及严格lint | 旧无时间历史不自动补录；模板、完整账号历史迁移与外部时间信任仍开放；见[WhatsApp时间来源记录](ledger/native-whatsapp-provenance-20260914.json) |
| M3-02 / M3-03 | 原生会话/审批、持久化 run/outbox/ACK、精确取消、epoch 拒旧；sessions.describe读取真实归属会话、chat.history支持limit、sessions.send接受key；实际重启与跨设备拒绝测试 | 完整上游 payload、历史游标/完整归档、完整渠道回执恢复和跨对象原子恢复 |
| M3-05 | CLI 发送/精确取消/run 查询/结果页/ACK/审批、describe与history --limit；OS 密钥存储 profile、真实双进程身份连续性 | 窄命令任务完成；完整 onboarding/流式交互仍属 M5-01 |
| M3-09 | MCP 独立 owner/只读凭据、边界输入与真实服务拒绝验证 | 该窄任务完成；完整 claw-mcp 装配仍归 M3-10 |
| M1-10 / M3-10 | HTTP MCP活动工具请求按凭据主体/有类型ID登记与取消；全局256/主体32容量、重号/坏ID零执行、实际双主体TCP并发取消和ID释放复用；HTTP/daemon319通过/4忽略及严格lint | 不含同凭据多客户端会话隔离、完整claw-mcp/OAuth/stdio/ACP装配；取消非回滚；见[MCP取消记录](ledger/native-mcp-cancellation-20260914.json) |
| M1-10 / M3-10 | MCP随机会话ID/凭据归属、同凭据请求隔离、DELETE撤销/SSE双层限额；原生McpClient连接真实daemon发现/只读拒绝/关闭；三包388通过/4忽略，HTTP/daemon严格lint | MCP旧stdio夹具7项lint、初始化状态机/失效时序、出站/OAuth/stdio/ACP完整装配仍开放；见[MCP会话记录](ledger/native-mcp-session-20260914.json) |
| M1-10 / M3-10 | MCP完整握手字段、共享initialized/固定协议版本、现代初始化批量拒绝、原始JSON重复键拒绝；TCP零执行负例及真实客户端通过；HTTP/daemon323通过/4忽略及严格lint | 服务关闭/后台失效、出站授权、事件/旧ID取消归因与完整OAuth/stdio/ACP仍开放；见[MCP握手记录](ledger/native-mcp-handshake-20260914.json) |
| M2-06 / M3-10 | MCP共享关闭根先于HTTP drain、会话/无会话调用和SSE撤销、慢tools/list可取消；实际TCP半读请求拒绝及真实daemon存活SSE下clean退出；HTTP/daemon324通过/4忽略及严格lint | 非合作后端仍受原关闭预算；后台失效、出站/OAuth/stdio/ACP和完整事件仍开放；见[MCP关闭记录](ledger/native-mcp-drain-20260914.json) |
| M1-03 / M1-07 / M3-10 | 显式loopback HTTP MCP工具进入模型/HTTP/MCP统一审批审计；已审阅描述/schema绑定、目录变化拒发、调用一次并关闭；真实daemon审批和11种服务场景、HTTP失效不重放、stdio环境隔离及程序固定；四包560通过/6忽略和严格lint | 远端HTTPS/代理/OAuth、stdio产品启动授权/工作目录、目录持久撤销及完整资源/提示/ACP仍开放；见[MCP出站记录](ledger/native-mcp-outbound-20260914.json) |
| M1-03 / M2-08 / M3-10 | 后端reviewRevision整组持久撤销、256条事务配额、同组取消/独立后端隔离、启动拒旧publication；真实daemon重启后仍拒旧、显式新版本仍需审批；state/daemon252通过/4忽略及严格lint | 未落盘崩溃/写入失败不算持久成功；远端通知恢复、全局审阅/远端传输及完整MCP仍开放；见[MCP撤销记录](ledger/native-mcp-revocation-20260914.json) |
| M1-03 / M1-07 / M3-10 | Windows stdio固定SHA/argv/环境/cwd，启动显式审批及宿主权限确认；真实daemon取消回收、篡改拒发和重启撤销、真实子进程无凭据继承；四包563通过/6忽略和严格lint | 非Windows启动明确拒绝；OS隔离/真实第三方后端、远端HTTPS/代理/OAuth及完整MCP仍开放；见[MCP stdio记录](ledger/native-mcp-stdio-20260914.json) |
| M1-08 / M3-10 | MCP HTTPS固定端点+显式loopback CONNECT代理，零环境代理/直连回退；SSRF静态目标检查、代理进入审批绑定、真实本地TLS/失败零直连及daemon审批/凭据边界；三包403通过/4忽略和严格lint | 远端DNS由可信代理负责；真实远端服务/代理节点、OAuth/代理认证和完整MCP仍开放；见[MCP HTTPS记录](ledger/native-mcp-https-20260914.json) |
| M1-03 / M3-10 | 已审阅MCP resource/prompt固定目标与封闭参数schema，能力/对应目录核对、审批读取和有界不可信结果；16种真实服务及daemon HTTP/MCP审批、撤销通过；daemon214通过/4忽略及严格lint | 资源模板/订阅/事件恢复、自动上下文、真实第三方资源和完整MCP仍开放；见[MCP资源提示记录](ledger/native-mcp-data-20260914.json) |
| M1-11 / M3-10 | MCP tokenRef专用origin/后端绑定、原生keyring读取，连接前和目录后复查、轮换/删除持久撤销；实际Windows独立凭据及daemon审批/重启通过；两包290通过/4忽略及严格lint | macOS实机、CLI管理/OAuth、stdio秘密引用及完整账号生命周期仍开放；见[MCP keyring记录](ledger/native-mcp-keyring-20260914.json) |
| M1-11 / M3-10 | 本地MCP凭据CLI reference/status/确认stdin写入/确认删除，写后验证且不重试/回滚；七种存储故障、实际Windows独占条目清理和零连接；CLI/MCP156通过/1忽略及严格lint | 完整OAuth、stdio秘密引用、macOS实机、远端撤销与崩溃持久回执仍开放；见[MCP凭据CLI记录](ledger/native-mcp-credential-cli-20260915.json) |
| M1-11 / M3-10 | OAuth库原始上下文封存、10分钟/单次兑换、刷新未知结果锁定及256绑定上限，严格token响应校验；真实本地取消/并发/失败和新授权恢复；MCP79通过/0忽略及严格lint | 保护仅本client及clone，非跨重启；产品OAuth路由/浏览器/持久token存储/真实账号仍开放；见[OAuth保护记录](ledger/native-mcp-oauth-guards-20260915.json) |
| M1-11 / M3-10 | OAuth库with_routes最多16个精确URL，复用显式loopback/HTTPS CONNECT且拒绝元数据扩张；实际本地完整流程、未登记零连接和独立代理通过；MCP82通过/0忽略及严格lint | 旧构造器保持兼容；产品配置/浏览器/原生TokenStore/跨重启刷新锁定和远端OAuth仍开放；见[OAuth路由记录](ledger/native-mcp-oauth-routes-20260915.json) |
| M1-11 / M3-10 | Windows stdio专用keyring环境引用、CLI管理、程序/变量绑定及审批摘要；实际子进程注入/取消、独占凭据轮换清理和预算；三包382通过/5忽略及严格lint | 非OS沙箱，无原生存储/启动原子性或全内存擦除保证；其他平台stdio、完整OAuth及账号生命周期仍开放；见[stdio凭据记录](ledger/native-mcp-stdio-credentials-20260915.json) |
| M1-11 / M3-10 | OAuth token绑定issuer/client/resource，原生专用TokenStore封闭记录和请求前pending标记；实际Windows重开、丢响应后新授权及故障矩阵；三包389通过/5忽略及严格lint | 同步存储需产品调度，外部写入无CAS；完整登录/浏览器/daemon消费、macOS与断电验收仍开放；见[原生OAuth记录](ledger/native-mcp-oauth-store-20260915.json) |
| M1-11 / M3-10 | 本地OAuth CLI reference/status/确认logout，区分可用/过期/pending/损坏，不刷新或输出秘密；实际Windows独占条目及零网络；两包175通过/1忽略及严格lint | 仅本地状态/删除，非远端认证/撤销；浏览器登录、daemon消费、并发协调和macOS仍开放；见[OAuth CLI记录](ledger/native-mcp-oauth-cli-20260915.json) |
| M1-11 / M3-10 | 公共client的确认式OAuth login、精确端点/代理、手动授权URL、有界loopback回调和原生保存；实际CLI五场景验证PKCE/pending/端口回收；两包180通过/1忽略及严格lint | 非真实账号/浏览器验收；daemon OAuth消费、macOS、confidential client及并发协调仍开放；见[OAuth登录记录](ledger/native-mcp-oauth-login-20260915.json) |
| M1-11 / M3-10 | daemon显式OAuth消费，完整代次绑定、连接/目录后fresh复查、变化持久撤销且不刷新；七种原生记录场景及真实daemon双凭据审批/重启；三包398通过/5忽略和严格lint | 仍无自动refresh/跨进程协调、真实账号、macOS或confidential client验收；见[daemon OAuth记录](ledger/native-mcp-oauth-daemon-20260915.json) |
| M1-11 / M3-10 | CLI显式confirm-refresh、原始端点/client/resource绑定、一次请求与原生pending，scope/refresh省略保留；真实CLI成功/拒绝/丢响应和重复拒绝；三包399通过/5忽略及严格lint | 新凭据代次仍须重审，非daemon自动刷新；跨进程协调/真实账号/macOS/confidential client仍开放；见[OAuth刷新记录](ledger/native-mcp-oauth-refresh-20260915.json) |
| M1-03 / M3-10 | 已审阅资源模板、RFC6570有界展开/固定authority、精确参数及URI摘要审批，完整模板目录/结果URI校验；30种服务场景与双凭据真实daemon审批；两包312通过/4忽略及严格lint | 仅必填标量变量，无订阅/自动上下文；真实第三方、列表映射模板和完整生命周期仍开放；见[资源模板记录](ledger/native-mcp-templates-20260915.json) |
| M1-03 / M3-10 | SDK确认订阅归属/32项未知状态保留；daemon短时resource_watch固定URI/参数审批、计数不读内容、退订关闭；九种观察场景及真实双模式审批；最终三包405通过/5忽略及严格lint | 长期事件恢复仍开放；首轮OAuth状态单次失败未定位，诊断增强后复验通过但不算根因修复；见[资源观察记录](ledger/native-mcp-observation-20260915.json) |
| M1-06 / M3-10 | 入站MCP单任务deadline主动空闲过期，取消请求/SSE且配额到实际释放才归还；活动隔离/任务重建/实际body结束通过；两包342通过/4忽略及严格lint | 内部短时fixture非真实30分钟耐久；跨平台/系统挂起及完整生命周期仍开放；见[主动过期记录](ledger/native-mcp-expiry-20260915.json) |
| M1-06 / M3-10 | 确定性修复旧请求时间样本误过期/倒退活动时间；先失败后通过、精确TTL与持有许可不变，HTTP/daemon360通过/4忽略及严格lint | 历史SessionExpired无轨迹不能证明唯一根因；凭据/OAuth/stdio异常与完整生命周期仍开放；见[活动顺序记录](ledger/native-mcp-activity-order-20260915.json) |
| M1-05 / M3-10 | 原生OAuth写后缺失/变更/读取失败分开脱敏诊断，单次写入故障注入与四键并发隔离回归；SDK/MCP/daemon589通过/5忽略及严格lint | 首次删除后读回异常保留，后续通过非修复证据；未改后端/重试/锁策略，所有旧凭据/stdio异常仍开放；见[凭据读回记录](ledger/native-keyring-readback-20260915.json) |
| M1-06 / M3-10 | operator status按真实MCP任务报告activeInvocations/收尾状态；stdio取消后待实际任务结束才检验固定句柄释放，daemon235通过/4忽略及严格lint | 仅状态快照非维护锁/远端效果核对，取消仍unknown不可重放；原文件锁失败保留，凭据及完整生命周期仍开放；见[收尾观测记录](ledger/native-mcp-drain-20260915.json) |
| M1-11 / M3-10 | OAuth新CLI同profile/origin非阻塞进程锁，覆盖login/refresh/logout完整生命周期；Windows锁路径不可替换，真实竞争/中断后释放；四包570通过/7忽略及严格lint | 仅同协调目录的协作CLI，非原生CAS；外部编辑器/旧客户端/直接SDK/macOS仍有边界；见[OAuth协调记录](ledger/native-oauth-coordination-20260915.json) |
| M3-06 / M3-07 | 原生OpenAI/Anthropic显式策略装配、独立凭据origin、无自动付费重试；目录内其他模型也不能覆盖固定默认模型 | 统一配置、完整能力目录、真实账号与所有流式合同 |
| M3-08 | 显式原生Responses、store:false文本/图片/函数历史、终态/片段/usage校验；Chat缺结束信号和坏工具回合拒绝；真实daemon三方言与HTTP取消/断流/并发释放，三包694通过/5忽略及严格lint | reasoning续接/phase、远端内置工具、完整费用unknown/切换与真实账号仍开放；见[Responses记录](ledger/native-provider-responses-20260915.json) |
| M3-08 | Chat固定response/model/choice及函数ID，拒绝终结后追加、跨索引重用/更换ID和越界；六种真实HTTP错误关闭/不重放，最终三包697通过/5忽略及严格lint | 联合回归出现原生凭据查询失败，仅增诊断后通过，未定位根因；完整方言/费用/真实服务仍开放；见[Chat身份记录](ledger/native-chat-identity-20260915.json) |
| M3-08 | Anthropic完整消息/块终态、工具延后完成、唯一ID和部分文本；缓存输入三项合计/累计回退溢出拒绝；七种HTTP场景，三包703通过/5忽略及严格lint | 签名thinking续接、完整计价/unknown账单、实号及先前凭据异常仍开放；见[Anthropic记录](ledger/native-anthropic-lifecycle-20260915.json) |
| M3-08 | Chat完整/部分usage一致性、UTF8累计输出/工具参数限额、DONE释放与部分事件保留；真实HTTP达到4MiB超限，三包707通过/5忽略及严格lint | usage-known、完整计价/unknown持久回执、模型配置与实号仍开放；见[Chat预算记录](ledger/native-chat-budget-20260915.json) |
| M3-08 | 实际ProviderAdapter拒绝不完整/未知终态假成功，stream工具待终态确认；三方言daemon和受控barrier/历史回归，HTTP/daemon345通过/4忽略及严格lint | 当前为503失败门禁，尚非无损partial/usage跨运行时持久化；见[适配终态记录](ledger/native-generation-terminal-20260915.json) |
| M2-05 / M3-08 | 有类型HTTP partial文本/usage/终态、完成工具待摘要核对；runtime错误/EOF保留partial不合成MessageEnd；三方言Gateway幂等与redb重开，三包585通过/4忽略、严格lint及根check | 替代已知partial统一503；Gateway仍保护outcome_unknown，runtime费用/usage持久化、查询UX和实号未关闭；见[部分结果记录](ledger/native-partial-generation-20260915.json) |
| M3-05 / M3-08 / M5-01 | 原生agent.wait及CLI只读partial-run按设备/run/revision和SHA分页，UTF8边界/2048字节/不ACK、不泄漏reasoning与工具参数；真实跨设备/RPC子进程，318通过/5忽略及严格lint | 自动多页导出、TUI/桌面视图、费用/usage持久化与实号仍开放；见[partial页记录](ledger/native-partial-pages-20260915.json) |
| M1-03 / M3-08 / M4-01 | 原call ID结构化助手/工具历史进checkpoint和三方言真实请求；外部结果/检索/摘要不提升system；审批/身份隔离及redb重开，621通过/4忽略、严格lint/根check | 未配对历史恢复、推理签名、旧版本降级、实号和完整提示注入防御仍开放；见[工具历史记录](ledger/native-tool-history-20260915.json) |
| M2-05 / M3-08 / M4-01 | 未配对历史作为不可信未确认数据供新请求使用，完整组仍类型化；最终投影预算复核，自有Chat审批前进程中断/重启/拒旧重放，231通过/4忽略及严格lint | 已批准外部效果核对、其他方言实机中断、超预算自动压缩与费用仍开放；见[历史恢复记录](ledger/native-tool-history-recovery-20260915.json) |
| M2-05 / M3-08 | 明确区分缺失/部分/完整主计数及零值；实际provider身份/终态逐轮进入terminal TurnRecord，redb重开与三方言Gateway固定汇总；七包1283通过/5忽略、严格lint及根check | 执行中逐轮日志/价格账单/准确流来源仍开放；stdio锁与凭据撤销联合失败保留，未声称修复；见[用量记录](ledger/native-provider-accounting-20260915.json) |
| M3-08 | SDK带来源流快照保留分帧主字段/明确零值，原生HTTP摘要不再一律部分；50组合屏障与真实HTTP三方言/Copilot，三包725通过/5忽略、严格lint及根全目标check | 非自动HTTP流持久化；执行中日志、费用核对、外部SDK消费者与实号仍开放；先前凭据/stdio异常未关闭；见[流来源记录](ledger/native-stream-usage-20260915.json) |
| M2-05 / M3-08 | 独立CAS逐轮意图/首个报告在请求/输出前落盘，原子封闭terminal turn；写失败/取消/竞争/重开与真实Chat进程中断仍保留报告不重放，四包674通过/4忽略、严格lint及根check | 意图可未发送、报告提交前仍可能未知；价格/预算/HTTP流持久化及降级未验收，MCP会话/OAuth联合失败根因开放；见[逐轮日志记录](ledger/native-provider-journal-20260915.json) |
| M3-08 | 可选maxObservedTurnTokens启动门槛，完整已观察主计数达到阈值或未知/溢出不再调用下一轮；真实默认/零/正值Gateway与幂等，475通过/4忽略、严格lint及根check | 不是单请求硬限额/货币预算，不回滚已批准工具，不覆盖HTTP/全局配额；全部旧异常未关闭；见[观察门槛记录](ledger/native-observed-budget-20260915.json) |
| M3-05 / M3-08 / M5-01 | CLI export-partial固定身份/epoch收集有界页并验全文SHA后create-new写明文；不ACK/重放/覆盖，七种实际子进程场景，CLI95通过/1忽略及严格lint | 非atomic rename，本地I/O失败可留文件；TUI/桌面、加密partial、续传/持续保存及旧异常仍开放；见[完整导出记录](ledger/native-partial-export-20260915.json) |
| M3-08 / M5-01 | TUI partial/partial-next固定连接与选中run终态逐页查看，旧游标拒绝/不新增ACK；七种真实WebSocket与窄宽渲染，全目标66通过/0忽略及严格lint | 续页只固定全文摘要非独立全文校验，有界transcript非归档；费用/桌面/实机与旧异常仍开放；见[TUI部分页记录](ledger/native-tui-partial-20260915.json) |
| M3-08 / M5-01 / M5-02 | TUI和Slint接入已有providerAccounting，共用有界协议模型；区分缺失/未报/部分/明确零值/溢出、终态与日志来源和未结算费用；九种真实WebSocket、七种桌面状态及多尺寸软件像素，protocol/TUI138与桌面86通过、严格lint/根check | 非货币硬限额/已结算账单，桌面完整partial导出、模型配置生命周期、实号/交互平台与旧凭据异常仍开放；见[客户端用量记录](ledger/native-accounting-clients-20260915.json) |
| M4-01 / M4-02 | 显式memory_notes接入模型/HTTP/MCP统一审批审计；身份分区、CAS保存/纠正/删除、分页/UTF-8游标、关键词跨会话召回；实际双设备模型夹具及两次重启验证 | 语义/自动召回、完整客户端/来源/备份遗忘、完整磁盘配额与真实模型账号；见[显式记忆记录](ledger/native-explicit-memory-20260914.json) |
| M4-02 / M5-01 / M5-08 | CLI七种记忆动作使用持久设备与health能力预检；原生直接工具回合零模型请求、绑定审批/持久结果/幂等；固定revision摘要导出页、原子CAS导入、结构化stdin凭据分离；相关四包535测试通过 | 大归档分阶段导入/本地自动收集、TUI/Slint专用管理、语义与全历史/备份遗忘仍开放；见[记忆客户端记录](ledger/native-memory-client-20260914.json) |
| M1-06 / M2-07 / M4-02 | 记忆全库256个持久笔记本配额在同一redb写事务检查；最后名额竞争、满额已有记录维护、重启和空笔记本保留；写锁等待后再次核权，相关三包301测试通过 | 完整磁盘/归档/产物配额、身份退役、全平台故障仍开放；见[记忆配额记录](ledger/native-memory-quota-20260914.json) |
| M4-02 / M5-01 / M5-08 | TUI七种类型化记忆动作、同连接能力预检与持久profile；有界输入/归档、跨会话草稿拒发、原键重试、未发送与历史未知区分；62项测试及严格lint通过 | 完整管理页面、崩溃后草稿/键恢复、自动加密归档、Slint与实机仍开放；见[终端记忆记录](ledger/native-memory-tui-20260914.json) |
| M4-02 / M5-02 / M5-08 | Slint七动作表单/覆盖选择/完整结果区/原键重试；已保存身份与同epoch预检、严格归档、会话绑定及收据晚到保护；84项测试与严格lint通过 | 完整来源/遗忘、自动加密归档、崩溃恢复和跨平台实机仍开放；见[桌面记忆记录](ledger/native-memory-desktop-20260914.json) |
| M2-10 / M4-02 / M5-01 | CLI逐页获批归档固定revision/游标/摘要核验后age加密新文件；加密导入先认证解密后联网，支持双秘密stdin；76测试通过/1保留忽略及严格lint | 大归档分阶段导入、GUI文件流程、自动ACK/崩溃恢复、目录耐久和完整遗忘仍开放；见[记忆文件记录](ledger/native-memory-files-20260914.json) |
| M1-03 / M4-03 / M4-06 / M4-07 | 原生、受限GET、签名Wasm技能接入同一工具/审批/审计；完整离线schema与manifest/参数/资源/发布绑定；真实MCP/HTTP/Gateway及签名组件、取消回收通过 | 全部bundled/upstream技能移植、通用HTTP/代理、完整插件能力同意与平台验收；见[技能和事件记录](ledger/native-skills-device-events-20260914.json) |
| M1-10 / M3-03 | Gateway运行/工具/结果事件入队前按认证device过滤；同设备多连接、其他管理员设备、scope与真实双设备撤权测试通过 | 所有事件族、外部上游互操作与完整客户端缺口恢复 |
| M5-01 / M5-08 | TUI原生profile、发送/精确取消、多结果ACK、双游标恢复、连接代号拒旧、会话视图隔离、宽字符布局和明确unknown | onboarding、完整流式/快照协调、平台用户验收 |
| M6-07 | Rust CLI有界只读OpenClaw预览、8项分页、指纹续页、容器识别/秘密内容排除；已有JSON/JSON5深度64/节点16384预算及重复键/非有限值拒绝 | 精确版本/schema、外部根/includes、SQLite/WAL一致快照和导入 |
| M5-02 / M5-03 / M5-08 | Slint OS profile、历史版本/epoch 拒旧、结果恢复/精确停止/完整审批；unknown独立终态、durable结果及精确ACK revision、旧/非当前会话结果拒ACK | 原生设置/信任、完整流式/展示恢复协调和真实用户/平台验收 |
| M1 / M6 依赖安全 | Node九类告警依赖及实际内嵌CSV、Restify/Node26兼容修复；JWT10.3+既有ring RS256和19签名夹具；rustls0.23.45/Wasmtime47.0.4；六包828通过/6忽略、严格lint/根check、Node31断言及两类audit零漏洞；main推送后GitHub确认0开放/56已修复，原41告警关闭 | cargo-deny既有违规及新增signature双版本未放行，原生OAuth联合失败保留且根因未修复；非发布/实号/设备验收，见[依赖安全记录](ledger/native-dependency-security-20260915.json) |
| M6 发布 | 没有发布或切换 | 受保护策略/打包器仍锁定 Rust 1.97.1；开发已为 1.98.1，需审查升级，不能改 validator 放行 |

## OpenClaw / Hermes 差距追踪

本次把能力对比落实到已有任务，不新增重复任务或勾选完成状态。模型目录当前为
28 个 `Implemented`、38 个 `EndpointRequired`、12 个 `RegistrationOnly`；前两类的协议
客户端存在不等于全部生产接入/真实账号验收。51 个技能目录和 137 个插件描述符同样
不能当作执行数量。源码出处见 [PROJECT_PLAN.md](PROJECT_PLAN.md) 第 2.4 节。

| 能力差距 | 必须追踪的任务 | 完整验收要求 |
|---|---|---|
| 聊天/历史/恢复 | M2-02、M2-03、M3-02、M3-03、M3-04、M5-01、M5-08 | 真实流式工作流、断线/重启核对和固定版本互操作，不止握手成功 |
| 模型选择与能力 | M0-05、M3-06、M3-07、M3-08、M7-02 | 分开记录客户端、端点、产品配置、账号和各模态证据 |
| 工具/浏览器/执行后端 | M1-03、M1-07、M1-08、M1-09、M3-10、M7-05、M7-07、M7-09 | 真实任务调用、拒绝零执行、隔离/代理/取消与副作用核对；未支持后端明确拒绝 |
| 跨会话记忆/偏好 | M4-01、M4-02 | 检索来源与权限正确，用户可纠正/删除，重启与重建索引不复活已遗忘内容 |
| 技能/插件/经验改进 | M4-03、M4-04、M4-05、M4-06、M4-07、M7-03、M7-04 | 技能实际执行与插件状态独立计数；经验生成草案、审核、回归和回滚形成完整流程 |
| 自动化/多 Agent | M4-08、M7-07、M7-08、M7-09 | 持久调度、身份/预算隔离、取消树、结果归属和恢复；不以模块存在代替任务完成 |
| 渠道可靠收发 | M2-04、M2-05、M3-11、M3-12、M3-13、M3-14、M7-01 | 保留已完成的 Telegram/Discord 持久接收/投递增量，继续验证 cursor/resume、恢复和真实账号 |
| 客户端/移动/设备 | M5-01、M5-02、M5-03、M5-04、M5-05、M5-06、M5-07、M5-09、M5-10、M7-06、M7-10 | 实际客户端完成聊天/附件/审批和平台授权；连接壳不算完整应用 |
| 数据迁移/安装交付 | M6-04、M6-05、M6-06、M6-07、M6-08、M6-14、M6-15、M6-16、M6-18、M6-20 | 预览、快照、导入、恢复、安装升级逐项验收；旧 Node 镜像不等于 Rust 已交付 |

联合验收必须走完整的“真实模型 -> 审批工具/技能 -> 可检索记忆 -> 定时执行 ->
可靠投递 -> 重启核对”场景，并记录拒绝/撤权/未知结果的负例，归 M0-10、M2-05、
M4-01、M4-03、M4-08、M5-01、M6-16 共同验证，不能用各 crate 的测试总数替代。
上述对标不是新的外部执行授权；真实账号、付费后端、设备及部署仍按既定边界批准。
四项已完成、94 项未达完整验收的统计不因文档补充改变，也不是代码完成率或能力追平率。

## M0 基线与设计

前置: 无。退出: 双基线、完整差异盘点、设计决策和验收预算可复核。

- [ ] M0-01 固定 stable release/tag/commit、资料出处和校验值；独立验证来源/签名，不把 release 文案当成自己的验签结果。

  归属/入口：`claw-conformance`、`claw-repo-policy`；[版本化候选](../compat/releases/) 与 [旧基线](../compat/upstream/baseline.json)。前置：无；网络读取遵循已有代理边界。当前：OpenClaw 九月身份元数据已存在，Hermes 有版本化官方资料，独立本地验签仍未关闭。

  - [ ] M0-01.01 分别保存 OpenClaw release/tag 对象、解引用 commit、tree、发布时间及 Hermes 能力参考来源，注明可变网页与固定源码的区别。
  - [ ] M0-01.02 记录获取到的原始字节和 SHA-256，列明签名/attestation 的信任根、验证命令与缺失材料；API 显示 verified 不替代本地验证。
  - [ ] M0-01.03 验证标签不匹配、签名错误、文件篡改、重定向异常及无法独立验证时的拒绝/待决结果，既有封存字节不变。
  - [ ] M0-01.04 形成可复核来源记录并交给合同提取器；不能验证的部分明确标记，不自动选择 main 或旧版本顶替。

  验收：两组来源均可定位到确切材料，OpenClaw 合同仅使用已固定源码；失败处置：保留旧回归和候选证据，暂停新版兼容/发布声明。证据：原始响应、对象关系、摘要、验证输出与限制。

- [ ] M0-02 保存当前源码、旧封存合同、部署和数据布局快照；确认哪些是真实使用场景，哪些只是注册项。

  归属/入口：`claw-conformance`、daemon、`claw-migrate`；[旧迁移义务](legacy-node-port-obligations.md)。前置：M0-01 的来源标识。当前：已有增量源码见证，不是完整、冻结的构建输入或用户数据快照。

  - [ ] M0-02.01 列出四个 workspace、源码/配置/lock/生成输入和相关部署入口，记录 HEAD 与已修改/未跟踪文件，不覆盖任何已有改动。
  - [ ] M0-02.02 区分本地开发版、当前容器入口、实际安装制品及待发布候选；用户目录仅在授权范围内列清单，凭据只记引用。
  - [ ] M0-02.03 为模型、渠道、技能、插件、客户端逐项登记库实现/生产装配/真实使用三种证据，验证注册数量不能冒充启用数量。
  - [ ] M0-02.04 生成可恢复的输入清单和差异报告；不能冻结的并行变化标记见证范围，备份保留和清理单独审批。

  验收：从记录能确认被比较/构建的实际版本和输入，没有遗漏已知外部根或把未授权目录当已检查。失败处置：停止有关兼容断言，保留全部源码及源数据。证据：清单、哈希、部署身份、未检查范围。

- [ ] M0-03 从七月基线到固定九月提交完整盘点 Gateway/HTTP/config/provider/channel/tool/skill/plugin/client/migration 的新增、修改、删除。

  归属/入口：`claw-conformance` 与各能力 owner；[旧清单](../compat/upstream/manifest.json)。前置：M0-01、M0-02。当前：已识别高影响变化，完整语义 diff 尚未完成。

  - [ ] M0-03.01 按 Gateway、HTTP、配置、模型、渠道、工具、技能、插件、客户端、迁移和交付逐面列出旧/新来源，不从发布摘要推导完整覆盖。
  - [ ] M0-03.02 提取字段、默认值、鉴权、取消/恢复、弃用和删除行为，记录新增/修改/删除及对应 Rust owner，而不只对比文件或符号数量。
  - [ ] M0-03.03 用人为漏项、重复项、改默认值和删字段的候选验证差异检测；未识别输入保留 unknown，不生成空成功。
  - [ ] M0-03.04 给每条差异关联实现/适配/明确拒绝/待决与退出测试，输出覆盖缺口及后续任务，旧 ledger 保持只读。

  验收：每个提取面都有可追溯输入、差异和处置，删除能力有用户诊断。失败处置：保留不完整标记，阻止相关新版兼容声明，不改总量掩盖缺项。证据：来源对照、差异记录、检测负例。

- [ ] M0-04 建立新版版本化合同、正反向 fixture 和双基线读取器；旧 `compat/upstream/`、`compat/legacy/` 字节不变。

  归属/入口：`claw-conformance`、`claw-protocol`；[crate 入口](../crates/claw-conformance/Cargo.toml)。前置：M0-03。当前：候选元数据和双基线读取器已存在，完整新版合同仍未交付。

  - [ ] M0-04.01 为候选合同定义 schema/version、上游源码、feature ID、源证据和摘要，清楚分开身份元数据与完整行为合同。
  - [ ] M0-04.02 在既有读取器接入新版 schema 与正反向 fixture；同时保留七月和 legacy 回归，拒绝未知版本、重复键和缺失材料。
  - [ ] M0-04.03 验证错 SHA、错计数、删 fixture、引用不存在或未启用的 Rust 测试均失败，未实现方法返回明确 unsupported。
  - [ ] M0-04.04 记录原始封存字节未变、候选来源与可达测试清单；仅在提取完整时允许声明 complete contract。

  验收：同一 harness 可独立校验旧/新合同，候选缺项不能通过。失败处置：隔离无效候选，不回写旧封存数据或放宽 validator。证据：双基线命令、变异负例、摘要比较。

- [ ] M0-05 关闭 D01：逐项固定 OpenClaw/Hermes 能力参考的版本与来源、owner、生产入口、实现层级、兼容结论和退出测试；客户端/注册项与端到端能力分开，未支持项明确显示。

  归属/入口：`claw-conformance`、所有能力 owner；[Provider 状态定义](../crates/claw-providers/src/descriptor.rs)。前置：M0-04。当前：九类差距已映射，完整逐能力发布范围仍未核销。

  - [ ] M0-05.01 为 OpenClaw 与 Hermes 分别固定比较材料，按功能而非语言或注册总数列出用户场景、适用配置、依赖和支持级别。
  - [ ] M0-05.02 对每项记录库实现/生产装配/端到端证据及精确/适配/待决/未验证结论；模型方言、已知端点、实际账号分开。
  - [ ] M0-05.03 验证 51 条技能或 137 个插件描述符不能变为可执行数量；待批准、提取失败、未实现不能被默认归为不适用。
  - [ ] M0-05.04 形成有明确差异的发布范围与用户诊断，任何范围删减经过批准；Hermes 工作流参考不扩大 Python/Node 或外部执行授权。

  验收：所有已知能力都有 owner、状态、差异和退出检查，不能藏起未支持项。失败处置：保留待决行和原目标，暂停对应发布声明。证据：逐能力矩阵、来源、批准记录与可达测试。

- [ ] M0-06 关闭 D02：状态库候选通过精确依赖/MSRV/license、事务、备份和三平台崩溃验证，不自研数据库。

  归属/入口：`claw-state`、`claw-platform`；[状态库依赖](../crates/claw-state/Cargo.toml)。前置：M0-02、M0-05。当前：redb 4.2.0 已装配并有 Windows 事务/进程恢复证据，其他保证未齐。

  - [ ] M0-06.01 固定 redb 精确依赖、许可证、MSRV、平台/文件系统条件，核对已用事务、锁和恢复 API 的官方保证。
  - [ ] M0-06.02 以现有 StatePort 验证 CAS、快照读、单写入者、备份一致性和 schema 升级，不用内存替身代替磁盘库。
  - [ ] M0-06.03 在 Windows/Linux/macOS 分别验证进程中断、空间/权限/锁/损坏失败；物理断电另列，不能从进程退出推导。
  - [ ] M0-06.04 输出 D02 决策与恢复范围，记录同步、加密、备份和迁移限制；不能满足的发布平台保持阻塞。

  验收：已有状态库的保证和应用职责清楚，三平台需要各自证据。失败处置：保留源库与只读核对入口，不回退空内存库，不以换库掩盖数据损失。证据：依赖审查、真实数据库测试和平台限制。

- [ ] M0-07 关闭 D03：证明 OpenClaw SQLite/规范化导出可读取选定数据和 WAL 状态；无读取方案不得承诺全状态迁移。

  归属/入口：`claw-migrate`、`claw-state`；[OpenClaw 预览实现](../crates/claw-migrate/src/openclaw.rs)。前置：M0-01、M0-06。当前：有界只读预览存在，SQLite/WAL 一致内容导入未实现。

  - [ ] M0-07.01 记录目标实际 schema、共享/per-agent DB、WAL/SHM、整数字段和外部根；未知 schema 必须停止解析而非猜测字段。
  - [ ] M0-07.02 比较满足政策的现成读取库与源系统规范化导出，验证类型保真、Unicode/NUL、64 位整数、事务边界和文件尺寸预算。
  - [ ] M0-07.03 用写入中的 WAL、遗漏 WAL、截断页、损坏索引、未来版本和超限输入证明不能生成伪一致快照，源文件始终不变。
  - [ ] M0-07.04 形成 D03 决策、可支持版本和可复现快照流程；若需政策例外先批准，否则仅交付明确受限的预览。

  验收：能解析并核对选定数据和一致性，而非仅复制数据库文件。失败处置：拒绝 import，保存诊断和源快照，不启动源端 doctor/升级。证据：读取方案审查、真实格式 fixture、WAL 正负例。

- [ ] M0-08 关闭 D04：指令内容、声明式 HTTP、Rust/Wasm 移植和不支持的 JS/hook 分类，禁止嵌入式解释器。

  归属/入口：`claw-skills`、`claw-plugin-api`、`claw-plugin-host`；[插件兼容分类](../crates/claw-plugin-api/src/compat.rs)。前置：M0-03、M0-05。当前：Wasm 宿主和分类基础已有，不能直接执行上游 JS 插件。

  - [ ] M0-08.01 对每项 skill/plugin/hook 分离纯指令、配置、脚本、二进制和运行时依赖，记录来源、许可证和所需能力。
  - [ ] M0-08.02 为可移植项选择 Rust 原生、受限声明式 HTTP 或 Wasm 组件，写明参数、资源、错误、取消和版本映射。
  - [ ] M0-08.03 验证 npm 包、JS 解释器、伪装 Wasm 解释器、未批准脚本及缺移植证据均不可激活，内容导入不授予执行权限。
  - [ ] M0-08.04 发布可执行/仅内容/待移植/不支持状态与替代方案，Code Mode 和退役技能的差异必须向用户可见。

  验收：每个执行资产有明确合法路径和测试，不以 WASM 文件后缀替代审查。失败处置：隔离执行物、保留原始内容和诊断，不自动安装依赖。证据：分类表、移植设计、拒绝测试与批准范围。

- [ ] M0-09 关闭 D05/D06：确定平台/插件兼容差异、严格授权与代理模式；不擅自改 JS/Slint/Linux 政策。

  归属/入口：`claw-repo-policy`、`claw-platform`、各 UI workspace；[架构政策](../crates/claw-repo-policy/Cargo.toml)。前置：M0-05、M0-08。当前：四 workspace、无嵌入式 JS、Linux GUI 拒绝和发布工具链边界已明确。

  - [ ] M0-09.01 列 Windows/macOS/Linux/Android/iOS 的服务、CLI、GUI、凭据与硬件能力，区分已支持、待实现和需政策决策。
  - [ ] M0-09.02 记录 allow/deny/ask、未知副作用、代理拒绝、JS 退役等与上游/legacy 的行为差异，定义用户提示和迁移处置。
  - [ ] M0-09.03 检查根依赖图不引入 Slint/Node、未支持代理不直连、Linux GUI 不因删 CI 断言变为支持，受保护发布策略不自授权。
  - [ ] M0-09.04 对真正需要改变的技术或平台约束列独立批准项；未获批准的能力保留阻塞，不改写总目标。

  验收：D05/D06 的范围、允许差异和待决项均可复核。失败处置：保持既有政策和当前服务，不以“为了兼容”放开执行。证据：平台/网络矩阵、决策、政策负例与批准记录。

- [ ] M0-10 固定功能、性能、故障注入、真实账号和设备验证矩阵及整条任务流程；横向比较使用同模型/输入/权限/预算，记录成功率、成本、时延与恢复结果，先确认隔离环境和执行授权。

  归属/入口：各模块测试、`claw-conformance`、发布工作流；[现有 Rust CI](../.github/workflows/rust.yml)。前置：M0-05、M0-06、M0-09。当前：已有多组局部测试，不是冻结的完整产品验证矩阵。

  - [ ] M0-10.01 冻结功能场景、故障点、OS/架构、文件系统、模型/渠道、测试数据和输入指纹；用任务 ID 关联每个必测单元。
  - [ ] M0-10.02 定义本地替身、真实账号、真机、发布制品四层验证，明确测试所有权、端口、时限、费用上限、隐私数据和清理范围。
  - [ ] M0-10.03 建立同模型/输入/权限/预算对比方法，分别统计任务成功、额外时延、token/费用、RSS/句柄、恢复时间；预先固定阈值。
  - [ ] M0-10.04 登记授权和资源阻塞，用一条完整任务贯通工具/记忆/调度/投递/重启；跳过、失败、未运行必须独立呈现。

  验收：执行者可以从矩阵确定该跑什么、成功标准和禁止动作，不需临时猜测。失败处置：缺资源的单元保持 blocked，代码可继续用隔离替身验证，不调整阈值掩盖失败。证据：矩阵、数据摘要、预算及授权。

## M1 安全执行

前置: M0。退出: 所有入口遵守同一授权规则，拒绝动作的实际执行次数为 0。
主要 owner: `claw-tools`、`claw-security`、`claw-runtime`、`claw-platform`、daemon。

- [x] M1-01 修正 `ToolPortBridge` 统一 `requires_approval: false`、`mutates_workspace: false` 的风险元数据；实际 bridge 的审批/拒绝/取消/超时测试证明插件不再被当作只读免审批工具。见开发记录。

  保留验收：仅覆盖已记录的保守风险默认值与 bridge 执行分支，证据见 [原生基础记录](ledger/native-foundation-20260914.md)。新增工具类别、渠道主体与插件完整能力同意由 M1-02、M1-03、M1-05 继续验收。

- [ ] M1-02 去掉调用上下文写死的 `sender_is_owner: true`，身份/账号/会话/工作区权限从认证入口传播到工具。

  归属/入口：`claw-application`、`claw-runtime`、daemon；[实际 runtime 适配](../apps/gta-claw-daemon/src/adapters/agent_runtime.rs)。前置：M0-05、M0-09。当前：Gateway/HTTP/MCP 与 Telegram/Discord 已有主体传播和会话隔离增量，Teams/WhatsApp 等缺口保留。

  - [ ] M1-02.01 逐入口登记认证 source/principal/account、会话所有者、scope 和 workspace，区分真实 owner、普通使用者与 legacy 兼容身份。
  - [ ] M1-02.02 将剩余渠道、目标指令和工具执行统一接入不可伪造的 authority/lease，历史无主记录只保留不自动归属新主体。
  - [ ] M1-02.03 用同文本/同 sender ID 不同账号、跨设备历史/取消、伪造 owner 参数和重启/reset 验证无越权、无串会话。
  - [ ] M1-02.04 验证撤销一设备只终止其权限，所有入口的旧 generation 和失效 lease 都拒绝，记录未支持的 legacy 身份差异。

  验收：从入站到真实文件/目标/插件操作主体保持不变，未认证执行为零。失败处置：拒绝该入口的副作用，保留历史与审计，不回退为 owner。证据：入口矩阵、跨主体正负例、真实装配调用次数。

- [ ] M1-03 将 `claw-tools` 接入 daemon，原生/插件/HTTP/MCP 使用一致工具目录、参数 schema、权限和审计。

  归属/入口：`claw-tools`、`claw-skills`、runtime、daemon；[原生工具适配](../apps/gta-claw-daemon/src/adapters/native_tools.rs)。前置：M1-02、M0-08。当前：文件/固定程序/固定地址读取和插件已有共同审批审计，完整能力和技能目录仍缺。

  - [ ] M1-03.01 统一实际可调用工具的名称、schema、来源/版本、风险、资源和能力状态；无策略或未装配能力不可列为可执行。
  - [ ] M1-03.02 将模型、HTTP、MCP、原生、插件和技能调用汇入既有 executor；发现/describe/dry-run 与 effects 分开，拒绝旁路调用。
  - [ ] M1-03.03 验证坏 schema、未知字段、重复名称、非法替换、无能力同意和缺审计均不执行，目录中不存在虚假的成功工具。
  - [ ] M1-03.04 使用真实 bound daemon 分别跑批准/拒绝/取消与发布替换，确认旧工具撤权、资源回收及状态查询一致。

  验收：同一调用经不同入口产生相同权限和审计结果，实际能力可被查询。失败处置：撤下失效 publication，保留旧历史，不以空结果伪装成功。证据：目录/schema、生产测试、审计及调用计数。

- [x] M1-04 接入真实 ApprovalPort 展示及 CLI/TUI 决策通道；验证 `SilentApprovalPort` 只丢通知，不把换名当成修复。实现、实际 daemon 审批闭环及 CLI/TUI 负例见 [原生执行记录](ledger/native-execution-20260914.md)。

  保留验收：已实现完整预览、指纹复核和单次决策端口，不扩大成全部客户端产品完成。新增展示竞态、平台工作流和长期恢复由 M1-06、M5-01、M5-02、M5-08 承接。

- [ ] M1-05 覆盖 allow/deny/ask、缺失/空 allowlist、只读、重复批准、错主体、过期、取消、断线、重载撤权；deny 不自动变 ask。

  归属/入口：runtime 审批与工具执行；[tool.rs](../crates/claw-runtime/src/tool.rs)、[approval.rs](../crates/claw-runtime/src/approval.rs)。前置：M1-02、M1-03。当前：单次 broker 和多个负例已有，全部入口/风险类别矩阵未关闭。

  - [ ] M1-05.01 固定每个配置来源的 allow/deny/ask、缺失/空列表、只读、owner 与主体规则优先级，绝不将显式 deny 转 ask。
  - [ ] M1-05.02 将读/写文件、进程、网络、目标、插件和技能分别纳入矩阵，验证 allow 也不能绕过资源或能力限制。
  - [ ] M1-05.03 对错审批人、重复、过期、断线、cancel/reload/revoke 竞争断言实际执行零次；批准与取消同时到达不能复活请求。
  - [ ] M1-05.04 验证无人审批、前端退出、服务关闭和未被消费的批准都能结算/撤销，UI 与 runtime 不留下可兑换旧许可。

  验收：矩阵每格有明确结果和调用次数，迟到事件不生效。失败处置：默认拒绝并保留诊断，禁止为了可用性放宽权限。证据：策略表、确定性竞态测试、真实入口回放。

- [ ] M1-06 审批绑定工具版本、参数摘要、资源与 generation；审批后参数/路径变化必须重新评估，旧许可不可跨会话重放。

  归属/入口：runtime、`claw-protocol`、三类客户端；[审批合同](../crates/claw-protocol/src/native_approval.rs)。前置：M1-03、M1-04。当前：完整参数、版本、主体与指纹已绑定，完整发布/文件竞争矩阵未齐。

  - [ ] M1-06.01 固定预览字段、完整规范化参数和大小限制，包含 caller/account/session/resource/publication/revision/generation，不把缺字段当默认正确。
  - [ ] M1-06.02 确保 UI 展示、用户批准、broker 兑换和执行读取同一绑定对象，重新解析同名资源或换参数必须重新审批。
  - [ ] M1-06.03 验证截断预览、错指纹、换工具版本、换根路径、跨会话 token、旧连接命令和重启前许可全部拒绝。
  - [ ] M1-06.04 检查完整预览可滚动/读取，拒绝超限而不隐藏参数；终态/撤销通知能清除等待 UI 和执行许可。

  验收：批准的内容与实际作用对象一致，部分预览不可批准。失败处置：失效原预览并要求新审批，未知执行不重发。证据：合同测试、三客户端负例、真实资源变更检查。

- [ ] M1-07 文件/进程/网络工具验证工作区约束、路径穿越、符号链接/junction、参数注入及子进程清理；区分固定程序/cwd 限制和 OS 沙箱，通用执行后端单列支持矩阵，仅清理自己拥有的进程。

  归属/入口：`claw-tools`、`claw-platform`、daemon 原生工具。前置：M1-06、M0-09。当前：Windows 根/祖先 pin、硬链接拒绝、固定程序摘要与取消回收已有窄证据，不是全 OS 沙箱。

  - [ ] M1-07.01 文件读写以批准的根/句柄身份校验，覆盖 traversal、symlink/junction、硬链接、祖先替换、Windows 保留名/大小写、Unix namespace。
  - [ ] M1-07.02 固定程序维持完整 argv、trusted SHA、环境最小集、cwd、时间/输出上限；写明动态库/输入文件/网络权限不受 exe 摘要担保。
  - [ ] M1-07.03 对批准后路径/文件变更、同长同 mtime 替换、输出洪泛、超时、future drop、后代进程和句柄泄漏实施实际负例。
  - [ ] M1-07.04 为通用本机/容器/SSH 等后端确定真正的隔离与生命周期合同，未验证默认关闭；取消只回收本次拥有的资源。

  验收：越界操作被阻止、源文件未受改动、进程取消可证明清理；每个平台单独留证。失败处置：关闭该能力并报告 unknown/需核对，不扩大 allowlist。证据：平台路径矩阵、真实进程测试及资源计数。

- [ ] M1-08 盘点 provider、role/skill、插件 HTTP、渠道 REST/WSS、MCP、updater 全部出站；补齐或明确拒绝每种代理模式。

  归属/入口：`claw-provider-sdk`、插件宿主、渠道和 updater；[daemon 装配](../apps/gta-claw-daemon/src/production.rs)。前置：M0-09、M1-03。当前：共享策略存在，固定地址工具和部分 WSS/updater 路由仍有限制。

  - [ ] M1-08.01 按消费者和协议登记实际网络实现、凭据、DNS、代理、bypass、redirect、大小/时间和取消上限，不能只记录 policy 传参。
  - [ ] M1-08.02 复用统一出站策略接入尚未覆盖的 transport；明确直连、CONNECT、TLS/WSS 隧道和不支持模式的启动/发送前拒绝。
  - [ ] M1-08.03 通过独立本地代理/目标 fixture 观察真实连接路径，验证显式代理故障没有目标直连、WSS 不从 REST 支持推导。
  - [ ] M1-08.04 在配置检查、诊断和文档公布各消费者支持矩阵与限制，生产代理配置/节点/进程不参与修改。

  验收：每条出站有可验证路由与策略，不存在未盘点直连。失败处置：拒绝相关功能或保持 pending，不静默改变网络模式。证据：消费者矩阵、连接观测、故障负例和诊断输出。

- [ ] M1-09 覆盖代理失败、重定向、DNS 重绑定、IPv4-mapped IPv6、元数据地址和 TLS；严格代理模式不得静默直连。

  归属/入口：出站策略、`claw-tools` 网络与插件 HTTP。前置：M1-08。当前：固定 IP/HTTPS 和部分负例已有，通用 DNS/代理组合仍未实现完毕。

  - [ ] M1-09.01 固定域名、解析地址、实际 peer、TLS/SNI、认证 origin 的绑定顺序，定义地址分类和每跳 redirect 重新授权。
  - [ ] M1-09.02 对 localhost/私网/元数据/mapped IPv6、混合公私地址、DNS 变化、非标准数字 IP、用户信息 URL 和证书错误逐项测试。
  - [ ] M1-09.03 验证超时/部分响应/超大 header/body、代理认证失败、CONNECT 目标变化、取消/drop 均停止受控连接且无自动直连。
  - [ ] M1-09.04 记录读取与副作用请求的重试分类；授权后的 GET 也可能有远端效果，未知状态必须可查询/核对。

  验收：危险目标零请求、证书/peer 不匹配拒绝、失败无凭据泄漏。失败处置：保留 unknown 和安全诊断，不用禁用 TLS 或换路由规避。证据：TLS/代理/DNS fixture、请求计数和 socket 回收。

- [ ] M1-10 HTTP/Gateway/MCP 分别验证匿名、owner、非 owner、Origin、限额和凭据撤销；不能以 loopback 代替鉴权。

  归属/入口：`claw-http-api`、`claw-gateway`、daemon listeners。前置：M1-02、M1-05。当前：各入口已有部分鉴权和专用 MCP 凭据，legacy 差异仍需完整回放。

  - [ ] M1-10.01 为每个真实路由/RPC/订阅列最低 scope、认证源、owner 语义、Origin/CSRF 条件及匿名行为，包含 legacy 管理路径。
  - [ ] M1-10.02 验证主 HTTP token、MCP token、设备凭据不可跨协议误用；配对、撤销、限流和请求大小在副作用前生效。
  - [ ] M1-10.03 对匿名/非 owner/越账号/错误 Origin/过期和超额请求断言拒绝，loopback 不能凭位置取得新模式管理权。
  - [ ] M1-10.04 验证认证重载/撤销期间已有请求和事件订阅的可见范围，外部 bind/TLS 前置不足时拒绝启动。

  验收：按入口的权限矩阵完整，未经授权实际作用为零，订阅不泄漏他人元数据。失败处置：关闭越权路径并保留差异证据，不改 sealed legacy 期望。证据：实际 TCP/WebSocket/MCP 正反向测试。

- [ ] M1-11 机密使用 SecretRef/平台存储，argv/日志/审计/错误/支持包均脱敏；审计写失败的处置可测试。

  归属/入口：`claw-config`、`claw-platform`、`claw-observability`、daemon audit。前置：M1-02、M1-03、M0-09。当前：SecretRef、OS profile、结构化脱敏和审计故障栅栏已有，完整 ACL/尾部恢复/支持包未关闭。

  - [ ] M1-11.01 盘点所有密钥来源、存储、缓存和出口，模型凭据/设备种子按 endpoint 与身份分区，禁止 argv/普通配置/报告明文。
  - [ ] M1-11.02 统一错误/预览/审计/支持包结构化脱敏，记录自由文本检测限制；日志有界，审计不能走丢弃型队列。
  - [ ] M1-11.03 验证 keyring 失败/锁冲突/读回错误不生成替代身份，审计只读/磁盘满/并发写失败阻止新副作用并保留故障。
  - [ ] M1-11.04 补 ACL/祖先/链接、审计尾部损坏和容量轮转恢复；本地 forget 与远端 revoke 分开，删除只限被明确选择的凭据。

  验收：测试秘密在所有输出中均不可见，审计失败不会仍报告成功。失败处置：撤下执行权限、保留可读审计和恢复说明，不创建明文 fallback。证据：泄漏扫描、真实平台存储及文件故障测试。

## M2 持久化与恢复

前置: M1 权限/对象合同稳定。退出: 已确认数据可恢复，未知外部副作用不被自动重放。
主要 owner: `claw-state`、`claw-runtime`、`claw-goals`、`claw-memory`、daemon。

- [ ] M2-01 完善已接入 redb 的 StatePort 事务边界与 schema 管理，禁止退回空内存库掩盖读取失败。

  归属/入口：`claw-application`、`claw-state`、daemon；[状态适配](../crates/claw-state/src/runtime.rs)。前置：M0-06、M1-02。当前：生产 redb 与 schema/CAS 已有，完整事务端口和升级契约未齐。

  - [ ] M2-01.01 清点 StatePort 所有读写，定义事务粒度、revision、冲突、提交未知、schema/version 和记录预算，避免隐式独立提交。
  - [ ] M2-01.02 在既有 redb 适配实现缺少的事务/升级入口和受控 blocking worker，生产只使用持久适配，不混用测试内存库。
  - [ ] M2-01.03 验证 CAS 冲突、未来 schema、空/损坏/锁定库、升级中断和 worker 丢失均有明确结果，不能返回空成功。
  - [ ] M2-01.04 验证升级前备份和 reopen/只读核对路径，记录哪些版本可以读写、哪些只能恢复，禁止自动降版本。

  验收：生产事务结果与磁盘实物一致，异常后不建立空库。失败处置：锁住写入口、保留库和错误状态，按验证备份恢复。证据：真实 redb 正负例、schema 兼容和生产装配。

- [ ] M2-02 持久化 session/message/turn/tool/result/context checkpoint，验证 revision 冲突和同一会话并发写入。

  归属/入口：`claw-state`、runtime、持久 context；[检查点适配](../apps/gta-claw-daemon/src/adapters/persistent_context.rs)。前置：M2-01。当前：会话/turn/高水位/checkpoint/run 已持久化，完整历史对象与一致视图仍需补齐。

  - [ ] M2-02.01 明确 session、message、turn、tool call/result、附件引用和 checkpoint 的 ID/顺序/revision，保留原始关联与失败部分输出。
  - [ ] M2-02.02 实现缺少的历史写入、分页/归档读取和一致快照，按主体检查权限，不把当前 context 当完整聊天档案。
  - [ ] M2-02.03 用同会话并发提交、迟到 tool result、同文本不同 run、reset/restart、revision 冲突测试无覆盖/串写/重复。
  - [ ] M2-02.04 在实际 daemon 重启后核对消息数量、顺序、引用、所有权及高水位，明确截断/缺失不能被 ACK 为完整。

  验收：可完整重建选定历史及当前上下文，失败记录不会污染新成功回合。失败处置：拒绝冲突、保留失败/不完整标记与原数据，不静默截断。证据：磁盘重开、并发和历史分页测试。

- [ ] M2-03 明确 goal、context、审批终态和 run 的一致性恢复；独立文件提交不报告成一个原子事务。

  归属/入口：runtime、`claw-goals`、`claw-state`、daemon。前置：M2-01、M2-02、M1-06。当前：goal 文件和 redb 已存在，跨对象原子性没有被证明。

  - [ ] M2-03.01 为每个写流程画出 goal/context/run/approval/audit 的提交顺序和崩溃窗口，选择同库事务或显式提交日志/补偿语义。
  - [ ] M2-03.02 在拥有者实现缺少的跨对象协调和恢复判断，状态事件只能在相应事实持久化后发布，不能由前端拼凑一致性。
  - [ ] M2-03.03 在每个对象提交之间注入失败，验证目标和回合不互相矛盾、不丢所有权、不把半完成任务当完整。
  - [ ] M2-03.04 提供只读对账和明确 manual/unknown 处置，记录可自动恢复的纯本地事务及不可回滚外部效果。

  验收：每个崩溃窗口均有确定恢复结论，独立文件不被包装成原子成功。失败处置：停止相关写入并保留所有对象副本，先对账再恢复。证据：提交顺序、故障矩阵和恢复结果。

- [ ] M2-04 建立持久化 inbox/outbox、cursor 和去重键，接收 ACK 发生在提交后，并按账号/渠道隔离。

  归属/入口：`claw-state`、`claw-channels`、daemon；[持久 run](../crates/claw-state/src/runs.rs)。前置：M2-01、M1-02。当前：Gateway 和 Telegram/Discord 已有持久接收/结果/去重增量，Telegram处理后确认与凭据绑定cursor、Discord连续结算resume checkpoint均有持久恢复/失效；provider保留期外完整休眠队列恢复仍缺。

  - [ ] M2-04.01 固定按 source/account/principal/session/message ID 的幂等键与完整输入摘要，明确同键同内容复用、异内容冲突。
  - [ ] M2-04.02 补齐渠道 cursor/resume 与持久接收的原子或可恢复边界，poll offset 仅在消息保存后推进，队列满不得丢接收记录。
  - [ ] M2-04.03 用重复输入、账号碰撞、接收后进程退出、队列满、旧 offset/reconnect 重放验证工具和回复不会二次执行。
  - [ ] M2-04.04 提供按身份分页的 inbox/outbox/active 状态和休眠队列处理，客户端展示 ACK 与远端投递确认明确分离。

  验收：已返回接收确认的输入可在重启后找到，去重覆盖完整操作包括 reset。失败处置：保留旧 cursor 和持久记录，停止消费/进入核对，不把失败批次跳过。证据：真实进程退出、重复处理和游标测试。

- [ ] M2-05 测试投递未发送、已发送、已确认、不确定四种状态；重试不会重复发信、执行工具或消耗不确定的付费请求。

  归属/入口：`claw-state`、daemon 渠道与 provider/runtime。前置：M2-04、M1-09。当前：唯一 delivery claim、Delivered/Unknown 和本地回执检查已有，完整分片导出/外部核对未齐。

  - [ ] M2-05.01 定义执行结果与投递阶段的独立状态、结果 revision/digest、目标账号、分片顺序和远端 receipt，不能以 2xx 直接认定完整送达。
  - [ ] M2-05.02 实现缺少的分片持久回执、状态查询与受控恢复；Sending/Unknown 不能重新 claim，明确已未发送才考虑安全重试。
  - [ ] M2-05.03 对发送前/响应丢失/部分分片/确认后崩溃、付费 provider 超时和客户端重复 ACK 验证无盲目重放。
  - [ ] M2-05.04 暴露可读对账材料和需人工处置的 unknown，记录外部 API 幂等支持与无法承诺 exactly-once 的边界。

  验收：本地保存、发出、受理、确认与 unknown 有准确证据，重复调用次数可核对。失败处置：暂停有疑义投递，查询外部事实或人工确认，不自动补发。证据：分片 receipt、故障时序、请求计数。

- [ ] M2-06 恢复队列/审批/任务时撤销过期权限；执行中的写操作保留 unknown/manual 状态，取消后迟到结果不复活。

  归属/入口：runtime、state、Gateway/渠道恢复。前置：M1-05、M1-06、M2-04、M2-05。当前：旧 lease 撤销和 claimed unknown 已有，休眠队列的完整用户批准恢复仍待开发。

  - [ ] M2-06.01 规定排队、claimed、等待审批、执行中和终态恢复规则，携带原主体/输入但不恢复可兑换旧许可。
  - [ ] M2-06.02 接入按当前策略重新授权的恢复命令和查询，排队任务必须明确操作者/预算，不在启动扫描时无条件运行。
  - [ ] M2-06.03 测试重启前批准、过期许可、已撤销设备、取消后迟到结果、重载期间恢复及同任务并发恢复均不能越权。
  - [ ] M2-06.04 区分读取最终结果、继续确定未开始工作和重新执行外部副作用，持久化用户恢复决定及失败原因。

  验收：恢复不会扩大原权限或复活取消任务，unknown 不自动执行。失败处置：保留 dormant/manual 状态与原记录，拒绝恢复并给出可核对原因。证据：启动/撤权竞态、恢复命令正负例。

- [ ] M2-07 区分内存 TTL/LRU、历史归档、用户删除、记忆遗忘；分页、保留、配额和引用清理有验收。

  归属/入口：state、memory、persistent context 和历史查询。前置：M2-02、M1-02。当前：LRU 只驱逐缓存不删持久历史，完整归档/配额/清理尚未完成。

  - [ ] M2-07.01 定义会话缓存、历史、记忆、附件、审计各自保留/配额策略，区分用户删除与管理员保留义务，默认不破坏旧数据。
  - [ ] M2-07.02 实现稳定 cursor 分页、归档索引、超限诊断和按身份清理，引用仍在使用的内容不能被删除。
  - [ ] M2-07.03 验证并发分页/写入、LRU 驱逐再加载、相同时间戳、cursor 过期、跨账号请求和超额输入不丢/串数据。
  - [ ] M2-07.04 测试删除/遗忘后的引用回收、索引重建和重启，清理中断能恢复且不误删其他会话共享文件。

  验收：缓存容量、历史保留与用户删除相互独立且可解释。失败处置：停止清理、保留 tombstone/原文件和修复任务，不静默丢历史。证据：分页/容量/删除中断和身份隔离测试。

- [ ] M2-08 在写前/写中/提交后/发送后/关机中注入进程故障，Windows/Unix 原子性分别验证；断电保证单列。

  归属/入口：state/runtime/daemon 集成测试；[生产装配测试](../apps/gta-claw-daemon/tests/production_composition.rs)。前置：M2-02、M2-03、M2-04、M2-05。当前：已有真实进程退出边界，尚非完整三平台/断电矩阵。

  - [ ] M2-08.01 列准入、claim、审批、工具、状态提交、结果发布、发送、确认、迁移与 shutdown 的精确故障点和预期磁盘事实。
  - [ ] M2-08.02 在现有父/子进程测试实现缺失故障点，用真实退出而非仅 panic/Drop 模拟，临时目录和子进程归测试所有。
  - [ ] M2-08.03 Windows/Linux/macOS 分别重开核对记录、顺序、权限、回执与 unknown，故障点本身未触发也必须失败。
  - [ ] M2-08.04 记录文件系统及 flush 条件，物理断电/存储设备故障需要独立环境和批准，不能借正常重启结果宣称通过。

  验收：每个故障点都有前后事实与恢复输出，已确认本地事务不丢、外部 unknown 不重放。失败处置：保留测试现场和失败日志，修复对应窗口再重跑。证据：故障命中、子进程退出码、恢复比对。

- [ ] M2-09 覆盖磁盘满、只读、锁竞争、损坏、未来 schema、迁移失败和恢复重试；原数据不被覆盖。

  归属/入口：state、platform、daemon operator status。前置：M2-01、M2-08。当前：提交/worker unknown 写栅栏和只读核对已有，完整存储故障矩阵未关闭。

  - [ ] M2-09.01 使用隔离文件系统/故障端口模拟磁盘满、只读、锁冲突、失效句柄、损坏和未来 schema，禁止填满用户真实磁盘。
  - [ ] M2-09.02 验证 worker 提交后丢结果、caller drop、panic 和并发写失败都会锁住后续写入，读核对与故障状态仍可访问。
  - [ ] M2-09.03 检查 startup/readiness/HTTP/Gateway/shutdown 保留非重试 unknown 分类，不转换为普通 unavailable 或 invalid params。
  - [ ] M2-09.04 完成显式 reopen/恢复重试与原操作对账，验证不能自动清除外部不确定性或创建空库取代源库。

  验收：所有失败均保留原始数据和可解释的阻塞状态，写栅栏不因 caller 消失而失效。失败处置：停止新写、隔离副本、使用已验证恢复流程。证据：故障矩阵、磁盘前后摘要和状态输出。

- [ ] M2-10 验证备份/恢复/导出、加密与权限、完整性和跨版本读取；记录实际恢复时间与数据范围。

  归属/入口：state、migrate、crestodian、platform。前置：M0-06、M2-02、M2-03、M1-11。当前：各模块有局部持久/备份基础，完整产品备份包与恢复尚未验收。

  - [ ] M2-10.01 定义数据库、goal/context、配置 include、附件、源记忆和凭据引用的备份清单与一致快照方式，索引是否重建必须明确。
  - [ ] M2-10.02 实现受访问控制的备份/导出及独立目录恢复，加密使用成熟库和受保护密钥；默认不导出实际秘密。
  - [ ] M2-10.03 验证缺文件/错哈希/错密钥/旧新 schema/备份中断/目标冲突都拒绝覆盖，恢复后按数量、引用、身份和内容核对。
  - [ ] M2-10.04 在冻结数据集记录备份大小、恢复时长、RPO 范围及无法恢复的外部状态，验证备份不是仅一个可打开压缩包。

  验收：独立恢复实例能读全部选定数据，源与现有目标不被污染。失败处置：保留失败备份/报告、禁止激活，原服务继续按授权运行。证据：备份 manifest、加密/完整性负例、真实恢复结果。

- [ ] M2-11 shutdown 停止接收、撤权、取消、join、flush 的顺序正确；有遗留任务/写失败时不报告 clean。

  归属/入口：daemon 生命周期、runtime、state、provider/channel/plugin 适配。前置：M1-05、M2-09。当前：tracked task/shutdown 和未知写栅栏已有，多对象/所有外部适配覆盖仍需齐全。

  - [ ] M2-11.01 列每种 listener、poller、WSS、provider stream、blocking worker、插件、子进程及 audit writer 的拥有者和关闭预算。
  - [ ] M2-11.02 按停止准入、撤销许可、取消、等待、持久结算、flush、资源释放顺序装配，关闭后未 poll 的任务不能新建批准或副作用。
  - [ ] M2-11.03 验证关闭与提交/批准/发送/重载竞争、caller drop、worker panic、cleanup 超时等仍被跟踪并报告。
  - [ ] M2-11.04 验证所有资源清理和 stop summary，强制中止仅限本服务拥有资源；遗留/unknown/flush 失败不得标 clean。

  验收：关闭后无新请求/副作用，未完成状态可在重启核对，任务与句柄预算明确。失败处置：报告 unclean 与恢复路径，不吞错误或停止无关进程。证据：生命周期时序、实际任务/进程回收和停止报告。

## M3 协议、模型与接入

前置: M1/M2。退出: 真实聊天、审批、持久化恢复和选定接入可端到端复现。
主要 owner: protocol/gateway/client/http-api/provider-sdk/providers/mcp/acp/channels、daemon/CLI。

- [ ] M3-01 固定 Gateway v4 的 handshake/认证/角色/scope/v3 限定窗口；内部 headless v1 分开管理。

  归属/入口：`claw-protocol`、`claw-gateway`、`claw-gateway-client`；[Gateway crate](../crates/claw-gateway/Cargo.toml)。前置：M0-04、M1-10。当前：v4 传输/角色和配对已有，完整固定版本互操作仍待验收。

  - [ ] M3-01.01 从固定合同核对版本协商、challenge/signature、角色/scope、Origin、设备身份和帧上限，区分 headless v1。
  - [ ] M3-01.02 完成必要适配和诊断；v3 仅按上游限定角色窗口，worker 使用专用票据而非普通客户端握手。
  - [ ] M3-01.03 验证错误版本/角色、重复挑战、过期签名、凭据撤销、超大握手和分阶段帧限额都被拒绝。
  - [ ] M3-01.04 双向连接固定参考实现，记录实际协商和拒绝差异，不把 TCP/WebSocket 建连等同于协议通过。

  验收：每个角色版本窗口和认证分支有 wire 证据。失败处置：拒绝连接并返回安全诊断，不自动降版本或扩大角色权限。证据：握手 fixture、参考互操作和失败帧。

- [ ] M3-02 完成 session/chat/history/abort/approval/health/model/config 的精确 payload、默认值、null/缺失和错误合同。

  归属/入口：protocol/gateway/http-api、daemon runtime Gateway 适配。前置：M3-01、M2-02、M1-06。当前：原生会话/审批/run 已可用，不声称与九月上游 payload 等价。

  - [ ] M3-02.01 按方法提取请求/响应/error 的 required、默认、null/缺失、ID、时间、分页和大小语义，区分原生独立合同。
  - [ ] M3-02.02 在控制行为的 handler 实现差异，session ownership、run-bound abort、配置 readonly 和模型选择均走真实拥有者。
  - [ ] M3-02.03 验证未知/缺失字段、坏 cursor、错误主体、旧 revision、超限内容和不支持方法不返回空成功或错误的 invalid params。
  - [ ] M3-02.04 用实际 daemon 回放每组正常/负向合同并比对固定上游结果，记录有意适配或待决差异。

  验收：方法不只是存在，字段与行为都有版本化对照。失败处置：保留 explicit unsupported/unknown，阻止有关精确兼容声明。证据：逐方法 fixtures、生产回放和差异表。

- [ ] M3-03 验证事件排序、重复、断线、背压、分页和缺口恢复；未实现 RPC 明确报错而不是空成功。

  归属/入口：gateway event bus/client、runtime 与三客户端状态投影。前置：M3-02、M2-04、M2-05。当前：epoch、持久结果/ACK、部分视图隔离已有，完整流式快照协调仍未关闭。

  - [ ] M3-03.01 定义 epoch/sequence、session/run/turn/revision 与 snapshot/delta 的先后关系，终态事件和持久结果分开。
  - [ ] M3-03.02 实现缺口探测、稳定分页、重连查询和幂等合并，输出/事件背压不能静默丢终态或改变取消目标。
  - [ ] M3-03.03 注入重复/乱序/迟到/缺口、旧连接重用 ID、满队列、分页中写入和历史响应竞态，验证无覆盖/跨会话泄漏。
  - [ ] M3-03.04 核对 ACK 仅发生在完整匹配结果展示后，重连只恢复查询不盲目发新 run，unsupported RPC 正确展示。

  验收：可由持久数据重建同一会话视图，事件顺序变化不导致重复执行或数据丢失。失败处置：标记待同步/unknown，重新读取受限快照，不删除本地待确认输入。证据：双连接/背压/分页竞态测试。

- [ ] M3-04 运行固定版本双向互操作：Rust 客户端对上游、参考客户端对 Rust；本地 fixture 不冒充外部互通。

  归属/入口：conformance、gateway-client、daemon；[参考网关工作流](../.github/workflows/upstream-gateway-reference.yml)。前置：M0-04、M3-01、M3-02、M3-03。当前：有合同和参考入口，未声明本轮真实双向互操作全部通过。

  - [ ] M3-04.01 冻结参考服务/客户端版本、安装来源、测试身份、token、端口和支持方法范围，外部 Node 工具需隔离批准。
  - [ ] M3-04.02 分别运行 Rust client -> 固定上游、固定参考 client -> Rust daemon，覆盖配对、会话、发送、审批、取消、历史和结果恢复。
  - [ ] M3-04.03 比较错误/null/默认/事件/权限、断线和超额请求，测试自身跳过或只连通不能记 pass。
  - [ ] M3-04.04 输出逐场景 wire 差异与兼容分类，保留旧基线回归；参考环境不得进入产品依赖或扩展 JS 白名单。

  验收：两方向实际执行且每个差异有结论，账户和资源隔离。失败处置：记录具体不兼容面，暂停精确兼容声明，保留失败抓取并清理仅自有参考实例。证据：版本、命令、wire 记录和差异报告。

- [x] M3-05 交付最小 CLI 发送/取消/查询 run 与审批命令，替换当前 deliberately unsupported 的发送路径。真实 CLI 子进程传输、持久身份和精确 run 参数验证见 [原生执行记录](ledger/native-execution-20260914.md)。

  保留验收：最小业务命令、原始幂等键、run 目标和持久身份连续性，不扩大到 onboarding/完整流式/所有平台。完整终端产品与制品验证由 M5-01、M5-08、M6-16 承接。

- [ ] M3-06 在已装配的 Copilot、OpenAI-compatible、Anthropic 路径上完成统一配置、就绪与切换；真实授权成功与 smoke/local fixture 成功分别记录。

  归属/入口：provider-sdk/providers/config、daemon；[原生策略](../apps/gta-claw-daemon/src/production/native_provider.rs)。前置：M1-08、M1-11、M3-02。当前：显式 provider policy 和本地真实 HTTP 夹具已接通，typed 主配置与真实账号未齐。

  - [ ] M3-06.01 将 provider/model/SecretRef/base URL/origin/timeout 纳入统一 typed 配置及来源诊断，保留现有显式模式的安全兼容路径。
  - [ ] M3-06.02 实现准备、认证/能力校验、发布和旧 provider 退役；固定默认模型不能被普通角色/配置 reload 静默覆盖。
  - [ ] M3-06.03 验证空/禁用/冲突配置、未登记 origin、无凭据、认证失败、切换取消和 smoke 混用均明确拒绝，不降级成假就绪。
  - [ ] M3-06.04 用批准的专用账号分别跑三类提供商最小聊天/工具/取消流程，记录实际授权和局部协议替身的区别。

  验收：用户选择与实际请求模型/endpoint/账号完全对应，失败切换不破坏旧有效配置。失败处置：保持旧 generation 或 pending，禁止泄漏密钥和自动换付费模型。证据：配置/HTTP 请求和真实账号 receipt。

- [ ] M3-07 覆盖模型精确 ID、alias、endpoint、账号、显式默认/禁用/空 fallback、工具/图像/上下文能力和目录刷新。

  归属/入口：providers/config、daemon model catalog、客户端模型选择。前置：M3-06、M0-05。当前：注册表和默认模型 pin 已有，完整能力目录及选择体验未完成。

  - [ ] M3-07.01 为每个模型区分 provider ID、精确模型 ID、alias、账号、endpoint、上下文/输出上限与各模态能力，标明来源和刷新时间。
  - [ ] M3-07.02 实现显式默认/禁用/空 fallback 和目录刷新，列表仅发现不发起生成，刷新不能替换用户选择。
  - [ ] M3-07.03 验证别名碰撞、已删除模型、catalog 内其他模型、错误能力、无工具/图像支持、权限变化和过期缓存。
  - [ ] M3-07.04 CLI/TUI/Slint 展示可用、需配置、待认证、未支持状态；从客户端选择后核对真实请求及保存/生效边界。

  验收：列表、配置、实际调用三者一致，不把 78 个描述符当已验证模型能力。失败处置：保持显式选择并显示不可用原因，不自动回落更贵或不同能力模型。证据：目录/配置矩阵和请求捕获。

- [ ] M3-08 覆盖 Chat Completions/Responses/Anthropic 流尾、部分输出、工具参数、usage、限流、OAuth 更新、取消及安全重试。

  归属/入口：provider-sdk decoder/reliability、各方言 client、runtime provider port。前置：M3-06、M1-09、M2-05。当前：已接入显式stateless Responses与真实HTTP/daemon回归，Chat无终态、坏工具回合和身份/choice/重复ID冲突拒绝；reasoning续接、完整费用/unknown、账号切换和真实服务合同仍未关闭，见[Responses记录](ledger/native-provider-responses-20260915.json)与[Chat身份记录](ledger/native-chat-identity-20260915.json)。

  - [ ] M3-08.01 分别实现/核对 Chat Completions、Responses、Anthropic、Copilot 的流事件、finish reason、tool 参数碎片、usage 和 error 映射。
  - [ ] M3-08.02 连接 runtime 取消、预算、并行工具顺序及部分输出保存，OAuth 刷新和新凭据只影响合法 generation。
  - [ ] M3-08.03 测试分块 UTF-8/JSON、空流/缺流尾、坏参数、重复 call ID、429/503、超时、撤权及 paid request 结果丢失。
  - [ ] M3-08.04 核对请求次数、token/费用、完整/部分/unknown 终态；只有可证明未产生副作用的错误按政策安全重试。

  验收：每种方言独立通过，流尾缺失不当成功，取消不留下生成任务。失败处置：保存部分结果和费用未知，停止继续工具执行，不自动补发有疑义推理。证据：流 fixture、调用次数、真实账号选定场景。

- [x] M3-09 修复专用 MCP owner/non-owner 凭据装配，真实服务验证只读角色不能调用写工具、主 HTTP token 不被接受；凭据重复/超长/空白/控制字符和错误脱敏负例通过。见开发记录。

  保留验收：HTTP MCP facade 的专用凭据和只读隔离；不表示 `claw-mcp`/OAuth/stdio/ACP 已装配。后续 SecretRef、生命周期与工具授权由 M1-11、M3-10 继续完成。

- [ ] M3-10 将 `claw-mcp` server/client/OAuth/stdio/streamable HTTP 生命周期接入产品，统一发现、授权、预算和关闭；ACP 版本及后端另行验收。

  归属/入口：`claw-mcp`、`claw-acp`、config、daemon；[MCP crate](../crates/claw-mcp/Cargo.toml)。前置：M1-03、M1-08、M1-11、M3-09。当前：入站生命周期、三类出站传输、已审阅tool/resource/标量资源模板/prompt/短时观察、HTTP/stdio绑定keyring与本地凭据CLI复用审批/审计、不重放/持久撤销；OAuth公共client显式登录/刷新、来源/代次绑定、原生pending及daemon消费已通过Windows本地流程；自动刷新/跨进程协调、真实服务、其他平台、复合模板/长期事件恢复及原生状态间歇异常仍未关闭。

  - [ ] M3-10.01 固定 MCP/ACP 版本与配置、stdio 可执行物/argv/env、HTTP/SSE endpoint、OAuth redirect/PKCE/state/token 和审批边界。
  - [ ] M3-10.02 将连接/初始化、tools/resources/prompts 发现、目录变更、调用、取消、重连及关闭接入真实产品拥有者和统一工具目录。
  - [ ] M3-10.03 验证不可信 schema、协议版本冲突、错误 OAuth state、越权资源、断开/超额/慢响应、目录替换和遗留子进程。
  - [ ] M3-10.04 在自有本地 stdio/HTTP fixtures 与获准外部服务分别验证；ACP 后端单列支持，未知效果重连不重放。

  验收：真实入口能发现和受权调用，关闭回收仅自有进程/连接，配置状态可诊断。失败处置：撤销远端工具 publication，保留 unknown/错误，禁用无支持后端。证据：协议往返、OAuth 负例和生命周期测试。

- [ ] M3-11 Teams 完成 JWT/活动绑定、入站归一化、分片、真实发送与负向合同回放。

  归属/入口：channels/channel-sdk、http-api legacy 与 daemon Teams transport。前置：M1-02、M1-08、M2-04、M2-05。当前：app/tenant/发送者会话与持久活动/reset已有，消息/命令/欢迎回复均以claim和逐片资源回执控制；完整外部JWT/租户收发、activity编辑和远端核对仍需验收。

  - [ ] M3-11.01 核对 JWT issuer/audience/签名/时效、tenant/account/activity ID、conversation/sender 和 service URL 信任，不采信正文身份。
  - [ ] M3-11.02 将 Teams 统一到持久入站、session ownership、工具 authority、分片发送和回执状态，保留明确 legacy 差异。
  - [ ] M3-11.03 回放坏 JWT/账号错配/重复 activity/恶意 service URL、长消息、429、超时/部分回复和取消，拒绝零副作用。
  - [ ] M3-11.04 用专用 tenant/bot 验证真实收发、撤销和重启恢复，记录签名密钥刷新与外部回执语义。

  验收：真实 activity 对应正确主体和唯一 run，出站只能到受信目标。失败处置：拒绝入站或暂停 uncertain 回复，保留 cursor/回执和诊断，不转 owner。证据：JWT fixtures、bound HTTP 与真实账号记录。

- [ ] M3-12 Telegram 完成轮询 cursor、鉴权、限流、分片、重启去重和真实收发验收。

  归属/入口：claw-channels Telegram 状态机、daemon channels。前置：M1-02、M1-08、M2-04、M2-05、M2-06。当前：持久入站后推进 offset、去重和回复 claim 已有，完整 cursor/队列恢复及实号未齐。

  - [ ] M3-12.01 固定 bot/account/update/message/conversation/sender 映射与持久 poll cursor，失败批次或队列满不能提前推进。
  - [ ] M3-12.02 完成 long poll、重启/凭据变更、休眠队列恢复、长度计数/分片和远端 message receipt，媒体另列能力。
  - [ ] M3-12.03 测试重复 update、同 ID 异内容、429/超时、部分分片、offset 丢失、关闭和轮询恢复不重复执行或补发 unknown。
  - [ ] M3-12.04 用批准测试 bot 做真实收发/长消息/撤权/重启核对；原生安全语义与 sealed legacy 回放分别报告。

  验收：消息先持久接受，游标和执行可恢复，所有者隔离且有真实账号证据。失败处置：保留旧 offset 和持久记录，暂停消费/投递核对，不丢失失败消息。证据：poll/去重/进程退出和实号回执。

- [ ] M3-13 Discord 完成 WSS 代理或明确拒绝、心跳/恢复、bot 过滤、分片与真实收发验收。

  归属/入口：claw-channels Discord 状态机、daemon WSS/REST transport。前置：M1-08、M1-09、M2-04、M2-05。当前：真实transport、持久入站/回复及按连续结算的resume checkpoint已有；本地worker重启/坏地址/未知投递通过，完整外部恢复窗口、分片回执和实号未关闭。

  - [ ] M3-13.01 固定账号/guild/channel/thread/sender/message ID、intent/bot 过滤、heartbeat ACK、sequence/session 与 resume URL 信任。
  - [ ] M3-13.02 完成 WSS 代理能力或明确拒绝、持久恢复、重连退避、分片与匹配 channel/message ID 的 REST 回执。
  - [ ] M3-13.03 验证重复/乱序事件、失效 resume、心跳超时、恶意重连 URL、429、空成功响应和部分发送不产生重复效果。
  - [ ] M3-13.04 用专用 bot/server 验证真实收发、线程、断线/重启和撤权，确认只回收本连接并保留未知投递。

  验收：WSS 和 REST 分别有路由证据，重连/去重与身份绑定正确。失败处置：保持持久记录并报告 resume/投递风险，不静默直连或从头重执行。证据：协议脚本、实际连接和渠道 receipt。

- [ ] M3-14 WhatsApp Cloud API/webhook 完成挑战、签名、账号隔离与真实收发；个人号配对明确不是该项完成范围。

  归属/入口：channels、http-api webhook 与 daemon WhatsApp transport。前置：M1-02、M1-08、M2-04、M2-05。当前：验签/phone匹配后身份与持久入站、原生回复claim/严格wamid逐片回执及重启拒重发已接通；四类回调已按已知回执持久化，乱序/冲突不改本地投递claim；原生文本24小时保守窗口已复核到每片且时间绑定不可变输入，模板审批/外部时间信任、远端核对与实号验收仍不足。

  - [ ] M3-14.01 对原始 webhook body 验签并校验 challenge、app/account/phone/sender/message ID，拒绝只校验解析后 JSON 的替代做法。
  - [ ] M3-14.02 接入 authority、持久入站/去重、会话隔离、分片/模板适用限制及发送状态回调，区分 accepted/delivered/read。
  - [ ] M3-14.03 回放错签名、重放/账号碰撞、重复回调、部分发送、限流、超时和凭据撤销，未知效果不自动重试。
  - [ ] M3-14.04 用批准 Cloud 测试账号核对真实消息及回执；个人号 QR/桥接单列未支持，不借 Cloud 通过宣称完成。

  验收：实际 Cloud 收发和身份闭环成立，回执含义精确。失败处置：拒绝异常 webhook，保留 unknown 发送和对账材料，不重新配对真实个人号。证据：签名 fixtures、HTTP/状态回调和实号记录。

- [ ] M3-15 HTTP/SSE 完成输出上限/incomplete、超时、断开取消、readiness 与 legacy 路由回归；停用路由不可误报可用。

  归属/入口：http-api、daemon listeners/runtime bridge；[HTTP crate](../crates/claw-http-api/Cargo.toml)。前置：M1-10、M2-11、M3-02、M3-08。当前：17 主路由及独立 MCP/legacy 已绑定，完整合同和生命周期矩阵仍缺。

  - [ ] M3-15.01 为每条路由固定鉴权、输入/输出限额、流事件、timeout/disconnect、错误类和是否有实际功能；禁用外部端口明确拒绝。
  - [ ] M3-15.02 补 SSE 流尾/incomplete、背压、取消、provider/storage 分层 readiness 和 tracked shutdown，不能只测 listener。
  - [ ] M3-15.03 实际 TCP 客户端测试慢读、断线、大输出、半流、工具 unknown、服务关闭与 legacy 正负合同，验证任务回收。
  - [ ] M3-15.04 对照 frozen 路由回归输出差异并保留安全批准项，最终应用返回状态与磁盘/外部事实一致。

  验收：完整/部分/未知结果在 HTTP 与 SSE 中一致，停用能力无假成功。失败处置：取消自有任务并报告真实状态，不截断伪成功或吞掉副作用不确定性。证据：bound API/SSE 测试、限额和关闭报告。

## M4 Agent 能力

前置: M2/M3。退出: 真实任务通过被授权的能力完成，有可恢复、可解释的结果。
主要 owner: memory/skills/tools/plugin-api/plugin-host/goals/runtime/config/crestodian。

- [ ] M4-01 将跨会话检索、来源引用、用户偏好、压缩锚点和 token 预算接入真实任务；检索按身份隔离，超时降级不丢指令/目标，持久历史不冒充主动记忆。

  归属/入口：`claw-memory`、state、provider、runtime context；[记忆入口](../crates/claw-memory/src/lib.rs)。前置：M2-02、M2-07、M3-06。当前：已接入显式身份分区笔记和模型工具关键词召回，确定性组装/检查点继续复用；语义检索、自动召回及完整用户流程仍未关闭。

  - [ ] M4-01.01 为历史、摘要、用户保存内容和推断偏好定义来源/owner/版本/可信度，先按权限过滤，再进行 keyword/vector 检索。
  - [ ] M4-01.02 将真实检索与必要 embedding/总结适配接入会话和工具目录，保持系统/目标锚点、token 预算、超时及取消。
  - [ ] M4-01.03 用跨账号相似文本、跨会话问答、过期偏好、检索洪泛、provider 超时和恶意记忆验证来源正确、零越权、不提升指令权限。
  - [ ] M4-01.04 在实际任务中保存并于新会话引用选定记忆，显示来源与降级原因，记录固定数据集召回而不声称哈希 embedding 等价语义检索。

  验收：任务确实获得获准历史知识并可追溯，预算/降级不丢系统规则。失败处置：回退有界无检索模式或拒绝不足上下文，保留源数据，不注入错误权限。证据：召回/来源矩阵、上下文预算和生产工作流。

- [ ] M4-02 记忆及偏好可查询、纠正、导入/导出/删除/遗忘；索引重建与 embedding 变更有权限验收，重启/重建不复活已删除内容。

  归属/入口：memory/state、migrate、客户端记忆管理。前置：M4-01、M2-07、M2-10。当前：显式笔记可CAS纠正/删除，CLI/TUI/Slint无需模型管理，CLI已验证归档页后加密落盘及联网前认证解密导入；单次导入仍限16KiB，重启/重建不复活当前已删项，但主动导入旧归档可恢复旧笔记，完整来源/历史/备份遗忘和GUI文件流程仍未完成。

  - [ ] M4-02.01 实现按身份查询、纠正和撤销偏好，保留来源/冲突版本，用户指令优先于过期推断但不能改变系统权限。
  - [ ] M4-02.02 定义并接入 source/tombstone、索引、缓存和引用清理，导入/导出保留删除与可见性语义，秘密默认不导出。
  - [ ] M4-02.03 测试删除/遗忘与并发检索、重启、索引重建、embedding 模型/维度改变及恢复旧备份，删除内容不可静默复活。
  - [ ] M4-02.04 客户端提供可审核的记忆管理和备份保留说明，验证纠正后的真实新会话不再引用旧事实。

  验收：用户能控制存了什么以及是否继续使用，所有变化和索引状态可查询。失败处置：停用不一致索引、保留源和删除标记，明确重建而非恢复旧错误内容。证据：删除/纠正/重建矩阵和跨会话测试。

- [ ] M4-03 区分纯指令技能与执行资产，接入 native/声明式 HTTP/Wasm 技能分发并完成真实任务；独立统计 discovered/validated/active/executable，不用 registry/插件激活数冒充技能执行数。

  归属/入口：`claw-skills`、runtime、daemon；[技能 crate](../crates/claw-skills/Cargo.toml)、[实际装配](../apps/gta-claw-daemon/src/production.rs)。前置：M0-08、M1-03、M1-06。当前：技能执行抽象和 Wasm bridge 存在，生产主要计数，未形成完整分发。

  - [ ] M4-03.01 定义技能发现/验证/激活/可执行独立状态和名称优先级，指令技能只提供内容，引用脚本不可顺带获得执行权。
  - [ ] M4-03.02 在 production 连接 native、声明式 HTTP、Wasm 分发及参数/风险/资源绑定，使用真实目录与统一 executor/audit。
  - [ ] M4-03.03 验证未移植技能、坏参数、同名冲突、缺依赖/权限、取消和版本更换不能执行，插件数不再充当 active skill 数。
  - [ ] M4-03.04 从真实客户端调用选定技能完成读取/处理/产物或记忆任务，重启核对结果，拒绝路径实际执行零次。

  验收：技能被实际选择、授权、执行和结算，而非只在状态页显示。失败处置：撤下不可用技能并给出移植/配置原因，保存 unknown，不回落 JS 执行。证据：目录状态、真实技能任务和负例。

- [ ] M4-04 为有界远程 skill 获取指定 owner，验证取消、大小、重定向、部分成功、输入顺序、来源与签名。

  归属/入口：skills/config 的来源合同、daemon 网络适配、plugin-host。前置：M1-08、M1-09、M0-08。当前：技能发现/验证存在，完整远程并发获取仍缺明确生产拥有者。

  - [ ] M4-04.01 指定远程获取拥有者及 URL/来源/预期摘要、并发数、单项/总字节、超时和稳定输入顺序合同，不新建无界后台任务。
  - [ ] M4-04.02 用统一 transport 实现 fetch -> staging -> validate -> publish，签名/移植证据和 origin 检查在激活前完成。
  - [ ] M4-04.03 测试 redirect、私网/DNS变化、截断/坏 UTF-8、超量、部分成功、重名和乱序完成，部分内容不被发布为 active。
  - [ ] M4-04.04 验证 cancel/drop/reload/shutdown 能停止自有请求并清理自有临时文件，报告各输入结果与来源而不丢失败项。

  验收：远程获取有可取消的生产路径和准确部分成功语义。失败处置：保留原有效版本或明确不可用，拒绝半包和未经同意的新来源。证据：本地 HTTP fixtures、资源上限和任务回收。

- [ ] M4-05 接入移植证据读取，未移植 JS/Code Mode/hook 只给迁移诊断，不执行；退役 `video-frames` 有明确替代。

  归属/入口：skills/plugin-api、conformance/migrate。前置：M0-08、M4-03。当前：上游描述符分类存在，没有全部组件移植。

  - [ ] M4-05.01 为每个移植物记录上游版本/源码、原行为、Rust/Wasm 映射、许可证、能力差异和已启用测试，执行物与指令内容分开。
  - [ ] M4-05.02 将证据读取接入实际技能/插件激活，未移植、错摘要/版本或缺证据不能仅凭 registry 进入执行目录。
  - [ ] M4-05.03 验证 JS/hook/Code Mode、伪装解释器、篡改记录和退役项均返回具体迁移诊断，绝不下载 npm 或静默运行脚本。
  - [ ] M4-05.04 对 `video-frames` 等退役功能提供受批准原生/外部工具替代或明确不支持，并验证文档/目录一致。

  验收：兼容声明有实际移植和测试支撑，不支持项可解释。失败处置：隔离执行资产、保留可读内容和报告，不用旧版本数量假装支持。证据：移植记录、激活负例、替代任务验收。

- [ ] M4-06 插件版本固定、capability consent、同名来源优先级、WIT ABI、签名失败、trap、fuel/内存/超时限制均经过验证。

  归属/入口：plugin-api/plugin-host、runtime、daemon；[签名插件适配](../apps/gta-claw-daemon/src/adapters/signed_plugins.rs)。前置：M1-03、M1-06、M4-05。当前：Wasm 宿主/签名/schema/audit 已有，完整能力同意和正向组件效果验收仍缺。

  - [ ] M4-06.01 固定组件版本/WIT ABI、可信签名、source 优先级、依赖和能力/资源预算，安装同意与执行批准分开。
  - [ ] M4-06.02 补能力同意、实际服务绑定、schema/参数和审计先后，模型/HTTP/MCP/skill 均通过同一插件 publication。
  - [ ] M4-06.03 测试坏签名/ABI、重复来源、能力提升、非法 schema、trap、fuel/内存/超时、host call 超限及取消回收。
  - [ ] M4-06.04 用一个真实签名有效组件走批准效果、拒绝零效果和 durable audit；缺插件/关闭 host 的负例不能替代该成功路径。

  验收：组件真正运行于规定能力边界，失败不会影响其他 Store 或泄漏权限。失败处置：撤下组件、取消拥有调用、保留失败/unknown 与审计，禁止放开 WASI。证据：组件哈希/签名、实际调用和资源测试。

- [ ] M4-07 插件/模型/上下文 generation 的发布、撤权、取消、回滚和真实清理正确；旧权限不随资源滞留继续有效。

  归属/入口：runtime/config、plugin-host、provider、persistent context 与 daemon reload。前置：M1-06、M2-11、M3-06、M4-06。当前：若干 generation/lease 防护已存在，全部资源更换组合未齐。

  - [ ] M4-07.01 为配置、provider、插件、技能和 context 建立 prepare/validate/publish/revoke/retire 顺序与持有引用关系。
  - [ ] M4-07.02 新候选全部验证后原子发布所需控制面，失败保持旧合法配置；撤销信号立即到达待审批和进行中的调用。
  - [ ] M4-07.03 测试同名版本替换、并发 reload、旧调用返回、取消后批准、rollback 和未释放引用，旧 authority 不可因对象存活继续使用。
  - [ ] M4-07.04 记录每个 generation 的活动任务与清理结果，shutdown/回退无法清理时公开 unclean，不假装已退役。

  验收：权限与资源生命周期分开且可观测，迟到结果不污染新模型/会话。失败处置：撤权并停止相关准入，保留旧合法资源供结算，不复活旧许可。证据：reload 竞态、引用/任务回收和回退测试。

- [ ] M4-08 Cron/heartbeat 使用成熟调度器并持久化；从用户创建任务到工具执行、结果投递和重启核对完整验收，覆盖 DST、时区、错过触发、重载、停用、租约，未知副作用不自动重跑。

  归属/入口：runtime/goals/state、config、daemon 调度拥有者。前置：M2-03、M2-04、M2-05、M2-06、M4-03。当前：目标和任务合同有基础，持久调度产品流程未交付。

  - [ ] M4-08.01 审查成熟 cron/timezone 库的许可/MSRV，定义 job owner/输入/skill版本/工具预算/时区/misfire/并发/目标/revision，导入默认暂停。
  - [ ] M4-08.02 实现预览下一触发、启用/编辑/停用、唯一触发 run、lease 与当前权限检查，调用现有 runtime 和 outbox，不独立直接执行工具。
  - [ ] M4-08.03 用确定时钟验证 DST 两类跳变、回拨、漏触发、长任务重叠、禁用竞争、重启、费用超限和部分投递不重复执行。
  - [ ] M4-08.04 从客户端创建实际任务并完成记忆/工具/产物/投递/重启核对，展示 skipped/queued/running/failed/unknown 与可审计恢复动作。

  验收：调度、授权、执行、结果和投递形成可恢复流程，timer 被触发不是完成证明。失败处置：暂停 job 或保留 unknown，撤销旧权限，不因 lease 过期自动重跑写操作。证据：时区/故障矩阵与完整任务日志。

- [ ] M4-09 Workspace/artifact 支持审核后的读写、修改冲突、附件来源、配额及导出；共享历史/文件删除不破坏其他主体。

  归属/入口：tools/state、runtime、http-api 与客户端 workspace/diff/artifact。前置：M1-07、M2-02、M2-07。当前：原生文件工具已有，完整 workspace/附件/产物工作流与引用清理未完成。

  - [ ] M4-09.01 定义 workspace trust、文件/附件 owner、哈希/大小/类型/来源、revision、配额及引用，Gateway 连接不自动授予目录信任。
  - [ ] M4-09.02 接入有界树/读取/编辑/diff/保存、staging 发布、下载/导出和可查询产物，写前核对预期摘要避免静默覆盖。
  - [ ] M4-09.03 验证路径攻击、跨身份引用、冲突编辑、超限/压缩炸弹、半下载/缺文件、恶意附件名和清理中断不发布假完整文件。
  - [ ] M4-09.04 用真实任务产生并审核导出 artifact，验证重启、共享引用/删除、配额回收与客户端错误状态，不自动执行附件。

  验收：产物可追溯、可访问且归属正确，修改冲突和不完整状态清晰。失败处置：保留 staging/冲突报告、不覆盖原文件、不删除其他主体引用。证据：哈希/引用矩阵、真实编辑与恢复。

- [ ] M4-10 将 guided setup、只读受管配置、SecretRef 和受限 doctor/rescue 接入真实入口；修复不提升权限、不重置模型选择。

  归属/入口：config/crestodian/platform、daemon/CLI/Slint；[恢复 crate](../crates/claw-crestodian/Cargo.toml)。前置：M1-11、M3-06、M4-07。当前：配置层级与 inspect guidance 已有，完整 setup/受限修复产品流程未完成。

  - [ ] M4-10.01 盘点 47 配置域实际消费状态，统一新 provider/workspace/network 策略，保留 readonly、SecretRef、来源/覆盖和模型默认选择。
  - [ ] M4-10.02 将 setup -> validate -> save -> apply/restart-required 与受限 doctor/rescue 接入真实入口，修复前预览差异与备份。
  - [ ] M4-10.03 验证 include/层级冲突、空列表、只读配置、坏 secret、部分 reload、remote role 改权限和修复失败均不破坏旧有效配置。
  - [ ] M4-10.04 从中断 setup 恢复并完成受控修复/回退；doctor 默认只读，不提权、不改生产代理、不替换用户固定模型。

  验收：用户可理解保存/生效/需重启/失败，诊断与修复权限受限。失败处置：保留备份与旧配置，退出需人工处置，不自动下载/重装/放宽权限。证据：配置域矩阵、setup/修复实际入口测试。

## M5 客户端产品化

前置: M3 合同稳定、M4 选定功能通过。退出: 每个平台分别完成真实用户流程。
主要 owner: CLI/TUI、`desktop/`、`android/`、`ios/`、client contracts/platform。

- [ ] M5-01 CLI/TUI 完成 onboarding、会话历史、流式聊天、取消、审批/问题、模型、迁移预览和诊断；JSON stdout 纯净。

  归属/入口：CLI/TUI、gateway-client、platform；[CLI 指南](../apps/gta-claw-cli/README.md)。前置：M3-02、M3-03、M3-06、M4-03、M4-10。当前：原生业务命令、profile、TUI composer/ACK/恢复已有，完整 onboarding/流式尚未关闭。

  - [ ] M5-01.01 完成 endpoint/profile/配对/模型就绪 onboarding 与准确 help/JSON 错误，保存/退出/继续不会重置已有身份或用户选择。
  - [ ] M5-01.02 接入完整会话/流式工具进度、run 精确取消、审批/问题、模型/记忆/技能/迁移预览与诊断，复用当前命令而非另建客户端。
  - [ ] M5-01.03 测试 TTY/非 TTY、EOF、Ctrl-C、长输入、中文宽字符、背压/断线/未知结果/旧连接命令，stdout 不混日志或秘密。
  - [ ] M5-01.04 用实际 CLI 子进程和 TUI 对 bound daemon 跑完整任务，核对持久身份、原幂等键、结果查询/展示 ACK 和终端恢复。

  验收：用户从首次连接到任务结果不依赖手动拼 RPC，错误和恢复可操作。失败处置：保留原键和可读结果，恢复终端状态，不自动重新执行任务。证据：命令/TTY 矩阵、实际子进程和工作流记录。

- [ ] M5-02 Windows/macOS 壳接入真实聊天/任务/审批/设置/工作区信任，不保留伪装已就绪的预览操作。

  归属/入口：desktop Slint、gateway-client、platform；[桌面 workspace](../desktop/Cargo.toml)。前置：M3-02、M3-03、M4-09、M4-10。当前：真实聊天/历史/完整审批/profile 已有，完整设置、工作区信任和产品页面仍缺。

  - [ ] M5-02.01 为会话/任务/审批/模型/工作区/记忆/技能/调度/迁移/诊断定义实际数据源、操作、空/加载/不支持/失败/unknown 状态。
  - [ ] M5-02.02 将页面操作接到真实服务合同，设置展示保存/应用/重启，信任绑定 root，文件/diff/artifact 未实现时明确不可操作。
  - [ ] M5-02.03 自动验证旧历史覆盖、跨会话事件、发送失败、审批超限、模型不可用、配置冲突及隐藏演示数据，不显示虚假成功。
  - [ ] M5-02.04 在 Windows/macOS 实际应用从配对到任务/审批/产物/重启核对走完整流程，截图与 RPC/磁盘事实相互对应。

  验收：不是诊断壳，所有承诺的页面都有真实工作流和平台证据。失败处置：禁用无实现动作、保留输入与恢复查询，不伪造 ready 或填演示消息。证据：软件渲染/状态测试、实际窗口和操作记录。

- [ ] M5-03 桌面凭据、设备身份、自动重连、用户注销和升级编排真实接入平台存储并可撤销。

  归属/入口：claw-platform identity、desktop connection/controller；[身份适配](../crates/claw-platform/src/identity.rs)。前置：M1-11、M3-01、M3-03。当前：Windows/macOS OS profile 已装配，完整注销/重连/升级产品验收未齐。

  - [ ] M5-03.01 固定 endpoint/profile/设备键的作用域、跨进程锁、存储权限和读取失败行为；禁用记住设备时不意外持久化。
  - [ ] M5-03.02 完成连接 generation 与 keyring worker 拥有/取消/超时、自动重连和本地 forget/远端 revoke 的独立交互。
  - [ ] M5-03.03 测试 keyring 拒绝、读回失败、锁竞争、窗口退出后迟到完成、endpoint 切换、升级重启与旧凭据不会串身份。
  - [ ] M5-03.04 在两平台验证重启后身份连续、注销实际清理所选项且撤销状态准确，更新前保留待核对 run 和数据。

  验收：凭据生命周期真实且可撤销，存储失败不换匿名身份。失败处置：中止连接并提示受控恢复，不写明文 fallback、不删其他 profile。证据：平台存储/进程测试、注销和升级流程。

- [ ] M5-04 Android 完成 Keystore、网络回调、配对及生命周期桥接；以现有 arm64 能力为准，不宣称未支持 ABI。

  归属/入口：Android client core、独立 Slint shell、platform；[Android 指南](../android/README.md)。前置：M1-11、M3-01、M3-03、M0-09。当前：连接状态壳和 client core 已有，真实平台桥接未完整。

  - [ ] M5-04.01 定义 Keystore profile/凭据作用域、网络可用/切换与 Activity 前后台/销毁事件，不用初始布尔值冒充平台回调。
  - [ ] M5-04.02 在现有原生/Slint 边界接入密钥保存、配对、连接所有权和生命周期恢复，回调只作用于正确 attempt/generation。
  - [ ] M5-04.03 验证旋转/重建、网络切换、Keystore 失效/拒绝、进程死亡、重复回调和旧 attempt 完成不复活旧连接。
  - [ ] M5-04.04 在批准的 arm64 真机确认系统 API 与签名包行为，其他 ABI/设备能力独立列状态，不因构建成功宣称全支持。

  验收：平台事件和密钥真实接入，连接/配对能安全恢复。失败处置：停止失效 attempt、保留合法 profile，必要时明确重新配对，不明文存储。证据：设备/OS/ABI、平台回调和 Keystore 测试。

- [ ] M5-05 Android 完成聊天/附件/审批、配置变更、失网、进程死亡、通知与配对恢复的适用验收。

  归属/入口：Android Slint shell、core、gateway-client。前置：M5-04、M3-02、M3-03、M4-09。当前：完整移动聊天/附件/审批工作流尚未交付。

  - [ ] M5-05.01 实现会话/流式输入、run 停止、完整审批、模型状态和附件选择/上传/下载，遵循移动权限及数据预算。
  - [ ] M5-05.02 完成配置变更、失网/恢复、缓存身份隔离、原幂等键和待结果查询；通知仅提示可查询结果，不携带执行许可。
  - [ ] M5-05.03 测试软键盘/旋转/折叠、后台限制、通知拒绝、上传中断、进程死亡后 unknown、旧审批和跨账号缓存。
  - [ ] M5-05.04 在实际安装包上从配对到聊天/附件/审批/通知/重启核对完整验证，记录 OS 后台限制而不承诺永久常驻。

  验收：移动用户可完成被承诺任务，系统中断不导致重复发送或权限泄漏。失败处置：保留可恢复输入/查询状态，停止失效上传或审批，不后台盲目重发。证据：真机步骤、截图、RPC/附件摘要和恢复结果。

- [ ] M5-06 iOS 完成 Keychain、UIKit/NWPathMonitor、配对和回前台重连；不以初始 foreground/route 值代替平台回调。

  归属/入口：iOS client core、Slint shell、platform；[iOS 指南](../ios/README.md)。前置：M1-11、M3-01、M3-03、M0-09。当前：连接壳存在，完整系统生命周期/凭据桥接未齐。

  - [ ] M5-06.01 定义 Keychain access/profile、UIKit scene/前后台、NWPathMonitor 状态、配对 attempt 和恢复合同，指定实际 Xcode/设备条件。
  - [ ] M5-06.02 将真实平台事件送入现有 client core，处理主线程/异步所有权、连接撤销和回前台查询，不以静态默认值替代事件。
  - [ ] M5-06.03 验证 Keychain 锁定/失效、route 切换、后台挂起、scene 销毁、重复回调和旧连接结果不能改变新会话。
  - [ ] M5-06.04 在获准签名 iPhone/iPad 验证身份持续和前后台重连，模拟器/Windows 静态检查分别记证据。

  验收：实际系统回调/Keychain 能支撑安全配对与恢复。失败处置：停止失效连接，提示受控重新授权，不绕过平台隐私或写明文凭据。证据：macOS 构建、设备日志和平台恢复流程。

- [ ] M5-07 iPhone/iPad 完成聊天/附件/审批、隐私权限和真实签名运行；模拟器编译不算设备/分发验证。

  归属/入口：iOS Slint 产品页面、core、gateway-client。前置：M5-06、M3-02、M3-03、M4-09。当前：完整移动用户工作流与真实分发验收未完成。

  - [ ] M5-07.01 实现会话/流式聊天、附件、run 查询/停止、完整审批与模型状态，文件/相册/麦克风等能力只按实际支持申请权限。
  - [ ] M5-07.02 连接前后台恢复、输入持久状态、通知和隐私拒绝处理，区分 iPhone/iPad scene、布局和安全区。
  - [ ] M5-07.03 测试网络/上传中断、后台挂起、权限撤销、签名/Keychain 变化、旧审批、长文本和缓存身份隔离。
  - [ ] M5-07.04 在真实签名安装制品完成完整任务，记录 provisioning/export/设备运行和数据保留；无签名资源明确 blocked。

  验收：真实设备而非仅模拟器可以完成所选功能，权限和未知状态准确。失败处置：保留待核对结果，禁用缺权限能力，不自动启用后台操作。证据：签名身份元数据、安装步骤、截图和实际 RPC。

- [ ] M5-08 Gateway connected、provider authenticated、chat ready、queued/sent/unknown 分开显示；离线缓存按身份隔离。

  归属/入口：gateway-client、CLI/TUI/desktop/mobile 投影与 runtime 状态。前置：M3-03、M2-05。当前：generation/epoch、部分快照/ACK/unknown 防护已有，完整各端状态一致性仍开放。

  - [ ] M5-08.01 为连接、凭据、模型、run、投递、恢复分别定义用户可见状态和转换，不将端口可达或本地排队显示为发送成功。
  - [ ] M5-08.02 补 snapshot/delta 版本合并、多结果独立 ACK、双 cursor 背压恢复和持久幂等键，旧连接 effect 命令一律拒绝。
  - [ ] M5-08.03 测试旧快照覆盖、同文本不同 run、错 durable/revision ACK、跨 session 事件、endpoint/profile 切换和重启后的未知发送。
  - [ ] M5-08.04 在所有已交付客户端核对状态与服务/磁盘/远端事实一致，离线只读缓存与可执行权限分开展示。

  验收：用户不会被误导为已发送/已保存/已撤权，缓存不串身份。失败处置：保留 unknown/待同步与原输入，不移除未匹配结果或自动换键重发。证据：状态转换矩阵、竞态测试及客户端工作流。

- [ ] M5-09 中文/英文、长文本、缩放、键盘、屏幕阅读器、窄屏、折叠屏、软键盘和安全区分别检查。

  归属/入口：TUI 与各 Slint workspace、client contracts。前置：M5-01、M5-02、M5-05、M5-07 的对应页面。当前：部分宽字符/软件渲染检查已有，完整人工平台可用性未验证。

  - [ ] M5-09.01 建立页面状态/语言/窗口/缩放/字体/输入法矩阵，包含长审批 JSON、长路径、多行输入、流式工具和空/失败/unknown 状态。
  - [ ] M5-09.02 实现稳定尺寸、可换行/滚动、焦点顺序、完整键盘路径、语义标签、对比度和可访问状态通知，沿用现有设计系统。
  - [ ] M5-09.03 自动断言不越界/重叠/裁掉关键按钮，TUI 按显示列计算；移动软键盘、安全区、旋转和折叠变化不丢输入。
  - [ ] M5-09.04 在获准平台截图并人工走键盘/读屏和中英文流程，截图、布局断言与真实操作结果分别留证。

  验收：最长必需参数可读，批准/拒绝等关键操作均可访问，文本不遮挡内容。失败处置：修复对应布局/语义，不通过隐藏信息或减小测试范围放行。证据：矩阵、渲染断言、截图和操作步骤。

- [ ] M5-10 Linux server/CLI/TUI 可安装使用；Linux GUI/Web/浏览器扩展明确标记差异或政策阻塞，不通过删门槛虚构支持。

  归属/入口：daemon/CLI/TUI、platform、packaging、repo-policy；[部署指南](../deploy/README.md)。前置：M0-09、M5-01、M2-11。当前：Linux 服务/终端源码和打包原型存在，Linux GUI 受政策限制。

  - [ ] M5-10.01 明确 Linux server/CLI/TUI 目标发行环境、凭据后端/限制、用户权限、状态目录和服务入口，不声称未支持的持久 profile 可用。
  - [ ] M5-10.02 在实际 Linux 包/服务配置接入健康、日志、状态卷、SIGTERM 和终端工作流，系统包管理与 updater 边界保持。
  - [ ] M5-10.03 测试非 root、只读/磁盘/权限失败、TTY/非 TTY、重启恢复、卸载保留数据及 root graph 不解析 Slint。
  - [ ] M5-10.04 公布 Web/Linux GUI/扩展的待决与差异，任何新增实现先走 M7-10 批准，不删现有拒绝测试。

  验收：Linux 实际安装后服务和终端可用，未支持表面诚实拒绝。失败处置：保留当前包/状态与诊断，不以扩大权限或改政策逃避问题。证据：Linux 实机/runner、包生命周期和政策测试。

## M6 迁移与交付

前置: M0-M5 发布范围全部通过。A/B 两条线互不代替；切换真实服务需用户明确批准。
主要 owner: `claw-migrate`、config/state/crestodian、daemon/updater、packaging/deploy。

### A 线: Node 退役

- [ ] M6-01 对照 [legacy-node-port-obligations.md](legacy-node-port-obligations.md) 为每一旧模块附生产装配和合同证据，不能笼统勾选整个 crate。

  归属/入口：legacy 对应各 owner、daemon 与 repo-policy。前置：M0-02、M0-03、M1-M5 的相关实现。当前：多数模块已有部分 Rust 装配，删除义务并未因此自动完成。

  - [ ] M6-01.01 按旧源文件、运行依赖、容器/工作流逐项列行为、Rust owner、控制路径、用户数据和删除条件。
  - [ ] M6-01.02 将未完成项区分缺实现、缺装配、缺合同证据、明确技术差异和待批准，不用“crate 完成”覆盖所有模块。
  - [ ] M6-01.03 验证每项删除会影响的调用/配置/fixture 都有替代或获准诊断，旧 registry/白名单不提前减少。
  - [ ] M6-01.04 在固定候选源码形成逐项交付记录，关联实际生产测试和回退制品，保留没有等价物的明确处置。

  验收：全部 legacy 义务都有逐项结论且可追溯。失败处置：保留对应旧文件/依赖和阻塞，不先删再补验收。证据：模块映射、测试引用、差异/删除条件。

- [ ] M6-02 真实 bound daemon 回放 legacy 行为/HTTP/负向/超时/TTL/reload/channel/persistence/shutdown；外部替身不得替代被验收服务。

  归属/入口：daemon production tests、conformance；[封存 legacy](../compat/legacy/contract.json)。前置：M6-01、M3-15、M2-08。当前：生产测试已有，完整 sealed legacy 回放尚未证明。

  - [ ] M6-02.01 将 sealed 行为/HTTP/负向 fixture 读取接入真实 bound daemon，确定 trace 输入、外部模型/渠道替身与观测点。
  - [ ] M6-02.02 覆盖会话/TTL、角色/技能、工具、四渠道、分片、reload、持久化和 shutdown，服务本身必须是真正生产装配。
  - [ ] M6-02.03 对缺 fixture、未触达路由、超时未命中、替身代替服务和输出差异验证 harness 会失败，原 oracle 字节不变。
  - [ ] M6-02.04 保存逐合同结果及批准的安全差异，连续在同一候选输入上复验，不把历史不同时刻通过相加。

  验收：实际服务与封存合同对照可重复，差异有决策。失败处置：保留失败 fixture/日志，修复拥有者或提交差异审批，不修改测试适配新代码。证据：bound 地址、trace、合同摘要和逐项结果。

- [ ] M6-03 JS 执行移除、自更新移除及新增安全差异经过批准并有迁移提示，封存 fixture 不被改成“适合新实现”。

  归属/入口：runtime/tools/skills、updater、repo-policy、migrate。前置：M0-08、M0-09、M6-02。当前：禁止嵌入式 JS 和供应链边界既定，逐使用场景替代提示仍需闭合。

  - [ ] M6-03.01 列 `isolated-vm`/`node:vm`、包管理器自更新、owner/loopback/代理变化等有意差异及受影响配置/任务。
  - [ ] M6-03.02 为每项提供原生/Wasm 替代、内容迁入或明确不支持路径，迁移预览和实际调用显示相同诊断。
  - [ ] M6-03.03 验证旧 JS/hook/自更新配置不会静默执行或放宽权限，diff/负例保留原 sealed 期望与新行为对照。
  - [ ] M6-03.04 获取适用差异批准并纳入发布支持矩阵，未批准的差异继续阻止相关替换，不修改受保护政策。

  验收：用户知道哪些旧行为不再执行及替代方法，不能宣称无损全兼容。失败处置：保持旧部署不切换，保留拒绝诊断，不恢复 JS 引擎。证据：差异清单、替代验收、批准记录。

- [ ] M6-04 原生候选镜像通过非 root、状态卷、health、真实入口、信号退出、启用渠道及包内容检查。

  归属/入口：packaging/deploy、daemon、repo-policy；[当前容器入口](../Dockerfile)。前置：M6-02、M6-03、M2-11、M5-10。当前：当前 Dockerfile 仍是 Node 服务，原生候选并非已发布替换。

  - [ ] M6-04.01 设计独立原生候选镜像/包，精确锁定工具链/基镜像和构建输入，配置/状态/凭据引用不打入程序层。
  - [ ] M6-04.02 完成非 root、只读程序路径、持久状态卷、端口/TLS前置、分层 health/readiness 和信号退出。
  - [ ] M6-04.03 实际检查包内容无 Node/JS runtime，安装后跑所选模型/渠道配置与拒绝场景、卷权限/重启/停止，不能只 build 成功。
  - [ ] M6-04.04 保存候选 digest/SBOM/provenance 和测试范围，当前发布入口不改，工具链 trust mismatch 先走独立审查。

  验收：原生实际制品能承担声明范围且保留状态，未执行渠道不显示 ready。失败处置：不激活候选、保留旧镜像与卷，不放宽 root/签名要求。证据：镜像清单、安装后命令、health/停止和摘要。

- [ ] M6-05 完成停写快照、唯一入口/消费者切换、观察窗口与回退演练；影子模式无真实双重副作用。

  归属/入口：deploy、daemon、state/migrate、渠道运营手册。前置：M6-04、M2-10、M6-15，且用户明确批准实际切换。当前：未进行生产切换。

  - [ ] M6-05.01 在复制数据/独立入口预演停写、未完成任务结算、快照验证、账号消费者/监听所有权与回退，影子出站禁止真实副作用。
  - [ ] M6-05.02 形成实际切换批准包，包含候选指纹、源/目标目录、最后 cursor、未决 unknown、恢复命令与观察门槛。
  - [ ] M6-05.03 批准后仅停止指定旧写入者并切换唯一入口，验证无双消费者、无重复工具/发信/付费模型调用及无权限放宽。
  - [ ] M6-05.04 观察后决定继续或回退，先保留候选新增数据与外部对账；旧备份和旧制品不自动删除。

  验收：演练和实际动作分别记录，切换/恢复均可确定所有权与数据范围。失败处置：停止候选新准入并按批准预案恢复，保留审计和新增数据，不影响其他服务。证据：批准、时间线、消费者/副作用计数及恢复结果。

- [ ] M6-06 批准切换后替换容器/发布流程，再同一变更删除 legacy 源码和 inventory；Node 清单不提前移除。

  归属/入口：repo-policy、部署/发布流程、各 legacy owner。前置：M6-01、M6-05，且删除集合和发布文案已审查。当前：legacy 源码和 Node 入口按义务保留；完成后由 M6-20 核销最终发布，不把发布当作删除前置。

  - [ ] M6-06.01 核对已切换候选与所有模块删除证据，列要删除的源码、manifest、依赖、工作流入口和 inventory 的精确集合。
  - [ ] M6-06.02 在同一受审查变更将正式入口改为已验收原生制品，再移除对应旧路径和运行依赖；不动用户数据/封存 oracle。
  - [ ] M6-06.03 运行政策扫描与构建/安装后测试，验证无遗漏 Node 命令/包/隐藏 JS 运行时且所有剩余 inventory 与文件一致。
  - [ ] M6-06.04 更新迁移/部署/支持说明和旧版本恢复材料，提交/发布仍需明确授权，不以文档任务自动执行 Git 操作。

  验收：原生正式入口、源码删除和政策 ratchet 同步且有回退依据。失败处置：停止发布该变更，保留原合法入口和证据，不扩大白名单。证据：精确 diff、依赖/制品扫描、政策和实际安装回归。

### B 线: OpenClaw 数据迁入

- [ ] M6-07 实现 OpenClaw 专用 detect/preview：实际版本/schema/profile/state-dir/workspace/插件/账号清单完整，预览无写入和外部激活。

  归属/入口：claw-migrate、CLI；[OpenClaw 预览](../crates/claw-migrate/src/openclaw.rs)。前置：M0-03、M0-07、M1-07。当前：Rust CLI 有界只读/分页/指纹及深度/节点/重复键检查已存在，不是完整 schema/快照/导入。

  - [ ] M6-07.01 扩展精确版本/schema/profile/root/workspace/include/插件/账号识别，明确不支持来源和可读取数据范围，秘密默认只记引用。
  - [ ] M6-07.02 复用预览入口完成分类/数量/冲突/损失/手动步骤，设置文件/总字节/深度/节点/JSONL/页输出预算与来源指纹。
  - [ ] M6-07.03 测试深度/节点炸弹、坏编码、未知版本、root/link/UNC/device、输入枚举中变化、错 cursor 和敏感内容不得泄漏或写入。
  - [ ] M6-07.04 在 fixture 与获准副本跑实际 CLI，核对 source/target 均无改动；无一致快照/导入能力时保持相应 readiness false。

  验收：预览完整报告其实际检查范围和不足，不能暗示未读取的数据库已验证。失败处置：拒绝超限/变更输入并提示重新预览，不执行 include/hook/账号激活。证据：CLI 正负例、前后摘要和预算验证。

- [ ] M6-08 停写或使用已验证快照机制生成一致备份，包含 SQLite/WAL、配置 includes、外部根和适用凭据；原目录不改写。

  归属/入口：migrate/state/config、platform。前置：M0-07、M6-07、M2-10；停真实源写入需批准。当前：OpenClaw 一致快照机制尚未交付。

  - [ ] M6-08.01 固定快照来源、停写/在线机制、DB/WAL/SHM 与外部 workspace/include 关系，列必须复制和明确排除的敏感项。
  - [ ] M6-08.02 实现受控快照/备份 manifest、哈希、权限/加密与空间预检，源数据库不开写连接，外部根逐项授权。
  - [ ] M6-08.03 验证活跃 WAL、漏文件、跨时刻副本、快照中断、来源变更、权限/空间不足和密钥错误拒绝一致性声明。
  - [ ] M6-08.04 用独立目录恢复备份核对 schema/数量/引用及源摘要不变，记录停写时间和实际数据范围。

  验收：快照能证明一致而非文件都存在，且原目录零改动。失败处置：停止 import/activation，保留未完成备份与诊断，不修改源日志/WAL。证据：snapshot manifest、并发写负例和独立恢复。

- [ ] M6-09 staging 中逐字段迁配置及路径，记录 unknown/manual/conflict；只读配置不被覆盖，跨平台路径规则正确。

  归属/入口：migrate/config/crestodian。前置：M6-08、M4-10、M0-09。当前：现有格式 plan/apply 可复用，OpenClaw 全字段映射尚未完成。

  - [ ] M6-09.01 为配置域/层级/include/profile/model/endpoint/账号/工具策略逐字段建立源到目标映射，明确缺失/空/默认/只读语义。
  - [ ] M6-09.02 将路径和权限映射到独立 staging，保留外部根来源、跨平台名称和目标冲突，不使用文本替换误改凭据或 URL。
  - [ ] M6-09.03 测试 Windows 保留名/大小写冲突、路径穿越、未知字段、空 fallback、readonly 和远程内容提升权限，必须显式拒绝/待处理。
  - [ ] M6-09.04 生成逐字段结果/差异预览，经用户确认的映射才进入 apply，保存原值来源但不把秘密打印出来。

  验收：模型/账号/策略不会被偷偷替换，unknown 和冲突无遗漏。失败处置：保留原配置及 staging，阻止激活，不用默认值掩盖丢失字段。证据：映射表、fixture、差异及输入输出摘要。

- [ ] M6-10 迁移会话/消息/工具记录/附件/归档/绑定，校验数量、顺序、哈希及引用；执行中历史不自动续跑。

  归属/入口：migrate/state/memory、runtime 只读历史入口。前置：M0-07、M2-02、M2-03、M6-08、M6-09。当前：OpenClaw 预览识别容器，完整历史规范化和导入未实现。

  - [ ] M6-10.01 按源实际 schema 定义 session/message/turn/call/result/附件/归档/agent 关系与整数/时间/Unicode 保真，不从文件名猜归属。
  - [ ] M6-10.02 分批规范化并事务写入 staging 状态库，保持原始 ID 映射、顺序、所有权、失败部分记录和引用索引。
  - [ ] M6-10.03 验证重复/冲突 ID、缺附件、孤立 result、未来 schema、大整数/NUL、部分批次失败和异主体绑定，不能静默丢记录。
  - [ ] M6-10.04 用数量/顺序/摘要/引用完整性与客户端只读历史核对，所有运行中/定时/投递记录默认暂停或 unknown，禁止自动续跑。

  验收：迁入的是可解释历史和数据而非仅备份文件，原记录映射可追踪。失败处置：回退未发布 staging 批次、保留源与诊断，不合并到活跃目标掩盖冲突。证据：规范化 fixtures、批次账本和历史对照。
- [ ] M6-11 密钥默认仅迁引用，实际复制须 opt-in；OAuth、设备和渠道配对按身份兼容或重新登录，禁止泄漏及轮换凭据双用。

  归属/入口：migrate/config/platform secret store 与 security identity。前置：M1-11、M6-08、M6-09。当前：既有适配有秘密外置基础，OpenClaw 全部凭据/配对迁移未验收。

  - [ ] M6-11.01 逐类列 API key、OAuth、设备种子、channel 配对、MCP token 的源格式/引用、可导出性、轮换和目标兼容要求。
  - [ ] M6-11.02 默认仅迁 SecretRef；显式批准复制时写目标受保护 store 并读回验证，无法导出/身份不兼容给出重新登录步骤。
  - [ ] M6-11.03 测试真实形态的合成秘密在 argv/log/diff/report/普通配置中零泄漏，重复引用/目标冲突/失败清理不删除预先存在密钥。
  - [ ] M6-11.04 验证旧/新 OAuth 轮换不双用、设备/账号不被提升 owner；实际重新授权作为独立获准操作留证。

  验收：凭据保持机密且使用身份明确，复制成功不冒充目标已授权。失败处置：保留源凭据不变，仅清理本次确认新建的目标项，暂停相关账号激活。证据：凭据矩阵、泄漏/回滚测试和授权记录。

- [ ] M6-12 记忆源文件可读且索引重建；未支持插件/脚本/hook 给明确诊断，迁入 cron/投递默认暂停。

  归属/入口：migrate/memory/skills/plugin-api/runtime。前置：M4-01、M4-02、M4-05、M6-10。当前：部分格式内容导入可复用，OpenClaw 完整记忆/扩展语义尚缺。

  - [ ] M6-12.01 迁移源记忆、来源/owner/删除标记和技能内容，旧 embedding 索引只在模型/维度兼容且验证后使用，默认重建。
  - [ ] M6-12.02 插件配置/hook/script 映射到内容/待移植/拒绝，导入实际工具能力须走原生/Wasm 证据及新同意。
  - [ ] M6-12.03 测试索引损坏/重建失败、已遗忘内容复活、跨主体记忆、JS/hook 自动激活和过期任务触发均被阻止。
  - [ ] M6-12.04 导入 cron/worker/delivery 仅保留可解释历史与 paused/unknown，用户从新系统明确审核后才可启用新执行。

  验收：可检索记忆和扩展差异正确，导入不会产生外部副作用。失败处置：保持内容可读和任务暂停，保留索引重建/移植诊断，不恢复旧执行许可。证据：内容/索引/任务状态对照和零执行测试。

- [ ] M6-13 迁移 fingerprint、阶段提交和重试幂等可验证；同名目标、部分失败、清理失败和断电恢复分别报告。

  归属/入口：migrate transaction engine、state/platform。前置：M6-09、M6-10、M6-11、M6-12、M2-08。当前：既有 plan/apply/rollback 基础存在，完整 OpenClaw 批次幂等与恢复需补。

  - [ ] M6-13.01 将源快照/目标身份/映射版本/schema 绑定 fingerprint，定义各阶段输入/输出/提交/失败 journal 与可安全重试范围。
  - [ ] M6-13.02 实现同 fingerprint 重试核对已提交数据、分批恢复、目标冲突保护和仅本批次临时资源清理，journal 也校验身份。
  - [ ] M6-13.03 注入来源改变、目标/journal 替换、提交后丢响应、只读/满盘、清理失败和中断，验证不重拷覆盖或隐藏部分提交。
  - [ ] M6-13.04 输出 complete/partial/manual/unknown 与恢复路径，进程退出和物理断电分别留证，源永不就地修改。

  验收：相同输入重试得到同一批次事实，输入变化要求重新计划。失败处置：停止激活并保留批次日志/staging/备份，不对不匹配对象执行清理。证据：批次 hash/journal、故障命中与重试对照。

- [ ] M6-14 完成固定稳定版到 GTA-Claw 的真实恢复演练及负向矩阵；其他版本只在独立通过后加入支持列表。

  归属/入口：migrate/state、CLI/客户端、conformance。前置：M6-07 至 M6-13 的实现合同、M6-15 的恢复预案。当前：没有真实 OpenClaw 完整导入/恢复验收。

  - [ ] M6-14.01 使用已固定版本生成或获准复制的真实格式资料，记录配置/会话/附件/记忆/扩展/任务基准及明确不迁项。
  - [ ] M6-14.02 从 detect/preview/snapshot/stage/import/validate 到独立恢复实例走完整流程，按数据和客户端可读事实核对。
  - [ ] M6-14.03 跑未知版本/损坏 WAL/缺凭据/外部根/重名/部分失败/重试/恢复失败矩阵，确保拒绝不损坏源数据。
  - [ ] M6-14.04 形成精确支持版本/平台/数据类型列表与用户可见损失说明，其他版本不得自动继承通过，真实账号激活另行批准。

  验收：一套固定输入可重复迁入并恢复，所有负例给出正确数据边界。失败处置：继续 preview-only 或限制支持范围并明确公布，不修改源系统来适应导入器。证据：源目标 manifest、实际命令、对照和恢复报告。

- [ ] M6-15 实现独立恢复目录、候选新增数据保全、schema 不兼容拒绝和切换后副作用对账；明确备份后的变化可能损失。

  归属/入口：migrate/state/updater/deploy 恢复流程。前置：M2-10、M2-05、M6-10、M6-13；真实恢复另需批准。当前：各模块回滚基础存在，跨产品激活后恢复手册和实现未齐。

  - [ ] M6-15.01 定义程序降级与数据恢复的分支、schema 兼容判定、源/目标/备份身份及唯一写入者，不通过改版本号强行读取。
  - [ ] M6-15.02 实现恢复到独立目录、候选新增数据导出/保全、目标冲突拒绝与恢复前完整性核对，回退不覆盖源。
  - [ ] M6-15.03 模拟切换后新增消息/工具/投递/配对、快照太旧、schema 太新、备份缺失和回退中断，验证不能伪装零损失。
  - [ ] M6-15.04 形成按顺序可执行的批准/停写/备份验证/恢复/外部核对/重开流程，说明哪些远端效果须人工补偿。

  验收：恢复过程可保全并解释新旧数据和外部状态，演练不依赖不可重现手工步骤。失败处置：停止相关写入者并保留两份数据，等待人工核对，不删除候选新增记录。证据：回退时序、schema 负例、独立恢复对照。

### 原生发布

- [ ] M6-16 各发布平台从安装后的实际制品走端到端流程，生成 SBOM/provenance/校验值，签名与篡改拒绝有效。

  归属/入口：packaging/workflows、repo-policy、各应用。前置：M0-09、M6-04、对应 M5 平台流程与独立发布政策批准。当前：开发与受保护发布工具链不一致，原生正式发布阻塞。

  - [ ] M6-16.01 审查 Rust/Slint/MSRV、各 workspace lock、基镜像/依赖摘要、许可证和 trusted policy 升级，不能让候选自改校验器通过。
  - [ ] M6-16.02 用固定输入生成各平台实际制品和 SBOM/provenance/hash/signature，签名材料留在受保护环境，不输出密钥。
  - [ ] M6-16.03 验证制品篡改、签名/版本/目标架构错误、缺依赖、夹带 Node/JS runtime 和安装后入口错误都会拒绝。
  - [ ] M6-16.04 从安装路径运行完整所选聊天/工具/恢复流程，记录制品与测试身份/平台，不把 build-tree 测试当安装后验收。

  验收：发布制品可复核且安装后功能成立，每个平台有独立结果。失败处置：不签发/不发布无效候选，保留上一合法制品和数据，不放宽 trusted fixtures。证据：构建输入、签名/provenance、篡改和安装后记录。

- [ ] M6-17 updater 完成下载策略、签名、唯一所有权、中断恢复、程序/数据兼容检查；Linux 保留系统包管理边界。

  归属/入口：updater/platform、daemon startup check、packaging；[Updater crate](../apps/gta-claw-updater/Cargo.toml)。前置：M1-08、M1-09、M6-15、M6-16。当前：签名/续传/回滚实现基础存在，完整平台/代理/安装生命周期尚未关闭。

  - [ ] M6-17.01 核对 update manifest、版本/架构、origin/代理、续传 range、大小/摘要/签名和数据兼容，Linux 明确转系统包管理。
  - [ ] M6-17.02 完善 staging、目标/备份对象身份、唯一更新者、替换/journal/restart-required 与回滚，不在未知身份目录写入。
  - [ ] M6-17.03 测试断流/错 range/坏缓存、篡改、旧/新 schema、更新中断、备份替换、权限失败和不支持原子操作的提前拒绝。
  - [ ] M6-17.04 在实际安装制品进行受控升级/中断/回退及重启后健康核对，程序恢复与数据/远端效果分别报告。

  验收：下载、替换、重启和回退均有准确所有权/持久证据，失败不破坏旧可用版本。失败处置：保留或恢复已验证旧程序与 journal，暂停自动更新，不静默直连。证据：平台更新矩阵、哈希、故障和恢复日志。

- [ ] M6-18 Windows/macOS 安装升级卸载保留用户数据；Android 发布签名和 iOS provisioning/导出分别取得真实证据。

  归属/入口：packaging、desktop/android/ios 工作流与 platform。前置：M6-16、M6-17 的平台适用合同、对应 M5 真机流程。当前：安装/签名原型存在，完整跨平台发布生命周期未验收。

  - [ ] M6-18.01 按平台定义安装/程序/用户数据/凭据/缓存目录、版本升级与卸载保留规则，删除用户数据需要独立明确选择。
  - [ ] M6-18.02 实际验证 Windows/macOS 新装、升级、中断/修复、卸载、重新安装，保留会话、profile、配置和未决 run。
  - [ ] M6-18.03 Android 签名/ABI/安装升级与 iOS provisioning/archive/export/设备运行分别验证，错误证书/包/平台权限必须拒绝。
  - [ ] M6-18.04 发布逐平台制品、兼容数据版本和限制，签名/设备资源缺失标 blocked，不把模拟器或 unsigned archive 当分发成功。

  验收：真实安装生命周期可用且不误删数据，移动签名/设备证据完整。失败处置：保留用户数据及上一版本，停止发布该平台，不自动改系统权限或证书。证据：安装步骤、前后 manifest、签名与设备结果。

- [ ] M6-19 完成至少 100 次受控恢复、24 小时 soak 及 M0 冻结的性能/资源预算；失败项不可通过事后放宽门槛掩盖。

  归属/入口：daemon/runtime/state、测试与发布验收。前置：M0-10、M2-08、M2-11、M6-16。当前：局部通过日志存在，不是完整 soak/恢复/性能验收。

  - [ ] M6-19.01 冻结同一候选输入、平台/数据、负载、故障点、100 次恢复分配、24 小时场景及资源/时延/恢复阈值，先明确运行预算。
  - [ ] M6-19.02 运行本地确定性 provider 的会话/连接/工具/取消/重连/投递负载，采样 RSS、句柄、队列、任务数、磁盘与额外延迟。
  - [ ] M6-19.03 注入规定故障并核对已确认数据 RPO、未知效果不重放、资源增长和恢复时间；真实账号/付费负载另按批准限额。
  - [ ] M6-19.04 保留所有失败、跳过和原始指标；改源码后按受影响范围重建证据，不能事后加大阈值或删除失败样本。

  验收：100 次及 24 小时门槛确实运行并达到冻结标准，模型时间与 Gateway 开销分开。失败处置：停止候选发布、定位拥有者修复，保留日志和恢复现场。证据：负载/故障 manifest、原始样本、统计和退出结果。

- [ ] M6-20 更新使用文档、支持矩阵、已知差异和运维手册，用户确认切换/回退边界后才发布候选为正式可替换版本。

  归属/入口：各 owner、部署/发布文档与 checklist。前置：M6-06、M6-14、M6-18、M6-19 的发布范围结果。当前：完整原生正式替换尚未验收，当前计划不是发布证明。

  - [ ] M6-20.01 发布前准备准确的安装/使用/配置/迁移/恢复/升级说明，列模型/渠道/平台/插件已支持与未支持，实例不含秘密。
  - [ ] M6-20.02 汇总同一候选的实现、合同、真实账号/设备、恢复/soak 和制品证据，所有跳过/blocked/有意差异都有处置。
  - [ ] M6-20.03 用户确认实际切换、数据损失边界、外部副作用对账、回退与备份保留后，再执行获准发布/交付，不自动提交推送。
  - [ ] M6-20.04 安装后复核版本/指纹和运维入口，更新支持矩阵及下一版本未完成项，不能宣称全部 OpenClaw/Hermes 已追平。

  验收：用户拿到的是能安装、可恢复、范围明确的正式候选，资料与实际制品一致。失败处置：保留候选/未发布状态，不将测试包升级为正式支持。证据：发布核销表、用户批准、制品指纹和运维验证。

## M7 扩展和持续兼容

前置: 核心门槛持续满足。退出: 每个新增能力独立达到端到端验证，没有隐瞒的长尾缺口。
产品多 Agent 能力的规划不允许本开发过程调用任何子 agent。

- [ ] M7-01 按使用价值扩展 Slack/Feishu/Matrix/Signal 等渠道，逐账号测试权限、媒体、线程和限流，不以 registry 数量验收。

  归属/入口：channel-sdk/channels、daemon、config。前置：M1-02、M2-04、M2-05、M3-11 至 M3-14 的通用合同。当前：29 条旧目录仅四条路径部分装配，长尾不等于已支持。

  - [ ] M7-01.01 从固定新版清单逐渠道登记认证/账号/线程/媒体/长度/限流/游标、owner 和优先级，不能省略低优先级未支持项。
  - [ ] M7-01.02 分别实现 Slack、Feishu、Matrix、Signal 等所选渠道真实 transport 与统一身份、持久入站、工具权限和投递状态。
  - [ ] M7-01.03 测试各渠道签名/重放、跨账号、线程错配、媒体超限、429、断线/重启、撤权和部分发送，不能只复用文本 happy path。
  - [ ] M7-01.04 逐专用账号验证真实收发/权限/恢复并公布支持矩阵，未验收者保留状态，不一次性把 registry 改 Full。

  验收：每个声明支持的渠道独立完成端到端，身份和回执可靠。失败处置：禁用对应账号/能力并保留待核对消息，不影响其他渠道消费。证据：来源合同、实际传输测试和专用账号 receipt。

- [ ] M7-02 扩展 provider 方言及本地模型；分别验收文本、embedding、图像、音频、视频和成本，不从一种能力推导其他能力。

  归属/入口：provider-sdk/providers/config、runtime 与媒体工具。前置：M3-06、M3-07、M3-08、M1-08。当前：28/38/12 是旧注册表层级，其他方言和各模态的完整生产验证未齐。

  - [ ] M7-02.01 按固定能力清单登记方言、认证、模型、endpoint、模态/工具/上下文和费用，区分客户端存在、需端点、仅注册与真实账号支持。
  - [ ] M7-02.02 实现缺少的 Gemini/Bedrock/Vertex 等协议/鉴权和本地服务适配，复用兼容方言但独立验证服务差异，禁止自动下载权重。
  - [ ] M7-02.03 分模态测试格式/大小/usage/取消/错误、IAM/OAuth/origin、预算和 unknown；文本/embedding/图像/音视频不可互相推导通过。
  - [ ] M7-02.04 在获准账号/本地服务跑选定实际任务，核对配置/请求/产物/费用和禁用行为，刷新不覆盖用户默认模型。

  验收：每项能力有独立真实入口与证据，目录准确显示支持等级。失败处置：拒绝该模态/账号并保留费用未知，不自动切换服务或重复生成。证据：方言 fixtures、真实请求/产物和成本记录。

- [ ] M7-03 建立 ClawHub 来源/移植目录、签名发行、版本固定、安装同意、禁用/卸载/更新恢复；不直接运行 npm 插件。

  归属/入口：skills/plugin-api/plugin-host/migrate、客户端目录。前置：M0-08、M4-04、M4-05、M4-06、M4-07。当前：宿主和描述符基础存在，完整 GTA-Claw 可执行生态未交付。

  - [ ] M7-03.01 建立来源/版本/license/摘要/签名/移植状态/能力依赖目录，ClawHub 发现与 GTA-Claw 可安装可执行级别分开。
  - [ ] M7-03.02 实现查看差异、安装同意、版本固定、验证/激活、禁用/卸载和更新回退，源换名/换权限不继承旧许可。
  - [ ] M7-03.03 测试篡改包/摘要、坏签名、依赖冲突、npm/JS 执行物、能力提升、半安装和卸载中断不会遗留可执行旧权限。
  - [ ] M7-03.04 从实际客户端安装并调用一个已移植组件，再禁用/升级失败/回退，证明目录状态与实际宿主一致。

  验收：生态工作流真实可用且可恢复，不把可发现包当可执行能力。失败处置：隔离候选、恢复合法旧版或明确禁用，保留数据与同意记录。证据：包指纹、安装/调用/退役及故障流程。

- [ ] M7-04 交付任务经验提炼 -> 技能草案 -> 预览批准 -> 回归验证 -> 使用后改进的 Workshop 流程，保留来源/差异/版本/回滚；生成不自动执行或安装，不让不可信历史改系统指令或权限。

  归属/入口：skills/memory/runtime/state、CLI/TUI/Slint Workshop。前置：M4-01、M4-02、M4-03、M7-03。当前：该完整经验改进流程尚未实现。

  - [ ] M7-04.01 从获准任务证据提炼脱敏经验，标明来源/owner/版本/可信度，草案独立存放；失败或低价值经验可不生成技能。
  - [ ] M7-04.02 实现草案预览、差异/风险审核、明确批准、固定任务回归、版本激活与使用反馈，创建草案不等于执行授权。
  - [ ] M7-04.03 测试不可信历史注入、越权经验、秘密、循环改写、遗漏约束和权限提升，不能修改系统指令/自动装依赖或启脚本。
  - [ ] M7-04.04 用同任务和反例比较新旧技能行为，保留来源/版本/结果及一键受控回退，用户可纠正或删除经验资料。

  验收：完整学习闭环可审计且由用户控制，不承诺模型“越用越强”而无验证。失败处置：保留草案不激活或恢复旧版，撤销新增许可，不影响原始任务记录。证据：草案/diff、批准、回归比较与回退。

- [ ] M7-05 接入 browser/CDP/relay 的真实传输和工作区权限，验证弹窗、超时、断线、迟到结果和已有副作用。

  归属/入口：claw-relay、tools/runtime、daemon；[Relay crate](../crates/claw-relay/Cargo.toml)。前置：M1-07、M1-09、M1-06、M4-09。当前：鉴权/CDP 策略有库实现，真实浏览器产品能力未装配。

  - [ ] M7-05.01 定义浏览器实例/profile/tab/URL/动作/时限/预算/产物合同，采用现成受审查 CDP/传输库，默认独立获准 profile。
  - [ ] M7-05.02 装配导航/读取/截图/输入/点击/下载上传与目标绑定、敏感提交审批和统一工具审计，不接管现有用户会话。
  - [ ] M7-05.03 测试恶意页面、redirect、错 tab/过期目标、弹窗、超额下载、断线/取消及提交后失联，unknown 不自动再次点击。
  - [ ] M7-05.04 在批准本地测试站点跑真实浏览器任务与重连，核对实际页面/产物和仅自有实例清理；真实网站另获授权。

  验收：浏览器动作确实发生在获准目标且结果可核对，页面内容不能提升权限。失败处置：停止自有动作并保留截图/回执/unknown，不关闭他人标签或重复提交。证据：CDP/页面 fixtures、实际浏览器与产物摘要。

- [ ] M7-06 设备节点、相机/语音/屏幕等能力分别经过平台授权、资源限额、撤销和真实设备验收。

  归属/入口：platform/client cores、tools/runtime、设备 Gateway 合同。前置：M1-02、M1-06、M3-01、对应 M5 平台桥接。当前：设备协议/客户端基础不等于真实硬件能力。

  - [ ] M7-06.01 逐平台列节点身份、硬件/OS 能力、隐私权限、捕获/录制指示、时长/尺寸/频率和数据保留，缺硬件显示未支持。
  - [ ] M7-06.02 在平台适配接入相机、语音、屏幕等独立能力与精确设备/资源绑定，媒体 provider 和硬件采集分别建目录。
  - [ ] M7-06.03 验证错设备/旧 lease、权限撤销、后台限制、取消后缓冲输出、超时/过量、断线及隐私泄漏，实际拒绝零采集。
  - [ ] M7-06.04 在获准真机逐项核对产物、时长/资源和撤权清理，模拟输出/截图不作为硬件成功证据。

  验收：每个设备能力有实际系统授权与输出，撤销立即停止相应采集。失败处置：禁用失效能力并删除仅本次允许清理的临时数据，不绕过 OS 权限。证据：设备/权限矩阵、真实产物和取消测试。

- [ ] M7-07 受控多 Agent/worker 的身份、预算、取消树、租约、结果归属和重启恢复有独立合同；区分本机、容器、SSH 和云后端，逐后端验证隔离/清理/支持边界，默认不开启未验证远端执行。

  归属/入口：claw-worker/runtime/state/tools、daemon；[Worker crate](../crates/claw-worker/Cargo.toml)。前置：M1-02、M1-07、M2-06、M3-03、M4-08 的任务合同。当前：worker 准入协议存在，完整多 Agent 产品工作流未接通。

  - [ ] M7-07.01 定义 parent/child/run、输入/结果 schema、单次 ticket/nonce、最小权限、workspace、并发/费用/期限和 lease，子权限不得超过父权限。
  - [ ] M7-07.02 实现有界 fan-out、等待/取消树、结果归属验证与重启恢复；本机/容器/SSH/云分别装配真实隔离和清理拥有者。
  - [ ] M7-07.03 测试重复 ticket/result、错父主体、父退出/子离线、租约过期、预算耗尽、取消后迟到与孤儿任务，未知远端效果不重派。
  - [ ] M7-07.04 跑受控协作任务并核对每个子结果和资源；按授权导出脱敏轨迹/压缩与有界批量评估，不自动上传或启动训练。

  验收：协作真正发生且权限/预算/取消/恢复可证明，子结果不能成为系统指令。失败处置：撤销本任务 ticket、保留 unknown/孤儿信息并核对，不影响生产机器。证据：任务树、准入/故障、后端资源和轨迹测试。

- [ ] M7-08 discovery/fleet 从 oracle 到真实网络适配，并验证发现不等于信任、无凭据泄漏、节点退役和重连。

  归属/入口：claw-discovery、gateway/worker、platform 与 daemon；[Discovery crate](../crates/claw-discovery/Cargo.toml)。前置：M1-09、M3-01、M7-07 的节点合同。当前：wire/policy oracle 有实现，真实网络/fleet 未装配。

  - [ ] M7-08.01 定义 DNS-SD/节点目录、网段/接口、TTL/缓存、身份声明和发现/配对/信任的独立状态，广播不得含凭据。
  - [ ] M7-08.02 接入获准网络适配、限速/大小/取消、节点登记/退役/重连，使用真实认证而非相信发现字段。
  - [ ] M7-08.03 测试伪造/重放/重复/过期广播、地址变化、接口切换、错身份、节点退役后旧 ticket 和网络洪泛。
  - [ ] M7-08.04 在独立测试网验证发现、明确配对、受控任务和退役回收，未批准真实网段不扫描，不触碰生产节点。

  验收：发现只提供候选地址，信任和执行必须独立建立，资源有界。失败处置：移除失效候选/撤销节点权限，保留诊断，不自动重建信任。证据：codec/网络负例、实际测试网和节点生命周期。

- [ ] M7-09 云 worker/快照/准备池的计费、凭据、一次性绑定、幂等激活和确认删除通过验证后才允许启用。

  归属/入口：worker/discovery/platform/state、云 provider 适配。前置：M7-07、M1-08、M1-11、M2-05，且明确云账号/费用批准。当前：没有已验收完整云 worker 工作流。

  - [ ] M7-09.01 逐后端定义 API/region/镜像/快照、SecretRef、配额/计费上限、idle/持久卷和资源命名归属，不默认开准备池。
  - [ ] M7-09.02 实现创建/唤醒/一次 ticket 绑定、幂等激活、运行/休眠、快照和最终删除确认，记录 provider resource ID 与账本。
  - [ ] M7-09.03 用受控 API fixtures 验证创建后丢响应、重复请求、过期凭据、超额计费、取消、孤儿资源和删除未确认不会重复创建或报清理成功。
  - [ ] M7-09.04 经批准用最小真实资源跑生命周期并独立查询删除/费用结果；创建/删除 unknown 留待对账，暂停自动重试。

  验收：实际计费资源的所有权、预算和终止都可核对，不以 API 受理替代删除。失败处置：停新准入并核对自有资源，按批准预案清理，禁止全账号批量删除。证据：API trace、resource ID、账单/删除确认。

- [ ] M7-10 对 Linux GUI/Web UI/浏览器扩展作明确决策；需要新技术例外先批准，再实现、打包和验收，未完成继续公布差异。

  归属/入口：client/platform、repo-policy、对应 UI workspace。前置：M0-09、M5-10、M7-05 的适用合同。当前：Linux GUI 被政策拒绝，Web/扩展未作为已交付产品。

  - [ ] M7-10.01 为各入口列用户价值、功能范围、可选技术、现有纯 Rust/Slint/JS 政策影响、运维和安全成本，形成 D05 决策。
  - [ ] M7-10.02 仅在明确批准范围后设计并实现身份/会话/工具/审批/配置与浏览器权限，不新建独立不受权 runtime。
  - [ ] M7-10.03 验证网络暴露、Origin/CSRF、凭据存储、扩展权限、内容注入、跨身份缓存和安装/升级，保留旧政策回归。
  - [ ] M7-10.04 分平台打包并完成真实用户流程；未批准或未验收者继续列差异，不通过删除 CI 拒绝测试获得“支持”。

  验收：明确政策决策和实际产品证据都存在，不能自动改变用户技术约束。失败处置：保持未支持状态，隔离未发布实现，不扩大 Node/JS 白名单。证据：决策批准、架构/威胁模型、平台与制品验收。

- [ ] M7-11 定期观察 OpenClaw/Hermes 的安全/弃用与能力变化，分别更新固定来源和差异矩阵；OpenClaw 新 stable 以独立 diff/fixture/回归升级，不让 main 自动重写正在验收的目标。

  归属/入口：conformance/repo-policy、各能力 owner、计划/ledger。前置：M0-01、M0-03、M0-04、M0-05，后续版本持续执行。当前：OpenClaw/Hermes 已固定参考版本，持续升级流程未完整验收。

  - [ ] M7-11.01 定期只读观察两上游发布/安全/弃用，记录新版本来源与影响，不把 main 或 latest 静默写入已验收基线。
  - [ ] M7-11.02 按 M0 方法创建独立候选 diff/合同/数据迁移影响和实现任务，保留旧 fixture、平台差异和回退要求。
  - [ ] M7-11.03 验证来源篡改/缺项/删除能力/测试失效会阻止升级，运行窄回归、实际互操作和适用迁移/制品测试。
  - [ ] M7-11.04 经审查更新支持版本/差异矩阵/文档与证据，旧版支持退役明确通知；没有全量证据不发布追平比例。

  验收：一次完整基线升级可复核，安全变化能落到拥有者任务而非只更新版本字符串。失败处置：保留原支持版本和候选失败记录，暂停升级不掩盖安全风险。证据：来源、语义 diff、回归/互操作和支持矩阵。

## 本轮交付边界

本轮已落地原生安全、状态、Gateway、CLI 和 Slint 的部分生产路径，并有本地构建、
正反向及进程测试。四项窄任务完成，94 项仍未达到各自完整验收门槛，八个里程碑均未关闭。
本次详细化为这 94 个开放主项增加 376 个未核证子项；四项已完成主项保留原窄范围。
一级/子项分别统计，文档详细化不产生新的功能通过或发布授权。
完整的新基线提取、事务恢复、模型/渠道/移动产品、真实迁移与跨平台发布仍需继续开发和验证。
不把本清单、监听成功或测试总数当作整个项目完成证明。