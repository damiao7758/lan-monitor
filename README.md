# 局域网监控提醒（lan-monitor）

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

Windows 常驻托盘的小工具：**发送端**监控本机 jar 是否完全启动，启动后向多台机器的 **监听端** 发送 UDP 提醒；托盘右键可随时切换模式。单文件 Python 脚本，无窗口、低占用。

```
发送端（监控 jar 进程 / 日志 / 端口）  ──UDP 17777──▶  监听端（Windows 气泡提醒 + 消息历史）
```

## 功能特性

- **双模式托盘程序**：右键菜单一键切换发送端 / 监听端，模式写回配置，下次启动沿用。
- **可靠的启动判定**：优先扫描日志增量关键字（跳过历史内容，避免重启后秒报），不可用时回退 TCP 端口探测。
- **UDP 冗余发送 + 消息去重**：每条消息盲发多次提高到达率，监听端按消息 id 去重，不重复弹窗；兼容纯文本旧协议。
- **附加提醒**：启动超时、进程掉线、进程重启均可独立开关，提醒模板支持占位符。
- **零配置上手**：首次运行自动生成 `config.json`，也可全程托盘菜单图形化管理目标 IP 与各项参数。
- **内置自测**：`--selftest` 覆盖协议、去重、日志检测、端口探测、滚动切换等全部核心逻辑，无需桌面环境。

## 快速开始

### 方式一：直接运行 exe（免装 Python）

到 [Releases](https://github.com/damiao7758/lan-monitor/releases) 下载 `LanMonitor.exe`：单文件、无控制台，双击即常驻托盘。首次运行会在 **exe 同目录** 生成 `config.json` 和 `lan_monitor.log`，换机器时把 exe 和配置一起拷走即可。

- exe 未做数字签名，首次运行 Windows SmartScreen 可能提示「已保护你的电脑」→ 点「更多信息」→「仍要运行」；部分杀软可能对 PyInstaller 单文件误报，加入信任即可。
- 自测同样可用：`LanMonitor.exe --selftest`、`LanMonitor.exe --smoke 10`。

### 方式二：源码运行

需要 Python 3.10+（已在 3.12 实测）：

```bat
pip install -r requirements.txt
python lan_monitor.py
```

仅依赖三个常用库：`pystray`、`Pillow`、`psutil`。通知使用 Windows 系统气泡（pystray 自带），不需要 winotify / win10toast。

- 启动后在右下角托盘出现图标（发送端绿色 / 监听端蓝色），**没有主窗口**，右键图标打开菜单。
- 后台常驻可用 `pythonw lan_monitor.py`。
- 调试用：
  - `python lan_monitor.py --selftest` 运行内置自测（不需要桌面/托盘）。
  - `python lan_monitor.py --smoke 10` 启动托盘并在 10 秒后自动退出，用于冒烟测试。

## 两种模式

托盘菜单 →「模式」→ 选择「发送端」或「监听端」。切换立即生效：停止旧任务、启动新任务，并写回 `config.json`，下次启动沿用。

### 发送端

1. 每 3 秒轮询一次 java 进程：进程名以 `java` 开头，且命令行包含「jar 关键字」（留空表示任意 java 进程）；日志每 10 秒检查一次。
2. 判定「完全启动」：
   - 配置了**日志目录**且**日志关键字**非空 → 每 10 秒扫描目录，取文件名中**日期最新、同日序号最大**的 `info-YYYY-MM-DD.N.log`（如 `info-2026-10-30.1.log` 优先于 `.0`），该文件出现关键字即判定启动（默认关键字 `wx agentMini js_ticket`）。
   - **只认程序启动之后新写入的内容**：监控启动时已存在的文件会跳过其历史内容，上次启动残留的关键字不算数，避免重启后秒报「已启动」。监控期间新出现/滚动出的更大序号文件会从头读（内容都属于本次启动）；旧文件追加的内容不再读取。文件截断/轮转后自动从头读。
   - 如果**程序启动时 jar 已经在运行**：不补发「已启动」提醒（历史日志不算数），但仍会跟踪它的掉线与后续重启。
   - 日志目录留空、目录里暂无匹配文件或读不到 → 回退 **TCP 端口探测**（默认 `127.0.0.1:8383`，能连上即视为启动完成）；此模式下已在运行的 jar 会立即按端口判定为已启动。
   - 注意：日志目录有可读文件但关键字一直没出现时，会持续等待，**不会**回退端口探测（避免误报）。
3. 启动完成后向所有「已启用」的目标同时发送 UDP 提醒（默认端口 17777）：每个目标**盲发 3 次**（默认间隔 300ms，不依赖 sendto 报错），监听端按消息 id 去重，不会重复弹通知。
4. 附加提醒（均可在「发送端设置」里开关）：
   - 启动超时（默认 300 秒内未判定启动完成）
   - 进程掉线
   - 进程重启（掉线后再次启动）
5. 菜单项：
   - **立即发送测试消息**：向全部启用目标发一条测试消息，验证链路。
   - **新增消息…** / 自定义消息列表：点击即发送；每条最多 10 个字。
   - **目标 IP 管理…**：添加 / 编辑 / 启用停用 / 删除目标 IP。
   - **发送端设置…**：jar 关键字、日志目录（带「浏览…」选择）、日志文件名规则与关键字、探测地址/端口、各提醒模板与开关、超时时间。

提醒模板占位符：`{host}` 主机名、`{ip}` 本机 IP、`{app}` 应用名、`{event}` 事件、`{time}` 时间、`{timeout}` 超时秒数。

### 监听端

1. 绑定本机 UDP 端口（默认自动取本机局域网 IP，端口 17777），收到消息弹 Windows 气泡，显示来源 IP 与内容。
2. 「查看历史消息…」保留最近 100 条（可配置），可刷新 / 清空。
3. 「监听端设置…」可改监听 IP、端口、历史条数：
   - 监听 IP 填 `auto`：自动取本机局域网 IP；
   - 填 `0.0.0.0`：监听所有网卡（多网卡/不确定 IP 时推荐）。
4. 绑定失败会提示原因，并每 2 秒自动重试（同一错误 60 秒内不重复弹窗）。

## 消息与去重

发送端把消息封装为 JSON：`{v, id, ts, host, app, kind, text}`，监听端按 `id` 去重（重发不会重复弹气泡），同时兼容纯文本旧消息。协议细节见脚本内 `build_payload / parse_message`。

## 配置文件

程序首次运行自动在脚本（或 exe）同目录生成 `config.json`，所有菜单设置都会写回，也可直接编辑后重启程序。仓库提供脱敏模板 [`config.example.json`](config.example.json)，需要手工预置配置时可复制为 `config.json` 再修改。注意：运行时的 `config.json` 已在 `.gitignore` 中，不会被提交。

下方示例为便于阅读加了 `//` 注释，实际文件是标准 JSON，不能带注释：

```json
{
  "mode": "sender",                  // sender 发送端 / listener 监听端
  "sender": {
    "jar_keyword": "agentMini",      // 匹配 java 命令行关键字，空=任意 java
    "log_dir": "",                   // 日志所在目录，空=用端口探测
    "log_file_pattern": "info-*.log",// 只扫描匹配的通配符
    "log_keyword": "wx agentMini js_ticket",
    "probe_host": "127.0.0.1",
    "probe_port": 8383,
    "targets": [{"ip": "127.0.0.1", "port": 17777, "enabled": true}],
    "message": "【{host}】{app} 已启动 {time}",
    "timeout_message": "【{host}】{app} 启动超时（{timeout} 秒）{time}",
    "down_message": "【{host}】{app} 已掉线 {time}",
    "restart_message": "【{host}】{app} 已重启 {time}",
    "timeout_seconds": 300,
    "notify_on_timeout": true,
    "notify_on_down": true,
    "notify_on_restart": true,
    "probe_interval": 3.0,           // 进程/掉线轮询间隔（秒）
    "log_check_interval": 10.0,      // 日志文件检查间隔（秒）
    "send_retries": 3,
    "retry_interval_ms": 300
  },
  "listener": {"bind_ip": "auto", "port": 17777, "history_size": 100},
  "custom_messages": ["服务重启中", "例行测试中"]
}
```

配置文件损坏时程序不会覆盖原文件：回退默认配置运行，并在日志里记录原因。用记事本等编辑器保存成「带 BOM 的 UTF-8」也能正常读取。

旧版配置里的单个 `log_path` 会自动升级：取其父目录作为 `log_dir`，旧字段不再使用。

## 日志

同目录 `lan_monitor.log`（滚动，512KB × 3）。托盘菜单「打开日志文件」可直接查看。

## 自测

```bat
python lan_monitor.py --selftest
```

覆盖：配置读写与损坏回退、消息协议兼容、多目标 UDP 发送与重失去重、UDP 盲发重试次数、日志增量关键字检测（跳过历史）、日志文件选择（日期最新/同日最大序号）、TCP 端口探测、发送端日志关键字启动/掉线/重启（含「旧关键字不触发、新关键字才触发」回归）、启动超时提醒、端口回退（未配置/目录无匹配文件两例）、日志文件滚动切换（新序号文件从头读、旧文件追加不生效）、日志检查 10 秒节流、监听端停止后可重新绑定。

## 打包成单 exe

在项目目录执行：

```bat
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name LanMonitor ^
  --icon icon.ico --exclude-module numpy ^
  --distpath dist --workpath build lan_monitor.py
```

> 必须带 `--exclude-module numpy`：Pillow 会可选导入 numpy，不加会把 Anaconda 整套 numpy/MKL 打进包里（实测 250MB → 24MB）。代码本身不使用 numpy。

## 常见问题

- **收不到提醒**：确认监听端已启动、两端端口一致；Windows 防火墙首次运行会弹窗，需允许 Python（专用/公用网络都勾选）。跨网段时确保路由可达。
- **监听绑定失败**：端口被占用或 IP 不属于本机。改用 `0.0.0.0` 或换端口。
- **一直判定未启动**：检查「运行状态…」里的启动判定方式；日志关键字需与日志实际输出完全一致（区分大小写），并确认日志目录里确实有 `info-YYYY-MM-DD.N.log` 且最新文件在持续写入；或清空日志目录改用端口探测。
- **启动后没收到「已启动」**：如果程序启动时 jar 已经在跑，这是预期行为——历史日志不算数，不会补发；之后 jar 重启会正常提醒。想让本次启动也提醒，可重启 jar 或在 jar 启动前先开监控。
- **托盘图标不显示**：Windows 可能把新图标折叠到「隐藏的图标」里，点任务栏小箭头拖出来即可。

## 贡献

欢迎提交 Issue 和 Pull Request，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交前请确保 `python lan_monitor.py --selftest` 全部通过。

## 开源协议

[MIT License](LICENSE)，Copyright (c) 2026 damiao。
