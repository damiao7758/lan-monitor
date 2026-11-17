#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""局域网监控提醒工具（Windows 托盘常驻，单脚本）

功能概览
--------
* 发送端：监控本机 java 进程（按 jar 文件名 / 命令行关键字匹配），判定目标应用
  "完全启动" 后，向多个目标 IP 同时发送 UDP 提醒。判定规则：
      1) 配置了日志目录 -> 每 10 秒扫描一次，取日期最新、同日序号最大的
         info-YYYY-MM-DD.N.log（如 info-2026-10-30.1.log），出现关键字即判定启动
         （主判定）。只认监控启动之后新写入的内容，历史关键字不算数；监控启动时
         jar 已在运行则不补发 "已启动" 提醒，但仍跟踪掉线与重启。
      2) 日志目录留空 / 目录里没有匹配文件 / 读不到 -> 回退 TCP 端口探测。
* 进程/掉线每 3 秒轮询一次，日志每 10 秒检查一次，线程用 Event.wait 等待，不忙等。
* 监听端：绑定本机局域网 IP 的 UDP 端口，收到提醒后弹 Windows 托盘气泡，
  保留最近消息历史可查看。
* 提醒按目标盲发多次（默认 3 次）提高 UDP 到达率，监听端按消息 id 去重。
* 托盘右键菜单切换发送端 / 监听端，模式写入 config.json，下次启动沿用。

运行：python lan_monitor.py（后台常驻建议用 pythonw lan_monitor.py）
自测：python lan_monitor.py --selftest
"""

from __future__ import annotations

import argparse
import copy
import datetime
import fnmatch
import ipaddress
import json
import logging
import logging.handlers
import os
import queue
import re
import socket
import sys
import tempfile
import threading
import time
import traceback
import uuid
from collections import OrderedDict, deque
from pathlib import Path

APP_NAME = "局域网监控提醒"
APP_ID = "lan_monitor_tray"
LOG_FILE_NAME = "lan_monitor.log"
CONFIG_FILE_NAME = "config.json"

KIND_LABELS = {
    "start": "启动完成",
    "restart": "重启完成",
    "down": "进程掉线",
    "timeout": "启动超时",
    "test": "测试消息",
    "manual": "自定义消息",
}

log = logging.getLogger("lan_monitor")

# ---------------------------------------------------------------------------
# 可选依赖：缺失时给出清晰提示，避免直接抛 ImportError
# ---------------------------------------------------------------------------
MISSING_DEPS: list[str] = []

try:
    import psutil
except Exception:  # noqa: BLE001 - 依赖缺失要降级提示
    psutil = None  # type: ignore[assignment]
    MISSING_DEPS.append("psutil")

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception:  # noqa: BLE001
    pystray = None  # type: ignore[assignment]
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
    MISSING_DEPS.extend(["pystray", "Pillow"])

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
except Exception:  # noqa: BLE001
    tk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    simpledialog = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    MISSING_DEPS.append("tkinter")


# ---------------------------------------------------------------------------
# 默认配置
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "mode": "sender",  # sender | listener
    "sender": {
        "jar_keyword": "agentMini",          # 匹配 java 进程命令行；留空=任意 java 进程
        # 日志目录 + 文件名规则：优先监控日期最新、同日序号最大的 info-YYYY-MM-DD.N.log
        "log_dir": "",                       # 日志所在目录；留空=仅端口探测
        "log_file_pattern": "info-*.log",    # 只扫描匹配该通配符的文件
        "log_keyword": "wx agentMini js_ticket",  # 日志出现该关键字视为启动完成
        "probe_host": "127.0.0.1",
        "probe_port": 8383,
        "targets": [
            {"ip": "127.0.0.1", "port": 17777, "enabled": True},
        ],
        "message": "【{host}】{app} 已启动 {time}",
        "timeout_message": "【{host}】{app} 启动超时（{timeout} 秒）{time}",
        "down_message": "【{host}】{app} 已掉线 {time}",
        "restart_message": "【{host}】{app} 已重启 {time}",
        "timeout_seconds": 300,
        "notify_on_timeout": True,
        "notify_on_down": True,
        "notify_on_restart": True,
        "probe_interval": 3.0,               # 进程/掉线检测间隔（秒）
        "log_check_interval": 10.0,          # 日志文件检查间隔（秒）
        "send_retries": 3,
        "retry_interval_ms": 300,
    },
    "listener": {
        "bind_ip": "auto",  # auto=自动取本机局域网 IP；也可填 0.0.0.0 或具体 IP
        "port": 17777,
        "history_size": 100,
    },
    "custom_messages": [
        "服务重启中",
        "例行测试中",
    ],
}


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def app_dir() -> Path:
    """脚本所在目录；PyInstaller 打包后取 exe 所在目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def default_config() -> dict:
    return copy.deepcopy(DEFAULT_CONFIG)


def _to_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "是")
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _to_int(value, default: int, low: int, high: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return min(max(result, low), high)


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _coerce_targets(value) -> list[dict]:
    """目标 IP 列表规范化：去空、去重、端口收敛到合法范围，最多 50 个。"""
    result: list[dict] = []
    seen: set[tuple[str, int]] = set()
    if not isinstance(value, list):
        return result
    for raw in value[:50]:
        if not isinstance(raw, dict):
            continue
        ip = str(raw.get("ip", "")).strip()
        if not ip:
            continue
        port = _to_int(raw.get("port", 17777), 17777, 1, 65535)
        enabled = _to_bool(raw.get("enabled", True), True)
        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)
        result.append({"ip": ip, "port": port, "enabled": enabled})
    return result


def normalize_config(raw) -> dict:
    """把外部配置合并进默认值并做边界校验，任何非法项都回退默认值。"""
    cfg = default_config()
    if not isinstance(raw, dict):
        return cfg

    if raw.get("mode") in ("sender", "listener"):
        cfg["mode"] = raw["mode"]

    raw_sender = raw.get("sender") if isinstance(raw.get("sender"), dict) else {}
    sender = cfg["sender"]
    sender["jar_keyword"] = str(raw_sender.get("jar_keyword", sender["jar_keyword"]) or "").strip()
    # 日志目录；兼容旧配置的单个日志文件路径（取其父目录，旧字段不再使用）
    log_dir = str(raw_sender.get("log_dir", "") or "").strip()
    legacy_log_path = str(raw_sender.get("log_path", "") or "").strip()
    if not log_dir and legacy_log_path:
        parent = os.path.dirname(legacy_log_path)
        log_dir = "" if parent in ("", ".") else parent
        log.info("旧配置 log_path=%s 已升级为日志目录 %s", legacy_log_path, log_dir or "(空)")
    sender["log_dir"] = log_dir
    pattern = str(raw_sender.get("log_file_pattern", sender["log_file_pattern"]) or "").strip()
    sender["log_file_pattern"] = pattern or DEFAULT_CONFIG["sender"]["log_file_pattern"]
    sender["log_keyword"] = str(raw_sender.get("log_keyword", sender["log_keyword"]) or "").strip()
    probe_host = str(raw_sender.get("probe_host", sender["probe_host"]) or "").strip()
    sender["probe_host"] = probe_host or "127.0.0.1"
    sender["probe_port"] = _to_int(raw_sender.get("probe_port", sender["probe_port"]), 8383, 1, 65535)
    sender["targets"] = _coerce_targets(raw_sender.get("targets", sender["targets"]))
    for key in ("message", "timeout_message", "down_message", "restart_message"):
        text = str(raw_sender.get(key, sender[key]) or "").strip()
        sender[key] = text or DEFAULT_CONFIG["sender"][key]
    sender["timeout_seconds"] = _to_int(
        raw_sender.get("timeout_seconds", sender["timeout_seconds"]), 300, 10, 86400
    )
    for key in ("notify_on_timeout", "notify_on_down", "notify_on_restart"):
        sender[key] = _to_bool(raw_sender.get(key, sender[key]), sender[key])
    try:
        interval = float(raw_sender.get("probe_interval", sender["probe_interval"]) or 3.0)
    except (TypeError, ValueError):
        interval = 3.0
    sender["probe_interval"] = min(max(interval, 0.5), 10.0)
    try:
        log_interval = float(
            raw_sender.get("log_check_interval", sender["log_check_interval"]) or 10.0
        )
    except (TypeError, ValueError):
        log_interval = 10.0
    sender["log_check_interval"] = min(max(log_interval, 1.0), 3600.0)
    sender["send_retries"] = _to_int(raw_sender.get("send_retries", sender["send_retries"]), 3, 1, 5)
    sender["retry_interval_ms"] = _to_int(
        raw_sender.get("retry_interval_ms", sender["retry_interval_ms"]), 300, 50, 5000
    )

    raw_listener = raw.get("listener") if isinstance(raw.get("listener"), dict) else {}
    listener = cfg["listener"]
    bind_ip = str(raw_listener.get("bind_ip", listener["bind_ip"]) or "auto").strip()
    if bind_ip.lower() != "auto" and bind_ip != "0.0.0.0" and not _is_ipv4(bind_ip):
        bind_ip = "auto"
    listener["bind_ip"] = bind_ip
    listener["port"] = _to_int(raw_listener.get("port", listener["port"]), 17777, 1, 65535)
    listener["history_size"] = _to_int(
        raw_listener.get("history_size", listener["history_size"]), 100, 10, 1000
    )

    raw_msgs = raw.get("custom_messages")
    if isinstance(raw_msgs, list):
        msgs: list[str] = []
        for item in raw_msgs[:30]:
            text = str(item).strip()
            if text and text not in msgs:
                msgs.append(text[:10])  # 沿用参考代码的 10 字限制
        cfg["custom_messages"] = msgs

    return cfg


def load_config(path: Path) -> dict:
    """读取配置；文件不存在时写入默认配置，文件损坏时保留原文件并用默认值启动。"""
    try:
        if not path.exists():
            cfg = default_config()
            save_config(path, cfg)
            return cfg
        # utf-8-sig：兼容记事本等编辑器保存的带 BOM 的 UTF-8 配置
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        return normalize_config(raw)
    except (OSError, ValueError, TypeError) as exc:
        log.error("配置文件读取失败，使用默认配置（原文件保留）：%s", exc)
        return default_config()


def save_config(path: Path, config: dict) -> bool:
    """原子写入配置，避免断电/崩溃留下半截 json。"""
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(config, ensure_ascii=False, indent=2)
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return True
    except OSError as exc:
        log.error("配置保存失败：%s", exc)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def get_local_ip() -> str:
    """取本机局域网 IP；无默认路由时退回主机名解析，再退回 127.0.0.1。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))  # UDP connect 不真正发包
            return sock.getsockname()[0]
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def resolve_bind_ip(value: str) -> str:
    text = (value or "auto").strip()
    if text.lower() == "auto":
        return get_local_ip()
    return text


def now_time() -> str:
    return time.strftime("%H:%M:%S")


def format_template(template: str, *, app: str, event: str, timeout: int | None = None) -> str:
    """展开模板占位符；模板写错时原样返回，绝不因格式化异常而漏发提醒。"""
    values = {
        "host": socket.gethostname(),
        "ip": get_local_ip(),
        "app": app or "java",
        "event": event,
        "time": now_time(),
    }
    if timeout is not None:
        values["timeout"] = timeout
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError) as exc:
        log.warning("提醒模板占位符有误，按原文发送：%s (%s)", template, exc)
        return template


# ---------------------------------------------------------------------------
# 消息协议
# ---------------------------------------------------------------------------
def build_payload(kind: str, text: str, app: str = "") -> dict:
    return {
        "v": 1,
        "id": uuid.uuid4().hex,
        "ts": time.time(),
        "host": socket.gethostname(),
        "app": app or "",
        "kind": kind,
        "text": text,
    }


def parse_message(raw: str) -> dict:
    """解析 JSON 协议；兼容参考代码的纯文本 UDP 消息。"""
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        obj = None
    if isinstance(obj, dict) and obj.get("text"):
        return {
            "id": str(obj.get("id") or ""),
            "kind": str(obj.get("kind") or "manual"),
            "app": str(obj.get("app") or ""),
            "host": str(obj.get("host") or ""),
            "text": str(obj.get("text"))[:2000],
        }
    return {"id": "", "kind": "manual", "app": "", "host": "", "text": raw[:2000]}


def send_udp(
    targets: list[dict],
    payload: dict,
    retries: int = 3,
    retry_interval: float = 0.3,
) -> list[str]:
    """向每个目标盲发 retries 次（间隔 retry_interval 秒），返回最终失败描述列表。

    UDP 没有确认，所以不等 sendto 报错：每个目标都按次数重发以提高到达率；
    接收端按消息 id 去重，不会重复弹通知。两次发送之间才等待，最后一次不等。
    """
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    attempts = max(1, int(retries))
    items = [{"ip": str(t["ip"]), "port": int(t["port"])} for t in targets]
    if not items:
        return []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        return [f"创建 UDP socket 失败：{exc}"]

    ok: set[tuple[str, int]] = set()
    errors: dict[tuple[str, int], str] = {}
    try:
        for attempt in range(attempts):
            for target in items:
                key = (target["ip"], target["port"])
                try:
                    sock.sendto(data, (target["ip"], target["port"]))
                except OSError as exc:
                    errors[key] = str(exc)
                else:
                    ok.add(key)
            if attempt < attempts - 1:
                time.sleep(max(0.0, retry_interval))
    finally:
        sock.close()
    return [f"{ip}:{port} {errors[(ip, port)]}" for ip, port in errors if (ip, port) not in ok]


def tcp_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


LOG_FILE_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
LOG_FILE_SEQ_RE = re.compile(r"\.(\d+)$")


def parse_log_file_name(name: str) -> tuple[int, int, int, int] | None:
    """解析 info-YYYY-MM-DD[.N].log，返回 (年, 月, 日, N)；文件名不合规返回 None。"""
    filename = os.path.basename(str(name))
    match = LOG_FILE_DATE_RE.search(filename)
    if not match:
        return None
    try:
        day = datetime.date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None
    stem = filename[:-4] if filename.lower().endswith(".log") else filename
    seq_match = LOG_FILE_SEQ_RE.search(stem)
    seq = int(seq_match.group(1)) if seq_match else 0
    return (day.year, day.month, day.day, seq)


def find_latest_log_file(log_dir: str, pattern: str = "info-*.log") -> str | None:
    """扫描日志目录，返回日期最新、同日序号最大的文件；找不到返回 None。"""
    directory = str(log_dir or "").strip()
    if not directory:
        return None
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return None
    glob = (pattern or "info-*.log").strip()
    best_key: tuple[int, int, int, int] | None = None
    best_path: str | None = None
    for entry in entries:
        try:
            if not entry.is_file():
                continue
        except OSError:
            continue
        if not fnmatch.fnmatch(entry.name.lower(), glob.lower()):
            continue
        key = parse_log_file_name(entry.name)
        if key is None:
            continue
        if best_key is None or key > best_key:
            best_key = key
            best_path = entry.path
    return best_path


# ---------------------------------------------------------------------------
# 日志增量读取
# ---------------------------------------------------------------------------
class LogTail:
    """按偏移量增量读取日志并查找关键字，避免每秒重读整个大文件。

    * 默认 skip_existing=True：以构造时文件末尾为基准，只认之后新写入的内容，
      历史内容（比如上次启动留下的关键字）不算数；
    * 文件不存在时从 0 开始，后续创建/写入的内容都算新的；
    * 日志被清空/轮转时自动回到文件开头；
    * 单次检查最多读 max_chunks_per_check 个分片，避免日志暴涨时长时间占用线程；
    * 关键字跨分片出现也能识别（保留关键字长度-1 的尾巴做拼接）。
    """

    def __init__(
        self,
        path: str,
        keyword: str,
        skip_existing: bool = True,
        initial_bytes: int = 8 * 1024 * 1024,
        chunk_bytes: int = 1024 * 1024,
        max_chunks_per_check: int = 4,
    ) -> None:
        self.path = path
        self.keyword_bytes = (keyword or "").encode("utf-8", errors="ignore")
        self.skip_existing = skip_existing
        self.initial_bytes = initial_bytes
        self.chunk_bytes = chunk_bytes
        self.max_chunks_per_check = max_chunks_per_check
        self._carry = b""
        if skip_existing:
            try:
                self.offset = os.path.getsize(path)  # 跳过历史内容，只看新写入
            except OSError:
                self.offset = 0  # 文件还不存在，之后创建的内容都算新的
        else:
            self.offset = 0

    def check(self) -> bool:
        if not self.keyword_bytes:
            return False
        try:
            size = os.path.getsize(self.path)
        except OSError:
            self.offset = 0
            self._carry = b""
            return False
        if size < self.offset:  # 文件被截断/轮转，从头读新内容
            self.offset = 0
            self._carry = b""
        if size <= 0:
            return False
        if self.offset == 0 and not self.skip_existing and size > self.initial_bytes:
            self.offset = size - self.initial_bytes

        chunks = 0
        while self.offset < size and chunks < self.max_chunks_per_check:
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(self.offset)
                    data = fh.read(min(self.chunk_bytes, size - self.offset))
            except OSError as exc:
                log.debug("读取日志失败 %s：%s", self.path, exc)
                return False
            if not data:
                return False
            self.offset += len(data)
            blob = self._carry + data
            if self.keyword_bytes in blob:
                return True
            keep = max(0, len(self.keyword_bytes) - 1)
            self._carry = blob[-keep:] if keep else b""
            chunks += 1
        return False


def extract_app_name(command: str, keyword: str) -> str:
    """从 java 命令行提取 jar 文件名用于提醒文案。"""
    match = re.search(r"-jar\s+(\"[^\"]+\"|\S+)", command or "", re.IGNORECASE)
    if match:
        name = os.path.basename(match.group(1).strip('"'))
        if name:
            return name[:60]
    return (keyword or "java")[:60]


def list_java_processes(keyword: str) -> list[tuple[int, str]]:
    """返回匹配关键字的 java 进程 [(pid, cmdline)]；keyword 为空表示任意 java。"""
    if psutil is None:
        return []
    result: list[tuple[int, str]] = []
    needle = (keyword or "").strip().lower()
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            if not name.startswith("java"):
                continue
            command = " ".join(info.get("cmdline") or [])
            if needle and needle not in command.lower():
                continue
            pid = int(info.get("pid"))
            result.append((pid, command))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except (TypeError, ValueError):
            continue
    return result


# ---------------------------------------------------------------------------
# 发送端
# ---------------------------------------------------------------------------
class ProcState:
    __slots__ = ("pid", "command", "app", "first_seen", "started", "timeout_sent", "claim_hit")

    def __init__(self, pid: int, command: str, now: float) -> None:
        self.pid = pid
        self.command = command
        self.app = "java"
        self.first_seen = now
        self.started = False
        self.timeout_sent = False
        # 上一轮刚检测到关键字、但进程列表里还没出现（列表与日志读取有几毫秒空档）
        self.claim_hit = False


class SenderService:
    """后台轮询 java 进程，判定启动完成后向多个目标 IP 发送提醒。"""

    def __init__(self, config: dict, notify=None, process_lister=None) -> None:
        self._config = config
        self._notify = notify or (lambda title, message: None)
        self._lister = process_lister or list_java_processes
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._states: dict[int, ProcState] = {}
        self._restart_pending = False
        self._status_lock = threading.Lock()
        # 日志基准：服务启动时只认“启动之后写入”的关键字（历史内容不算数）
        self._log_tail: LogTail | None = None
        self._log_dir = ""
        self._log_pattern = ""
        self._log_keyword = ""
        self._current_log_path = ""
        self._log_hit_at: float | None = None
        self._hit_pending = False
        self._hit_pending_at = 0.0
        self._log_file_at_start = False
        self._last_log_check = 0.0
        # 服务启动瞬间已在运行、且日志判定生效的进程：不补发“已启动”
        self._initial_pids: set[int] = set()
        self.status = {"matched": 0, "started": 0, "apps": "", "judge": "-", "last_event": "-", "last_send": "-"}
        self._init_log_state(self._sender_cfg())
        if self._log_tail is not None:
            try:
                keyword = self._sender_cfg().get("jar_keyword", "")
                self._initial_pids = {int(item[0]) for item in self._lister(keyword)}
            except Exception:  # noqa: BLE001 - 初始化快照失败不应阻止监控启动
                log.exception("初始化进程快照失败")
                self._initial_pids = set()

    # ---- 生命周期 ----
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="sender", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread and thread.is_alive():
            thread.join(timeout=3.0)

    def _sender_cfg(self) -> dict:
        raw = self._config.get("sender") if isinstance(self._config, dict) else None
        return copy.deepcopy(raw if isinstance(raw, dict) else {})

    def _init_log_state(self, sender: dict) -> None:
        """服务启动时确定日志目录/规则，并把当前最新文件的基准放到末尾（历史不算数）。"""
        self._log_hit_at = None
        self._log_tail = None
        self._log_dir = str(sender.get("log_dir") or "").strip()
        self._log_pattern = str(sender.get("log_file_pattern") or "info-*.log").strip()
        self._log_keyword = str(sender.get("log_keyword") or "").strip()
        self._current_log_path = ""
        self._log_file_at_start = False
        if not (self._log_dir and self._log_keyword):
            return
        latest = find_latest_log_file(self._log_dir, self._log_pattern)
        if not latest:
            log.info("日志目录暂无可监控文件，先回退端口探测：%s", self._log_dir)
            return
        self._log_tail = LogTail(latest, self._log_keyword, skip_existing=True)
        self._current_log_path = latest
        self._log_file_at_start = True
        log.info("日志监控文件：%s（关键字：%s）", latest, self._log_keyword)

    def _log_active(self) -> bool:
        """日志判定当前是否生效（配置完整且最新文件可访问），否则回退端口探测。"""
        if self._log_tail is None or not self._current_log_path:
            return False
        try:
            return os.path.isfile(self._current_log_path) and os.access(
                self._current_log_path, os.R_OK
            )
        except OSError:
            return False

    def _check_log(self, now: float) -> None:
        """按 log_check_interval 节流调用：重新选最新文件、必要时切换、查一次关键字。"""
        if not (self._log_dir and self._log_keyword):
            return
        latest = find_latest_log_file(self._log_dir, self._log_pattern)
        if not latest:
            if self._log_tail is not None:
                log.info("日志目录暂无可监控文件，回退端口探测：%s", self._log_dir)
            self._log_tail = None
            self._current_log_path = ""
            return
        if self._log_tail is None or latest != self._current_log_path:
            # 监控期间新出现/滚动的文件：内容都属于本次启动，从头读
            self._log_tail = LogTail(latest, self._log_keyword, skip_existing=False)
            self._current_log_path = latest
            log.info("切换监控日志文件：%s", latest)
        try:
            if self._log_tail.check():
                self._log_hit_at = now
                self._hit_pending = True
                self._hit_pending_at = now
        except Exception:  # noqa: BLE001 - 单个文件读失败不应中断监控
            log.exception("日志关键字检查异常")

    # ---- 主循环：进程按 probe_interval 轮询，日志按 log_check_interval 检查，不忙等 ----
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001 - 后台线程必须兜底，否则监控静默停止
                log.exception("发送端轮询异常")
            interval = float(self._sender_cfg().get("probe_interval", 3.0) or 3.0)
            self._stop.wait(min(max(interval, 0.5), 10.0))

    def _tick(self, now: float | None = None) -> None:
        sender = self._sender_cfg()
        if not sender:
            return
        now = time.time() if now is None else float(now)
        procs = self._lister(sender.get("jar_keyword", ""))
        current: dict[int, str] = {}
        for item in procs:
            try:
                pid, command = int(item[0]), str(item[1] or "")
            except (TypeError, ValueError, IndexError):
                continue
            current[pid] = command

        for pid, command in current.items():
            if pid not in self._states:
                state = ProcState(pid, command, now)
                state.app = extract_app_name(command, sender.get("jar_keyword", ""))
                # 服务启动时 jar 已在运行：日志模式只认启动之后写入的内容，历史关键字
                # 不算数，因此不补发“已启动”；仍按已启动跟踪掉线/重启，避免漏报。
                if self._log_tail is not None and self._log_file_at_start and pid in self._initial_pids:
                    state.started = True
                    self._initial_pids.discard(pid)
                elif self._hit_pending and now - self._hit_pending_at <= max(
                    120.0, float(sender.get("log_check_interval", 10.0) or 10.0) * 6
                ):
                    # 先读到关键字、这一轮才列出进程（同一次启动）；节流期间命中保留待领
                    state.claim_hit = True
                    self._hit_pending = False
                self._states[pid] = state

        # 进程掉线
        for pid in [pid for pid in self._states if pid not in current]:
            state = self._states.pop(pid)
            if state.started:
                self._restart_pending = True
                if sender.get("notify_on_down", True):
                    self._send_event("down", sender, state.app, timeout=sender.get("timeout_seconds"))

        # 日志按独立间隔检查（默认 10 秒），避免高频轮询；只读本次监控开始后新写入的内容
        if sender.get("log_dir") and sender.get("log_keyword"):
            log_interval = float(sender.get("log_check_interval", 10.0) or 10.0)
            if now - self._last_log_check >= min(max(log_interval, 1.0), 3600.0):
                self._last_log_check = now
                self._check_log(now)

        judge = (
            "日志关键字"
            if self._log_active()
            else f"端口 {sender.get('probe_host')}:{sender.get('probe_port')}"
        )

        # 逐个判定是否启动完成 / 是否超时
        for state in list(self._states.values()):
            if state.started:
                continue
            try:
                started = self._is_started(state, sender)
            except Exception:  # noqa: BLE001 - 单次探测异常不影响下一轮
                log.exception("启动判定异常 pid=%s", state.pid)
                started = False
            if started:
                state.started = True
                self._hit_pending = False  # 本次关键字已被消费，避免下次进程出现时误领
                kind = "restart" if (self._restart_pending and sender.get("notify_on_restart", True)) else "start"
                self._restart_pending = False
                self._send_event(kind, sender, state.app, timeout=sender.get("timeout_seconds"))
            elif (
                not state.timeout_sent
                and sender.get("notify_on_timeout", True)
                and now - state.first_seen >= float(sender.get("timeout_seconds", 300))
            ):
                state.timeout_sent = True
                self._send_event("timeout", sender, state.app, timeout=sender.get("timeout_seconds"))

        with self._status_lock:
            self.status = {
                "matched": len(self._states),
                "started": sum(1 for item in self._states.values() if item.started),
                "apps": "、".join(
                    f"{item.app}(pid {item.pid})" for item in list(self._states.values())[:5]
                ) or "无",
                "judge": judge,
                "last_event": self.status.get("last_event", "-"),
                "last_send": self.status.get("last_send", "-"),
            }

    def _is_started(self, state: ProcState, sender: dict) -> bool:
        """日志关键字优先（只认本次监控开始后新写入的内容）；日志不可用时回退端口探测。"""
        if self._log_active():
            if state.claim_hit:
                return True
            return self._log_hit_at is not None and self._log_hit_at >= state.first_seen
        return tcp_port_open(
            str(sender.get("probe_host") or "127.0.0.1"),
            int(sender.get("probe_port") or 8383),
        )

    # ---- 对外手动发送 ----
    def send_test(self) -> int:
        sender = self._sender_cfg()
        text = format_template("测试消息：链路正常 {time}", app="", event="测试消息")
        return self._send_text("test", text, sender, app="", manual=True)

    def send_manual(self, text: str) -> int:
        sender = self._sender_cfg()
        text = format_template(text, app="", event="自定义消息")
        return self._send_text("manual", text, sender, app="", manual=True)

    def _send_event(self, kind: str, sender: dict, app: str, timeout=None) -> int:
        event_names = {"start": "启动完成", "restart": "重启完成", "down": "进程掉线", "timeout": "启动超时"}
        templates = {
            "start": sender.get("message"),
            "restart": sender.get("restart_message"),
            "down": sender.get("down_message"),
            "timeout": sender.get("timeout_message"),
        }
        template = str(templates.get(kind) or DEFAULT_CONFIG["sender"]["message"])
        text = format_template(
            template,
            app=app,
            event=event_names.get(kind, kind),
            timeout=timeout if timeout is not None else sender.get("timeout_seconds"),
        )
        return self._send_text(kind, text, sender, app=app, manual=False)

    def _send_text(self, kind: str, text: str, sender: dict, app: str, manual: bool) -> int:
        targets = [
            {"ip": str(item.get("ip")), "port": int(item.get("port"))}
            for item in sender.get("targets", [])
            if item.get("enabled", True) and str(item.get("ip") or "").strip()
        ]
        if not targets:
            log.warning("没有启用的目标 IP，提醒未发送：%s", text)
            if manual:
                self._set_status(text)
                self._notify("未发送", "没有启用的目标 IP，请先在「目标 IP 管理」中添加")
            return 0

        payload = build_payload(kind, text, app)
        errors = send_udp(
            targets,
            payload,
            retries=int(sender.get("send_retries", 3)),
            retry_interval=int(sender.get("retry_interval_ms", 300)) / 1000.0,
        )
        self._set_status(text)
        if errors:
            detail = "；".join(errors)[:300]
            log.warning("提醒发送失败：%s", detail)
            self._notify("发送失败", detail)
            return 0
        log.info("已发送[%s] %s -> %s", kind, text, ", ".join(f"{t['ip']}:{t['port']}" for t in targets))
        if manual:
            self._notify("已发送", f"『{text}』→ {len(targets)} 个目标")
        return len(targets)

    def _set_status(self, text: str) -> None:
        with self._status_lock:
            self.status = dict(self.status)
            self.status["last_event"] = text
            self.status["last_send"] = now_time()


# ---------------------------------------------------------------------------
# 消息历史
# ---------------------------------------------------------------------------
class MessageHistory:
    """线程安全的消息历史，最多保留 1000 条，界面按配置展示最近 N 条。"""

    def __init__(self, maxlen: int = 1000) -> None:
        self._items: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, item: dict) -> None:
        with self._lock:
            self._items.append(item)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._items)

    def count(self) -> int:
        with self._lock:
            return len(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


# ---------------------------------------------------------------------------
# 监听端
# ---------------------------------------------------------------------------
class ListenerService:
    """UDP 监听线程：收消息 -> 去重 -> 记录历史 -> 托盘气泡通知。"""

    DEDUPE_TTL = 10.0
    DEDUPE_MAX = 500

    def __init__(self, config: dict, notify=None, history: MessageHistory | None = None) -> None:
        self._config = config
        self._notify = notify or (lambda title, message: None)
        self.history = history or MessageHistory()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._last_error_notify = 0.0
        self.bound: tuple[str, int] | None = None
        self.status = {"state": "未启动", "error": "", "addr": "-"}

    @property
    def port(self) -> int:
        if self.bound:
            return self.bound[1]
        try:
            return int(self._config.get("listener", {}).get("port", 17777))
        except (TypeError, ValueError):
            return 17777

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="listener", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        thread = self._thread
        self._thread = None
        if thread and thread.is_alive():
            thread.join(timeout=2.5)

    def _listener_cfg(self) -> dict:
        raw = self._config.get("listener") if isinstance(self._config, dict) else None
        return copy.deepcopy(raw if isinstance(raw, dict) else {})

    def _run(self) -> None:
        while not self._stop.is_set():
            cfg = self._listener_cfg()
            bind_ip = resolve_bind_ip(str(cfg.get("bind_ip", "auto")))
            try:
                port = int(cfg.get("port", 17777))
            except (TypeError, ValueError):
                port = 17777
            if not 0 <= port <= 65535:  # 端口 0 仅自测使用，生产配置会被 normalize 收敛
                port = 17777
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(1.0)
                sock.bind((bind_ip, port))
            except OSError as exc:
                log.error("监听绑定失败 %s:%s：%s", bind_ip, port, exc)
                self.status = {"state": "绑定失败", "error": str(exc), "addr": f"{bind_ip}:{port}"}
                self._notify_bind_error(bind_ip, port, exc)
                if self._stop.wait(2.0):
                    return
                continue

            actual = sock.getsockname()
            self._sock = sock
            self.bound = (str(actual[0]), int(actual[1]))
            self.status = {"state": "监听中", "error": "", "addr": f"{actual[0]}:{actual[1]}"}
            log.info("UDP 监听已启动 %s:%s", actual[0], actual[1])
            self._notify("监听已启动", f"地址 {actual[0]}:{actual[1]}")
            self._recv_loop(sock)
            try:
                sock.close()
            except OSError:
                pass
            self._sock = None
            self.bound = None
            if self._stop.is_set():
                return
            log.warning("监听套接字已关闭，2 秒后重建")
            if self._stop.wait(2.0):
                return

    def _notify_bind_error(self, bind_ip: str, port: int, exc: OSError) -> None:
        now = time.monotonic()
        if now - self._last_error_notify < 60:
            return
        self._last_error_notify = now
        self._notify(
            "监听启动失败",
            f"{bind_ip}:{port} 绑定失败：{exc}\n请检查 IP/端口是否被占用，或改用 0.0.0.0",
        )

    def _recv_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                log.warning("UDP 接收异常，准备重建监听", exc_info=True)
                return
            if not data:
                continue
            raw = data.decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            message = parse_message(raw)
            if message["id"] and self._is_duplicate(message["id"]):
                continue
            kind_label = KIND_LABELS.get(message["kind"], "消息")
            item = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": addr[0],
                "kind": kind_label,
                "kind_raw": message["kind"],
                "text": message["text"],
            }
            self.history.add(item)
            log.info("收到提醒 来自 %s：%s", addr[0], message["text"])
            self._notify(f"局域网提醒 · {kind_label}", f"来自 {addr[0]}\n{message['text']}")

    def _is_duplicate(self, message_id: str) -> bool:
        now = time.monotonic()
        while self._seen and now - next(iter(self._seen.values())) > self.DEDUPE_TTL:
            self._seen.popitem(last=False)
        if message_id in self._seen:
            return True
        self._seen[message_id] = now
        if len(self._seen) > self.DEDUPE_MAX:
            self._seen.popitem(last=False)
        return False


# ---------------------------------------------------------------------------
# 托盘图标绘制
# ---------------------------------------------------------------------------
def make_icon_image(mode: str, size: int = 64):
    """动态生成图标：发送端绿色，监听端蓝色。

    size 为边长（默认 64，托盘用）；生成 .ico 时传 256 避免放大发虚。
    """
    size = max(16, int(size))
    scale = size / 64.0

    def box(left: float, top: float, right: float, bottom: float) -> tuple[int, int, int, int]:
        return (
            int(round(left * scale)),
            int(round(top * scale)),
            int(round(right * scale)),
            int(round(bottom * scale)),
        )

    def point(x: float, y: float) -> tuple[int, int]:
        return (int(round(x * scale)), int(round(y * scale)))

    def width(value: float) -> int:
        return max(1, int(round(value * scale)))

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    color = (46, 125, 50, 255) if mode == "sender" else (21, 101, 192, 255)
    # 显示器
    draw.rounded_rectangle(box(5, 8, 59, 43), radius=max(1, width(6)), fill=color)
    draw.rounded_rectangle(box(10, 13, 54, 38), radius=max(1, width(3)), fill=(255, 255, 255, 255))
    draw.rectangle(box(28, 44, 36, 49), fill=color)
    draw.rounded_rectangle(box(17, 49, 47, 55), radius=max(1, width(3)), fill=color)
    if mode == "sender":
        # 向右上发出的箭头
        draw.line([point(22, 32), point(41, 19)], fill=color, width=width(4))
        draw.polygon([point(44, 14), point(47, 25), point(36, 22)], fill=color)
    else:
        # 声波
        cx, cy = 22 * scale, 32 * scale
        for radius in (6, 11, 16):
            r = radius * scale
            draw.arc(
                (cx - r, cy - r, cx + r, cy + r),
                start=-55,
                end=55,
                fill=color,
                width=width(2),
            )
        dot = max(1.0, 2 * scale)
        draw.ellipse((cx - dot, cy - dot, cx + dot, cy + dot), fill=color)
    return img


# ---------------------------------------------------------------------------
# 主程序（Tk 主线程 + 托盘子线程，服务线程全部 daemon）
# ---------------------------------------------------------------------------
class App:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.base_dir / CONFIG_FILE_NAME
        self.log_path = self.base_dir / LOG_FILE_NAME
        self.config = load_config(self.config_path)
        self.history = MessageHistory()
        self.ui: queue.Queue = queue.Queue()
        self.icon = None
        self.tray_ready = threading.Event()
        self.tray_error: Exception | None = None
        self.sender: SenderService | None = None
        self.listener: ListenerService | None = None
        self._lock = threading.RLock()
        self._closing = False
        self._shutdown_done = False
        self._last_title = ""
        self._history_win = None
        self._targets_win = None
        self._custom_win = None

        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP_NAME)

    # ---- 启动 / 退出 ----
    def run(self, auto_exit: int = 0) -> int:
        self._start_tray()
        if not self.tray_ready.wait(8.0):
            self._fatal("系统托盘未能在 8 秒内就绪，请查看日志：" + str(self.log_path))
            return 1
        if self.tray_error is not None:
            self._fatal(f"无法创建系统托盘图标：{self.tray_error}\n请查看日志：{self.log_path}")
            return 1

        self._apply_mode(self.config["mode"], persist=False)
        if auto_exit > 0:
            self.root.after(auto_exit * 1000, self._quit)
        self.root.after(150, self._poll_ui)
        try:
            self.root.mainloop()
        finally:
            self._shutdown()
        return 0

    def _fatal(self, message: str) -> None:
        log.error(message)
        try:
            messagebox.showerror(APP_NAME, message)
        except Exception:  # noqa: BLE001
            pass
        self._shutdown()

    def _start_tray(self) -> None:
        self.icon = pystray.Icon(
            APP_ID,
            make_icon_image(self.config["mode"]),
            self._tray_title(),
            menu=self._build_menu(),
        )
        threading.Thread(target=self._tray_run, name="tray", daemon=True).start()

    def _tray_run(self) -> None:
        try:
            self.icon.run(setup=self._on_tray_ready)
        except Exception as exc:  # noqa: BLE001 - 托盘线程异常需带回主线程展示
            self.tray_error = exc
            log.exception("托盘线程异常")
        finally:
            self.tray_ready.set()

    def _on_tray_ready(self, icon) -> None:
        try:
            icon.visible = True
        except Exception as exc:  # noqa: BLE001
            self.tray_error = exc
            log.exception("托盘图标显示失败")
        finally:
            self.tray_ready.set()

    def _shutdown(self) -> None:
        if self._shutdown_done:
            return
        self._shutdown_done = True
        self._closing = True
        self._stop_services()
        icon = self.icon
        self.icon = None
        if icon is not None:
            try:
                icon.stop()
            except Exception:  # noqa: BLE001
                log.debug("停止托盘图标时出现异常", exc_info=True)
        try:
            self.root.destroy()
        except Exception:  # noqa: BLE001
            pass

    def _quit(self) -> None:
        self._shutdown()

    def _stop_services(self) -> None:
        with self._lock:
            sender, self.sender = self.sender, None
            listener, self.listener = self.listener, None
        if sender is not None:
            sender.stop()
        if listener is not None:
            listener.stop()

    # ---- 模式切换 ----
    def _apply_mode(self, mode: str, persist: bool = True) -> None:
        if mode not in ("sender", "listener") or self._closing:
            return
        with self._lock:
            self._stop_services()
            self.config["mode"] = mode
            if persist:
                save_config(self.config_path, self.config)
            if mode == "sender":
                self.sender = SenderService(self.config, self._service_notify)
                self.sender.start()
            else:
                self.listener = ListenerService(self.config, self._service_notify, self.history)
                self.listener.start()
        if self.icon is not None:
            try:
                self.icon.icon = make_icon_image(mode)
            except Exception:  # noqa: BLE001
                log.debug("更新托盘图标失败", exc_info=True)
        self._rebuild_menu()
        self._refresh_tray_title(force=True)
        log.info("当前模式：%s", "发送端" if mode == "sender" else "监听端")

    def _service_notify(self, title: str, message: str) -> None:
        """服务线程只入队，所有 Tk/托盘 UI 操作都回主线程执行。"""
        self.ui.put(("notify", (title, message)))

    def _rebuild_menu(self) -> None:
        icon = self.icon
        if icon is None:
            return
        try:
            icon.menu = self._build_menu()
            icon.update_menu()
        except Exception:  # noqa: BLE001
            log.debug("刷新托盘菜单失败", exc_info=True)

    # ---- 托盘菜单 ----
    def _build_menu(self):
        mode = self.config["mode"]
        items = [
            pystray.MenuItem(lambda item: self._status_line(), None, enabled=False),
            pystray.Menu.SEPARATOR,
        ]
        if mode == "sender":
            items.extend(
                [
                    pystray.MenuItem("立即发送测试消息", self._queue_call(self._send_test_message)),
                    pystray.MenuItem("新增消息…", self._queue_call(self._add_custom_message)),
                ]
            )
            for text in self.config.get("custom_messages", []):
                items.append(
                    pystray.MenuItem(text, self._queue_call(lambda m=text: self._send_custom(m)))
                )
            items.extend(
                [
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem("目标 IP 管理…", self._queue_call(self._open_targets)),
                    pystray.MenuItem("发送端设置…", self._queue_call(self._open_sender_settings)),
                    pystray.MenuItem("自定义消息管理…", self._queue_call(self._open_custom_messages)),
                ]
            )
        else:
            items.extend(
                [
                    pystray.MenuItem("查看历史消息…", self._queue_call(self._open_history)),
                    pystray.MenuItem("监听端设置…", self._queue_call(self._open_listener_settings)),
                ]
            )
        items.extend(
            [
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("运行状态…", self._queue_call(self._open_status)),
                pystray.MenuItem(
                    "模式",
                    pystray.Menu(
                        pystray.MenuItem(
                            "发送端（监控 jar 并提醒）",
                            self._queue_call(lambda: self._apply_mode("sender")),
                            checked=lambda item: self.config["mode"] == "sender",
                            radio=True,
                        ),
                        pystray.MenuItem(
                            "监听端（接收提醒）",
                            self._queue_call(lambda: self._apply_mode("listener")),
                            checked=lambda item: self.config["mode"] == "listener",
                            radio=True,
                        ),
                    ),
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("打开配置文件", self._queue_call(self._open_config_file)),
                pystray.MenuItem("打开日志文件", self._queue_call(self._open_log_file)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("退出", self._queue_call(self._quit)),
            ]
        )
        return pystray.Menu(*items)

    def _queue_call(self, func):
        def action():
            self.ui.put(("call", func))

        return action

    def _status_line(self) -> str:
        mode = self.config["mode"]
        if mode == "sender":
            sender = self.sender
            if sender is None:
                return "发送端 · 启动中"
            with sender._status_lock:  # 只读取快照，不参与状态更新
                status = dict(sender.status)
            cfg = self.config["sender"]
            return f"发送端 · {status['judge']} · 匹配 {status['matched']} · 目标 {len(cfg['targets'])}"
        listener = self.listener
        addr = listener.status.get("addr") if listener else "-"
        return f"监听端 · {addr} · 已收 {self.history.count()}"

    def _tray_title(self) -> str:
        mode = self.config["mode"]
        label = "发送端" if mode == "sender" else "监听端"
        return f"{APP_NAME} · {label}"

    def _refresh_tray_title(self, force: bool = False) -> None:
        icon = self.icon
        if icon is None:
            return
        title = self._tray_title()
        if force or title != self._last_title:
            self._last_title = title
            try:
                icon.title = title
            except Exception:  # noqa: BLE001
                log.debug("更新托盘提示失败", exc_info=True)

    # ---- UI 事件循环（主线程） ----
    def _poll_ui(self) -> None:
        try:
            while not self._closing:
                try:
                    kind, payload = self.ui.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._handle_ui(kind, payload)
                except Exception:  # noqa: BLE001 - 单个 UI 任务失败不能拖垮主循环
                    log.exception("UI 任务执行失败")
                if self._closing:
                    return
        finally:
            if not self._closing:
                self.root.after(150, self._poll_ui)

    def _handle_ui(self, kind: str, payload) -> None:
        if kind == "notify":
            title, message = payload
            self._notify_now(title, message)
        elif kind == "call":
            payload()
        elif kind == "refresh_menu":
            self._rebuild_menu()

    def _notify_now(self, title: str, message: str) -> None:
        icon = self.icon
        if icon is None or self._closing:
            return
        try:
            icon.notify(str(message)[:500], str(title))
        except Exception:  # noqa: BLE001 - 通知失败不影响主流程
            log.warning("托盘气泡通知失败", exc_info=True)

    # ---- 手动发送 ----
    def _send_test_message(self) -> None:
        if self.sender is None:
            self._notify_now("提示", "当前不是发送端模式")
            return
        self.sender.send_test()

    def _send_custom(self, text: str) -> None:
        if self.sender is None:
            self._notify_now("提示", "当前不是发送端模式")
            return
        self.sender.send_manual(text)

    def _add_custom_message(self) -> None:
        text = simpledialog.askstring("新增消息", "请输入自定义消息（最多 10 个字）：", parent=self.root)
        if not text or not text.strip():
            return
        text = text.strip()
        if len(text) > 10:
            messagebox.showwarning("提示", "消息长度不能超过 10 个字！", parent=self.root)
            return
        messages = self.config["custom_messages"]
        if text in messages:
            messagebox.showinfo("提示", "已存在相同的自定义消息。", parent=self.root)
            return
        if len(messages) >= 30:
            messagebox.showwarning("提示", "自定义消息最多 30 条，请先删除一些。", parent=self.root)
            return
        messages.append(text)
        save_config(self.config_path, self.config)
        self._rebuild_menu()

    def _send_custom_message_by_text(self, text: str) -> None:
        self._send_custom(text)

    # ---- 设置对话框 ----
    def _form_dialog(self, title: str, fields: list[dict], on_save, hint: str = "") -> None:
        top = tk.Toplevel(self.root)
        top.title(title)
        top.resizable(False, False)
        top.attributes("-topmost", True)
        frame = tk.Frame(top, padx=14, pady=12)
        frame.pack(fill="both", expand=True)
        variables: dict[str, tuple] = {}
        for row, field in enumerate(fields):
            tk.Label(frame, text=field["label"], anchor="e").grid(
                row=row, column=0, sticky="e", padx=(0, 10), pady=4
            )
            if field.get("kind") == "bool":
                var = tk.BooleanVar(value=bool(field["value"]))
                widget = tk.Checkbutton(frame, variable=var)
            elif field.get("kind") == "dir":
                var = tk.StringVar(value=str(field["value"]))
                holder = tk.Frame(frame)
                entry = tk.Entry(holder, textvariable=var, width=46)
                entry.pack(side="left")

                def pick_dir(v=var) -> None:
                    chosen = filedialog.askdirectory(parent=top, initialdir=v.get() or None)
                    if chosen:
                        v.set(chosen)

                tk.Button(holder, text="浏览…", command=pick_dir).pack(side="left", padx=(6, 0))
                widget = holder
            else:
                var = tk.StringVar(value=str(field["value"]))
                widget = tk.Entry(frame, textvariable=var, width=56)
            widget.grid(row=row, column=1, sticky="w", pady=4)
            variables[field["key"]] = (var, field.get("kind", "str"), field["label"])

        if hint:
            tk.Label(frame, text=hint, fg="#666666", justify="left", wraplength=520).grid(
                row=len(fields), column=0, columnspan=2, sticky="w", pady=(8, 0)
            )

        def confirm() -> None:
            values: dict = {}
            for key, (var, kind, label) in variables.items():
                if kind == "bool":
                    values[key] = bool(var.get())
                elif kind == "int":
                    try:
                        values[key] = int(str(var.get()).strip())
                    except ValueError:
                        messagebox.showwarning("输入有误", f"「{label}」需要填写整数。", parent=top)
                        return
                else:
                    values[key] = str(var.get()).strip()
            top.destroy()
            on_save(values)

        buttons = tk.Frame(top, padx=14, pady=10)
        buttons.pack(fill="x")
        tk.Button(buttons, text="保存", width=10, command=confirm).pack(side="right", padx=(8, 0))
        tk.Button(buttons, text="取消", width=10, command=top.destroy).pack(side="right")
        top.lift()
        top.focus_force()

    def _open_sender_settings(self) -> None:
        sender = self.config["sender"]
        fields = [
            {"key": "jar_keyword", "label": "jar 关键字", "value": sender["jar_keyword"]},
            {"key": "log_dir", "label": "日志目录", "value": sender["log_dir"], "kind": "dir"},
            {"key": "log_file_pattern", "label": "日志文件名规则", "value": sender["log_file_pattern"]},
            {"key": "log_keyword", "label": "日志关键字", "value": sender["log_keyword"]},
            {"key": "probe_host", "label": "端口探测地址", "value": sender["probe_host"]},
            {"key": "probe_port", "label": "端口探测端口", "value": sender["probe_port"], "kind": "int"},
            {"key": "message", "label": "启动提醒模板", "value": sender["message"]},
            {"key": "timeout_message", "label": "超时提醒模板", "value": sender["timeout_message"]},
            {"key": "down_message", "label": "掉线提醒模板", "value": sender["down_message"]},
            {"key": "restart_message", "label": "重启提醒模板", "value": sender["restart_message"]},
            {"key": "timeout_seconds", "label": "启动超时（秒）", "value": sender["timeout_seconds"], "kind": "int"},
            {"key": "notify_on_timeout", "label": "启动超时提醒", "value": sender["notify_on_timeout"], "kind": "bool"},
            {"key": "notify_on_down", "label": "掉线提醒", "value": sender["notify_on_down"], "kind": "bool"},
            {"key": "notify_on_restart", "label": "重启提醒", "value": sender["notify_on_restart"], "kind": "bool"},
        ]
        hint = (
            "日志目录：监控目录中日期最新、同日序号最大的 info-YYYY-MM-DD.N.log（每 10 秒检查一次），"
            "出现关键字即判定启动；目录留空或暂无文件时回退端口探测。\n"
            "占位符：{host} 主机名  {ip} 本机IP  {app} 应用名  {event} 事件  {time} 时间  {timeout} 超时秒数"
        )

        def save(values: dict) -> None:
            sender.update(
                {
                    "jar_keyword": values["jar_keyword"],
                    "log_dir": values["log_dir"],
                    "log_file_pattern": values["log_file_pattern"] or "info-*.log",
                    "log_keyword": values["log_keyword"],
                    "probe_host": values["probe_host"] or "127.0.0.1",
                    "probe_port": values["probe_port"],
                    "message": values["message"],
                    "timeout_message": values["timeout_message"],
                    "down_message": values["down_message"],
                    "restart_message": values["restart_message"],
                    "timeout_seconds": values["timeout_seconds"],
                    "notify_on_timeout": values["notify_on_timeout"],
                    "notify_on_down": values["notify_on_down"],
                    "notify_on_restart": values["notify_on_restart"],
                }
            )
            self._apply_config(normalize_config(self.config))
            self._restart_sender()
            self._rebuild_menu()
            self._notify_now("设置已保存", "发送端参数已更新，监控已重新开始")

        self._form_dialog("发送端设置", fields, save, hint)

    def _open_listener_settings(self) -> None:
        listener = self.config["listener"]
        fields = [
            {"key": "bind_ip", "label": "监听 IP", "value": listener["bind_ip"]},
            {"key": "port", "label": "监听端口", "value": listener["port"], "kind": "int"},
            {"key": "history_size", "label": "历史消息条数", "value": listener["history_size"], "kind": "int"},
        ]
        hint = "监听 IP 填 auto 自动取本机局域网 IP；填 0.0.0.0 监听全部网卡。"

        def save(values: dict) -> None:
            listener.update(
                {
                    "bind_ip": values["bind_ip"] or "auto",
                    "port": values["port"],
                    "history_size": values["history_size"],
                }
            )
            self._apply_config(normalize_config(self.config))
            self._restart_listener()
            self._rebuild_menu()
            self._notify_now("设置已保存", "监听端参数已更新，监听已重新开始")

        self._form_dialog("监听端设置", fields, save, hint)

    def _apply_config(self, new_config: dict) -> None:
        """原地更新配置 dict，保持服务持有的引用有效。"""
        self.config.clear()
        self.config.update(new_config)
        save_config(self.config_path, self.config)

    def _restart_sender(self) -> None:
        with self._lock:
            if self.sender is not None:
                self.sender.stop()
                self.sender = None
            if self.config["mode"] == "sender":
                self.sender = SenderService(self.config, self._service_notify)
                self.sender.start()

    def _restart_listener(self) -> None:
        with self._lock:
            if self.listener is not None:
                self.listener.stop()
                self.listener = None
            if self.config["mode"] == "listener":
                self.listener = ListenerService(self.config, self._service_notify, self.history)
                self.listener.start()

    # ---- 目标 IP 管理 ----
    def _open_targets(self) -> None:
        if self._targets_win is not None and self._targets_win.winfo_exists():
            self._targets_win.lift()
            self._targets_win.focus_force()
            return
        top = tk.Toplevel(self.root)
        self._targets_win = top
        top.title("目标 IP 管理")
        top.attributes("-topmost", True)
        top.resizable(False, False)

        listbox = tk.Listbox(top, width=36, height=9, activestyle="dotbox")
        listbox.grid(row=0, column=0, rowspan=5, padx=(12, 8), pady=12, sticky="nsew")

        def refresh() -> None:
            listbox.delete(0, "end")
            for target in self.config["sender"]["targets"]:
                mark = "[启用]" if target["enabled"] else "[停用]"
                listbox.insert("end", f"{mark} {target['ip']}:{target['port']}")

        def selected_index():
            selection = listbox.curselection()
            return selection[0] if selection else None

        def after_change() -> None:
            self._apply_config(normalize_config(self.config))
            refresh()
            self._rebuild_menu()

        def add_target() -> None:
            target = self._ask_target(None)
            if target:
                self.config["sender"]["targets"].append(target)
                after_change()

        def edit_target() -> None:
            index = selected_index()
            if index is None:
                messagebox.showinfo("提示", "请先选中一个目标。", parent=top)
                return
            target = self._ask_target(self.config["sender"]["targets"][index])
            if target:
                self.config["sender"]["targets"][index] = target
                after_change()

        def toggle_target() -> None:
            index = selected_index()
            if index is None:
                messagebox.showinfo("提示", "请先选中一个目标。", parent=top)
                return
            target = self.config["sender"]["targets"][index]
            target["enabled"] = not target["enabled"]
            after_change()

        def delete_target() -> None:
            index = selected_index()
            if index is None:
                messagebox.showinfo("提示", "请先选中一个目标。", parent=top)
                return
            target = self.config["sender"]["targets"][index]
            if not messagebox.askyesno("确认", f"删除目标 {target['ip']}:{target['port']}？", parent=top):
                return
            del self.config["sender"]["targets"][index]
            after_change()

        buttons = [
            ("添加", add_target),
            ("编辑", edit_target),
            ("启用/停用", toggle_target),
            ("删除", delete_target),
            ("关闭", top.destroy),
        ]
        for row, (text, command) in enumerate(buttons):
            tk.Button(top, text=text, width=12, command=command).grid(
                row=row, column=1, padx=(0, 12), pady=(12 if row == 0 else 2, 2), sticky="ew"
            )
        refresh()
        top.lift()
        top.focus_force()

    def _ask_target(self, initial: dict | None) -> dict | None:
        top = tk.Toplevel(self.root)
        top.title("目标 IP")
        top.resizable(False, False)
        top.attributes("-topmost", True)
        initial = initial or {"ip": "127.0.0.1", "port": 17777, "enabled": True}
        ip_var = tk.StringVar(value=initial["ip"])
        port_var = tk.StringVar(value=str(initial["port"]))
        enabled_var = tk.BooleanVar(value=bool(initial["enabled"]))
        frame = tk.Frame(top, padx=14, pady=12)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="IP 地址").grid(row=0, column=0, sticky="e", padx=(0, 10), pady=4)
        tk.Entry(frame, textvariable=ip_var, width=28).grid(row=0, column=1, sticky="w", pady=4)
        tk.Label(frame, text="端口").grid(row=1, column=0, sticky="e", padx=(0, 10), pady=4)
        tk.Entry(frame, textvariable=port_var, width=28).grid(row=1, column=1, sticky="w", pady=4)
        tk.Checkbutton(frame, text="启用", variable=enabled_var).grid(
            row=2, column=1, sticky="w", pady=4
        )
        result: dict = {}

        def confirm() -> None:
            ip = ip_var.get().strip()
            if not _is_ipv4(ip):
                messagebox.showwarning("输入有误", "请填写合法的 IPv4 地址。", parent=top)
                return
            try:
                port = int(port_var.get().strip())
            except ValueError:
                messagebox.showwarning("输入有误", "端口必须是整数。", parent=top)
                return
            if not 1 <= port <= 65535:
                messagebox.showwarning("输入有误", "端口范围 1-65535。", parent=top)
                return
            result.update({"ip": ip, "port": port, "enabled": bool(enabled_var.get())})
            top.destroy()

        buttons = tk.Frame(top, padx=14, pady=10)
        buttons.pack(fill="x")
        tk.Button(buttons, text="确定", width=10, command=confirm).pack(side="right", padx=(8, 0))
        tk.Button(buttons, text="取消", width=10, command=top.destroy).pack(side="right")
        top.lift()
        top.focus_force()
        self.root.wait_window(top)
        return result or None

    # ---- 自定义消息管理 ----
    def _open_custom_messages(self) -> None:
        if self._custom_win is not None and self._custom_win.winfo_exists():
            self._custom_win.lift()
            self._custom_win.focus_force()
            return
        top = tk.Toplevel(self.root)
        self._custom_win = top
        top.title("自定义消息管理")
        top.attributes("-topmost", True)
        top.resizable(False, False)
        listbox = tk.Listbox(top, width=34, height=8, activestyle="dotbox")
        listbox.grid(row=0, column=0, rowspan=4, padx=(12, 8), pady=12, sticky="nsew")
        hint = tk.Label(top, text="每条最多 10 个字，点击菜单直接发送。", fg="#666666")
        hint.grid(row=4, column=0, columnspan=2, padx=12, pady=(0, 10), sticky="w")

        def refresh() -> None:
            listbox.delete(0, "end")
            for text in self.config["custom_messages"]:
                listbox.insert("end", text)

        def add_message() -> None:
            text = simpledialog.askstring("新增消息", "请输入自定义消息（最多 10 个字）：", parent=top)
            if not text or not text.strip():
                return
            text = text.strip()
            if len(text) > 10:
                messagebox.showwarning("提示", "消息长度不能超过 10 个字！", parent=top)
                return
            if text in self.config["custom_messages"]:
                messagebox.showinfo("提示", "已存在相同的自定义消息。", parent=top)
                return
            if len(self.config["custom_messages"]) >= 30:
                messagebox.showwarning("提示", "自定义消息最多 30 条。", parent=top)
                return
            self.config["custom_messages"].append(text)
            save_config(self.config_path, self.config)
            refresh()
            self._rebuild_menu()

        def delete_message() -> None:
            selection = listbox.curselection()
            if not selection:
                messagebox.showinfo("提示", "请先选中一条消息。", parent=top)
                return
            del self.config["custom_messages"][selection[0]]
            save_config(self.config_path, self.config)
            refresh()
            self._rebuild_menu()

        tk.Button(top, text="新增", width=12, command=add_message).grid(
            row=0, column=1, padx=(0, 12), pady=(12, 2), sticky="ew"
        )
        tk.Button(top, text="删除", width=12, command=delete_message).grid(
            row=1, column=1, padx=(0, 12), pady=2, sticky="ew"
        )
        tk.Button(top, text="关闭", width=12, command=top.destroy).grid(
            row=2, column=1, padx=(0, 12), pady=2, sticky="ew"
        )
        refresh()
        top.lift()
        top.focus_force()

    # ---- 历史 / 状态 / 文件 ----
    def _open_history(self) -> None:
        if self._history_win is not None and self._history_win.winfo_exists():
            self._history_win.lift()
            self._history_win.focus_force()
            return
        top = tk.Toplevel(self.root)
        self._history_win = top
        top.title("最近消息")
        top.geometry("760x360")
        top.attributes("-topmost", True)
        limit = int(self.config["listener"].get("history_size", 100))
        columns = ("time", "ip", "kind", "text")
        bar = tk.Frame(top)
        bar.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        content = tk.Frame(top)
        content.pack(side="top", fill="both", expand=True)
        tree = ttk.Treeview(content, columns=columns, show="headings", height=14)
        headings = {"time": "时间", "ip": "来源 IP", "kind": "类型", "text": "内容"}
        widths = {"time": 150, "ip": 110, "kind": 90, "text": 380}
        for name in columns:
            tree.heading(name, text=headings[name])
            tree.column(name, width=widths[name], anchor="w")
        scrollbar = ttk.Scrollbar(content, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", pady=10, padx=(0, 10))

        def refresh() -> None:
            tree.delete(*tree.get_children())
            for item in reversed(self.history.snapshot()[-limit:]):
                tree.insert("", "end", values=(item["time"], item["ip"], item["kind"], item["text"]))

        def clear_history() -> None:
            if messagebox.askyesno("确认", "清空全部历史消息？", parent=top):
                self.history.clear()
                refresh()

        bar = tk.Frame(top)
        tk.Button(bar, text="刷新", width=10, command=refresh).pack(side="left")
        tk.Button(bar, text="清空", width=10, command=clear_history).pack(side="left", padx=(8, 0))
        tk.Button(bar, text="关闭", width=10, command=top.destroy).pack(side="right")
        refresh()
        top.lift()
        top.focus_force()

    def _open_status(self) -> None:
        lines: list[str] = [f"模式：{'发送端' if self.config['mode'] == 'sender' else '监听端'}"]
        if self.config["mode"] == "sender" and self.sender is not None:
            sender = self.sender
            with sender._status_lock:
                status = dict(sender.status)
            cfg = self.config["sender"]
            lines.extend(
                [
                    f"jar 关键字：{cfg['jar_keyword'] or '（任意 java 进程）'}",
                    f"启动判定：{status['judge']}",
                    f"匹配进程：{status['matched']} 个（已启动 {status['started']} 个）",
                    f"进程详情：{status['apps']}",
                    "目标 IP：" + (
                        "、".join(
                            f"{t['ip']}:{t['port']}{'' if t['enabled'] else '(停用)'}"
                            for t in cfg["targets"]
                        )
                        or "（无）"
                    ),
                    f"最近事件：{status['last_event']}",
                    f"最近发送：{status['last_send']}",
                ]
            )
        elif self.config["mode"] == "listener" and self.listener is not None:
            listener = self.listener
            lines.extend(
                [
                    f"监听地址：{listener.status.get('addr', '-')}",
                    f"监听状态：{listener.status.get('state', '-')}",
                    f"历史消息：{self.history.count()} 条",
                ]
            )
        lines.extend(
            [
                f"配置文件：{self.config_path}",
                f"日志文件：{self.log_path}",
                f"本机 IP：{get_local_ip()}",
            ]
        )
        messagebox.showinfo("运行状态", "\n".join(lines), parent=self.root)

    def _open_config_file(self) -> None:
        try:
            if not self.config_path.exists():
                save_config(self.config_path, self.config)
            os.startfile(str(self.config_path))  # type: ignore[attr-defined]
        except OSError as exc:
            messagebox.showwarning("提示", f"无法打开配置文件：{exc}", parent=self.root)

    def _open_log_file(self) -> None:
        try:
            if not self.log_path.exists():
                self.log_path.touch()
            os.startfile(str(self.log_path))  # type: ignore[attr-defined]
        except OSError as exc:
            messagebox.showwarning("提示", f"无法打开日志文件：{exc}", parent=self.root)


# ---------------------------------------------------------------------------
# 自测（不需要托盘 / 桌面，覆盖核心逻辑）
# ---------------------------------------------------------------------------
def _wait_for(condition, timeout: float = 5.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if condition():
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(interval)
    return False


def _test_config_roundtrip(tmp: Path) -> None:
    path = tmp / "config.json"
    cfg = load_config(path)
    assert path.exists(), "首次加载应生成默认 config.json"
    cfg["mode"] = "listener"
    cfg["sender"]["targets"] = [{"ip": "192.168.1.9", "port": 18000, "enabled": False}]
    cfg["sender"]["probe_port"] = 9000
    assert save_config(path, cfg)
    again = load_config(path)
    assert again["mode"] == "listener"
    assert again["sender"]["targets"] == [{"ip": "192.168.1.9", "port": 18000, "enabled": False}]
    assert again["sender"]["probe_port"] == 9000

    # 损坏的配置：不覆盖原文件，回退默认值
    path.write_text("{not-json", encoding="utf-8")
    fallback = load_config(path)
    assert fallback["mode"] == "sender"
    assert path.read_text(encoding="utf-8") == "{not-json"

    # 超长自定义消息截断到 10 字
    normalized = normalize_config({"custom_messages": ["1234567890123", "短消息"]})
    assert normalized["custom_messages"] == ["1234567890", "短消息"]

    # 记事本等编辑器可能带 UTF-8 BOM，不能因此回退默认配置
    save_config(path, cfg)
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    bom_cfg = load_config(path)
    assert bom_cfg["mode"] == "listener", "带 BOM 的配置也应正常读取"
    assert bom_cfg["sender"]["probe_port"] == 9000


def _test_message_protocol(tmp: Path) -> None:
    payload = build_payload("start", "hello", "agentMini.jar")
    assert payload["kind"] == "start" and payload["id"], "消息必须带 id 用于去重"
    parsed = parse_message(json.dumps(payload, ensure_ascii=False))
    assert parsed["text"] == "hello" and parsed["id"] == payload["id"]
    legacy = parse_message("服务重启中...")
    assert legacy["text"] == "服务重启中..." and legacy["kind"] == "manual"


def _make_listener_cfg() -> dict:
    cfg = default_config()
    cfg["listener"]["bind_ip"] = "127.0.0.1"
    cfg["listener"]["port"] = 0  # 自测用随机端口
    return cfg


def _start_test_listener(cfg: dict, history: MessageHistory) -> ListenerService:
    listener = ListenerService(cfg, notify=None, history=history)
    listener.start()
    assert _wait_for(lambda: listener.bound is not None, 5.0), "监听端未在 5 秒内绑定端口"
    return listener


def _test_udp_multi_target(tmp: Path) -> None:
    cfg = _make_listener_cfg()
    history_a = MessageHistory()
    history_b = MessageHistory()
    listener_a = _start_test_listener(cfg, history_a)
    listener_b = _start_test_listener(cfg, history_b)
    try:
        targets = [
            {"ip": "127.0.0.1", "port": listener_a.port},
            {"ip": "127.0.0.1", "port": listener_b.port},
        ]
        errors = send_udp(targets, build_payload("test", "多目标测试"), retries=3, retry_interval=0.05)
        assert not errors, f"发送失败：{errors}"
        assert _wait_for(lambda: history_a.count() == 1, 3.0), "目标 A 未收到消息"
        assert _wait_for(lambda: history_b.count() == 1, 3.0), "目标 B 未收到消息"
        # 3 次重发 + 接收端去重 => 每个目标只有 1 条
        time.sleep(0.4)
        assert history_a.count() == 1 and history_b.count() == 1, "重发未正确去重"
        assert history_a.snapshot()[0]["text"] == "多目标测试"
    finally:
        listener_a.stop()
        listener_b.stop()


def _test_udp_blind_retries(tmp: Path) -> None:
    """盲发重试：即使 sendto 不报错，每个目标也应收到 send_retries 个报文。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(1.5)
    port = int(sock.getsockname()[1])
    try:
        payload = build_payload("test", "盲发重试")
        errors = send_udp(
            [{"ip": "127.0.0.1", "port": port}],
            payload,
            retries=3,
            retry_interval=0.05,
        )
        assert not errors, f"盲发重试不应报错：{errors}"
        received: list[bytes] = []
        deadline = time.time() + 2.0
        while len(received) < 3 and time.time() < deadline:
            try:
                received.append(sock.recvfrom(65535)[0])
            except socket.timeout:
                break
        assert len(received) == 3, f"盲发重试次数不符：收到 {len(received)} 个"
        assert len(set(received)) == 1, "重发的报文内容应完全一致（同一消息 id）"
    finally:
        sock.close()


def _test_log_tail(tmp: Path) -> None:
    path = tmp / "app.log"
    user_keyword = "wx agentMini access_token"
    path.write_text(f"old run\n{user_keyword}\n", encoding="utf-8")
    # 默认跳过历史：预埋关键字不应命中
    tail = LogTail(str(path), user_keyword)
    assert not tail.check(), "历史关键字不应判定启动"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("booting...\n")
    assert not tail.check(), "没有关键字的新内容不应命中"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(user_keyword + "\n")
    assert tail.check(), "追加关键字后应命中"
    # 日志被清空/轮转：偏移回 0，重新读新内容
    path.write_text("fresh without keyword\n", encoding="utf-8")
    assert not tail.check(), "日志截断后不应残留旧命中"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(user_keyword + "\n")
    assert tail.check(), "日志截断后追加关键字应重新命中"
    # skip_existing=False：允许回看历史（仅测试/兼容场景）
    assert LogTail(str(path), user_keyword, skip_existing=False).check(), "允许回看时应扫到历史关键字"
    # 关键字跨分片出现也要识别
    chunk_path = tmp / "chunk.log"
    chunk_path.write_text("", encoding="utf-8")
    small = LogTail(str(chunk_path), "READY_MARK", skip_existing=False, chunk_bytes=4)
    with open(chunk_path, "a", encoding="utf-8") as fh:
        fh.write("xxREADY_MARKxx")
    assert small.check(), "关键字跨分片时不应漏判"


def _test_tcp_probe(tmp: Path) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert tcp_port_open("127.0.0.1", port), "监听中的端口应探测为开启"
    finally:
        server.close()
    assert _wait_for(lambda: not tcp_port_open("127.0.0.1", port, 0.3), 3.0), "关闭后的端口应探测为关闭"


def _build_sender_cfg(log_dir: str, probe_port: int, target_port: int, **overrides) -> dict:
    cfg = default_config()
    cfg["sender"].update(
        {
            "jar_keyword": "agentMini",
            "log_dir": log_dir,
            "log_file_pattern": "info-*.log",
            "log_keyword": "wx agentMini js_ticket",
            "probe_host": "127.0.0.1",
            "probe_port": probe_port,
            "targets": [{"ip": "127.0.0.1", "port": target_port, "enabled": True}],
            "timeout_seconds": 30,
            "probe_interval": 0.5,
            "log_check_interval": 0.5,
            "send_retries": 1,
            "retry_interval_ms": 50,
            "message": "{app} {event}",
            "timeout_message": "{app} {event}",
            "down_message": "{app} {event}",
            "restart_message": "{app} {event}",
        }
    )
    cfg["sender"].update(overrides)
    return cfg


def _test_log_file_selection(tmp: Path) -> None:
    log_dir = tmp / "selection_logs"
    log_dir.mkdir(exist_ok=True)
    for name in (
        "info-2026-10-30.2.log",
        "info-2026-10-30.10.log",
        "info-2026-10-29.9.log",
        "other-2026-10-31.log",
        "info-bad.log",
    ):
        (log_dir / name).write_text("x", encoding="utf-8")
    latest = find_latest_log_file(str(log_dir))
    assert latest and os.path.basename(latest) == "info-2026-10-30.10.log", f"未选中最新日志：{latest}"
    assert parse_log_file_name("info-2026-10-30.10.log") == (2026, 10, 30, 10)
    assert parse_log_file_name("info-2026-10-30.2.log") == (2026, 10, 30, 2)
    assert parse_log_file_name("info-2026-10-30.log") == (2026, 10, 30, 0)
    assert parse_log_file_name("info-2026-13-40.log") is None
    assert parse_log_file_name("info-bad.log") is None
    assert find_latest_log_file(str(tmp / "no_such_dir")) is None
    assert find_latest_log_file("") is None


def _kinds(history: MessageHistory) -> list[str]:
    return [item.get("kind_raw", item.get("kind")) for item in history.snapshot()]


def _test_sender_log_pipeline(tmp: Path) -> None:
    """回归：日志里预埋上次启动的关键字，绝不能秒判“已启动/已重启”。"""
    keyword = "wx agentMini js_ticket"
    log_dir = tmp / "pipeline_logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "info-2026-10-30.0.log"
    log_file.write_text(f"history boot\n{keyword}\n", encoding="utf-8")
    cfg_listener = _make_listener_cfg()
    history = MessageHistory()
    listener = _start_test_listener(cfg_listener, history)
    procs: list[tuple[int, str]] = []
    sender = SenderService(
        _build_sender_cfg(str(log_dir), 1, listener.port),
        notify=None,
        process_lister=lambda kw: list(procs),
    )
    sender.start()
    try:
        assert _wait_for(lambda: sender.status["judge"] != "-", 3.0), "发送端首轮未执行"
        # 新进程出现：文件里残留的旧关键字必须不算数
        procs.append((424242, "java -jar D:/fake/agentMini.jar"))
        time.sleep(2.0)
        assert "start" not in _kinds(history), f"历史关键字被误判为启动：{_kinds(history)}"

        # 追加本次启动的新关键字 -> 判定启动
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(keyword + "\n")
        assert _wait_for(lambda: "start" in _kinds(history), 6.0), f"新关键字未触发启动提醒：{_kinds(history)}"

        # 进程掉线
        procs.clear()
        assert _wait_for(lambda: "down" in _kinds(history), 6.0), f"掉线提醒未触发：{_kinds(history)}"

        # 进程重新出现：旧关键字仍然不能触发重启，必须等新关键字
        procs.append((424242, "java -jar D:/fake/agentMini.jar"))
        time.sleep(2.0)
        assert "restart" not in _kinds(history), f"旧关键字被误判为重启：{_kinds(history)}"
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(keyword + "\n")
        assert _wait_for(lambda: "restart" in _kinds(history), 6.0), f"新关键字未触发重启提醒：{_kinds(history)}"
    finally:
        sender.stop()
        listener.stop()

    # 服务启动时 jar 已在运行：不补发“已启动”，但掉线仍要提醒
    history2 = MessageHistory()
    listener2 = _start_test_listener(cfg_listener, history2)
    procs2: list[tuple[int, str]] = [(434343, "java -jar D:/fake/agentMini.jar")]
    sender2 = SenderService(
        _build_sender_cfg(str(log_dir), 1, listener2.port),
        notify=None,
        process_lister=lambda kw: list(procs2),
    )
    sender2.start()
    try:
        time.sleep(2.0)
        assert _kinds(history2) == [], f"启动时已在运行的 jar 不应补发提醒：{_kinds(history2)}"
        procs2.clear()
        assert _wait_for(lambda: "down" in _kinds(history2), 6.0), f"启动时已在运行的 jar 掉线未提醒：{_kinds(history2)}"
    finally:
        sender2.stop()
        listener2.stop()


def _test_sender_timeout(tmp: Path) -> None:
    log_dir = tmp / "timeout_logs"
    log_dir.mkdir(exist_ok=True)
    (log_dir / "info-2026-10-30.0.log").write_text("still booting\n", encoding="utf-8")
    cfg_listener = _make_listener_cfg()
    history = MessageHistory()
    listener = _start_test_listener(cfg_listener, history)
    procs: list[tuple[int, str]] = []
    sender = SenderService(
        _build_sender_cfg(
            str(log_dir), 1, listener.port, timeout_seconds=1, probe_interval=0.5
        ),
        notify=None,
        process_lister=lambda kw: list(procs),
    )
    sender.start()
    try:
        # 等首轮跑过再让进程出现，确保不是“启动时已在运行”的场景
        assert _wait_for(lambda: sender.status["judge"] != "-", 3.0), "发送端首轮未执行"
        procs.append((525252, "java -jar D:/fake/agentMini.jar"))
        assert _wait_for(lambda: "timeout" in _kinds(history), 8.0), f"超时提醒未触发：{_kinds(history)}"
        # 超时只提醒一次
        time.sleep(1.2)
        assert _kinds(history).count("timeout") == 1, "超时提醒重复发送"
    finally:
        sender.stop()
        listener.stop()


def _test_sender_port_fallback(tmp: Path) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    probe_port = server.getsockname()[1]
    cfg_listener = _make_listener_cfg()
    history = MessageHistory()
    listener = _start_test_listener(cfg_listener, history)
    procs = [(626262, "java -jar D:/fake/agentMini.jar")]
    sender = SenderService(
        _build_sender_cfg("", probe_port, listener.port),
        notify=None,
        process_lister=lambda keyword: list(procs),
    )
    sender.start()
    try:
        assert _wait_for(lambda: "start" in _kinds(history), 6.0), f"端口回退未触发：{_kinds(history)}"
    finally:
        sender.stop()
        listener.stop()
        server.close()

    # 日志目录配置了但目录里没有匹配文件 -> 同样回退端口探测
    server2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server2.bind(("127.0.0.1", 0))
    server2.listen(1)
    probe_port2 = server2.getsockname()[1]
    empty_dir = tmp / "empty_logs"
    empty_dir.mkdir(exist_ok=True)
    history2 = MessageHistory()
    listener2 = _start_test_listener(cfg_listener, history2)
    sender2 = SenderService(
        _build_sender_cfg(str(empty_dir), probe_port2, listener2.port),
        notify=None,
        process_lister=lambda keyword: [(727272, "java -jar D:/fake/agentMini.jar")],
    )
    sender2.start()
    try:
        assert _wait_for(lambda: "start" in _kinds(history2), 6.0), f"日志缺失时端口回退未触发：{_kinds(history2)}"
    finally:
        sender2.stop()
        listener2.stop()
        server2.close()


def _test_sender_log_rotation(tmp: Path) -> None:
    """监控中新出现序号更大的日志文件：从头读到关键字即启动，旧文件追加不再生效。"""
    keyword = "wx agentMini js_ticket"
    log_dir = tmp / "rotation_logs"
    log_dir.mkdir(exist_ok=True)
    first = log_dir / "info-2026-10-30.0.log"
    first.write_text("booting\n", encoding="utf-8")
    cfg_listener = _make_listener_cfg()
    history = MessageHistory()
    listener = _start_test_listener(cfg_listener, history)
    procs: list[tuple[int, str]] = []
    sender = SenderService(
        _build_sender_cfg(str(log_dir), 1, listener.port),
        notify=None,
        process_lister=lambda kw: list(procs),
    )
    sender.start()
    try:
        assert _wait_for(lambda: sender.status["judge"] != "-", 3.0), "发送端首轮未执行"
        assert "start" not in _kinds(history), f"旧日志内容被误判：{_kinds(history)}"
        # 服务启动后再出现进程，才走正常“启动判定”路径
        procs.append((848484, "java -jar D:/fake/agentMini.jar"))
        time.sleep(1.0)
        assert "start" not in _kinds(history), f"未出现关键字就判定启动：{_kinds(history)}"

        # 新启动写出 .1：创建即含关键字，必须从头读到并判定启动（原子替换避免读到半截）
        second = log_dir / "info-2026-10-30.1.log"
        staging = log_dir / "info-2026-10-30.1.log.tmp"
        staging.write_text("boot\n" + keyword + "\n", encoding="utf-8")
        os.replace(staging, second)
        assert _wait_for(lambda: "start" in _kinds(history), 8.0), f"新日志文件未触发启动：{_kinds(history)}"
        assert sender._current_log_path.endswith("info-2026-10-30.1.log"), "未切换到新日志文件"

        # 切走后旧文件追加关键字：不应再有任何新提醒
        with open(first, "a", encoding="utf-8") as fh:
            fh.write(keyword + "\n")
        time.sleep(2.0)
        assert _kinds(history) == ["start"], f"旧日志文件仍被监控：{_kinds(history)}"
    finally:
        sender.stop()
        listener.stop()


def _test_log_check_throttle(tmp: Path) -> None:
    """日志检查按 log_check_interval 节流（默认 10 秒），不能跟着进程轮询每秒读。"""
    keyword = "wx agentMini js_ticket"
    log_dir = tmp / "throttle_logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "info-2026-10-30.0.log"
    log_file.write_text("booting\n", encoding="utf-8")
    cfg_listener = _make_listener_cfg()
    history = MessageHistory()
    listener = _start_test_listener(cfg_listener, history)
    procs: list[tuple[int, str]] = []
    sender = SenderService(
        _build_sender_cfg(str(log_dir), 1, listener.port, log_check_interval=10.0),
        notify=None,
        process_lister=lambda kw: list(procs),
    )
    try:
        sender._tick(now=1000.0)
        procs.append((959595, "java -jar D:/fake/agentMini.jar"))
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(keyword + "\n")
        sender._tick(now=1002.0)
        assert "start" not in _kinds(history), "不到 10 秒就重读了日志"
        sender._tick(now=1011.0)
        assert _wait_for(lambda: _kinds(history) == ["start"], 3.0), f"10 秒后未读到关键字：{_kinds(history)}"
    finally:
        sender.stop()
        listener.stop()


def _test_listener_rebind(tmp: Path) -> None:
    cfg = _make_listener_cfg()
    cfg["listener"]["port"] = 0
    history = MessageHistory()
    first = _start_test_listener(cfg, history)
    port = first.port
    first.stop()
    cfg["listener"]["port"] = port  # 模式切换后允许立即重新绑定同一端口
    second = ListenerService(cfg, notify=None, history=MessageHistory())
    second.start()
    try:
        assert _wait_for(lambda: second.bound is not None, 5.0), "监听端无法重新绑定端口"
        assert second.port == port
    finally:
        second.stop()


def run_selftest() -> int:
    print(f"=== {APP_NAME} 自测 ===")
    failures: list[tuple[str, str]] = []
    tests = [
        ("配置读写 / 损坏回退", _test_config_roundtrip),
        ("消息协议兼容", _test_message_protocol),
        ("多目标 UDP 发送 + 重失去重", _test_udp_multi_target),
        ("UDP 盲发重试次数", _test_udp_blind_retries),
        ("日志增量关键字检测（跳过历史）", _test_log_tail),
        ("日志文件选择（日期最新/同日最大序号）", _test_log_file_selection),
        ("TCP 端口探测", _test_tcp_probe),
        ("发送端：日志关键字启动/掉线/重启", _test_sender_log_pipeline),
        ("发送端：启动超时提醒", _test_sender_timeout),
        ("发送端：端口回退（未配置/目录无文件）", _test_sender_port_fallback),
        ("发送端：日志文件滚动切换", _test_sender_log_rotation),
        ("发送端：日志检查 10 秒节流", _test_log_check_throttle),
        ("监听端停止后可重新绑定", _test_listener_rebind),
    ]
    with tempfile.TemporaryDirectory(prefix="lan_monitor_selftest_") as tmp_dir:
        tmp = Path(tmp_dir)
        for name, func in tests:
            started = time.time()
            try:
                func(tmp)
                print(f"[PASS] {name}（{time.time() - started:.2f}s）")
            except AssertionError as exc:
                failures.append((name, str(exc) or "断言失败"))
                print(f"[FAIL] {name}：{exc}")
            except Exception as exc:  # noqa: BLE001
                failures.append((name, repr(exc)))
                print(f"[FAIL] {name}：{exc!r}")
                traceback.print_exc()
    if failures:
        print(f"\n自测失败 {len(failures)} 项：")
        for name, reason in failures:
            print(f"  - {name}：{reason}")
        return 1
    print("\n全部自测通过。")
    return 0


# ---------------------------------------------------------------------------
# 日志与入口
# ---------------------------------------------------------------------------
def setup_logging(base_dir: Path | None, console_level: int = logging.INFO) -> None:
    log.setLevel(logging.DEBUG)
    for handler in list(log.handlers):
        log.removeHandler(handler)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")

    if sys.stderr is not None:
        console = logging.StreamHandler()
        console.setLevel(console_level)
        console.setFormatter(formatter)
        log.addHandler(console)

    if base_dir is not None:
        base_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            base_dir / LOG_FILE_NAME,
            maxBytes=512 * 1024,
            backupCount=2,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME}（Windows 托盘常驻）")
    parser.add_argument("--selftest", action="store_true", help="运行内置自测（不需要图形界面）")
    parser.add_argument("--smoke", type=int, default=0, metavar="SECONDS", help="启动后 N 秒自动退出，用于冒烟测试")
    args = parser.parse_args(argv)

    if args.selftest:
        setup_logging(None, console_level=logging.WARNING)
        return run_selftest()

    if MISSING_DEPS:
        print("缺少依赖：" + "、".join(sorted(set(MISSING_DEPS))))
        print("安装命令：pip install pystray pillow psutil")
        return 2

    base_dir = app_dir()
    setup_logging(base_dir)
    log.info("启动 %s，目录 %s", APP_NAME, base_dir)
    try:
        app = App(base_dir)
        return app.run(auto_exit=args.smoke)
    except Exception:  # noqa: BLE001 - 未捕获异常必须落日志
        log.exception("程序异常退出")
        return 1


if __name__ == "__main__":
    sys.exit(main())
