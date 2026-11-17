# 贡献指南

感谢关注 lan-monitor！本项目是一个单文件 Python 工具，欢迎提交 Issue 和 Pull Request。

## 开发环境

1. Python 3.10+（在 3.12 实测）
2. 安装依赖：

   ```bat
   pip install -r requirements.txt
   ```

3. 运行程序：

   ```bat
   python lan_monitor.py
   ```

## 自测要求

提交前必须运行内置自测并确保全部通过（不需要桌面 / 托盘环境）：

```bat
python lan_monitor.py --selftest
```

涉及托盘界面的改动，再跑一次冒烟测试：

```bat
python lan_monitor.py --smoke 10
```

## 代码约定

- 全部逻辑保留在单文件 `lan_monitor.py` 中，自测用例与代码同文件，放在 `_test_*` 系列函数里。
- 兼容 Python 3.10+，使用类型注解；仅依赖标准库和 `psutil` / `pystray` / `Pillow`，**不要引入 numpy 等重型依赖**（打包体积会从 24MB 膨胀到 250MB）。
- 面向 Windows，通知走 pystray 自带的系统气泡，不引入 winotify / win10toast。
- 线程等待使用 `Event.wait`，不要忙等轮询。
- 用户可见文案保持中文。

## 提交 PR

1. Fork 仓库并新建特性分支。
2. 写清楚改动目的、测试方式与自测结果。
3. 确认 `--selftest` 全部通过。
4. 提交 PR，描述中关联相关 Issue（如有）。

## 报告问题

提 Issue 时请附上：Windows 版本、Python 版本（源码运行时）、复现步骤、`lan_monitor.log` 中相关片段（提交前注意脱敏内网 IP 与主机名）。
