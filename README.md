# 致谢

| 项目 | 版本 | 许可 | 在这个工具里它负责什么 |
| --- | --- | --- | --- |
| [mitmproxy](https://mitmproxy.org/) | 12.2.3 | MIT（Aldo Cortesi 与 contributors） | 全部明文腿：`--mode local:<进程>`、addon 接口、flow 存储与 TLS 中间人。没有它就没有本项目 |
| [mitmproxy-rs / mitmproxy-windows](https://github.com/mitmproxy/mitmproxy-rs) | 0.12.11 | MIT | 提供 `windows-redirector.exe`，把"按进程抓包"接到内核驱动上 |
| [WinDivert](https://github.com/basil00/WinDivert) | 2.2.2 | LGPLv3 与 GPLv2 双许可| 内核驱动：在 IP 层按 PID 重定向报文。整套机制里唯一必须进内核的一环 |
| [pydivert](https://github.com/ffalcinelli/pydivert) | 2.1.0 | LGPLv3 | WinDivert 的 Python 绑定，mitmproxy 在 Windows 上声明的依赖 |
| [zstandard](https://github.com/indygreg/python-zstandard) / [zstd](https://github.com/facebook/zstd) | 0.25.0 / 格式由 Meta 维护 | BSD-3 / BSD-2 | `tools/dictgen.py` 训练与导入 zstd 字典，把协议帧压成可解码的形状 |
| [cryptography](https://cryptography.io/) | 48.0.1 | Apache-2.0 或 BSD-3 任选 | 自签本地 CA、证书指纹（归属判定）、出舱快照里的加盐截断哈希 |
| [Wireshark](https://www.wireshark.org/)（dumpcap / capinfos / tshark） | | GPLv2+ | 第二层证据：全接口链路层 pcap，以及 pcap 与明文层之间的漏抓对账 |
| [Npcap](https://npcap.com/) |  |  | dumpcap 在 Windows 上取包的驱动 |
| [Python](https://www.python.org/) | ≥ 3.9 | PSF | 运行时 |
| [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) | 正文取自 FSF | GPLv3 | 本仓库 `LICENSE` 文本 |
