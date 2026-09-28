# 致谢

这个工具几乎不含真正的"新发明"。它做的是把别人造好的东西按一个方向接起来：
让一个进程的网络流量落到本地代理里，再同时留下链路层与连接台账两份底账。
下面每一项都是它能在 Windows 上跑起来的原因，版本号就是 `requirements.txt` 里钉住的那些。

| 项目 | 版本 | 许可 | 在这个工具里它负责什么 |
| --- | --- | --- | --- |
| [mitmproxy](https://mitmproxy.org/) | 12.2.3 | MIT（Aldo Cortesi 与 contributors） | 全部明文腿：`--mode local:<进程>`、addon 接口、flow 存储与 TLS 中间人。没有它就没有本项目 |
| [mitmproxy-rs / mitmproxy-windows](https://github.com/mitmproxy/mitmproxy-rs) | 0.12.11 | MIT | 提供 `windows-redirector.exe`，把"按进程抓包"接到内核驱动上 |
| [WinDivert](https://github.com/basil00/WinDivert) | 2.2.2 | LGPLv3 与 GPLv2 双许可，本项目按 LGPLv3 那一档取用 | 内核驱动：在 IP 层按 PID 重定向报文。整套机制里唯一必须进内核的一环 |
| [pydivert](https://github.com/ffalcinelli/pydivert) | 2.1.0 | LGPLv3 | WinDivert 的 Python 绑定，mitmproxy 在 Windows 上声明的依赖 |
| [zstandard](https://github.com/indygreg/python-zstandard) / [zstd](https://github.com/facebook/zstd) | 0.25.0 / 格式由 Meta 维护 | BSD-3 / BSD-2 | `tools/dictgen.py` 训练与导入 zstd 字典，把协议帧压成可解码的形状 |
| [cryptography](https://cryptography.io/) | 48.0.1 | Apache-2.0 或 BSD-3 任选 | 自签本地 CA、证书指纹（归属判定）、出舱快照里的加盐截断哈希 |
| [Wireshark](https://www.wireshark.org/)（dumpcap / capinfos / tshark） | 用你机器上已装的 | GPLv2+ | 第二层证据：全接口链路层 pcap，以及 pcap 与明文层之间的漏抓对账 |
| [Npcap](https://npcap.com/) | 用你机器上已装的 | 免费版可自用但不得外部再分发（最多 5 台，OEM 版另谈） | dumpcap 在 Windows 上取包的驱动 |
| [Python](https://www.python.org/) | ≥ 3.9 | PSF | 运行时 |
| [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) | 正文取自 FSF | GPLv3 | 本仓库 `LICENSE` 的那份文本 |

两点说明，免得这份致谢被读成别的意思：

Wireshark 与 Npcap 都是**你自己机器上已经装好的程序**，本仓库不携带、不重分发它们的任何文件；
代码只是找到可执行文件的路径然后调用它，找不到就明确报缺什么（见 `tools/ncenv.py`）。
mitmproxy 自身还有一长串依赖，这里不逐一列出——它们的许可随 mitmproxy 一起过去。

最后是给人的一次道谢：这个项目在把脱敏边界从采集口挪到出舱口的路上返工过好几次，
每一次都是被自己的判据当场抓住的。判据之所以抓得住，是因为上面这些工具的源码与文档
都写得可以被读懂——一个能被人读到底的实现，才让"我错在哪"变成一件可以查证的事。
