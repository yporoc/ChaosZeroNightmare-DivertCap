# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""ncenv.py — 全仓唯一的路径/依赖/常量来源。

存在的理由：同类实现里同一个绝对路径被抄在多处，换一台机器就整体失效，
而且报错只说"文件不存在"，不说该装什么。这里集中做三件事：

  1. Python 与 mitmdump：仓库自带 .venv 优先，其次 NC_PYTHON 指的路径，最后系统 python。
  2. dumpcap/capinfos/tshark：NC_<NAME>_EXE -> PATH -> 少数通用安装目录。
  3. 常量只有一份（进程名、端口、CA 名称、闸值），别处一律 import 本模块。

本文件不得出现任何机器专属路径：那会让"能不能跑"取决于某一个人的桌面。
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

MIN_PY = (3, 9)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

STATE = ROOT / "state"
SAMPLES = ROOT / "catchedsample"
CA_DIR = ROOT / "ca"
DICT_DIR = ROOT / "dicts"

# ---------------- 目标与判据常量（唯一一份） ----------------
DEFAULT_PROCS = "ssr-stove-shield.exe,ucldr_ChaosZeroNightmare_GL_loader_x64.exe,STOVE.exe"
# 身份字段是从帧里现算的，不是查文档来的。换目标只改这一处：
# 登录子命令名 + 它携带世界/用户身份的键名。
AUTH_SUBCMD = "auth_with_stove"
GAME_PORTS = ("13701", "13001")
# 443 只属于备胎方案（hosts 指向本机 + reverse 模式），不是主链路前提，
# 所以不做成闸门；见 README「备胎方案」一节。
GUARD_PORTS = ("7891", "8083") + GAME_PORTS
MIN_FREE_GB = 5.0
CA_ORG = "netcatch"
# ⚠ 新 CN 不能是库里已存在的任何 CN 的**子串**。实测教训：CN 取 "capture CA" 时，
# preflight 用 Subject -like '*<CN>*' 查库，会把上一代 "acme-capture CA" 也判成命中 ——
# 名字改了，身份没改，闸门会拿别人的证书证明自己的证书在位。
CA_CN = "netcatch local capture CA"
# 粗筛：只用来判断"这张是不是同类工具自造的"，绝不据此删除。
# 真正的归属判"是不是我这张"走 my_ca_record() 里的本地指纹。
SELF_BUILT_PAT = r"O=mitmproxy|netcatch|untrusted-lab"
THROWAWAY_ORG = "untrusted-lab"
THROWAWAY_CN = "untrusted-lab CA (never installed)"
ADDON_VER = "net_catch_addon/2026-09-28"

# Wireshark 系工具的通用落点。只列公开发行的默认安装目录，不列任何个人目录。
_TOOL_SUBDIRS = (
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
)


def _exe(name):
    return name + ".exe" if os.name == "nt" else name


_CFG_FILE = ROOT / "netcatch.local.cfg"
_CFG = None


def local_cfg():
    """仓库内的本机覆盖文件 `netcatch.local.cfg`（KEY=VALUE，被 .gitignore 排除）。

    存在的理由：Wireshark 装在非默认目录是常态。让每个人在自己机器上写两行就够用，
    而不是把任何人的安装路径硬编进代码、或者要求他每次去设环境变量。
    认得这些键：DUMPCAP_EXE / CAPINFOS_EXE / TSHARK_EXE / DICT / VENV / PYTHON
    """
    global _CFG
    if _CFG is None:
        _CFG = {}
        try:
            for line in _CFG_FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                _CFG[k.strip().upper()] = v.strip().strip('"')
        except Exception:
            _CFG = {}
    return _CFG


def find_tool(name, extra_dirs=()):
    """返回 (路径或 None, 给人看的说明)。找不到绝不静默当成"没有这个功能"。"""
    env = os.environ.get("NC_%s_EXE" % name.upper())
    if not env:
        env = local_cfg().get(name.upper() + "_EXE")
    if env:
        p = Path(env)
        return (p, "") if p.exists() else (None, "配置指向的路径不存在：%s" % p)
    found = shutil.which(_exe(name))
    if found:
        return Path(found), ""
    for d in tuple(extra_dirs) + _TOOL_SUBDIRS:
        p = Path(d) / _exe(name)
        if p.exists():
            return p, ""
    return None, ("缺 %s。装 Wireshark（自带 dumpcap/capinfos/tshark），"
                  "或在 netcatch.local.cfg 写 %s_EXE=<可执行文件全路径>，"
                  "或设 NC_%s_EXE。" % (name, name.upper(), name.upper()))


def venv_dirs():
    """候选 Scripts 目录，按优先级。"""
    out = []
    env = os.environ.get("NC_VENV") or local_cfg().get("VENV")
    if env:
        out.append(Path(env) / "Scripts")
    for name in (".venv", "venv"):
        out.append(ROOT / name / "Scripts")
    return out


def resolve_python():
    """返回 (python 路径或 None, mitmdump 路径或 None, 说明)。"""
    env = os.environ.get("NC_PYTHON") or local_cfg().get("PYTHON")
    if env:
        p = Path(env)
        if p.exists():
            return p, p.parent / _exe("mitmdump"), ""
        return None, None, "配置指向的解释器不存在：%s" % env
    for d in venv_dirs():
        py = d / _exe("python")
        if py.exists():
            return py, d / _exe("mitmdump"), ""
    sys_py = shutil.which("python") or shutil.which("python3")
    if sys_py:
        p = Path(sys_py)
        return p, p.parent / _exe("mitmdump"), "用的是系统 python，mitmproxy 可能未安装"
    return None, None, ("没有可用的 Python。装 Python 3.9+ 后运行 00_run.bat 选 9（建 .venv 并装依赖），"
                        "或设 NC_PYTHON 指向已有虚拟环境的 python。")


def python_major_ok(python_path=None):
    return sys.version_info >= MIN_PY


def mitm_version(python_path):
    """现查，不读缓存。返回 (版本串, zstd 是否可用) 。"""
    if not python_path:
        return None, False
    code = ("import mitmproxy.version,zstandard;"
            "print(mitmproxy.version.VERSION);print('ZSTD',zstandard.__version__)")
    try:
        out = subprocess.run([str(python_path), "-c", code], capture_output=True, timeout=60)
        raw = out.stdout or b""
        lines = raw.decode("utf-8", "replace").split()
        if not lines or not lines[0][0].isdigit():
            return None, False
        return lines[0], "ZSTD" in raw.decode("utf-8", "replace")
    except Exception:
        return None, False


# ---------------- 字典 ----------------
def dict_path():
    """zstd 字典。仓库不提供任何第三方资产，默认落在仓库自己的 dicts\\ 下，由用户自备或用 dictgen.py 训练。"""
    env = os.environ.get("NC_DICT") or local_cfg().get("DICT")
    if env:
        return Path(env)
    d = DICT_DIR / "default.dict"
    return d


def dict_status():
    p = dict_path()
    ok = p.exists() and p.stat().st_size > 1000
    return ok, p


# ---------------- 归属与安全落盘 ----------------
def my_ca_record():
    """本机自己签的那张 CA 的指纹记录。归属判定的唯一真相，不靠名称。"""
    return STATE / "my_ca.txt"


def salt_file():
    return STATE / "salt.bin"


def local_salt():
    """脱敏用的本地随机盐。绝不进版本库，也绝不与快照一起外带。"""
    from ca_store import _ensure_dirs
    _ensure_dirs()
    f = salt_file()
    if not f.exists():
        f.write_bytes(os.urandom(16))
    return f.read_bytes()


def ensure_dirs():
    STATE.mkdir(parents=True, exist_ok=True)
    SAMPLES.mkdir(parents=True, exist_ok=True)
    DICT_DIR.mkdir(parents=True, exist_ok=True)


def utf8_stdout():
    """中文 Windows 上 print 会先崩在写之后，所以每个入口第一件事是它。"""
    if hasattr(sys.stdout, "buffer"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def decode_mixed(data):
    """Windows 控制台/命令输出：先 BOM 判定，再 cp936（中文系统默认码页），最后 utf-8。"""
    if not data:
        return ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in data[:40]:
        return data.decode("utf-16", "replace")
    for enc in ("cp936", "utf-8"):
        try:
            return data.decode(enc, "replace")
        except Exception:
            pass
    return data.decode("utf-8", "replace")


def run_py(argv, timeout=120):
    """跑我们自己起的 Python 子进程。这类子进程输出是 UTF-8（入口都调了 utf8_stdout），
    必须按 utf-8 解 —— 走 decode_mixed 会先试 cp936，把中文报表解成一屏乱码（实测发生过）。
    外部 Windows 命令（certutil/sc/netstat）正相反，得走 decode_mixed。"""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False, env=env)
    except Exception as e:
        return 99, repr(e)
    raw = (p.stdout or b"") + (p.stderr or b"")
    try:
        return p.returncode, raw.decode("utf-8")
    except Exception:
        return p.returncode, decode_mixed(raw)


def writer_alive(run):
    """写产物之前先现算：**这批是不是还有人在写/在读**。
    在被测的 run 上动文件会让下一次测试对着半改的目录出结论，那种结论不可用。
    返回 (busy, why)。判据全是现算，不读任何缓存状态。"""
    run = Path(run)
    reasons = []
    meta = run / "meta.json"
    try:
        import json as _json
        m = _json.loads(meta.read_text(encoding="utf-8")) if meta.exists() else {}
        if meta.exists() and not m.get("ended"):
            reasons.append("meta.json 没有 ended —— 这批可能还在采集中")
    except Exception as e:
        reasons.append("meta.json 读不动：%r" % (e,))
    try:
        p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                            "@(Get-Process mitmdump,dumpcap -ErrorAction SilentlyContinue).Count"],
                           capture_output=True, timeout=25)
        cnt = decode_mixed(p.stdout or b"").strip()
        if cnt.isdigit() and int(cnt) > 0:
            reasons.append("本机还有 %s 个采集进程在跑" % cnt)
    except Exception:
        pass
    return (bool(reasons), "; ".join(reasons) or "没有活着的写入者")


_PK_RE = re.compile(r"Number of packets:\s*([\d,]+(?:\.\d+)?)\s*([kKmMgG]?)")
_SI = {"": 1, "k": 1000, "K": 1000, "m": 1000000, "M": 1000000, "g": 1000000000, "G": 1000000000}


def parse_packet_count(out):
    """capinfos 的 "Number of packets: 20 k" 是**约数**（它按千分位缩写）。
    真实教训：只取前导整数会把 20,314 读成 20，于是"pcap 有包"这条闸在正常批次上判红。
    返回 (整数或 None, 原始那行文本) —— 原始行要跟着打印，缩写变了能立刻看见。"""
    m = _PK_RE.search(out or "")
    if not m:
        return None, ""
    num = float(m.group(1).replace(",", ""))
    return int(round(num * _SI[m.group(2)])), m.group(0).strip()


def pcap_packet_count(pcap):
    """(包数或 None, 说明串, 原始行)。None 表示"测不到"，调用方必须把测不到单独成档，
    不许折算成 0（那会把"没有 capinfos"误报成"抓了个空 pcap"）。"""
    p = Path(pcap)
    if not p.exists():
        return None, "pcap 不存在", ""
    ci, hint = find_tool("capinfos")
    if not ci:
        return None, hint, ""
    try:
        r = subprocess.run([str(ci), str(p)], capture_output=True, timeout=180)
    except Exception as e:
        return None, "capinfos 跑不动：%r" % (e,), ""
    out = decode_mixed(r.stdout or b"")
    n, raw = parse_packet_count(out)
    trunc = "capinfos 报文件被截断" if b"cut short" in (r.stderr or b"") else ""
    return n, (trunc or "ok"), raw
