# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
preflight.py — 开抓前的闸门。

  任何 RED ⇒ 退出码非 0 ⇒ catch.py 什么都不启动（判据器不能红着还退 0）。
  WARN ⇒ 只提示不拦：那是"这一层证据会缺席"，不是"你环境坏了"。
  --selftest ⇒ 给每条判据下毒，要求它登记的**每一条**都变红；再对端口匹配这类
                纯函数跑一组"会咬 + 不误伤"的对照。翻不了红的判据不算闸。

本文件不出现任何机器专属路径：全部走 ncenv。
"""
import argparse
import ctypes
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402
import sanitize  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = []


def _run(argv, timeout=90):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False)
    except Exception as e:
        return 99, repr(e)
    return p.returncode, ncenv.decode_mixed((p.stdout or b"") + (p.stderr or b""))


def _ps(script):
    return _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])


def check(name, ok, detail, level="RED"):
    RESULTS.append((name, bool(ok), detail, level))
    return bool(ok)


_PORT_TOKEN = re.compile(r":(\d+)")


def port_hit(line, port):
    """netstat 行里的端口是 ':<十进制>' 形状。按整数比对，不按子串。
    子串写法会把 :4435 当成 443 命中，让别人的 443x 开发服务器被误判成端口冲突。"""
    return any(m.group(1) == str(port) for m in _PORT_TOKEN.finditer(line or ""))


# ---------------- 各条判据 ----------------
def c_admin(poison=False):
    adm = bool(ctypes.windll.shell32.IsUserAnAdmin()) if hasattr(ctypes.windll, "shell32") else False
    if poison:
        adm = False
    check("管理员权限（--mode local 加载内核驱动需要）", adm, "IsUserAnAdmin=%s" % adm)


def c_tools(poison=False):
    py, mitmdump, hint = ncenv.resolve_python()
    if poison:
        py, mitmdump, hint = None, None, "(selftest 下毒)"
    if not mitmdump or not Path(mitmdump).exists():
        check("python/mitmdump 可用", False, hint or ("找不到 mitmdump：%s" % mitmdump))
        check("该 Python 里有 mitmproxy+zstandard", False, "未测：上一条没过，先跑 00_run.bat 选 9")
        return
    rc, out = _run([str(mitmdump), "--version"])
    check("python/mitmdump 可用", rc == 0, out.splitlines()[0] if out else "找不到 %s" % mitmdump)
    ver, has_zstd = ncenv.mitm_version(py)
    if poison:
        ver, has_zstd = None, False
    check("该 Python 里有 mitmproxy+zstandard", bool(ver) and has_zstd,
          "mitmproxy=%s zstandard=%s" % (ver, has_zstd) if ver else
          "缺依赖：跑 00_run.bat 选 9（建 .venv 并 pip install -r requirements.txt）")


def c_dict(poison=False):
    """字典是**目标应用自己的资产**，本仓库不提供也不索取。
    缺它不该拦住开抓 —— 那只是"压缩帧解不出来，会整批落 undecoded"。"""
    ok, p = ncenv.dict_status()
    if poison:
        ok = False
    detail = "%s (%s B)" % (p, p.stat().st_size if p.exists() else 0) if ok else (
        "没有字典：未压缩/自带帧头的流量照样能解，但用字典压缩的帧会落 dec=undecoded 并另存原件。"
        "要自己做一份：python tools\\dictgen.py train --from <样本文件>")
    check("zstd 字典在位（可选）", ok, detail, level="WARN")


def c_ca(poison=False):
    cn = "bogus-ca-name" if poison else ncenv.CA_CN
    rc, out = _ps("Get-ChildItem Cert:\\CurrentUser\\Root,Cert:\\LocalMachine\\Root -ErrorAction SilentlyContinue "
                  "| Where-Object { $_.Subject -like '*%s*' } | ForEach-Object { 'HIT ' + $_.Thumbprint + ' ' + "
                  "$_.NotAfter.ToString('yyyy-MM-dd') }" % cn)
    hits = [l for l in out.splitlines() if l.startswith("HIT")]
    if poison:
        hits = []
    check("本工具的根 CA 已安装", bool(hits),
          hits[0] if hits else "库里没有 %s：跑 python tools\\ca_tool.py make && ca_tool.py install" % cn)
    # 别家自建 CA 并存 ≠ 坏：只是"解出来的证书是谁签的"要多看一眼 ca_sha1。
    rc2, legacy = _ps("Get-ChildItem Cert:\\CurrentUser\\Root,Cert:\\LocalMachine\\Root "
                      "-ErrorAction SilentlyContinue | Where-Object { $_.Issuer -match 'mitmproxy|netcatch|"
                      "untrusted-lab' } | ForEach-Object { $_.Thumbprint + '|' + $_.Subject }")
    lh = [l for l in legacy.splitlines() if l.strip() and "|" in l]
    if poison:
        lh = ["DEADBEEF|CN=legacy other-lab CA (selftest 下毒)"]
    # 命中行形状是 "HIT <thumbprint> <date>"，不是 ca_tool 的竖线格式；
    # 上一版在这里 split("|")[1] 直接 IndexError，整条判据被 run_all 的异常分支吞掉。
    my_tps = {l.split()[1] for l in hits if len(l.split()) >= 2}
    # 去重是必须的：上面那条 PS 同时枚举 Cert:\CurrentUser\Root 与 Cert:\LocalMachine\Root，
    # 而这两个都是**合并视图** —— 机器库的一张会在两个路径里各出现一次，不去重就报"并存 2 张"
    # （实测就是这样把 1 张数成了 2 张）。计数错了，人就会去找不存在的那张。
    uniq, seen_tp = [], set()
    for l in lh:
        tp = l.split("|")[0]
        if tp in my_tps or tp in seen_tp:
            continue
        seen_tp.add(tp)
        uniq.append(l)
    others = uniq
    check("除本工具外还有几张自建根证书", not others,
          ("另有 %d 张自建根证书：%s。并存时客户端认哪张不由我们决定 —— 先 python tools\\ca_tool.py list 看归属"
           % (len(others), "; ".join(o.split("|")[-1][:40] for o in others[:2]))
           if others else "干净"), level="WARN")


def c_trust(poison=False):
    """信任链两腿自证：本机 CA 签的叶子必须被两条栈接受，未装过的对照 CA 必须被拒。"""
    py, _m, _hint = ncenv.resolve_python()
    if poison or not py:
        check("TLS 信任链两腿自证", False, "(selftest 下毒)" if poison else "没有可用的 python")
        return
    rc, out = ncenv.run_py([str(py), str(HERE / "tls_trust_probe.py")], timeout=120)
    detail = (out.strip().splitlines()[-1] if out.strip() else "无输出")[:200]
    check("TLS 信任链两腿自证", rc == 0, detail)


def c_ports(poison=False):
    rc, out = _ps("netstat -ano -p tcp")
    lines = out.splitlines()
    guard = ncenv.GUARD_PORTS
    busy = [l.strip() for l in lines for p in guard if ("LISTEN" in l and port_hit(l, p))]
    if poison:
        busy = ["TCP 127.0.0.1:7891 0.0.0.0:0 LISTENING 9999 (selftest 下毒)"]
    check("守门端口无监听 %s" % "/".join(guard), not busy, "; ".join(busy[:3]) or "全空")
    gp = ncenv.GAME_PORTS
    live = [l.strip() for l in lines if any(port_hit(l, p) for p in gp)
            and ("ESTABLISHED" in l or "SYN_SENT" in l)]
    if poison:
        live = ["TCP 127.0.0.1:13701 10.0.0.1:9 ESTABLISHED (selftest 下毒)"]
    check("目标连接尚未建立（否则首连握手序列抓不到，必须冷启动）", not live,
          live[0][:90] if live else "无连接，可冷启动")


def c_procs(poison=False):
    rc, out = _ps("Get-Process mitmdump,mitmweb,mitmproxy,dumpcap,tshark -ErrorAction SilentlyContinue | "
                  "ForEach-Object { $_.Id.ToString() + ' ' + $_.ProcessName }")
    hits = [l for l in out.splitlines() if l.strip()]
    if poison:
        hits = ["9999 mitmdump (selftest 下毒)"]
    check("无遗留抓包进程", not hits, "; ".join(hits[:3]) or "干净")
    rc3, out3 = _run(["sc", "query", "WinDivert"])
    stale = ("RUNNING" in out3) or poison
    check("WinDivert 无遗留运行实例", not stale,
          "RUNNING —— 先跑 python tools\\ca_tool.py kernel --clean" if stale else "不存在/已停")


def c_disk(poison=False):
    free = shutil.disk_usage(str(ROOT))[2] / 1024 ** 3
    if poison:
        free = 0.1
    check("落盘盘符剩余 >= %.0f GB" % ncenv.MIN_FREE_GB, free >= ncenv.MIN_FREE_GB, "%.1f GB free" % free)


def c_pcap(poison=False):
    p, hint = ncenv.find_tool("dumpcap")
    if poison:
        p, hint = None, "(selftest 下毒)"
    if not p:
        check("dumpcap 可用（L2 链路层）", False, hint + "；不需要这层就明确加 --no-pcap", level="WARN")
        return
    rc, out = _run([str(p), "-D"])
    nif = len([l for l in out.splitlines() if l.strip() and l[0].isdigit()])
    if poison:
        nif = 0
    check("dumpcap 可枚举接口（即 Npcap 在位）", nif >= 2,
          "%d 个接口" % nif if nif >= 2 else
          "枚举到 %d 个：Npcap 没装或没起来，L2 链路层证据会整体缺席" % nif, level="WARN")


def c_sanitize(poison=False):
    """出舱过滤器两向现算：① 已知秘密过一遍 redact 后必须查不到；② 未过 filter 的原样内容
    必须被审计报出来。第二向是防"过滤器写成永真"这种最常见的失效。"""
    ok, detail = sanitize.selftest_probe()
    if poison:
        ok, detail = False, "(selftest 下毒)"
    check("出舱过滤器两向有效（两腿自证）", ok, detail[:200])


def c_addon_selfproof(poison=False):
    """插件输出通道自证：真起一次 mitmdump，要求 events.jsonl 里出现 addon_selfproof=OK。
    "加载了"不等于"写得进盘"，不测这条会重演"跑 30 分钟发现 0 帧"。"""
    import tempfile
    _py, mitmdump, hint = ncenv.resolve_python()
    if poison or not mitmdump or not Path(mitmdump).exists():
        check("插件输出通道自证(真写盘+读回)", False,
              "(selftest 下毒)" if poison else hint)
        return
    run = Path(tempfile.mkdtemp(prefix="nc_selfproof_"))
    env = dict(subprocess.os.environ, NC_OUT=str(run))
    argv = [str(mitmdump), "--mode", "regular", "--listen-host", "127.0.0.1", "--listen-port", "8899",
            "-s", str(HERE / "net_catch_addon.py"), "--set", "confdir=%s" % ncenv.CA_DIR,
            "--set", "termlog_verbosity=warn", "--quiet"]
    try:
        proc = subprocess.Popen(argv, cwd=str(HERE), env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except Exception as e:
        check("插件输出通道自证(真写盘+读回)", False, "启动失败 %r" % e)
        return
    ev = run / "events.jsonl"
    ok, detail = False, "10s 内没等到 addon_selfproof"
    for _ in range(40):
        time.sleep(0.25)
        if ev.exists():
            try:
                last = [json.loads(l) for l in ev.read_text(encoding="utf-8").splitlines()]
            except Exception:
                last = []
            sp = [e for e in last if e.get("event") == "addon_selfproof"]
            if sp:
                ok = str(sp[-1].get("result", "")).startswith("OK")
                detail = str(sp[-1].get("result"))[:140]
                break
    if poison:
        ok, detail = False, "(selftest 下毒)"
    proc.terminate()
    try:
        errb = proc.stderr.read(400).decode("utf-8", "replace") if proc.stderr else ""
    except Exception:
        errb = ""
    check("插件输出通道自证(真写盘+读回)", ok,
          detail + ("| stderr:%s" % errb[:80] if errb else ""), level="WARN")


CHECKS = [c_admin, c_tools, c_dict, c_ca, c_trust, c_ports, c_procs, c_disk, c_pcap,
          c_sanitize, c_addon_selfproof]


def _summarize():
    reds = [r for r in RESULTS if not r[1] and r[3] == "RED"]
    warns = [r for r in RESULTS if not r[1] and r[3] != "RED"]
    return reds, warns


def run_all(poison=None, quiet=False):
    RESULTS.clear()
    for fn in CHECKS:
        if poison is not None and fn.__name__ != poison:
            continue
        try:
            fn(poison=(poison is not None))
        except Exception as e:
            check(fn.__name__, False, "探测本身炸了 %r" % e)
    reds, warns = _summarize()
    if not quiet:
        for name, ok, detail, lvl in RESULTS:
            tag = "OK" if ok else (lvl if lvl != "RED" else "RED")
            print("%-4s %-46s %s" % (tag, name, detail))
        print("---- preflight: %d 项, RED %d, WARN %d ----" % (len(RESULTS), len(reds), len(warns)))
        if warns and not reds:
            print("     （WARN 不拦开抓，但那几层证据会缺席，读数口径要跟着改）")
    return 1 if reds else 0


def _unit_port_matcher():
    """端口这条尺子自己的对照：既会咬，也不误伤。"""
    cases = [
        ("TCP  0.0.0.0:443    0.0.0.0:0    LISTENING  1", "443", True),
        ("TCP  0.0.0.0:4435   0.0.0.0:0    LISTENING  1", "443", False),
        ("TCP  0.0.0.0:4430   0.0.0.0:0    LISTENING  1", "4430", True),
        ("TCP  [::]:13701     [::]:0       LISTENING  9", "13701", True),
        ("TCP  1.2.3.4:137010 0.0.0.0:0    ESTABLISHED 9", "13701", False),
        ("TCP  1.2.3.4:52110 1.2.3.4:13701 ESTABLISHED 9", "13701", True),
        ("UDP  0.0.0.0:8083   *:*                       1", "8083", True),
    ]
    bad = [(l, p, e) for l, p, e in cases if port_hit(l, p) != e]
    return not bad, ("7 例全对" if not bad else "尺子错了: %s" % (bad[:2],))


def selftest():
    bad = []
    for fn in CHECKS:
        RESULTS.clear()
        try:
            fn(poison=True)
        except Exception as e:
            print("  下毒时异常 %s: %r" % (fn.__name__, e))
        greens = [r[0] for r in RESULTS if r[1]]
        print("  %-22s 登记 %d 条，全红=%s%s" % (fn.__name__, len(RESULTS),
                                                "YES" if (RESULTS and not greens) else "NO",
                                                (" 仍绿: " + "; ".join(greens)) if greens else ""))
        if greens or not RESULTS:
            bad.append(fn.__name__)
    ok, detail = _unit_port_matcher()
    print("  %-22s 端口尺子对照: %s" % ("unit(port_hit)", "YES" if ok else "NO " + detail))
    if not ok:
        bad.append("port_hit")
    ok2, detail2 = sanitize.selftest_probe()
    print("  %-22s 出舱过滤器两向: %s" % ("unit(sanitize)", "YES" if ok2 else "NO " + detail2))
    if not ok2:
        bad.append("sanitize")
    if bad:
        print("SELFTEST RED: 这些判据下毒后仍有绿条目/尺子自己不合格 = 闸缺牙：%s" % ", ".join(bad))
        return 1
    print("SELFTEST OK: 每条判据都被毒翻，且两把尺子的对照组也过了")
    return 0


if __name__ == "__main__":
    ncenv.utf8_stdout()
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    sys.exit(selftest() if a.selftest else run_all())
