# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
selftest_pipeline.py — 把"能不能抓到"这件事拆成两条独立证据腿，全在本机跑完，不碰任何真实业务。

  腿 A  WS 钩子是否真落盘：mitmdump reverse 模式 + 假 WS 靶机（含一个 ping 控制帧）。
        证明 frames/events 的落盘、方向标记、握手字段、请求头非空、"ping 只在日志不在帧里"这条边界声明，
        以及插件自证里那条脱敏校验真的执行了。
  腿 B  抓包编排是否真工作：catch.py 的 local 模式（内核驱动按进程名拦）+ pcap 层 + 连接台账
        + meta 回填 + 收尾清理。用一个出网 HTTP 请求当靶，证明"被点名进程的远端流量确实进了插件"。

为什么要拆两条：实测证明 mitmproxy 的 Windows local 重定向**不碰"目的地是这台机器"的连接**——不只是 127.0.0.1，
客户端连本机自己的局域网 IP 同样不被重定向（2026-09-28 实测：靶机绑 WLAN 地址，服务端拿到完整 WS 会话，mitmdump 记录 0 条连接）。因此"假 WS 靶机 + local 模式"必然 0 帧 —— 那是驱动的重定向边界，不是工具坏了。
腿 A 用显式反向代理绕开这一点，专测插件；腿 B 专测拦进程与落盘编排。

跑法（管理员，因为腿 B 要加载内核驱动）： python tools/selftest_pipeline.py
"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
A_DIR = ncenv.STATE / "selftest_A"
B_RUNS = ncenv.SAMPLES


def _binaries():
    """(python, mitmdump, 说明)。腿 A/腿 B 都要真起 mitmdump，所以这里失败就没必要往下跑。"""
    py, md, hint = ncenv.resolve_python()
    return py, md, hint


def _free_port(start=8902):
    """腿 A 的 reverse 监听端口不能硬占：撞上一次真代理就整条腿必红，
    而那红的是端口，不是链路。找一个内核分配的可用口。"""
    for p in (start, start + 1, 0):
        try:
            s = socket.socket()
            if p == 0:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            else:
                s.bind(("127.0.0.1", p))
                port = p
            s.close()
            return port
        except OSError:
            continue
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def dec(b):
    return ncenv.decode_mixed(b or b"")


def jl(p):
    if not Path(p).exists():
        return []
    out = []
    for line in open(p, encoding="utf-8"):
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def mdump(mode_args, outdir, port=None):
    outdir.mkdir(parents=True, exist_ok=True)
    for f in ("events.jsonl", "frames.jsonl"):
        p = outdir / f
        if p.exists():
            p.unlink()
    _py, MD, _hint = _binaries()
    argv = [str(MD)] + mode_args + ["-s", str(HERE / "net_catch_addon.py"),
                                    "--set", "confdir=%s" % ncenv.CA_DIR,
                                    "--set", "ssl_insecure=true",
                                    "--set", "termlog_verbosity=info"]
    if port:
        argv += ["--listen-host", "127.0.0.1", "--listen-port", str(port)]
    log = open(outdir / "mitmdump.log", "w", encoding="utf-8", errors="replace")
    return subprocess.Popen(argv, cwd=str(HERE),
                            env=dict(subprocess.os.environ, NC_OUT=str(outdir), PYTHONUNBUFFERED="1"),
                            stdout=log, stderr=subprocess.STDOUT), log


def kill(p, log):
    if p.poll() is None:
        p.terminate()
        for _ in range(40):
            if p.poll() is not None:
                break
            time.sleep(0.25)
        if p.poll() is None:
            p.kill()
    try:
        log.close()
    except Exception:
        pass


def leg_a():
    print("\n########## 腿 A：WS 钩子落盘（reverse 模式 + 假 WS 靶机）##########")
    # 用 reverse 而不是 regular：regular 下代理语义会把我们的 Upgrade 请求判 400（实测），
    # 而这里要证的只是"WS 帧/握手/ping 有没有落盘"，与拦进程无关（那是腿 B 的事）。
    py, _md, hint = _binaries()
    if not py:
        return [(("腿 A 前置：python/mitmdump", False, hint))]
    peer_port = _free_port(8765)
    prox_port = _free_port(8902)
    p, log = mdump(["--mode", "reverse:http://127.0.0.1:%d" % peer_port], A_DIR, port=prox_port)
    time.sleep(6)
    r = subprocess.run([str(py), str(HERE / "_ws_probe_peer.py"), "127.0.0.1", str(prox_port),
                        "127.0.0.1", str(peer_port)], capture_output=True, timeout=60)
    peer_out = dec(r.stdout) + dec(r.stderr)
    (A_DIR / "peer.log").write_text(peer_out, encoding="utf-8")
    print("".join("       | " + l + "\n" for l in peer_out.strip().splitlines()[:8]))
    time.sleep(2)
    kill(p, log)
    frames = jl(A_DIR / "frames.jsonl")
    events = jl(A_DIR / "events.jsonl")
    raw_log = (A_DIR / "mitmdump.log").read_text(encoding="utf-8", errors="replace")
    ws_open = [e for e in events if e.get("event") == "ws_open"]
    reqs = [e for e in events if e.get("event") == "req"]
    sp = [e for e in events if e.get("event") == "addon_selfproof"]
    # 心跳这条边界必须用**同一把尺子**判（verify_run 的正则），不能用裸子串 "ping"：
    # 整份日志里任何一行含 ping 都会让它变绿，而它一绿就意味着 verify 的心跳计数有意义。
    from verify_run import _WS_PING
    from _ws_probe_peer import SUBPROTO
    ping_rows = _WS_PING.findall(raw_log)
    checks = [
        ("WS 帧 >= 3 条", len(frames) >= 3, "%d 条" % len(frames)),
        ("双向都有", {f["dir"] for f in frames} >= {"c2s", "s2c"}, sorted({f['dir'] for f in frames})),
        ("s2c session 首帧形状抓到", any("SELFTEST-SESSION" in (f.get("text") or "") for f in frames), ""),
        ("c2s 数组信封解析出 cmds", any((f.get("tag") or {}).get("cmds") == ["selftest.run"] for f in frames),
         str([(f.get("tag") or {}).get("cmds") for f in frames][:3])),
        ("握手事件含 path/子协议/双向扩展", bool(ws_open) and ws_open[0].get("ws_server_protocol") == SUBPROTO
         and "/selftest" in str(ws_open[0].get("path")),
         json.dumps(ws_open[0], ensure_ascii=False)[:150] if ws_open else "无 ws_open"),
        ("ping 控制帧只出现在日志、不在帧里", bool(ping_rows) and not any(f.get("opcode") == 9 for f in frames),
         "日志 %d 行 ping/pong，帧里无 opcode 9" % len(ping_rows) if ping_rows else "日志里也没有 ping/pong"),
        # 下面两条证明上一版静默失效的采集真的修好了：headers 不再恒空，自证里含脱敏校验
        ("请求头有落盘（曾经恒为 {}）", any(isinstance(e.get("headers"), dict) and e.get("headers") for e in reqs),
         "%d 条 req，headers 非空的 %d 条" % (len(reqs), sum(1 for e in reqs if e.get("headers")))),
        ("插件自证：原文留存且出舱过滤器有效",
         bool(sp) and "原文留存" in str(sp[-1].get("result"))
         and "出舱过滤器有效" in str(sp[-1].get("result")),
         str(sp[-1].get("result"))[:140] if sp else "无 addon_selfproof"),
    ]
    return checks


def leg_b():
    print("\n########## 腿 B：catch.py 编排（local 模式按进程拦 + pcap + 台账）##########")
    py, _md, hint = _binaries()
    if not py:
        return [("腿 B 前置：python/mitmdump", False, hint)]
    before = set(B_RUNS.glob("run_*"))
    p = subprocess.Popen(
        [str(py), str(HERE / "catch.py"), "start", "--label", "SELFTEST",
         "--trigger", "链路自检，非业务流量", "--procs", "python.exe",
         "--max-min", "1", "--seconds", "22", "--skip-preflight"],
        stdin=subprocess.PIPE, stdout=sys.stdout, stderr=subprocess.STDOUT, text=True)
    time.sleep(9)
    r = subprocess.run([str(py), "-c",
                        "import urllib.request;print(urllib.request.urlopen('http://example.com/',timeout=15).status)"],
                       capture_output=True, timeout=40)
    print("[leg B] 出网靶请求 ->", dec(r.stdout).strip() or dec(r.stderr)[:100])
    try:
        p.communicate(input="\n", timeout=120)
    except Exception:
        p.kill()
    new = sorted(set(B_RUNS.glob("run_*")) - before)
    if not new:
        return [("catch.py 产出 run 目录", False, "没有")]
    run = new[-1]
    events = jl(run / "events.jsonl")
    reqs = [e for e in events if e.get("event") == "req"]
    conns = jl(run / "conns.jsonl")
    meta = json.loads((run / "meta.json").read_text(encoding="utf-8")) if (run / "meta.json").exists() else {}
    pcap = run / "allif.pcapng"
    # 包数一律走 ncenv 的解析：capinfos 打的是缩写约数（"20 k" 其实是 20,314），
    # 直接取前导整数会把正常批次判红 —— 实测踩过，就在这条闸上。
    pk, pkhint, pkraw = ncenv.pcap_packet_count(pcap)
    p20 = ncenv.parse_packet_count("Number of packets:   20 k")[0]
    p0 = ncenv.parse_packet_count("Number of packets: 0")[0]
    p47 = ncenv.parse_packet_count("Number of packets:   47")[0]
    pk_ctl = (p20, p0, p47) == (20000, 0, 47)
    mlog = (run / "mitmdump.log").read_text(encoding="utf-8", errors="replace") if (run / "mitmdump.log").exists() else ""
    dlog = run / "dumpcap.log"
    dlog_txt = dlog.read_text(encoding="utf-8", errors="replace") if dlog.exists() else ""
    checks = [
        ("run 目录产出", True, run.name),
        ("local 模式抓到被点名进程的远端流量", any("example.com" in str(e.get("host")) for e in reqs),
         "%d 条 req，样例 %s" % (len(reqs), [e.get("host") for e in reqs[:2]])),
        ("连接台账有行且含 python", any(str(c.get("proc", "")).startswith("python") for c in conns),
         "%d 行，错误行 %d" % (len(conns), sum(1 for c in conns if "ledger_error" in c))),
        ("台账能区分 TCP/UDP", any(c.get("kind") in ("tcp", "udp") for c in conns),
         "kind 取值 %s" % sorted({c.get("kind") for c in conns})[:4] if conns else "空"),
        ("pcap 落盘且有包", pk is not None and pk > 100,
         "%s B / 包数 %s（capinfos 原文『%s』，%s）" % (
             pcap.stat().st_size if pcap.exists() else 0, pk, pkraw, pkhint)),
        ("包数解析对照（尺子自证）", pk_ctl,
         "20 k→%s / 0→%s / 47→%s；不展开千分位就会把 20,314 读成 20" % (p20, p0, p47)),
        ("dumpcap 进度不串进 mitmdump.log",
         ("Packets:" not in mlog) and (("Packets" in dlog_txt) or not pcap.exists()),
         "mitmdump.log 里 Packets 出现 %d 次；dumpcap.log %d B" % (mlog.count("Packets:"),
                                                                  dlog.stat().st_size if dlog.exists() else -1)),
        ("meta 记录了 CA/进程归属并声明出舱口径", bool(meta.get("ca_sha1")) and bool(meta.get("procs_filter"))
         and meta.get("export_redaction") == "at-export" and meta.get("shareable") is False,
         json.dumps(
            {"ca": str(meta.get("ca_sha1"))[:18], "procs": meta.get("procs_filter"),
             "export_redaction": meta.get("export_redaction"),
             "exe_n": len(meta.get("exe_identity", []))},
            ensure_ascii=False)),
        ("收尾无 mitmdump 遗留",
         # tasklist /FI 无匹配时那句提示本身就含 "mitmdump.exe"，字符串计数会把"干净"读成"没干净"。
         # 用 Get-Process 计数，0 才是 0。
         dec(subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                             "@(Get-Process mitmdump,dumpcap -ErrorAction SilentlyContinue).Count"],
                            capture_output=True).stdout).strip() == "0", ""),
        ("收尾无 WinDivert 遗留", "RUNNING" not in dec(subprocess.run(["sc", "query", "WinDivert"],
                                            capture_output=True).stdout), ""),
    ]
    return checks


def main():
    ncenv.utf8_stdout()
    allc = leg_a() + leg_b()
    print("\n================ 自检结论 ================")
    fails = []
    for name, ok, note in allc:
        print("%-5s %-42s %s" % ("OK" if ok else "RED", name, note))
        if not ok:
            fails.append(name)
    print("---- %d 项, RED %d ----" % (len(allc), len(fails)))
    if fails:
        return 1
    print("SELFTEST OK：两条证据腿都成立，可以按 README 抓真流量了")
    return 0


if __name__ == "__main__":
    sys.exit(main())
