# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
catch.py — 一条命令开抓。三层同时落盘，全进 catchedsample\\run_<时间>_<标签>\\

  L1 载荷层  mitmdump --mode local:<目标进程> + net_catch_addon.py -> frames.jsonl / events.jsonl
             只拦被点名进程的 TCP，靠内核驱动按 PID 摘包；不动系统代理、不改 hosts。
  L2 链路层  dumpcap 多接口 -> allif.pcapng（含 UDP/QUIC/DNS，mitmproxy 看不到的都在这）
  L3 归属层  每 ~1s 采一次连接台账 -> conns.jsonl（PID/进程名/本地-远端/状态）
  兜底       capture.flows = mitmdump 原生全量档

本机整批保持**原文** —— 那是数据持有者的分析材料。脱敏只发生在出舱口：
  可外带 = report.py 产的 snapshot/ 目录（出舱时过 sanitize，再强制审计，命中即拒绝）
  不可外带 = run 目录整体

子命令：
  start   --label <标签> [--trigger "..."] [--procs a,b] [--max-min 240]
          [--no-pcap] [--ifaces 4,8] [--seconds N] [--skip-preflight]
  mark    <标签> [备注]          现场打标，写进最近一次 run 的 markers.jsonl
  status                         列出已抓的 run 与体积
  verify  [--run <目录>]         重跑验收
  backfill [--run <目录>]        从帧里重算 meta 的归属字段
  snapshot [--run <目录>]        产出可外带的脱敏快照（report.py）
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402
import sanitize  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SAMPLES = ncenv.SAMPLES


def ps(script, timeout=60):
    p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, timeout=timeout)
    return ncenv.decode_mixed(p.stdout or b"") + ncenv.decode_mixed(p.stderr or b"")


def sha16(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                h.update(blk)
        return h.hexdigest()[:16]
    except Exception as e:
        return "unreadable:%s" % type(e).__name__


def observed_exe_identity(procs):
    """被点名进程的可执行文件指纹，**路径从运行中的进程现查**。
    不再硬列任何安装目录，也不再记录任何"客户端是否被改过"的信息 —— 那不属于本工具。"""
    names = [p.strip().lower().replace(".exe", "") for p in (procs or "").split(",") if p.strip()]
    if not names:
        return []
    filt = ",".join("'%s'" % n for n in names)
    # 必须用 ForEach-Object 输出字符串；放在 Where-Object 的脚本块里，管道吐出来的是
    # Process 对象而不是那行字符串（上一版因此永远解析不出 `|name|path`，exe_identity 恒为空）。
    out = ps("Get-Process -ErrorAction SilentlyContinue | ForEach-Object { "
             "$names = @(%s); $n = $_.ProcessName; "
             "foreach ($x in $names) { if ($n -like ($x + '*')) { '|' + $n + '|' + $_.Path } } }" % filt)
    res = []
    for line in out.splitlines():
        parts = [p for p in line.strip().split("|") if p]
        if len(parts) >= 2:
            proc, path = parts[0], parts[1]
            rec = {"proc": proc, "exe": Path(path).name, "sha256_16": sha16(path)}
            try:
                st = Path(path).stat()
                rec["size"] = st.st_size
            except Exception:
                pass
            res.append(rec)
    return res


def tun_active():
    """TUN/系统代理在场 = 出口路径非直连，读数归因要打折。**只读**，不写任何键。"""
    o = ps("$t=@(); if (Get-NetAdapter -ErrorAction SilentlyContinue | "
           "Where-Object { $_.InterfaceDescription -match 'tun|wintun|tap' -and $_.Status -eq 'Up' }) "
           "{ $t+='TUN-UP' }; "
           "$pe=(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet "
           "Settings' -ErrorAction SilentlyContinue); if ($pe.ProxyEnable -eq 1) { $t+='SYSPROXY' };"
           "($t -join ',')")
    marks = o.strip()
    return (bool(marks), marks)


# ---------------- L3 连接台账 ----------------
class Ledger(threading.Thread):
    def __init__(self, path):
        super().__init__(daemon=True)
        self.path = path
        self.stop_flag = threading.Event()
        self.rows = 0

    def run(self):
        # 注意：PowerShell 5.1 没有三元表达式，也不能假设 UDP 端点有 State/Protocol。
        # kind 由来源 cmdlet 决定（上一版取 $_.GetType().Name 恒为 CimInstance，无区分力）。
        one = ("foreach ($cmd in 'Get-NetTCPConnection','Get-NetUDPEndpoint') { "
               "$k = if ($cmd -like '*TCP*') { 'tcp' } else { 'udp' }; "
               "& $cmd -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess } | ForEach-Object { "
               "$p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
               "\"{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}`t{8}\" -f $k, "
               "$_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, "
               "$_.OwningProcess, $(if ($p) { $p.ProcessName } else { '?' }), "
               "$_.State, $_.Protocol } }")
        with open(self.path, "a", encoding="utf-8") as f:
            while not self.stop_flag.is_set():
                t0 = time.time()
                try:
                    out = ps(one, timeout=25)
                    n = 0
                    for line in out.splitlines():
                        parts = line.split("\t")
                        if len(parts) != 9:
                            continue
                        f.write(json.dumps({
                            "ts": _now(),
                            "kind": parts[0],
                            "laddr": parts[1], "lport": int(parts[2] or 0),
                            "raddr": parts[3], "rport": int(parts[4] or 0),
                            "pid": int(parts[5] or 0), "proc": parts[6],
                            "state": parts[7], "proto": parts[8] or ""}, ensure_ascii=False) + "\n")
                        n += 1
                    self.rows += n
                    if n == 0:
                        f.write(json.dumps({"ts": _now(), "ledger_error":
                                            "0 行; 输出=%r" % out[:200]}, ensure_ascii=False) + "\n")
                    f.flush()
                except Exception as e:
                    try:
                        f.write(json.dumps({"ts": _now(), "ledger_error": repr(e)[:200]}) + "\n")
                        f.flush()
                    except Exception:
                        pass
                self.stop_flag.wait(max(0.2, 1.0 - (time.time() - t0)))


def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


# ---------------- start ----------------
def cmd_start(a):
    ncenv.utf8_stdout()
    raw = (a.label or "").strip() or ("all_" + datetime.now().strftime("%H%M%S"))
    label = re.sub(r"[^.\w-]+", "-", raw)[:40]
    run = SAMPLES / ("run_%s_%s" % (datetime.now().strftime("%Y%m%d_%H%M%S"), label))
    run.mkdir(parents=True, exist_ok=False)
    print("[run]", run)

    if not a.skip_preflight:
        print("== preflight ==")
        import preflight
        rc = preflight.run_all()
        if rc:
            print("RED: preflight 没过，什么都没启动。先按上面每条修。")
            return 1

    procs = a.procs or ncenv.DEFAULT_PROCS
    tun, tun_marks = tun_active()
    my_sha = ""
    try:
        import ca_store
        my_sha = ca_store.record_read()
    except Exception as e:
        print("[warn] 读不到本机 CA 指纹:", repr(e)[:120])
    meta = {"label": label, "started": _now(), "trigger": a.trigger or "",
            "procs_filter": [p.strip() for p in procs.split(",") if p.strip()],
            "ca_sha1": my_sha,
            "tun_proxy_active": tun, "tun_marks": tun_marks,
            "addon": ncenv.ADDON_VER,
            "mitmproxy_layer": "local(仅点名进程的 TCP)",
            "pcap": not a.no_pcap, "max_minutes": a.max_min,
            "zstd_dict_loaded": ncenv.dict_status()[0],
            "export_redaction": "at-export", "shareable": False}
    (run / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
    if tun:
        print("[warn] 检测到 %s 在场 —— 出口非直连，本批归因打折；建议先干净退出再抓。" % (tun_marks or "TUN/代理"))

    kids = {}
    _py, mitmdump, hint = ncenv.resolve_python()
    if not mitmdump:
        print("RED:", hint)
        return 1
    # PYTHONUNBUFFERED：否则日志在管道里被块缓冲，收尾硬杀会整段丢掉
    env = dict(subprocess.os.environ, NC_OUT=str(run), PYTHONUNBUFFERED="1")
    logf = open(run / "mitmdump.log", "w", encoding="utf-8", errors="replace")
    kids["mitmdump"] = subprocess.Popen(
        [str(mitmdump), "--mode", "local:%s" % procs,
         "-s", str(HERE / "net_catch_addon.py"),
         "--set", "confdir=%s" % ncenv.CA_DIR,
         "--set", "ssl_insecure=true",
         "--set", "connection_strategy=lazy",
         "--set", "stream_large_bodies=64m",
         "--set", "termlog_verbosity=info",
         "-w", str(run / "capture.flows")],
        cwd=str(HERE), env=env, stdout=logf, stderr=subprocess.STDOUT)
    led = Ledger(run / "conns.jsonl")
    led.start()
    kids["ledger"] = led

    if not a.no_pcap:
        # dumpcap 的 "Packets: N" 进度会挤进 mitmdump 同一行，污染"心跳只能从日志数"这条判据
        # ⇒ 必须真分文件。上一版建了句柄却把 stdout 仍接到 logf，意图没落实（实测最脏一批混进 5587 行）。
        dcap, dhint = ncenv.find_tool("dumpcap")
        ifaces = []
        if dcap:
            out = subprocess.run([str(dcap), "-D"], capture_output=True)
            for line in ncenv.decode_mixed(out.stdout or b"").splitlines():
                m = re.match(r"\s*(\d+)\.\s+(\S+)", line)
                if m:
                    ifaces.append((m.group(1), m.group(2)))
            want = [i.strip() for i in (a.ifaces or "").split(",") if i.strip()]
            if want:
                args = sum([["-i", i] for i in want], [])
            else:
                args = sum([["-i", i] for i, n in ifaces
                            if not re.search(r"VMware|vmnet", n, re.I)], [])
            dlog = open(run / "dumpcap.log", "w", encoding="utf-8", errors="replace")
            # stdin 必须是管道：dumpcap 交互模式下收到 "q" 才会**优雅退出**并补完
            # pcapng 的最后一个块。 terminate() 在 Windows 上是 TerminateProcess，
            # 会留下截断文件（实测 capinfos 能报包数、tshark 直接拒绝读）。
            kids["dumpcap"] = subprocess.Popen(
                [str(dcap)] + args + ["-a", "duration:%d" % (a.max_min * 60),
                                      "-w", str(run / "allif.pcapng")],
                stdin=subprocess.PIPE, stdout=dlog, stderr=subprocess.STDOUT, env=env)
            print("[pcap] 接口:", " ".join("%s=%s" % x for x in ifaces)[:180])
            kids["dumpcap_loghandle"] = dlog
        else:
            print("[warn] 没有 dumpcap（%s）—— 本批没有 L2 链路层证据，"
                  "UDP/DNS/漏抓对账这些结论会整体缺席。" % dhint)

    print("\n== 已启动 %d 层：%s ==" % (len([k for k in kids if not k.endswith('loghandle')]),
                                        ",".join(k for k in kids if not k.endswith('loghandle'))))
    if a.seconds:
        print("[auto] %d 秒后自动收尾（自检用）" % a.seconds)
        time.sleep(a.seconds)
    else:
        print("现在按顺序做：干净退出目标程序 -> 确认 mitmdump 还在 -> 冷启动目标 -> 按台本操作")
        print("每次做动作前另开一个终端跑：  python tools\\catch.py mark <动作名>")
        print("抓完回到本窗口按【回车】收尾并出验收报告。\n")
        t_start = time.time()
        try:
            ans = input()
        except KeyboardInterrupt:
            print("\n[中断] 开始收尾")
            ans = "y"
        if time.time() - t_start < 20 and ans == "":
            print("[等一下] 距离开抓不到 20 秒就要收尾：这通常是误按（误按的那批结果 0 事件、插件根本没起来）。")
            try:
                if input("      真的要现在收尾吗？再按一次回车=继续抓，输入 y=收尾: ").strip().lower() != "y":
                    print("      继续抓。准备好再按回车。")
                    while True:
                        try:
                            input()
                            break
                        except KeyboardInterrupt:
                            break
            except KeyboardInterrupt:
                pass

    return finalize(run, kids, logf, a)


def backfill_meta(run: Path):
    """从帧里现算归属字段回填 meta.json。单独成函数是为了老批次不用重抓也能补。
    本机 meta 保持原文：数据持有者要能看见自己的 ID 和 token 形状。
    脱敏发生在出舱口（report.py 生成 snapshot 时），不在这里。"""
    mp = run / "meta.json"
    try:
        meta = json.loads(mp.read_text(encoding="utf-8"))
    except Exception:
        meta = {}
    meta.setdefault("label", run.name)
    if not meta.get("trigger"):
        meta["trigger"] = "(未填写) 与 label 同义：%s" % meta.get("label")
    found = {}
    try:
        for line in open(run / "frames.jsonl", encoding="utf-8"):
            r = json.loads(line)
            if r.get("dir") != "c2s":
                continue
            t = r.get("text") or ""
            if len(t) > 2_000_000:
                continue
            try:
                arr = json.loads(t)
            except Exception:
                continue
            for o in (arr if isinstance(arr, list) else [arr]):
                if not isinstance(o, dict):
                    continue
                p = o.get("params") if isinstance(o.get("params"), dict) else {}
                cmd, sub = o.get("cmd"), p.get("cmd")
                if cmd == "helo" and "build" not in found:
                    dd = p.get("device_data") or {}
                    found["build"] = dd.get("client_version") or p.get("client_version")
                    found["patch"] = dd.get("patch_version") or p.get("patch_version")
                    found["publisher_uid"] = p.get("publisher_uid")
                    found["nation"] = p.get("user_nation")
                if cmd == "auth" and sub == ncenv.AUTH_SUBCMD and "world" not in found:
                    found["world"] = p.get("world_id")
                    found["server_user_id"] = p.get("uuid")
                    found["token_len"] = len(str(p.get("user_access_token") or ""))
                if cmd == "load" and "load_world" not in found:
                    found["load_world"] = p.get("world_id")
    except FileNotFoundError:
        pass
    for k_src, k_dst in (("build", "build_hint"), ("patch", "patch_version"), ("nation", "user_nation"),
                         ("world", "world_hint"), ("load_world", "load_world_id"),
                         ("server_user_id", "game_user_id"), ("publisher_uid", "publisher_uid"),
                         ("token_len", "user_access_token_len")):
        if found.get(k_src) not in (None, ""):
            meta[k_dst] = found[k_src]
    meta.setdefault("world_hint", meta.get("load_world_id") or "未见于本批帧")
    meta.setdefault("export_redaction", "at-export")
    meta["shareable"] = False
    mp.write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    return meta


def cmd_backfill(a):
    run = Path(a.run) if a.run else latest_run()
    if not run or not Path(run).exists():
        print("RED: 找不到 run 目录")
        return 1
    m = backfill_meta(Path(run))
    print(json.dumps({k: m.get(k) for k in ("label", "trigger", "build_hint", "patch_version",
                                            "world_hint", "game_user_id", "user_access_token_len",
                                            "tun_proxy_active", "ca_sha1", "export_redaction", "shareable")},
                     ensure_ascii=False, indent=1))
    return 0


def finalize(run, kids, logf, a):
    for name in ("dumpcap", "mitmdump"):
        p = kids.get(name)
        if p and p.poll() is None:
            if name == "dumpcap":
                try:
                    p.stdin.write(b"q\n")
                    p.stdin.close()
                    p.wait(timeout=15)
                except Exception:
                    pass
            if p.poll() is None:
                p.terminate()
            for _ in range(40):
                if p.poll() is not None:
                    break
                time.sleep(0.25)
            if p.poll() is None:
                p.kill()
    led = kids.get("ledger")
    if isinstance(led, threading.Thread):
        led.stop_flag.set()
        led.join(timeout=30)
    for h in (logf, kids.get("dumpcap_loghandle")):
        try:
            if h:
                h.close()
        except Exception:
            pass
    # 内核驱动用完即走，不留运行实例
    subprocess.run(["sc", "stop", "WinDivert"], capture_output=True)
    subprocess.run(["sc", "delete", "WinDivert"], capture_output=True)

    meta = backfill_meta(run)
    meta["ended"] = _now()
    dc = kids.get("dumpcap")
    if dc is not None:
        meta["dumpcap_exit"] = dc.poll()
        pcap = run / "allif.pcapng"
        meta["pcap_bytes"] = pcap.stat().st_size if pcap.exists() else 0
    # 被点名进程的可执行文件指纹从运行中的进程现查（不硬列任何安装目录）
    if not meta.get("exe_identity"):
        meta["exe_identity"] = observed_exe_identity(",".join(meta.get("procs_filter") or []))
    (run / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1),
                                  encoding="utf-8")

    # run_summary.json 由收尾方来算：插件的 done() 在 terminate/kill 路径上不会被回调，
    # 把汇总挂在插件里等于挂一个永远不会出现的文件（上一版就是这么写的）。
    write_run_summary(run)

    print("\n== verify_run ==")
    import verify_run
    v = verify_run.verify(run)
    print("---- VERDICT: RED=%d WARN=%d ----" % (v["RED"], v["WARN"]))
    print("数据在:", run)
    print("本机整批是原文（分析材料）。可外带的只有 snapshot/，别把 run 目录整个发出去")
    return 1 if v["RED"] else 0


def write_run_summary(run: Path):
    ev = run / "events.jsonl"
    counts, errs = {}, 0
    open_ws, closed = {}, set()
    try:
        for line in ev.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except Exception:
                continue
            k = r.get("event", "?")
            counts[k] = counts.get(k, 0) + 1
            if k == "addon_error":
                errs += 1
            if k == "ws_open" and r.get("flow"):
                open_ws[r["flow"]] = True
            if k == "ws_close" and r.get("flow"):
                closed.add(r["flow"])
    except FileNotFoundError:
        pass
    fr = run / "frames.jsonl"
    nframes = sum(1 for _ in open(fr, encoding="utf-8")) if fr.exists() else 0
    (run / "run_summary.json").write_text(json.dumps({
        "events": counts, "addon_errors": errs, "frames": nframes,
        "ws_open": len(open_ws), "ws_closed_normal": len(closed),
        "ws_unclosed": sorted(set(open_ws) - closed),
        "note": "由 catch.py 收尾计算，不依赖插件 done()（terminate 路径不会回调）"
    }, ensure_ascii=False, indent=1), encoding="utf-8")


# ---------------- mark / status / verify / snapshot ----------------
def latest_run():
    runs = sorted([p for p in SAMPLES.glob("run_*") if p.is_dir()])
    return runs[-1] if runs else None


def cmd_mark(a):
    run = latest_run()
    if not run:
        print("RED: catchedsample 下还没有任何 run")
        return 1
    rec = {"ts": _now(), "label": a.label, "note": a.note or "", "run": run.name}
    with open(run / "markers.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("[marker@%s] %s %s" % (run.name[-25:], a.label, a.note or ""))
    return 0


def cmd_verify(a):
    run = Path(a.run) if a.run else latest_run()
    if not run or not Path(run).exists():
        print("RED: 还没有任何 run 可验收")
        return 1
    print("verifying", run)
    import verify_run
    v = verify_run.verify(Path(run))
    print("---- VERDICT: RED=%d WARN=%d ----" % (v["RED"], v["WARN"]))
    return 1 if v["RED"] else 0


def cmd_snapshot(a):
    run = Path(a.run) if a.run else latest_run()
    if not run or not Path(run).exists():
        print("RED: 找不到 run 目录")
        return 1
    import report
    return report.build(Path(run))


def cmd_status(_a):
    runs = sorted([p for p in SAMPLES.glob("run_*")])
    if not runs:
        print("(还没有任何 run)")
        return 0
    for r in runs:
        fr = r / "frames.jsonl"
        n = sum(1 for _ in open(fr, encoding="utf-8")) if fr.exists() else 0
        sz = sum(f.stat().st_size for f in r.rglob("*") if f.is_file()) / 1024 ** 2
        mk = r / "markers.jsonl"
        red = "?"
        try:
            red = json.loads((r / "meta.json").read_text(encoding="utf-8")).get("export_redaction", "?")
        except Exception:
            pass
        print("%-44s 帧 %5d  %7.1f MB  打标 %-3s 出舱口径=%s" % (
            r.name, n, sz, (sum(1 for _ in open(mk, encoding="utf-8")) if mk.exists() else 0), red))
    return 0


def main():
    ncenv.utf8_stdout()
    if not ncenv.python_major_ok():
        print("RED: 需要 Python >= %s" % (".".join(map(str, ncenv.MIN_PY)),))
        return 1
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--label", default="", help="可留空（自动 all_<时分秒>）。一次抓全程，不用按场景分批")
    s.add_argument("--trigger", default="", help="为什么这段值得抓（写进 meta.json）")
    s.add_argument("--procs", default="", help="逗号分隔进程名；默认 %s" % ncenv.DEFAULT_PROCS)
    s.add_argument("--max-min", type=int, default=240,
                   help="pcap 自动停止分钟数（默认 240；到点只停 pcap，明文层继续）")
    s.add_argument("--ifaces", default="", help="dumpcap 接口号，逗号分隔；默认全部非 VMware")
    s.add_argument("--no-pcap", action="store_true", help="不抓 pcap（只看 TCP 载荷）")
    s.add_argument("--seconds", type=int, default=0, help="N 秒后自动收尾（自检用，0=等回车）")
    s.add_argument("--skip-preflight", action="store_true")
    s.set_defaults(func=cmd_start)
    m = sub.add_parser("mark")
    m.add_argument("label")
    m.add_argument("note", nargs="?", default="")
    m.set_defaults(func=cmd_mark)
    q = sub.add_parser("status")
    q.set_defaults(func=cmd_status)
    v = sub.add_parser("verify")
    v.add_argument("--run", default="")
    v.set_defaults(func=cmd_verify)
    bf = sub.add_parser("backfill")
    bf.add_argument("--run", default="")
    bf.set_defaults(func=cmd_backfill)
    sn = sub.add_parser("snapshot")
    sn.add_argument("--run", default="")
    sn.set_defaults(func=cmd_snapshot)
    a = ap.parse_args()
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
