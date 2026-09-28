# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
verify_run.py — 抓完立刻现算验收。RED 必非零退出。

`--selftest` 是**多条腿**：每种坏法都要被判红，健康 run 必须判绿。
只喂一种坏样本的话，9 组判据里其余几组从没被验证过会咬东西。

用法： python verify_run.py ..\\catchedsample\\run_xxx
"""
import argparse
import collections
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402
import sanitize  # noqa: E402

HERE = Path(__file__).resolve().parent

# mitmproxy 12 的行形状： [HH:MM:SS.mmm][ip:port] Received WebSocket ping from server (...)
# peer 括号是可选的，且不假设 IPv4（上一版 \d+\.\d+\.\d+\.\d+ 会把 v6 心跳整批漏计）。
_WS_PING = re.compile(r"\[(\d{2}):(\d{2}):(\d{2})\.\d+\](?:\[([^\]]*)\])?\s*"
                      r"Received\s+WebSocket\s+(ping|pong)\s+from\s+(\S+)", re.I)

# 收尾时必填。exe_identity 允许为空数组（被点名进程没在跑是合法场景），单独降级为 WARN。
REQUIRED_META = ["label", "started", "ended", "trigger", "procs_filter", "ca_sha1",
                 "tun_proxy_active", "export_redaction"]
# 这两个字段是从 WS 帧里的 helo/auth 现算的。没有 WS 的目标（任何纯 HTTP 应用）永远填不上，
# 把它们列成必填等于宣布"通用工具只服务有 WebSocket 的目标"。有帧时才要求。
WS_REQUIRED_META = ["build_hint", "world_hint"]
OPTIONAL_META_EMPTY = ["exe_identity"]
L = []


def _capinfos():
    p, _hint = ncenv.find_tool("capinfos")
    return p


def _tshark_from(capinfos):
    if not capinfos:
        return None
    cand = Path(capinfos).with_name("tshark.exe")
    return cand if cand.exists() else (ncenv.find_tool("tshark")[0])


def _dec(b):
    return ncenv.decode_mixed(b or b"")


def _is_ip(s):
    import re
    s = str(s or "")
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s)) or (":" in s and bool(s))


def say(level, name, detail):
    L.append((level, name, detail))
    print("%-5s %-46s %s" % (level, name, str(detail)[:170]))


def _jlines(p):
    if not p.exists():
        return None
    out, bad = [], 0
    for line in open(p, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            bad += 1
    return out, bad


def _host_match(a, b):
    """域名对账用"同名或后缀同名"，不用双向子串。
    双向子串会把 svc-a 和 live-svc-a 判成同一个，把真漏说成已覆盖。"""
    a, b = str(a).lower().strip("."), str(b).lower().strip(".")
    if not a or not b:
        return False
    if a == b:
        return True
    return a.endswith("." + b) or b.endswith("." + a)


def pcap_reconcile(run: Path, l1_eps, game_eps):
    """pcap <-> L1 对账。范围只限被点名进程建立的远端 —— pcap 抓的是全网卡，
    不限范围会把浏览器/IDE 的流量算成"漏"。
    联结：ip --(pcap 内 DNS 应答)--> 域名，再与 L1 的 (host,port) 对。"""
    pcap = run / "allif.pcapng"
    if not pcap.exists():
        cand = sorted(run.glob("allif*.pcapng"))
        pcap = cand[0] if cand else pcap
    capinfos = _capinfos()
    tshark = _tshark_from(capinfos)
    if not pcap.exists() or not tshark:
        return None
    errs = []

    def tz(*args):
        p = subprocess.run([str(tshark), "-r", str(pcap)] + list(args), capture_output=True)
        if p.returncode != 0:
            errs.append((str(args[-1])[:20], _dec(p.stderr)[:120]))
        return _dec(p.stdout)

    ip2name = {}
    for line in tz("-Y", "dns.flags.response==1", "-T", "fields",
                   "-e", "dns.qry.name", "-e", "dns.a").splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1]:
            for ip in parts[1].split(","):
                if ip:
                    ip2name.setdefault(ip, parts[0])

    def covered(host, port):
        for h, p in l1_eps:
            if str(p) == str(port) and _host_match(h, host):
                return True
        return False

    miss, hit = [], 0
    for ip, port in sorted(game_eps, key=lambda x: (str(x[1]), str(x[0]))):
        if str(port) == "53":
            continue          # DNS 本来就没有明文业务层，混进来会掩盖真正的漏
        name = ip2name.get(ip, ip)
        if covered(name, port) or covered(ip, port):
            hit += 1
        else:
            miss.append((name, ip, port))

    game_ips = {ip for ip, _ in game_eps}
    game_udp, all_udp = collections.Counter(), collections.Counter()
    for line in tz("-q", "-z", "conv,udp").splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*(?:->|<->)\s*(\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if not m:
            continue
        for p in (m.group(2), m.group(4)):
            all_udp[p] += 1
        if "53" in (m.group(2), m.group(4)):
            continue          # DNS 回包的高位源端口不是业务端口
        if m.group(1) in game_ips or m.group(3) in game_ips:
            game_udp[m.group(4)] += 1
    notes = {"game_eps": len(game_eps), "covered": hit, "dns_resolved": len(ip2name),
             "udp_ports_all": dict(all_udp.most_common(6)),
             "udp_ports_game": dict(game_udp.most_common(8)), "errs": errs[:3]}
    return miss, notes


def verify(run: Path):
    verdict = {"RED": 0, "WARN": 0}

    def red(n, d):
        say("RED", n, d); verdict["RED"] += 1

    def warn(n, d):
        say("WARN", n, d); verdict["WARN"] += 1

    def ok(n, d):
        say("OK", n, d)

    try:
        files = sorted(p.name for p in run.iterdir())
    except (FileNotFoundError, NotADirectoryError) as e:
        red("run 目录存在", repr(e))
        return verdict
    say("INFO", "run 目录文件", ", ".join(files))

    # ---- V0 L1 到底有没有东西（先算，V1 要用它决定"没帧"是常态还是故障） ----
    ev = _jlines(run / "events.jsonl") or ([], 0)
    events = ev[0]
    kinds = collections.Counter(e.get("event") for e in events)
    l1_activity = sum(kinds.get(k, 0) for k in ("req", "resp", "ws_open"))
    say("INFO", "L1 活动", "req %d / resp %d / ws_open %d" % (
        kinds.get("req", 0), kinds.get("resp", 0), kinds.get("ws_open", 0)))

    # ---- V1 帧 ----
    fr = _jlines(run / "frames.jsonl")
    frames, bad = fr if fr else ([], 0)
    if fr is None:
        warn("frames.jsonl 存在", "缺文件 —— 若目标没有 WS 属正常，若有 WS 则插件没落盘")
    elif bad:
        red("frames.jsonl 每行可解析", "%d 行坏" % bad)
    else:
        ok("frames.jsonl 每行可解析", "%d 行" % len(frames))

    if not frames:
        # 上一版在这里直接 return：纯 HTTP 目标（没有 WS 是完全正常的形态）会被判 0 帧红，
        # 并且 V2~V10 整组不再评估 —— 验收对这类目标等于罢工，连"拦截通没通"都答不出来。
        if kinds.get("ws_open"):
            red("WS 会话有帧落盘", "%d 次 ws_open 却 0 帧 —— 插件收到握手但没写出帧"
                % kinds["ws_open"])
        elif l1_activity:
            ok("帧数 > 0 或 L1 有活动", "无 WS 帧，但 L1 有 %d 条 HTTP 活动 —— 本批是纯 HTTP 目标"
               % l1_activity)
        else:
            red("L1 什么都没有", "0 帧且 0 条 req/resp/ws_open：链路没通、进程筛错，或目标根本没连")
            say("INFO", "V2~V9 未评估", "L1 全空，后面的判据无从谈起")
            return verdict
    else:
        dirs = collections.Counter(f.get("dir", "?") for f in frames)
        ops = collections.Counter((f.get("dir"), f.get("type"), f.get("opcode")) for f in frames)
        decs = collections.Counter(f.get("dec") for f in frames)
        ok("方向分布", dict(dirs))
        say("INFO", "opcode 分布", dict(ops))
        say("INFO", "解码方式", dict(decs))
        und = [f for f in frames if f.get("dec") == "undecoded"]
        (warn if und else ok)("无未解码帧", "%d 条，原件在 %s" % (
            len(und), [u.get("raw_file") for u in und[:3]]) if und else "0 条")
        if und:
            dl = collections.Counter(f.get("dict_loaded") for f in frames)
            say("INFO", "解码时字典是否在场", dict(dl))
        if dirs.get("c2s", 0) == 0 or dirs.get("s2c", 0) == 0:
            red("双向都有帧", dict(dirs))

    # ---- V2 语义（只对 WS 帧有意义；纯 HTTP 批次跳过而不是判红） ----
    cmds, ress = collections.Counter(), collections.Counter()
    for f in frames:
        t = (f.get("tag") or {})
        for c in (t.get("cmds") or []):
            cmds[(f.get("dir"), c)] += 1
        for r in (t.get("res") or []):
            ress[r] += 1
    if not frames:
        say("INFO", "V2 语义", "本批无 WS 帧，方法数/res 分布不适用")
        n_cmd = 0
    else:
        n_cmd = len({c for d, c in cmds})
        ok("实测方法数(domain.subcmd)", "%d 种，命令对象共 %d 条" % (n_cmd, sum(cmds.values())))
    if frames:
        say("INFO", "c2s 前 12", ", ".join("%s×%d" % (c, n) for (d, c), n in cmds.most_common(12) if d == "c2s"))
        say("INFO", "响应 res 分布", dict(ress))
        errs = {r: n for r, n in ress.items() if r not in ("ok", "session")}
        if ress and not errs:
            warn("错误形态样本", "全是 ok/session —— 这批仍未包含任何 res!=ok")
        elif errs:
            ok("错误形态样本", "抓到非 ok 响应 %s" % errs)
        else:
            red("响应可解析出 res", "0 条响应带 res 字段")
        if "session" not in ress:
            warn("res:session 首帧", "没看到 session 首帧（连接不是冷启动？或服务器没先发话）")

    # ---- V3 会话与插件健康 ----
    say("INFO", "事件计数", dict(kinds))
    opens = [e for e in events if e.get("event") == "ws_open"]
    closes = [e for e in events if e.get("event") in ("ws_close", "ws_orphan")]
    if not opens:
        if kinds.get("req") or kinds.get("resp"):
            say("INFO", "WS 握手", "本批无 WS 会话（纯 HTTP 目标）。心跳/帧时间线这两组对本批不适用。")
        else:
            red("WS 握手至少 1 次", "0 次且也没有 HTTP 活动 —— 业务端口根本没进代理")
    else:
        ok("WS 握手次数", "%d 次，正常关闭 %d 次" % (len(opens), len(closes)))
    if kinds.get("addon_error", 0):
        red("插件零故障", "%d 条 addon_error" % kinds["addon_error"])
    elif not kinds.get("addon_selfproof"):
        red("插件输出通道自证", "events 里没有 addon_selfproof —— 落盘通道从未被证明")
    else:
        sp = [e for e in events if e.get("event") == "addon_selfproof"]
        (ok if str(sp[-1].get("result", "")).startswith("OK") else red)(
            "插件零故障+自证", str(sp[-1].get("result"))[:120])

    # ---- V4 归因 ----
    ipish = [o for o in opens if o.get("host_is_ip")]
    if not opens:
        say("INFO", "握手域名归因", "本批无 WS 握手，不适用（HTTP 侧归因看 V6）")
    elif ipish and not all(o.get("sni") for o in ipish):
        red("连接可归因到真域名", "%d 个握手只有 IP 且无 SNI —— 别按域名筛，先修归因" % len(ipish))
    elif ipish:
        warn("host 是 IP 但 SNI 可用", "%d 个（fake-IP/直连 IP 场景，已用 SNI 兜底）" % len(ipish))
    else:
        ok("握手域名归因", "全部为真域名")
    say("INFO", "握手目标", sorted({(o.get("host"), o.get("port")) for o in opens}))

    # ---- V4b 字段兑现：修好的采集不许再静默退化 ----
    reqs = [e for e in events if e.get("event") in ("req", "resp")]
    if reqs:
        nhdr = sum(1 for e in reqs if isinstance(e.get("headers"), dict) and e.get("headers"))
        if nhdr == 0:
            red("请求/响应头有落盘", "%d 条 req/resp 的 headers 全为空 —— "
                                  "_hdrs 又退回了（上一版就是静默空了 16 批）" % len(reqs))
        else:
            ok("请求/响应头有落盘", "%d/%d 条非空" % (nhdr, len(reqs)))
    tls_e = [e for e in events if e.get("tls_version")]
    cert_e = [e for e in events if e.get("server_cert")]
    (ok if cert_e else warn)("服务端证书落盘", "%d 条含 server_cert" % len(cert_e) if cert_e else
                             "0 条：这批没有 TLS 连接，或 _conninfo 又整体抛了（看 conninfo/server_cert_err）")
    broken = [e for e in events if any(k.endswith("_err") for k in e)]
    if broken:
        say("INFO", "连接描述里的局部失败", "%d 条带 *_err 字段，样例 %s" % (
            len(broken), sorted({k for e in broken for k in e if k.endswith("_err")})[:6]))

    # ---- V5 心跳（只能从日志数，mitmproxy 不把控制帧送进插件） ----
    logp = run / "mitmdump.log"
    if logp.exists():
        txt = logp.read_text(encoding="utf-8", errors="replace")
        rows = _WS_PING.findall(txt)
        gaps = collections.Counter()
        last = {}
        for hh, mm, ss, peer, kind, src in rows:
            if kind.lower() != "ping":
                continue
            cur = datetime.strptime("%s:%s:%s" % (hh, mm, ss), "%H:%M:%S")
            key = (peer or "?")
            if key in last:
                d = round((cur - last[key]).total_seconds())
                if d >= 0:      # 跨午夜不回绕，负数丢弃而不是算成假间隔
                    gaps[d] += 1
            last[key] = cur
        say("INFO", "WS 控制帧(仅存在于日志)", "ping %d / pong %d ；同连接相邻 ping 间隔(秒) %s" % (
            sum(1 for r in rows if r[4].lower() == "ping"),
            sum(1 for r in rows if r[4].lower() == "pong"),
            dict(sorted(gaps.items())[:8]) or "每连接不足两次"))
        if not rows:
            warn("心跳定性", "日志里也没有 ping/pong ⇒ 只能写'本批未见'，不能推'目标无心跳'")
        # 心跳读数的可信度依赖这份日志没被别的进程串流。这条要现查，不能靠"我记得分了文件"。
        pollute = len(re.findall(r"Packets:", txt))
        dlog = run / "dumpcap.log"
        if pollute:
            warn("mitmdump.log 未被串流污染", "%d 行 dumpcap 进度混进来了 —— 心跳计数可能被截断行漏掉"
                 % pollute)
        elif dlog.exists() and dlog.stat().st_size > 0:
            ok("mitmdump.log 未被串流污染", "dumpcap 独立在 dumpcap.log")
        else:
            warn("mitmdump.log 未被串流污染", "没污染，但 dumpcap.log %s" %
                 ("不存在" if not dlog.exists() else "0 字节"))
    else:
        red("mitmdump.log 在位", "缺文件 —— 心跳与握手外的信息全部丢失")

    # ---- V6 台账归属：按本批**实际见到的远端**判，不硬绑默认端口 ----
    # 上一版只看 GAME_PORTS，换一个目标（比如任何非 13701 的应用）就永远判红，
    # 而"能不能归因到进程"这件事和端口号无关。
    gp = set(ncenv.GAME_PORTS)
    led = _jlines(run / "conns.jsonl")
    if led is None:
        red("conns.jsonl 在位", "缺文件 —— 无法把流量归因到进程")
    else:
        rows, lbad = led
        ledger_err = [r for r in rows if r.get("ledger_error")]
        if ledger_err:
            warn("连接台账有错误行", "%d 行，样例 %s" % (len(ledger_err), ledger_err[0]["ledger_error"][:100]))
        want_eps = set()
        for e in events:
            if e.get("event") not in ("req", "resp", "ws_open"):
                continue
            port = str(e.get("port") or "")
            for cand in ((e.get("peer_ip") or [None, None])[0],
                         e.get("host") if _is_ip(e.get("host")) else None):
                if cand:
                    want_eps.add((str(cand), port))
        owners = collections.Counter()
        hit_eps = set()
        for r in rows:
            ra, rp = str(r.get("raddr") or ""), str(r.get("rport") or "")
            if not ra:
                continue
            if (ra, rp) in want_eps:
                hit_eps.add((ra, rp))
                owners[(r.get("proc"), r.get("state"), rp)] += 1
        gp_rows = collections.Counter()
        for r in rows:
            ports = {str(r.get("rport", "")), str(r.get("lport", ""))}
            if ports & gp:
                gp_rows[(r.get("proc"), r.get("state"), sorted(ports & gp)[0])] += 1
        if not want_eps:
            say("INFO", "台账归属", "L1 没有可对账的远端（本批无 req/resp/ws_open）")
        elif hit_eps:
            ok("L1 远端可归因到进程", "%d/%d 个远端在台账里有行；样例 %s" % (
                len(hit_eps), len(want_eps), dict(owners.most_common(4))))
        elif not rows:
            red("L1 远端可归因到进程", "台账一行都没有，L1 却见到 %d 个远端 —— 台账线程没起来"
                % len(want_eps))
        else:
            # 存活 <1s 的连接在 1 Hz 轮询下可以整条漏掉（DOC 里列为 L1/L3 交界的灰区）。
            # 这是工具的已知边界，不是配置错误，判红会让人去查一个不存在的问题。
            warn("L1 远端可归因到进程", "L1 见到 %d 个远端，台账里没有对应行（%d 行台账，采样 1Hz）—— "
                 "多半是存活 <1s 的瞬时连接；要字节级账本得上 ETW"
                 % (len(want_eps), len(rows)))
        say("INFO", "默认目标端口 %s 的连接" % "/".join(sorted(gp)), dict(gp_rows.most_common(6)) or "无")

    # ---- V7 / V7b pcap ----
    pcap = run / "allif.pcapng"
    if not pcap.exists():
        cand = sorted(run.glob("allif*.pcapng"))
        pcap = cand[0] if cand else pcap
    capinfos = _capinfos()
    ci_out = ""
    if capinfos and pcap.exists() and pcap.stat().st_size > 1000:
        # 一次 capinfos 同时取包数与时长：16 MB 的档扫两遍是白费的
        ci_out = _dec(subprocess.run([str(capinfos), str(pcap)],
                                     capture_output=True, timeout=300).stdout)
    npk, pkraw = ncenv.parse_packet_count(ci_out)
    if pcap.exists() and pcap.stat().st_size > 1000:
        if npk is not None:
            dur = [l for l in ci_out.splitlines() if l.startswith("Capture duration")]
            ok("pcap 在位", "%s B | 包数 %d（capinfos 原文『%s』，缩写要展开）| %s"
               % (pcap.stat().st_size, npk, pkraw, dur[:1]))
        else:
            warn("pcap 在位", "%s B，但包数读不出来（没 capinfos 或输出形状变了）—— "
                 "测不到不等于没抓到" % pcap.stat().st_size)
    elif pcap.exists():
        warn("pcap 有内容", "文件存在但只有 %d B" % pcap.stat().st_size)
    else:
        warn("pcap 在位", "无 allif.pcapng（本次关了 pcap？UDP/DNS/漏抓对账全部无证据）")

    l1_eps = set()
    for e in events:
        if e.get("event") in ("req", "ws_open"):
            l1_eps.add((str(e.get("host")), str(e.get("port"))))
            if e.get("sni"):
                l1_eps.add((str(e.get("sni")), str(e.get("port"))))
            # 也按对端 IP 建索引：DNS 没抓到名字时（走缓存）只按域名对账会把有明文的端点误报成漏
            pip = (e.get("peer_ip") or [None, None, None])[0]
            if pip:
                l1_eps.add((str(pip), str((e.get("peer_ip") or [0, 1])[1])))
    meta_p = run / "meta.json"
    try:
        m = json.loads(meta_p.read_text(encoding="utf-8")) if meta_p.exists() else {}
    except Exception as e:
        m = {}
        red("meta.json 可解析", repr(e)[:120])
    names = {str(x).lower().replace(".exe", "") for x in (m.get("procs_filter") or [])}
    game_eps = set()
    for r in (led[0] if led else []):
        ra, rp = str(r.get("raddr") or ""), str(r.get("rport") or "")
        if r.get("state") not in ("Established", "") or not ra or ra in ("0.0.0.0", "::"):
            continue
        if ra.startswith("127."):
            continue
        pr = str(r.get("proc") or "").lower()
        # 被点名进程 + 业务端口 + 代理自身的出向腿（local 模式下真连由 mitmdump 持有）
        if pr in names or rp in gp or pr in ("python", "mitmdump"):
            game_eps.add((ra, rp))
    rc_pc = pcap_reconcile(run, l1_eps, game_eps)
    if rc_pc is None:
        say("INFO", "pcap<->L1 对账", "未做（无 pcap 或无 tshark）—— 这两条结论本批不存在，不等于「没问题」")
    else:
        miss, notes = rc_pc
        say("INFO", "游戏远端 vs L1 明文", "远端 %d 个 / 对账命中 %d / 游戏侧 udp 端口 %s" % (
            notes.get("game_eps"), notes.get("covered"), notes.get("udp_ports_game")))
        if notes.get("errs"):
            warn("pcap<->L1 对账不可信",
                 "tshark 读失败而 capinfos 能报包数 ⇒ 大概率是 pcap 被硬杀截断（缺最后一个块），"
                 "而不是 tshark 坏了。原始错误: %s" % notes["errs"])
        elif miss:
            warn("游戏远端中 L1 无明文的", "%d 个: %s" % (len(miss), miss[:6]))
        else:
            ok("游戏远端中 L1 无明文的", "0 个（TCP 侧全覆盖）")
        odd = {p: n for p, n in (notes.get("udp_ports_game") or {}).items()
               if p not in ("53", "1900", "1901", "5353", "3702")}
        (warn if odd else ok)("UDP 是否承载游戏业务流量", odd or "无（只有 DNS/SSDP/mDNS 类）")
    ce = [e for e in events if e.get("event") == "conn_error"]
    if ce:
        warn("裸连接（建了但没发出请求）", "%d 条: %s" % (
            len(ce), sorted({((e.get("peer_ip") or ["?"])[0], str(e.get("sni"))[:34]) for e in ce}))[:260])
    else:
        ok("裸连接（建了但没发出请求）", "0 条")

    # ---- V8 meta 规格 ----
    if not meta_p.exists():
        red("meta.json 在位", "缺 —— 这批读数两个月后无法归因")
    else:
        need = list(REQUIRED_META) + (list(WS_REQUIRED_META) if frames else [])
        miss_k = [k for k in need if k not in m or m[k] in (None, "", [])]
        (red if miss_k else ok)("meta.json 字段齐", "缺: %s" % miss_k if miss_k else json.dumps(
            {k: m[k] for k in ("label", "procs_filter", "tun_proxy_active", "export_redaction")
             if k in m}, ensure_ascii=False))
        for k in OPTIONAL_META_EMPTY:
            if not m.get(k):
                warn("meta.%s 非空" % k, "为空：被点名进程当时没在跑属合法场景，但这批没有二进制指纹可对账")
        if m.get("tun_proxy_active") is True:
            warn("tun_proxy_active=true", "抓的时候有 TUN/代理在场，出口 IP 与域名解析非直连")

    # ---- V9 qid 配对 ----
    qids_req, qids_resp = set(), set()
    for f in frames:
        t = f.get("text")
        if not t or len(t) > 2_000_000:
            continue
        try:
            j = json.loads(t)
        except Exception:
            continue
        for o in (j if isinstance(j, list) else [j]):
            if isinstance(o, dict) and isinstance(o.get("qid"), int):
                (qids_resp if f.get("dir") == "s2c" else qids_req).add(o["qid"])
    unans = qids_req - qids_resp
    say("INFO", "qid 覆盖", "请求 %d / 响应 %d / 未被应答 %d" % (len(qids_req), len(qids_resp), len(unans)))
    if qids_req and len(unans) > len(qids_req) * 0.2:
        warn("未被应答的请求偏多", "%d/%d" % (len(unans), len(qids_req)))

    # ---- V10 脱敏审计（run 目录里除已知原文之外不许有可关联个人数据） ----
    # 审计对象是**出舱物**，不是本机原始档。run 目录按设计就是原文（数据持有者的分析材料），
    # 在它身上判"未脱敏"是误伤；只有 snapshot/ 存在时才判，命中即拒绝把它当成品。
    snap = run / "snapshot"
    if not snap.exists():
        say("INFO", "出舱物审计", "本批还没出舱（无 snapshot/）。原始档按设计留原文，不外带。")
    else:
        leaks = sanitize.audit_tree(snap)
        (red if leaks else ok)("出舱物 snapshot 已脱敏",
                               "%d 处命中，样例 %s" % (len(leaks), leaks[:2]) if leaks else
                               "%d 个文件审计无命中，可外带" % len(list(snap.glob("*"))))
    if m.get("export_redaction") != "at-export" or m.get("shareable") is not False:
        red("meta.json 声明了出舱口径",
            "export_redaction=%r shareable=%r —— 每批都要显式写明：本机是原文，只有 snapshot 可外带"
            % (m.get("export_redaction"), m.get("shareable")))
    # 出舱边界只声明一次、只在一处声明：meta 里的 export_redaction/shareable 是权威，
    # 具体哪些文件是原文由 report.py 的 raw_manifest.md 现算。这里不再往 meta 写第二份清单。
    say("INFO", "出舱边界", "本机整批为原文（分析材料）；可外带仅 snapshot/。清单见 raw_manifest.md")
    return verdict


# ---------------- 自检：每种坏法都要被判红 ----------------
_GOOD_FRAMES = [
    {"ts": "t", "flow": "a1", "seq": 0, "dir": "s2c", "opcode": 1, "type": "text", "size": 20,
     "dec": "text", "dict_loaded": True, "text": '{"res":"session","session":"x"}',
     "tag": {"json": True, "res": ["session"]}},
    {"ts": "t", "flow": "a1", "seq": 1, "dir": "c2s", "opcode": 1, "type": "text", "size": 30,
     "dec": "text", "dict_loaded": True,
     "text": '[{"cmd":"battle","qid":1,"params":{"cmd":"card_use"}}]',
     "tag": {"json": True, "cmds": ["battle.card_use"]}},
    {"ts": "t", "flow": "a1", "seq": 2, "dir": "s2c", "opcode": 1, "type": "text", "size": 30,
     "dec": "text", "dict_loaded": True, "text": '{"res":"err","qid":1}',
     "tag": {"json": True, "res": ["err"]}},
]
_GOOD_EVENTS = [
    {"event": "addon_selfproof", "result": "OK(写入3行,读回1条,probe已脱敏)"},
    {"event": "ws_open", "host": "svc.example-lab.test", "port": 13701, "host_is_ip": False,
     "sni": "svc.example-lab.test", "peer_ip": ["203.0.113.7", 13701], "path": "/api/",
     "tls_version": "TLSv1.3", "server_cert": {"cn": "svc.example-lab.test", "issuer": "O=netcatch"}},
    {"event": "ws_close", "flow": "a1", "close_code": 1005},
    {"event": "req", "host": "svc.example-lab.test", "port": 13701, "method": "GET",
     "path": "/api/", "headers": {"content-type": "application/json"},
     "tls_version": "TLSv1.3", "peer_ip": ["203.0.113.7", 13701]},
]


def _mk(kind="healthy", extra_files=None):
    run = Path(tempfile.mkdtemp(prefix="nc_vfy_"))
    if kind != "nometa":
        frames_rows = (_GOOD_FRAMES if kind not in ("empty", "onedir", "httponly") else
                       ([_GOOD_FRAMES[0]] if kind == "onedir" else []))
        (run / "frames.jsonl").write_text(
            "\n".join(json.dumps(f, ensure_ascii=False) for f in frames_rows), encoding="utf-8")
        if kind == "httponly":
            ev_rows = [e for e in _GOOD_EVENTS if e.get("event") not in ("ws_open", "ws_close")]
        else:
            ev_rows = _GOOD_EVENTS
        (run / "events.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in ev_rows), encoding="utf-8")
        (run / "conns.jsonl").write_text(json.dumps(
            {"rport": 13701, "raddr": "203.0.113.7", "state": "Established",
             "proc": "target-proc", "kind": "tcp"}, ensure_ascii=False), encoding="utf-8")
        (run / "mitmdump.log").write_text(
            "[09:00:00.100][203.0.113.7:13701] Received WebSocket ping from server (payload: b'hb')\n"
            "[09:00:45.120][203.0.113.7:13701] Received WebSocket ping from server (payload: b'hb')\n",
            encoding="utf-8")
        (run / "dumpcap.log").write_text("Packets: 12\n", encoding="utf-8")
        (run / "allif.pcapng").write_bytes(b"\x00" * 2000)
    meta = {k: "x" for k in list(REQUIRED_META) + WS_REQUIRED_META}
    meta.update({"tun_proxy_active": False, "exe_identity": [{"proc": "p", "sha256_16": "ab"}],
                 "export_redaction": "at-export", "shareable": False})
    if kind == "nometa":
        (run / "meta.json").write_text('{"label":"x"}', encoding="utf-8")
    elif kind == "badmeta":
        (run / "meta.json").write_text("{ not json", encoding="utf-8")
    else:
        (run / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    for name, content in (extra_files or {}).items():
        tgt = run / name
        tgt.parent.mkdir(parents=True, exist_ok=True)   # snapshot/ 这类子目录要先建出来
        tgt.write_text(content, encoding="utf-8")
    return run


_CASES = [
    ("empty", "有握手却 0 帧", True),
    ("httponly", "纯 HTTP 目标（无 WS）", False),
    ("onedir", "单向帧", True),
    ("nometa", "缺 meta", True),
    ("badmeta", "meta 不可解析", True),
    ("leak", "快照含未脱敏原值", True),
    ("healthy", "健康 run", False),
]
_LEAK = '{"user_access_token": "%s", "publisher_uid": "770000000202", "ca_sha1": "%s"}' % ("A" * 200, "0" * 40)


def selftest():
    bad = []
    for kind, desc, expect_red in _CASES:
        L.clear()
        run = _mk(kind, extra_files={"snapshot/leaky.csv": _LEAK} if kind == "leak" else None)
        try:
            v = verify(run)
        except Exception as e:
            print("  %-16s 异常 %r" % (desc, e))
            bad.append(desc)
            continue
        got_red = v["RED"] > 0
        tag = "OK" if got_red == expect_red else "NO"
        print("  %-4s %-16s RED=%d WARN=%d  期望%s红" % (tag, desc, v["RED"], v["WARN"],
                                                        "要" if expect_red else "不"))
        if got_red != expect_red:
            bad.append(desc)
    # 尺子自己的对照：域名匹配不许靠双向子串
    checks = [(_host_match("live-a.example.com", "live-a.example.com"), True),
              (_host_match("example.com", "live.example.com"), True),
              (_host_match("svc-a", "live-svc-a"), False),
              (_host_match("a.com", "ab.com"), False),
              (_host_match("203.0.113.7", "203.0.113.7"), True)]
    if any(g != e for g, e in checks):
        print("  NO   域名匹配对照     %s" % checks)
        bad.append("host_match")
    else:
        print("  OK   域名匹配对照     5 例全对（同后缀算命中，前缀包含不算）")
    from preflight import port_hit
    pc = [(port_hit("TCP  0.0.0.0:4435 0.0.0.0:0 LISTENING 1", "443"), False),
          (port_hit("TCP  [::]:13701 [::]:0 LISTENING 1", "13701"), True)]
    if any(g != e for g, e in pc):
        print("  NO   端口匹配对照     %s" % (pc,))
        bad.append("port_hit")
    else:
        print("  OK   端口匹配对照     4435 不误判成 443")
    if bad:
        print("SELFTEST RED: 不合格的用例：%s" % ", ".join(bad))
        return 1
    print("SELFTEST OK: 5 种坏法全判红、健康 run 判绿，两把尺子的对照也过了")
    return 0


if __name__ == "__main__":
    ncenv.utf8_stdout()
    ap = argparse.ArgumentParser()
    ap.add_argument("run", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if not a.run:
        print("用法: verify_run.py <run目录>")
        sys.exit(2)
    v = verify(Path(a.run))
    print("---- VERDICT: RED=%d WARN=%d ----" % (v["RED"], v["WARN"]))
    sys.exit(1 if v["RED"] else 0)
