# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
report.py — 呈现层：把一个 run 目录里三层证据汇成**可外带的脱敏快照**。

仓库里原本只有采集( catch/addon )、体检( preflight )、验收( verify_run )，
没有一件东西是"给人看的"。这个模块补的就是这一格：全量抓包的清晰呈现，
不局限于某一类数据。

产出 run/snapshot/：
  00_overview.md        本批硬数字 + 每层证据的有无 + 口径警告
  10_connections.csv    每个远端：地址、解析到的域名、L1/L2/L3 哪层有它、归属进程
  20_http.csv           req/resp：方法、状态、长度、头名、证书摘要
  30_ws_sessions.csv    每条 WS 会话：握手、子协议、帧数、字节、关闭码
  31_ws_frames.csv      帧时间线：方向、opcode、解码方式、tag、脱敏后的正文
  40_heartbeat.md       ping/pong 计数与相邻间隔直方图（只从干净的 mitmdump.log 数）
  50_certificates.csv   服务端证书：主体/颁发者/SAN/指纹/有效期/TLS 版本与套件
  raw_manifest.md       本目录里**不可外带**的原件清单（capture.flows、bodies/*.bin）

capture.flows 用内置的 tnetstring 读法离线解析（纯标准库，不起 mitmdump）：
jsonl 缺的证书/TLS/头信息在 flows 里是全的，老批次因此不用重抓也能补算。
从 flows 读出来的一切**先过 sanitize 再落盘**，所以 snapshot 里没有原文凭据。
"""
import argparse
import collections
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402
import sanitize  # noqa: E402

# ---------------- tnetstring（mitmproxy 的 flows 序列化格式） ----------------
def _read_ts(buf, i=0):
    """返回 (value, next_index)。格式: <len>:<payload><type>
    ',' 整数  ';' 字节  ']' 列表  '}' 字典"""
    j = buf.index(b":", i)
    n = int(buf[i:j])
    start = j + 1
    end = start + n
    tag = buf[end:end + 1]
    if tag == b",":
        return int(buf[start:end]), end + 1
    if tag == b";":
        return buf[start:end], end + 1
    if tag == b"]":
        out, k = [], start
        while k < end:
            v, k = _read_ts(buf, k)
            out.append(v)
        return out, end + 1
    if tag == b"}":
        out, k = {}, start
        while k < end:
            key, k2 = _read_ts(buf, k)
            val, k = _read_ts(buf, k2)
            out[key.decode("utf-8", "replace") if isinstance(key, bytes) else key] = val
        return out, end + 1
    raise ValueError("未知 tnetstring 类型标记 %r @%d" % (tag, end))


def iter_flows(path):
    """流式读：文件可能被硬杀截断，末尾半条要能容错。"""
    buf = Path(path).read_bytes()
    i = 0
    while i < len(buf):
        try:
            val, i = _read_ts(buf, i)
        except Exception:
            return
        yield val


def _s(x):
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8")
        except Exception:
            return x.decode("latin-1", "replace")
    return x


def _hdrs_to_dict(hs):
    out = {}
    if not isinstance(hs, list):
        return out
    for pair in hs:
        if not isinstance(pair, list) or len(pair) != 2:
            continue
        k = _s(pair[0])
        v = _s(pair[1])
        out[k] = (out[k] + ", " + v) if k in out else v
    return out


def parse_flows(path, max_flows=20000):
    """从 capture.flows 抽出连接/证书/HTTP 事实。形状不认识就整条标记 unparsed，不猜。"""
    flows, unparsed = [], 0
    for st in list(iter_flows(path))[:max_flows]:
        try:
            if not isinstance(st, dict):
                unparsed += 1
                continue
            sc = st.get("server_conn") or {}
            cc = st.get("client_conn") or {}
            req = st.get("request") or {}
            resp = st.get("response") or {}
            certs = []
            for c in (sc.get("certificate_list") or []):
                if isinstance(c, dict):
                    certs.append({k: _s(v) for k, v in c.items() if k in ("raw", "der")})
            f = {
                "id": _s(st.get("id", ""))[:8],
                "type": _s(st.get("type", "")),
                "marked": st.get("marked"),
                "server_addr": _s(sc.get("address")),
                "peername": _s(sc.get("peername")),
                "sockname": _s(sc.get("sockname")),
                "sni": _s(sc.get("sni")),
                "tls_version": _s(sc.get("tls_version")),
                "cipher": _s(sc.get("cipher")),
                "alpn": _s(sc.get("alpn")),
                "cert_count": len(certs),
                "client_peername": _s(cc.get("peername")),
                "method": _s(req.get("method")),
                "host": _s(req.get("host")),
                "port": req.get("port"),
                "path": _s(req.get("path"))[:300] if req.get("path") else None,
                "http_version": _s(req.get("http_version")),
                "req_headers": _hdrs_to_dict(req.get("headers")),
                "resp_status": resp.get("status_code") or resp.get("code"),
                "resp_headers": _hdrs_to_dict(resp.get("headers")),
                "resp_len": len(resp.get("content") or b""),
                "req_len": len(req.get("content") or b""),
                "error": _s(st.get("error")),
            }
            flows.append(f)
        except Exception:
            unparsed += 1
    return flows, unparsed


# ---------------- 视图 ----------------
def _jlines(p):
    if not p.exists():
        return []
    out = []
    for line in open(p, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


_WS_PING = re.compile(r"\[(\d{2}):(\d{2}):(\d{2})\.\d+\](?:\[([^\]]*)\])?\s*"
                      r"Received\s+WebSocket\s+(ping|pong)\s+from\s+(\S+)", re.I)


def _w(path, rows, fieldnames):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def build(run: Path, no_flows=False):
    ncenv.utf8_stdout()
    run = Path(run)
    if not run.exists():
        print("RED: 找不到 run 目录", run)
        return 1
    busy, why = ncenv.writer_alive(run)
    if busy:
        print("RED: 这批还有人在写/还没收尾，拒绝生成快照：%s" % why)
        print("     在一批正在被测的产物上改文件，下一次测试就是在对着半改的目录出结论。等收尾完再跑。")
        return 1
    out = run / "snapshot"
    out.mkdir(exist_ok=True)
    meta = {}
    try:
        meta = json.loads((run / "meta.json").read_text(encoding="utf-8"))
    except Exception as e:
        print("RED: meta.json 读不了 %r" % e)
        return 1
    # 快照不信任任何上游：即便某一批的 meta 是在旧版本（未脱敏）下写的，这里也不会把原值带进快照。
    # 出舱前的审计会兜住，但兜住之前先不该写进去。
    meta = sanitize.redact_meta(meta)
    events = _jlines(run / "events.jsonl")
    frames = _jlines(run / "frames.jsonl")
    conns = _jlines(run / "conns.jsonl")
    markers = _jlines(run / "markers.jsonl")
    summary = {}
    try:
        summary = json.loads((run / "run_summary.json").read_text(encoding="utf-8"))
    except Exception:
        pass

    flows, unparsed = ([], 0)
    flows_note = "未读"
    if not no_flows and (run / "capture.flows").exists():
        flows, unparsed = parse_flows(run / "capture.flows")
        flows_note = "%d 条 flow，%d 条形状不认识" % (len(flows), unparsed)

    # ---- 10 连接清单：L1/L2/L3 分层证据，一个远端一行 ----
    l1 = {}
    for e in events:
        if e.get("event") in ("req", "ws_open", "resp"):
            key = (str(e.get("host")), str(e.get("port")))
            d = l1.setdefault(key, {"events": 0, "sni": None, "tls": None, "hosts_ip": e.get("host_is_ip")})
            d["events"] += 1
            d["sni"] = d["sni"] or e.get("sni")
            d["tls"] = d["tls"] or e.get("tls_version")
    l3 = collections.defaultdict(lambda: {"samples": 0, "procs": set(), "pids": set(), "states": set()})
    for r in conns:
        if r.get("ledger_error"):
            continue
        ra, rp = str(r.get("raddr") or ""), str(r.get("rport") or "")
        if not ra or not rp:
            continue
        d = l3[(ra, rp)]
        d["samples"] += 1
        if r.get("proc"):
            d["procs"].add(str(r.get("proc")))
        if r.get("pid"):
            d["pids"].add(str(r.get("pid")))
        if r.get("state"):
            d["states"].add(str(r.get("state")))
    # DNS 名字：从 events 的 sni/host 与 flows 里凑，再退到 pcap（不在此处跑 tshark，那是 verify 的事）
    rows = []
    for (host, port), d in sorted(l1.items(), key=lambda x: (x[0][1], x[0][0])):
        rows.append({"scope": "L1", "host": host, "port": port, "peer_ip": "",
                     "sni": d.get("sni") or "", "tls": d.get("tls") or "",
                     "evidence": "L1", "l1_events": d["events"],
                     "procs": "", "pids": "", "states": "", "l3_samples": 0})
    for (ra, rp), d in sorted(l3.items(), key=lambda x: (x[0][1], x[0][0])):
        hit_l1 = any(_hostish(str(h), ra) and str(p) == rp for (h, p) in l1)
        rows.append({"scope": "L3", "host": "", "port": rp, "peer_ip": ra, "sni": "",
                     "tls": "", "evidence": ("L1+L3" if hit_l1 else "仅L3"),
                     "l1_events": 0, "procs": ",".join(sorted(d["procs"])[:4]),
                     "pids": ",".join(sorted(d["pids"])[:4]),
                     "states": ",".join(sorted(d["states"])), "l3_samples": d["samples"]})
    only_l3 = [r for r in rows if r["evidence"] == "仅L3" and r["scope"] == "L3"]
    _w(out / "10_connections.csv", rows,
       ["scope", "host", "port", "peer_ip", "sni", "tls", "evidence",
        "l1_events", "procs", "pids", "states", "l3_samples"])

    # ---- 20 HTTP ----
    hrows = []
    for e in events:
        if e.get("event") not in ("req", "resp"):
            continue
        hrows.append(sanitize.redact_event({
            "ts": e.get("ts"), "kind": e.get("event"), "flow": e.get("flow"),
            "host": e.get("host"), "port": e.get("port"), "method": e.get("method"),
            "path": e.get("path"), "status": e.get("status"), "reason": e.get("reason"),
            "len": e.get("len"), "sni": e.get("sni"), "tls": e.get("tls_version"),
            "cipher": e.get("tls_cipher"), "alpn": e.get("alpn"),
            "header_keys": ",".join(sorted((e.get("headers") or {}).keys())[:12]),
            "body_ref": e.get("body_ref"), "peer_ip": (e.get("peer_ip") or ["", ""])[0],
        }))
    for f in flows:
        if f.get("type") not in ("http", "") or not f.get("method"):
            continue
        if any(str(r.get("flow")) == str(f.get("id")) for r in hrows):
            continue
        hrows.append(sanitize.redact_event({
            "ts": "", "kind": "flow", "flow": f.get("id"), "host": f.get("host"),
            "port": f.get("port"), "method": f.get("method"), "path": f.get("path"),
            "status": f.get("resp_status"), "len": f.get("resp_len"),
            "tls": f.get("tls_version"), "alpn": f.get("alpn"), "sni": f.get("sni"),
            "header_keys": ",".join(sorted((f.get("req_headers") or {}).keys())[:12]),
        }))
    _w(out / "20_http.csv", hrows,
       ["ts", "kind", "flow", "host", "port", "method", "path", "status", "reason",
        "len", "sni", "tls", "cipher", "alpn", "header_keys", "body_ref", "peer_ip"])

    # ---- 30 WS 会话 / 31 帧 ----
    sess = [e for e in events if e.get("event") == "ws_open"]
    closes = {c.get("flow"): c for c in events if c.get("event") in ("ws_close", "ws_orphan")}
    srows = []
    for s in sess:
        c = closes.get(s.get("flow"), {})
        srows.append(sanitize.redact_event({
            "flow": s.get("flow"), "host": s.get("host"), "port": s.get("port"),
            "path": s.get("path"), "status": s.get("resp_status"),
            "client_proto": s.get("ws_client_protocols"), "server_proto": s.get("ws_server_protocol"),
            "client_ext": s.get("ws_client_extensions"), "server_ext": s.get("ws_server_extensions"),
            "opened_at": s.get("opened_at"), "closed_at": c.get("ts"),
            "msgs": c.get("msgs", s.get("msgs")), "bytes": c.get("bytes", s.get("bytes")),
            "close_code": c.get("close_code"), "close_reason": c.get("close_reason"),
            "closed_by_client": c.get("closed_by_client"),
            "event_kind": "closed" if c else ("orphan" if s.get("flow") in closes else "unclosed"),
            "sni": s.get("sni"), "tls": s.get("tls_version"),
        }))
    _w(out / "30_ws_sessions.csv", srows,
       ["flow", "host", "port", "path", "status", "client_proto", "server_proto",
        "client_ext", "server_ext", "opened_at", "closed_at", "msgs", "bytes",
        "close_code", "close_reason", "closed_by_client", "event_kind", "sni", "tls"])

    frows = []
    for f in frames:
        r = sanitize.redact_frame(f)
        t = r.get("text") or ""
        frows.append({"ts": r.get("ts"), "flow": r.get("flow"), "seq": r.get("seq"),
                      "dir": r.get("dir"), "opcode": r.get("opcode"), "type": r.get("type"),
                      "size": r.get("size"), "dec": r.get("dec"),
                      "dict_loaded": r.get("dict_loaded"),
                      "cmds": ",".join((r.get("tag") or {}).get("cmds") or [])[:120],
                      "res": ",".join((r.get("tag") or {}).get("res") or [])[:60],
                      "json": (r.get("tag") or {}).get("json"),
                      "flags": " ".join(k for k in ("dropped", "injected") if r.get(k)),
                      "body_file": r.get("body_file") or r.get("raw_file") or "",
                      "text_head": re.sub(r"\s+", " ", t)[:400]})
    _w(out / "31_ws_frames.csv", frows,
       ["ts", "flow", "seq", "dir", "opcode", "type", "size", "dec", "dict_loaded",
        "cmds", "res", "json", "flags", "body_file", "text_head"])

    # ---- 40 心跳 ----
    mlog = (run / "mitmdump.log").read_text(encoding="utf-8", errors="replace") \
        if (run / "mitmdump.log").exists() else ""
    rows_hb = _WS_PING.findall(mlog)
    gaps = collections.Counter()
    last = {}
    for hh, mm, ss, peer, kind, src in rows_hb:
        if kind.lower() != "ping":
            continue
        cur = datetime.strptime("%s:%s:%s" % (hh, mm, ss), "%H:%M:%S")
        key = peer or "?"
        if key in last:
            d = round((cur - last[key]).total_seconds())
            if d >= 0:
                gaps[d] += 1
        last[key] = cur
    pollute = mlog.count("Packets:")
    hb = ["# 心跳（WS 控制帧）", "",
          "mitmproxy 不把 ping/pong 交给插件，所以**只能**从 mitmdump.log 数。帧表里没有 opcode 9 是设计如此，"
          "不是漏采 —— selftest 腿 A 用负向断言钉着这条边界。", "",
          "- ping/pong 行数: %d（ping %d / pong %d）" % (
              len(rows_hb), sum(1 for r in rows_hb if r[4].lower() == "ping"),
              sum(1 for r in rows_hb if r[4].lower() == "pong")),
          "- 同连接相邻 ping 间隔(秒): %s" % (dict(sorted(gaps.items())[:10]) or "每连接不足两次"),
          "- 日志串流污染: %d 行 dumpcap 进度%s" % (pollute, "" if not pollute else "（心跳计数可能因此漏掉被截断的行）"),
          ""]
    if not rows_hb:
        hb.append("本批日志里没有 ping/pong。**只能写「本批未见」，不许写成「目标无心跳」。**")
    (out / "40_heartbeat.md").write_text("\n".join(hb), encoding="utf-8")

    # ---- 50 证书 ----
    crows = []
    for e in events:
        c = e.get("server_cert")
        if isinstance(c, dict):
            crows.append({"source": "events", "ts": e.get("ts"), "host": e.get("host"),
                          "port": e.get("port"), "sni": e.get("sni"),
                          "tls": e.get("tls_version"), "cipher": e.get("tls_cipher"),
                          "alpn": e.get("alpn"), "cn": c.get("cn"), "org": c.get("org"),
                          "issuer": c.get("issuer"), "serial": c.get("serial"),
                          "notbefore": c.get("notbefore"), "notafter": c.get("notafter"),
                          "san": ",".join(c.get("san") or []),
                          "fp_sha1": c.get("fingerprint_sha1"), "chain_len": e.get("server_cert_chain_len", 1)})
    for f in flows:
        if f.get("cert_count"):
            crows.append({"source": "capture.flows", "host": f.get("host"), "port": f.get("port"),
                          "sni": f.get("sni"), "tls": f.get("tls_version"), "cipher": f.get("cipher"),
                          "alpn": f.get("alpn"), "chain_len": f.get("cert_count"),
                          "cn": "", "issuer": "", "san": "", "fp_sha1": "", "serial": "",
                          "notbefore": "", "notafter": "", "org": "", "ts": ""})
    _w(out / "50_certificates.csv", crows,
       ["source", "ts", "host", "port", "sni", "tls", "cipher", "alpn",
        "cn", "org", "issuer", "serial", "notbefore", "notafter", "san", "fp_sha1", "chain_len"])
    if not any(r["source"] == "events" for r in crows):
        crows_note = ("events.jsonl 里没有 server_cert：要么这批全是明文连接，"
                      "要么插件的 _conninfo 又整体抛了。证书条数来自 flows 的只有链长。")
    else:
        crows_note = "events.jsonl 提供 %d 条完整证书摘要" % sum(1 for r in crows if r["source"] == "events")

    # ---- raw_manifest ----
    raws = []
    if (run / "capture.flows").exists():
        raws.append(("capture.flows", "mitmproxy 原生全量档，含未脱敏请求体/头/cookie 原文"))
    for p in sorted((run / "bodies").glob("*")) if (run / "bodies").exists() else []:
        if p.suffix == ".bin":
            raws.append(("bodies/%s" % p.name, "原始字节（未解码或响应体原文）"))
            if len(raws) > 6:
                raws.append(("bodies/*.bin 其余", "同上"))
                break
    (out / "raw_manifest.md").write_text(
        "\n".join(["# 本目录之外不可外带的文件", "",
                   "snapshot/ 里的一切都在出舱这一步过了 sanitize。下面这些是**原文**，别整目录发出去：", ""] +
                  ["- `%s` — %s" % r for r in raws] +
                  ["", "- allif.pcapng — 全网卡密文；不含明文，但含你的公网 IP、DNS 查询名字与时间线，"
                   "同样不要随意外发。",
                   "- mitmdump.log — 可能夹带未脱敏的 URL 与对端地址。",
                   ""] ), encoding="utf-8")

    # ---- 00 概览 ----
    decs = collections.Counter(f.get("dec") for f in frames)
    dirs = collections.Counter(f.get("dir") for f in frames)
    kinds = collections.Counter(e.get("event") for e in events)
    ov = ["# %s" % meta.get("label", run.name), "",
          "- 窗口: %s → %s" % (meta.get("started"), meta.get("ended")),
          "- 为什么抓: %s" % meta.get("trigger"),
          "- 点名进程: %s" % ", ".join(meta.get("procs_filter") or []),
          "- 出舱口径: %s（本机 run 是原文=分析材料；只有本 snapshot 可外带，见 raw_manifest.md）"
          % meta.get("export_redaction", "at-export"),
          "- 出口是否直连: tun_proxy_active=%s" % meta.get("tun_proxy_active"),
          "", "## 每层证据的有无",
          "- L1 载荷: %d 帧（%s）；事件 %s" % (len(frames), dict(dirs), dict(kinds)),
          "- L2 链路: %s" % ("有 allif.pcapng" if any(p.name.startswith("allif") and p.suffix == ".pcapng"
                                                  for p in run.iterdir()) else "**缺** —— UDP/DNS/漏抓对账本批无证据"),
          "- L3 归属: %d 行台账（%d 行错误）" % (len(conns), sum(1 for c in conns if c.get("ledger_error"))),
          "- 兜底 flows: %s" % flows_note,
          "", "## 解码与残留",
          "- 解码方式: %s" % dict(decs),
          "- zstd 字典在场: %s" % meta.get("zstd_dict_loaded"),
          "- undecoded 帧: %d 条，原件另存 bodies/raw_*" % decs.get("undecoded", 0),
          "- 打标: %d 条%s" % (len(markers), ("；" + ", ".join(str(m.get("label")) for m in markers[:10])) if markers
                       else "（这批没打标，动作与帧只能靠时间推断对齐）"),
          "", "## 分层对账",
          "- L1 远端 %d 个 / L3 远端 %d 个 / 只在 L3 出现的 %d 个" % (len(l1), len(l3), len(only_l3)),
          "- 只在 L3 的（TCP 建了但没走明文 / UDP / 瞬时连接）: %s" %
          (json.dumps([o["peer_ip"] + ":" + o["port"] for o in only_l3][:12], ensure_ascii=False) or "无"),
          "- 证书: %s" % crows_note,
          ""]
    if summary:
        ov += ["## 收尾汇总", "```json", json.dumps(summary, ensure_ascii=False, indent=1), "```", ""]
    if meta.get("build_hint"):
        ov += ["## 本批身份指纹（全部为加盐哈希或长度，无原值）", "```json", json.dumps(
            {k: meta.get(k) for k in ("build_hint", "patch_version", "world_hint", "load_world_id",
                                      "game_user_id", "publisher_uid", "user_access_token_len",
                                      "ca_sha1", "exe_identity") if k in meta},
            ensure_ascii=False, indent=1), "```", ""]
    (out / "00_overview.md").write_text("\n".join(ov), encoding="utf-8")

    # ---- 出舱前审计：尺子必须现过一遍 ----
    leaks = sanitize.audit_tree(out)
    if leaks:
        print("RED: snapshot 里审计到未脱敏内容，已生成但**不可外带**：%s" % (leaks[:3],))
        print("     不要把这批当脱敏成品交付。修 sanitize 的策略表，别手改产物。")
        return 1
    print("snapshot ->", out)
    for p in sorted(out.glob("*")):
        print("   %-24s %8d B" % (p.name, p.stat().st_size))
    print("OK: 出舱前审计无命中（snapshot/ 内 %d 个文件）" % len(list(out.glob('*'))))
    return 0


def _hostish(a, b):
    """L1 的 host 与 L3 的 IP 是不是同一个东西：同名、后缀同名，或一方就是另一方的解析结果。"""
    a, b = str(a).lower(), str(b).lower()
    if not a or not b:
        return False
    if a == b:
        return True
    return a.endswith("." + b) or b.endswith("." + a)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("run", nargs="?")
    ap.add_argument("--no-flows", action="store_true", help="不解析 capture.flows")
    a = ap.parse_args()
    if not a.run:
        print("用法: report.py <run目录> [--no-flows]   （或 python tools/catch.py snapshot）")
        sys.exit(2)
    sys.exit(build(Path(a.run), no_flows=a.no_flows))
