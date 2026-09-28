# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
net_catch_addon.py — mitmproxy 插件：把 TCP/WS 明文与连接事实落到 run 目录。

三个已知边界（不是漏了，是 mitmproxy 不给）：
  * WS 的 ping/pong **控制帧不进 addon**（mitmproxy 只写成 log 行）。心跳必须看同目录
    mitmdump.log，不要看 frames.jsonl。selftest 腿 A 用一条负向断言钉住这个事实。
  * 只覆盖 TCP。UDP/QUIC/DNS 由 catch.py 的 dumpcap 层负责。
  * 进程归属不来自 mitmproxy，来自 L3 连接台账（PID↔地址），别在这里猜。

字段名全部对着 mitmproxy 12.2.3 的 connection.py/certs.py 核过：
  Server.address=(host,port) / Server.peername=(解析后的 ip,port) / Server.sockname=(本机源 ip,port)
  Connection.certificate_list=[Cert]（Server.cert 已 deprecated）
  Cert.subject/issuer=list[(k,v)]，.cn/.organization=str，.altnames=GeneralNames，.fingerprint()=bytes
每个字段单独 try：一处属性名错不能让后面整批字段一起消失（上一版就是这么静默丢了证书与 TLS 参数）。

环境变量：NC_OUT=run 目录（必填，由 catch.py 注入）
"""
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402
import sanitize  # noqa: E402

try:
    import zstandard as _zstd
    HAS_ZSTD = True
except Exception:
    HAS_ZSTD = False

OUT = Path(os.environ["NC_OUT"]) if os.environ.get("NC_OUT") else None
TEXT_CAP = int(os.environ.get("NC_TEXT_CAP", str(1024 * 1024)))
HEX_CAP = int(os.environ.get("NC_HEX_CAP", "4096"))
BODY_CAP = 8 * 1024 * 1024
ADDON_VER = ncenv.ADDON_VER
_PKT_RE = re.compile(r"Packet_To[SC]_[A-Za-z0-9_]+")


def _iso(ts=None):
    ts = time.time() if ts is None else ts
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _is_ipish(s):
    s = str(s or "")
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s)) or ":" in s


def _hdrs(h):
    """mitmproxy 12 的 items(multi=True) 已经返回 str。对 str 调 .decode() 必抛，
    上一版把它吞成 {}，于是"完整请求头"这件事静默地从来没兑现过。"""
    out = {}
    try:
        for k, v in h.items(multi=True):
            k = k.decode("latin-1") if isinstance(k, bytes) else str(k)
            v = v.decode("latin-1") if isinstance(v, bytes) else str(v)
            prev = out.get(k)
            out[k] = (prev + ", " + v) if prev else v
    except Exception:
        return {"_hdrs_err": "unreadable"}
    return out


def _cert_summary(c):
    """只留可归因的小字段。PEM 全文不进 jsonl（大，且 capture.flows 里本来就有）。"""
    d = {}
    for key, fn in (("cn", lambda: c.cn), ("org", lambda: c.organization),
                    ("subject", lambda: ";".join("%s=%s" % kv for kv in c.subject)),
                    ("issuer", lambda: ";".join("%s=%s" % kv for kv in c.issuer)),
                    ("serial", lambda: str(c.serial)),
                    ("notbefore", lambda: c.notbefore.strftime("%Y-%m-%d %H:%M:%S")),
                    ("notafter", lambda: c.notafter.strftime("%Y-%m-%d %H:%M:%S")),
                    ("keyinfo", lambda: "%s/%s" % c.keyinfo),
                    ("is_ca", lambda: bool(c.is_ca))):
        try:
            d[key] = fn()
        except Exception:
            pass
    try:
        fp = c.fingerprint()
        d["fingerprint_sha1"] = fp.hex() if isinstance(fp, bytes) else str(fp)
    except Exception:
        pass
    try:
        d["san"] = [str(n.value) for n in list(c.altnames)[:8]]
    except Exception:
        pass
    return d


class NetCatch:
    def __init__(self):
        self.f_msg = None
        self.f_evt = None
        self.seen = {}
        self.flows = {}
        self.seq = 0
        self.zctx = None
        self.errors = 0
        self.dict_loaded = False

    # ---- 落盘与自证 ----
    def _open(self):
        if OUT is None:
            sys.stderr.write("[RED] net_catch_addon: NC_OUT 未设置，插件不会落盘任何数据\n")
            return False
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "bodies").mkdir(exist_ok=True)
        self.f_msg = open(OUT / "frames.jsonl", "a", encoding="utf-8")
        self.f_evt = open(OUT / "events.jsonl", "a", encoding="utf-8")
        self.zctx, self.dict_loaded = self._load_dict()
        self._event("addon_loaded", addon=ADDON_VER, loaded_at=_iso(),
                    has_zstd=HAS_ZSTD, zstd_dict_loaded=self.dict_loaded,
                    zstd_dict_path=str(ncenv.dict_path()), out=str(OUT))
        # 自证三条，方向各不相同：
        #   ① 写得进盘并读得回来      —— 输出通道可信
        #   ② 本机这条**必须还是原文** —— 采集口不该擦。查不到秘密反而是坏事，
        #      说明有人把脱敏挪回了写入点，那会让数据持有者看不见自己的分析材料
        #   ③ 过一遍出舱过滤器后必须查不到秘密，且非敏感形状字段原样保留
        # 只测③的话，"绿而不咬"照样能发生：把写入也擦了，③ 一样过。
        proof = "RED(not reached)"
        try:
            self._event("export_probe", user_access_token="X" * 40,
                        publisher_uid="770000000202", keep_me="shape-ok")
            self.f_evt.flush()
            lines = [json.loads(l) for l in open(OUT / "events.jsonl", encoding="utf-8")]
            back = [l for l in lines if l.get("event") == "addon_loaded"]
            if not back or back[-1].get("addon") != ADDON_VER:
                raise AssertionError("读回内容不含本次 addon 版本")
            raw = [l for l in lines if l.get("event") == "export_probe"][-1]
            if not sanitize.audit_text(json.dumps(raw, ensure_ascii=False)):
                raise AssertionError("本机落盘已被脱敏：采集口不该擦，脱敏只该发生在出舱口")
            export = sanitize.redact_event(raw)
            leaks = sanitize.audit_text(json.dumps(export, ensure_ascii=False))
            if leaks:
                raise AssertionError("出舱过滤器没生效，仍审计到 %s" % (leaks[:1],))
            if export.get("keep_me") != "shape-ok":
                raise AssertionError("出舱过滤器误伤了非敏感字段")
            if export.get("publisher_uid") == raw.get("publisher_uid"):
                raise AssertionError("ID 没被加盐哈希")
            proof = "OK(写入%d行,读回%d条,原文留存,出舱过滤器有效)" % (len(lines), len(back))
        except Exception as e:
            proof = "RED %r" % e
            sys.stderr.write("[RED] net_catch_addon 自证失败: %r\n" % e)
        self._event("addon_selfproof", result=proof, out=str(OUT))
        return proof.startswith("OK")

    def _load_dict(self):
        ok, path = ncenv.dict_status()
        if not (HAS_ZSTD and ok):
            return None, False
        try:
            raw = path.read_bytes()
            if raw[:4] == b"\x28\xb5\x2f\xfd":
                raw = _zstd.ZstdDecompressor().decompressobj().decompress(raw)
            return _zstd.ZstdCompressionDict(raw), True
        except Exception:
            return None, False

    def _event(self, kind, **kw):
        """落盘保持原文。脱敏是出舱口（report.py）的职责，不是采集口的 —— 见 sanitize 模块头。"""
        try:
            self.seq += 1
            rec = {"ts": _iso(), "seq": self.seq, "event": kind}
            rec.update(kw)
            if self.f_evt:
                self.f_evt.write(json.dumps(rec, ensure_ascii=False) + "\n")
                self.f_evt.flush()
        except Exception as e:
            self._die("event:" + kind, e)

    def _die(self, where, e):
        self.errors += 1
        try:
            if self.f_evt:
                self._event("addon_error", where=where, err=repr(e)[:300])
        except Exception:
            pass
        sys.stderr.write("[addon_error] %s: %r\n" % (where, e))

    # ---- 解码链 ----
    def _decode(self, raw):
        try:
            return raw.decode("utf-8"), "utf8"
        except Exception:
            pass
        if HAS_ZSTD:
            if self.zctx is not None:
                try:
                    return (_zstd.ZstdDecompressor(dict_data=self.zctx)
                            .decompressobj().decompress(raw).decode("utf-8"), "zstd-dict")
                except Exception:
                    pass
            try:
                return _zstd.ZstdDecompressor().decompressobj().decompress(raw).decode("utf-8"), "zstd-plain"
            except Exception:
                pass
        import gzip
        import zlib
        try:
            return gzip.decompress(raw).decode("utf-8"), "gzip"
        except Exception:
            pass
        for w in (15, -15, 31, 47):
            try:
                return zlib.decompress(raw, w).decode("utf-8"), "zlib%d" % w
            except Exception:
                pass
        return None, "undecoded"

    @staticmethod
    def _cmds(text):
        """c2s 常是数组，s2c 可能是数组或对象：把每条命令的 domain.subcmd 提出来。"""
        try:
            j = json.loads(text)
        except Exception:
            return None, None
        objs = j if isinstance(j, list) else [j]
        cmds, ress = [], []
        for o in objs:
            if not isinstance(o, dict):
                continue
            c, p = o.get("cmd"), o.get("params")
            if isinstance(c, str):
                sub = p.get("cmd") if isinstance(p, dict) else None
                cmds.append(c + ("." + sub if isinstance(sub, str) else ""))
            if "res" in o:
                ress.append(str(o.get("res")))
        return cmds, ress

    def _classify(self, text):
        tag = {"json": True}
        cmds, ress = self._cmds(text)
        if cmds is None:
            tag["json"] = False
            return tag
        if cmds:
            tag["cmds"] = cmds
        if ress:
            tag["res"] = ress
        low = text[:200000].lower()
        for k in ("seed", "step", "hash", "nonce", "rng"):
            if '"%s"' % k in low:
                tag["has_" + k] = True
        m = _PKT_RE.search(text[:200000])
        if m:
            tag["packet_hint"] = m.group(0)
        return tag

    def _dump_msg(self, fid, msg, idx):
        raw = getattr(msg, "content", b"") or b""
        ts = getattr(msg, "timestamp", None) or time.time()
        is_text = bool(getattr(msg, "is_text", False))
        rec = {"ts": _iso(ts), "flow": fid[:8], "seq": idx,
               "dir": "c2s" if getattr(msg, "from_client", False) else "s2c",
               "opcode": int(getattr(msg, "type", 1)),
               "type": "text" if is_text else "bin", "size": len(raw),
               "dict_loaded": self.dict_loaded}
        for flag, name in (("dropped", "dropped"), ("injected", "injected")):
            v = getattr(msg, flag, None)
            if v:
                rec[name] = True
        decoded, how = (raw.decode("utf-8", "replace"), "text") if is_text else self._decode(raw)
        if decoded is not None:
            rec["dec"] = how
            tag = self._classify(decoded)
            if tag:
                rec["tag"] = tag
            if len(decoded) <= TEXT_CAP:
                rec["text"] = decoded
            else:
                name = "body_%s_%05d.txt" % (fid[:8], idx)
                (OUT / "bodies" / name).write_text(decoded, encoding="utf-8")
                rec["body_file"] = "bodies/" + name
                rec["raw_unredacted"] = True
                rec["text_truncated"] = decoded[:512]
        else:
            rec["dec"] = "undecoded"
            h = raw.hex()
            if HEX_CAP and len(h) > HEX_CAP * 2:
                h = h[:HEX_CAP * 2] + "...(+%dB)" % (len(raw) - HEX_CAP)
            rec["hex"] = h
            name = "raw_%s_%05d.bin" % (fid[:8], idx)
            (OUT / "bodies" / name).write_bytes(raw)
            rec["raw_file"] = "bodies/" + name
        self.f_msg.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.f_msg.flush()
        m = self.flows.get(fid)
        if m:
            m["msgs"] = m.get("msgs", 0) + 1
            m["bytes"] = m.get("bytes", 0) + len(raw)

    # ---- 通用连接描述：每字段独立 try ----
    def _conninfo(self, flow):
        info = {}
        sc = getattr(flow, "server_conn", None)
        cc = getattr(flow, "client_conn", None)
        if sc is not None:
            for key, val in (("server_addr", sc.address), ("peer_ip", sc.peername),
                             ("local", sc.sockname)):
                try:
                    if val:
                        info[key] = [str(val[0]), val[1]]
                except Exception as e:
                    info[key + "_err"] = repr(e)[:80]
            for key, val in (("sni", sc.sni), ("tls_version", sc.tls_version),
                             ("tls_cipher", sc.cipher)):
                try:
                    if val is not None:
                        info[key] = val.decode("ascii", "replace") if isinstance(val, bytes) else str(val)
                except Exception as e:
                    info[key + "_err"] = repr(e)[:80]
            try:
                if sc.alpn:
                    info["alpn"] = sc.alpn.decode("ascii", "replace")
            except Exception:
                pass
            try:
                cl = list(getattr(sc, "certificate_list", ()) or ())
                if cl:
                    info["server_cert"] = _cert_summary(cl[0])
                    if len(cl) > 1:
                        info["server_cert_chain_len"] = len(cl)
            except Exception as e:
                info["server_cert_err"] = repr(e)[:120]
        if cc is not None:
            try:
                if cc.peername:
                    info["client_addr"] = [str(cc.peername[0]), cc.peername[1]]
            except Exception as e:
                info["client_addr_err"] = repr(e)[:80]
            try:
                if cc.sockname:
                    info["proxy_listener"] = [str(cc.sockname[0]), cc.sockname[1]]
            except Exception:
                pass
        return info

    # ---- mitmproxy 钩子 ----
    def configure(self, updated):
        try:
            if self.f_msg is None:
                if not self._open():
                    return
        except Exception as e:
            self._die("configure", e)

    def request(self, flow):
        try:
            req = getattr(flow, "request", None)
            if req is None:
                return
            self._event("req", flow=flow.id[:8], host=req.pretty_host,
                        host_is_ip=_is_ipish(req.pretty_host),
                        method=req.method, port=req.port, path=req.path[:300],
                        headers=_hdrs(req.headers), **self._conninfo(flow))
        except Exception as e:
            self._die("request", e)

    def response(self, flow):
        try:
            if getattr(flow, "websocket", None) is not None:
                return
            resp = getattr(flow, "response", None)
            req = flow.request
            if resp is None:
                return
            body_ref = None
            raw = b""
            try:
                raw = resp.raw_content or b""
                if raw:
                    body_ref = "bodies/resp_%s.bin" % flow.id[:8]
                    (OUT / body_ref).write_bytes(raw[:BODY_CAP])
            except Exception:
                body_ref = None
            self._event("resp", flow=flow.id[:8], host=req.pretty_host,
                        host_is_ip=_is_ipish(req.pretty_host), method=req.method,
                        path=req.path[:300], status=resp.status_code, reason=resp.reason,
                        len=len(raw), body_ref=body_ref,
                        headers=_hdrs(resp.headers), **self._conninfo(flow))
        except Exception as e:
            self._die("response", e)

    def error(self, flow):
        try:
            self._event("conn_error", err=str(getattr(flow, "error", None))[:300],
                        **self._conninfo(flow))
        except Exception as e:
            self._die("error", e)

    def websocket_start(self, flow):
        try:
            if self.f_msg is None:
                self._open()
            fid = flow.id
            req, resp = flow.request, getattr(flow, "response", None)
            meta = {"flow": fid[:8], "host": req.pretty_host, "host_is_ip": _is_ipish(req.pretty_host),
                    "port": req.port, "path": req.path[:400],
                    "ws_client_protocols": req.headers.get("sec-websocket-protocol"),
                    "ws_client_extensions": req.headers.get("sec-websocket-extensions"),
                    "ws_server_protocol": resp.headers.get("sec-websocket-protocol") if resp else None,
                    "ws_server_extensions": resp.headers.get("sec-websocket-extensions") if resp else None,
                    "resp_status": resp.status_code if resp else None,
                    "opened_at": _iso(), "msgs": 0, "bytes": 0}
            meta.update(self._conninfo(flow))
            self.flows[fid] = meta
            self.seen[fid] = 0
            self._event("ws_open", **meta)
        except Exception as e:
            self._die("websocket_start", e)

    def websocket_message(self, flow):
        try:
            fid = flow.id
            msgs = flow.websocket.messages
            seen = self.seen.get(fid, 0)
            if len(msgs) <= seen:
                return
            for i in range(seen, len(msgs)):
                self._dump_msg(fid, msgs[i], i)
            self.seen[fid] = len(msgs)
        except Exception as e:
            self._die("websocket_message", e)

    def websocket_end(self, flow):
        try:
            fid = flow.id
            meta = self.flows.pop(fid, None) or {}
            meta.pop("flow", None)
            self.seen.pop(fid, None)
            ws = flow.websocket
            self._event("ws_close", flow=fid[:8],
                        close_code=getattr(ws, "close_code", None),
                        close_reason=getattr(ws, "close_reason", None),
                        closed_by_client=getattr(ws, "closed_by_client", None), **meta)
        except Exception as e:
            self._die("websocket_end", e)

    def done(self):
        try:
            for fid, meta in list(self.flows.items()):
                self._event("ws_orphan", flow=fid[:8], **meta)
            for f in (self.f_msg, self.f_evt):
                if f:
                    f.flush()
                    f.close()
        except Exception:
            pass


addons = [NetCatch()]
