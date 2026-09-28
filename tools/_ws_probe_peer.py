# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
_ws_probe_peer.py — 自带 WS 靶机（服务端+客户端各一个线程，纯 socket，不依赖第三方）
给 selftest_pipeline.py 用：证明 catch.py 这条链路"真能落盘"，而不是等真目标上线才发现抓空。

协议形状故意仿真实业务：服务器先发 {"res":"session"}，客户端发数组信封，中途服务器发一个
ping 控制帧 —— 用来验证"心跳只在 mitmdump.log 里、不在 frames.jsonl 里"这条边界声明。
"""
import base64
import json
import socket
import struct
import sys
import threading
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SUBPROTO = "nc-v1"


def encode(opcode, payload, mask=False):
    """RFC6455 帧头顺序是：byte0(FIN|op) byte1(MASK|len) [扩展长度] [掩码键] 载荷。
    扩展长度必须在 byte1 **之后**追加 —— 上一版在算 byte1 之前就 b += b2，
    载荷长度落在 126..65535 时帧头会错位（当前用例 102 B 走不到那个分支，所以一直没暴露）。"""
    b = bytearray([0x80 | opcode])
    n = len(payload)
    key = b"\x01\x02\x03\x04"
    if n < 126:
        b.append(0x80 | n if mask else n)
    elif n < 65536:
        b.append(0x80 | 126 if mask else 126)
        b += struct.pack(">H", n)
    else:
        b.append(0x80 | 127 if mask else 127)
        b += struct.pack(">Q", n)
    if mask:
        b += key
        b += bytes(x ^ key[i % 4] for i, x in enumerate(payload))
    else:
        b += payload
    return bytes(b)


def read_frame(sock):
    hdr = _recv_n(sock, 2)
    if not hdr:
        return None, None
    op = hdr[0] & 0x0F
    masked = hdr[1] & 0x80
    n = hdr[1] & 0x7F
    if n == 126:
        n = struct.unpack(">H", _recv_n(sock, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", _recv_n(sock, 8))[0]
    key = _recv_n(sock, 4) if masked else None
    data = _recv_n(sock, n) if n else b""
    if key:
        data = bytes(x ^ key[i % 4] for i, x in enumerate(data))
    return op, data


def _recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def serve(host, port, log):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen(1)
    ls.settimeout(30)
    c, _ = ls.accept()
    req = b""
    while b"\r\n\r\n" not in req:
        req += c.recv(1024)
    key = [l.split(b":", 1)[1].strip() for l in req.split(b"\r\n") if l.lower().startswith(b"sec-websocket-key")][0]
    accept = base64.b64encode(__import__("hashlib").sha1(key + GUID.encode()).digest()).decode()
    c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n" % (accept, SUBPROTO)).encode())
    log("server: 101 sent")
    c.sendall(encode(0x1, json.dumps({"res": "session", "session": "SELFTEST-SESSION"}).encode()))
    c.sendall(encode(0x1, json.dumps({"res": "ok", "qid": 1, "selftest": True}).encode()))
    op, data = read_frame(c)
    log("server: got opcode=%r %r" % (op, data[:60]))
    c.sendall(encode(0x9, b"hb-probe"))          # ← 心跳控制帧，addon 看不见，只有日志有
    log("server: ping sent")
    time.sleep(0.6)
    c.sendall(encode(0x8, struct.pack(">H", 1000)))
    c.close()
    ls.close()


def client(host, port, log):
    time.sleep(0.6)
    s = socket.create_connection((host, port), timeout=20)
    target = "/selftest?probe=1"
    hosthdr = "%s:%d" % (host, port)
    key = base64.b64encode(b"0123456789abcdef").decode()
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\n\r\n"
               % (target, hosthdr, key, SUBPROTO)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(1024)
    log("client: handshake %s" % buf.split(b"\r\n")[0])
    for _ in range(2):
        op, data = read_frame(s)
        log("client: <- op=%r %r" % (op, (data or b"")[:60]))
    s.sendall(encode(0x1, json.dumps([{"cmd": "selftest", "qid": 1, "seqnum": 7, "ctk": 1,
                                      "cts": int(time.time() * 1000), "params": {"cmd": "run"}}]).encode(),
                    mask=True))
    op, data = read_frame(s)
    log("client: <- after send op=%r %r" % (op, (data or b"")[:60]))
    time.sleep(1.2)
    s.close()


def _roundtrip_selftest():
    """编解码对拍：三档长度 x 掩码与否，必须原样回来。
    上一版扩展长度追加位置错了，而这个分支从没被测过 —— 尺子要自己走一遍。"""
    import io

    class _Sock:
        def __init__(self, data):
            self.buf = data

        def recv(self, n):
            out, self.buf = self.buf[:n], self.buf[n:]
            return out

    fails = []
    for n in (5, 200, 70000):
        for mask in (False, True):
            payload = bytes((i * 7) % 251 for i in range(n))
            for op in (0x1, 0x9):
                f = _Sock(encode(op, payload, mask=mask))
                got_op, got = read_frame(f)
                if got_op != op or got != payload:
                    fails.append((n, mask, op, got_op, len(got or b"")))
    if fails:
        print("PEER SELFTEST RED: %s" % (fails[:3],))
        return 1
    print("PEER SELFTEST OK: 三档长度 x 掩码 x 两种 opcode 共 12 组编解码对拍全过")
    return 0


def main():
    if "--selftest" in sys.argv:
        sys.exit(_roundtrip_selftest())
    if len(sys.argv) < 3:
        print("用法: _ws_probe_peer.py <客户端目标 host> <端口> [<服务端监听 host> [<服务端端口>]]")
        print("      _ws_probe_peer.py --selftest")
        sys.exit(2)
    # 用法: _ws_probe_peer.py <客户端目标 host> <端口> [<服务端监听 host> [<服务端端口>]]
    ch, cp = sys.argv[1], int(sys.argv[2])
    sh = sys.argv[3] if len(sys.argv) > 3 else ch
    sp = int(sys.argv[4]) if len(sys.argv) > 4 else cp
    log = lambda m: print("[peer]", m, flush=True)
    t = threading.Thread(target=serve, args=(sh, sp, log), daemon=True)
    t.start()
    client(ch, cp, log)
    t.join(timeout=8)
    log("done")


if __name__ == "__main__":
    main()
