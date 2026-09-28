# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
tls_trust_probe.py — 自证"这台机器的 TLS 信任链到底认不认某张 CA"

为什么需要它：装证书这件事"certutil 说成功"不等于"目标的 TLS 栈会认"。
这类项目最常见的两个坑是：探针不下毒、只测成功侧。所以本脚本一次跑【两条腿】：

  正对照：leaf 由【已安装】的 CA 签  -> 必须 PASS
  负对照：leaf 由【从未安装】的 CA 签 -> 必须 FAIL

两条客户端栈各测一遍：
  A) Python ssl  —— Windows 上 create_default_context() 读的是系统证书库
  B) PowerShell Invoke-WebRequest (.NET/schannel) —— 与原生程序的 schannel 校验路径同一条，
     这条才是"目标会不会接受我们的 MITM 证书"的可用代理指标

FAIL 还要分性质：只有"信任校验失败"才算负对照成立。连不上/端口没人听/协议版本问题
一律判 RED —— 否则一次网络抖动就能让负对照"看起来通过"，尺子等于没有。

退出码：0=两腿都符合预期；非 0=RED（含"负对照竟然也通过"= 尺子在撒谎）。

用法：
  python tls_trust_probe.py                 # 两腿全测（默认对 ca/ 与 state/throwaway_ca/）
  python tls_trust_probe.py --expect fail --ca <dir>   # 单腿：断言该 CA 不被信任（卸载后复测用）
"""
import argparse
import http.server
import re
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt
except Exception as e:  # pragma: no cover
    print("cryptography 不可用:", e)
    raise


def load_ca(cadir: Path):
    """从 mitmproxy confdir 风格目录里取 (key, cert)。兼容'密钥+证书同文件'。"""
    blobs = []
    for f in sorted(cadir.glob("*.pem")):
        blobs.append(f.read_bytes())
    key = cert = None
    for b in blobs:
        for kb in re.findall(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", b, re.S):
            try:
                key = serialization.load_pem_private_key(kb, password=None)
            except Exception:
                pass
        for cb in re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", b, re.S):
            try:
                c = x509.load_pem_x509_certificate(cb)
            except Exception:
                continue
            try:
                bc = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if bc.value.ca:
                    cert = c
            except x509.ExtensionNotFound:
                pass
    if not (key and cert):
        raise SystemExit("RED: 在 %s 里找不到 CA 的 密钥+证书" % cadir)
    return key, cert


def mint_leaf(cadir: Path, out: Path):
    key, cacert = load_ca(cadir)
    now = _dt.datetime.now(_dt.timezone.utc)
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(cacert.subject)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - _dt.timedelta(days=1))
         .not_valid_after(now + _dt.timedelta(days=2))
         .add_extension(x509.SubjectAlternativeName(
             [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
             critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         # OpenSSL 3+/Py3.13 会因缺 AKI/SKI 直接判 "Missing Authority Key Identifier"，
         # mitmproxy 自己签的叶子就缺这两个扩展 —— 这里补齐，好让 python 这条腿测的是信任链而非扩展卫生。
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()), critical=False))
    cert = b.sign(key, hashes.SHA256())
    out.mkdir(parents=True, exist_ok=True)
    (out / "leaf.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM)
                                   + cacert.public_bytes(serialization.Encoding.PEM))
    (out / "leaf.key").write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                                   serialization.NoEncryption()))
    return out / "leaf.pem", out / "leaf.key"


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"trust-probe-ok\n"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve(ctx_path, ctx_key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(ctx_path, ctx_key)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def leg_python(port, label):
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection(("localhost", port), timeout=12)
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = b""
            while len(data) < 4096:
                try:
                    chunk = s.recv(4096)
                except Exception:
                    break
                if not chunk:
                    break
                data += chunk
        ok = b"trust-probe-ok" in data
        return ("PASS" if ok else "FAIL"), ("head=%r" % data[:24]) if ok else "head=%r" % data[:80]
    except Exception as e:
        return "FAIL", "%s: %s" % (type(e).__name__, str(e)[:150])


def leg_schannel(port):
    script = (
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "try{$r=Invoke-WebRequest -Uri 'https://localhost:%d/' -UseBasicParsing -TimeoutSec 12;"
        "'PASS ' + $r.StatusCode + ' len=' + $r.RawContentLength}catch{'FAIL ' + $_.Exception.Message}" % port
    )
    p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True)

    def dz(b):
        for enc in ("utf-8", "cp936"):
            try:
                return b.decode(enc)
            except Exception:
                continue
        return b.decode("utf-8", "replace")

    out = dz(p.stdout or b"").strip()
    err = dz(p.stderr or b"").strip()
    line = out or err
    if line.startswith("PASS"):
        return "PASS", line
    return "FAIL", (line[:180] or "no output")


_TRUST_FAIL = re.compile(
    r"(CERTIFICATE_VERIFY_FAILED|unable to get local issuer|self[- ]signed|"
    r"证书链|信任关系|未能为 SSL/TLS|AuthenticationException|"
    r"CERT_UNTRUSTED|ERR_CERT_AUTHORITY)", re.I)
_CONN_FAIL = re.compile(r"(refused|timed out|timeout|getaddrinfo|ConnectionReset|"
                        r"EOF occurred|握手|handshake failure|unsupported protocol)", re.I)


def fail_kind(why):
    """把 FAIL 分成"信任没通过"（负对照想要的）和"根本没连上"（尺子失效）。"""
    if _TRUST_FAIL.search(why or ""):
        return "trust"
    if _CONN_FAIL.search(why or ""):
        return "conn"
    return "other"


def run_one(cadir: Path, name: str, expect: str, keep=False):
    """返回 (退出码, 失败性质)。退出码只给上游判成败用；失败性质给人看，
    因为"正对照没过"和"尺子在撒谎"是完全不同的两件事，混成一句会让人去找不存在的问题。"""
    expect = expect.upper()
    leaf, key = mint_leaf(cadir, ncenv.STATE / ("probe_" + name))
    srv, port = serve(leaf, key)
    a, a_why = leg_python(port, name)
    b, b_why = leg_schannel(port)
    srv.shutdown()
    note = ""
    if a == expect and b == expect:
        if expect == "FAIL":
            kinds = {fail_kind(a_why), fail_kind(b_why)}
            if kinds - {"trust"}:
                rc, note = 1, ("负对照的 FAIL 性质是 %s，不是不受信 —— 连不上/协议问题也能读成 FAIL，"
                               "这条对照不成立" % sorted(kinds))
            else:
                rc = 0
        else:
            rc = 0
    elif expect == "PASS":
        rc = 1
        note = ("正对照没过：这张 CA 现在不被系统信任。最常见的原因是**还没装进 Root 库**，"
                "或装进去的不是手里这一张（跑 ca_tool.py list 对指纹）。")
    else:
        rc = 1
        note = "负对照竟然 PASS —— 校验根本没发生，尺子在撒谎，任何结论都不能用这张 CA 去解释。"
    print("[%s] 期望=%s  python-ssl=%s  schannel(PS)=%s  => %s%s"
          % (name, expect, a, b, "OK" if rc == 0 else "RED", ("  <= " + note) if note else ""))
    print("      A: %s" % a_why)
    print("      B: %s" % b_why)
    if not keep:
        try:
            (leaf).unlink()
            (key).unlink()
        except Exception:
            pass
    return rc, note


def main():
    ncenv.utf8_stdout()
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", choices=["pass", "fail"], default=None)
    ap.add_argument("--ca", default=None, help="单个 CA 目录（配 --expect 用）")
    ap.add_argument("--name", default="single")
    ap.add_argument("--keep", action="store_true", help="保留签出来的 leaf 供事后复查")
    a = ap.parse_args()

    if a.ca:
        rc, _note = run_one(Path(a.ca), a.name, a.expect or "pass", keep=a.keep)
        return rc

    # 两腿模式：本机 CA 必须被信任，对照 CA 必须**因不受信**被拒
    rc1, note1 = run_one(ncenv.CA_DIR, "mine", "pass", keep=a.keep)
    rc2, note2 = run_one(ncenv.STATE / "throwaway_ca", "throwaway", "fail", keep=a.keep)
    if rc1 or rc2:
        # 分开说：新机第一次跑就是 rc1（还没装 CA），那是"照下一步"而不是"工具坏了"
        if rc1 and "正对照没过" in note1:
            print("RED: 本机 CA 未被信任 —— 先跑 00_run.bat cainstall，再回来复跑本探针")
        elif rc2:
            print("RED: 负对照不成立 —— 尺子不可信，不要用这张 CA 去解释任何抓包结果")
        else:
            print("RED: 两腿没有同时成立 —— 见上面每条 RED 后面的原因")
        return 1
    print("OK: 正对照通过 + 负对照因不受信被拒 => 信任链探针自证有效")
    return 0


if __name__ == "__main__":
    sys.exit(main())
