# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
ca_store.py — 根证书库的"物理视图"读写（被 ca_tool.py 调用）

三条实测教训（2026-09-24，每条都踩过一次）：
  1) PowerShell 的 Cert:\\CurrentUser\\Root 与 .NET X509Store('Root','CurrentUser') 都是
     **合并视图**：机器库里的根证书也会出现在里面。按它遍历再 Remove()，会把机器库那份删掉
     （我机器库里那张 CA 就是这么被我自己误删的）。
     ⇒ 判断"物理上到底在哪个库"只能问 certutil（-store Root / -store -user Root）。
  2) certutil -addstore/-delstore 对 Root 库会弹图形确认框（标题「证书存储」）把脚本卡死。
     ⇒ 机器库的装/删走 X509Store API（不弹框）；用户库只能 certutil，装前要提醒人点『是』。
  3) Remove-Item Cert:\\CurrentUser\\Root\\<sha> 被系统禁止："不允许对用户根存储和 UI 执行操作"。
"""
import re
import subprocess

from ncenv import CA_CN, SELF_BUILT_PAT, my_ca_record, STATE

MY_CN = CA_CN
# 粗筛：只用来认出"这张是同类工具自造的"，从而绝不碰系统自带的根。
# 它**不是**归属判据 —— 别的机器上装的同类 CA 也会匹配这里，所以删除前必须再过
# belongs_to_us()。历史上一次误删就是"按一个不该当归属用的条件去删"。
_SELF_BUILT = re.compile(SELF_BUILT_PAT, re.I)
_LABELS = {
    "serial": ("序列号", "Serial Number"),
    "issuer": ("颁发者", "Issuer"),
    "subject": ("使用者", "Subject"),
    "sha1": ("证书哈希(sha1)", "Cert Hash(sha1)"),
    "notbefore": ("NotBefore", "日期有效期始"),
    "notafter": ("NotAfter", "日期有效期止"),
}


def _dec(b):
    if not b:
        return ""
    if b[:2] == b"\xff\xfe" or (len(b) > 40 and b"\x00" in b[:40]):
        return b.decode("utf-16-le", "replace")
    for enc in ("cp936", "utf-8"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", "replace")


def _run(argv):
    p = subprocess.run(argv, capture_output=True, shell=False)
    return p.returncode, _dec(p.stdout) + _dec(p.stderr)


def _value(line):
    for sep in (":", "："):
        if sep in line:
            return line.split(sep, 1)[1].strip()
    return ""


def _parse(text):
    entries, cur = [], {}

    def flush():
        if cur.get("sha1"):
            entries.append(dict(cur))
        cur.clear()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("===="):
            flush()
            continue
        for key, labels in _LABELS.items():
            for lab in labels:
                if line.startswith(lab):
                    v = _value(line)
                    if v and key not in cur:
                        cur[key] = v
                    break
            else:
                continue
            break
    flush()
    return entries


def physical(where, sha1=None):
    """该库里**物理存在**的自建 CA。where: 'user' | 'machine'。
    传 sha1 时只查这一张（快，且能当"存不存在"的判据）。"""
    argv = ["certutil", "-store"] + (["-user"] if where == "user" else []) + ["Root"]
    if sha1:
        argv.append(sha1)
    rc, out = _run(argv)
    if rc != 0:
        return []
    ents = [e for e in _parse(out)
            if _SELF_BUILT.search((e.get("issuer", "") + " " + e.get("subject", "")))]
    if sha1:
        want = sha1.lower().replace(":", "")
        ents = [e for e in ents if e.get("sha1", "").lower().replace(":", "") == want]
    return ents


def ps(script):
    p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True)
    return p.returncode, _dec(p.stdout) + _dec(p.stderr)


def add_machine(cert_path):
    return ps("$c=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('%s');"
              "$s=New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');"
              "$s.Open('ReadWrite'); $s.Add($c); $s.Close(); 'added|' + $c.Thumbprint" % cert_path)


def remove_machine(sha1):
    return ps("$s=New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');"
              "$s.Open('ReadWrite'); $c=@($s.Certificates | Where-Object { $_.Thumbprint -eq '%s' });"
              "foreach($x in $c){$s.Remove($x)}; $s.Close(); 'removed ' + $c.Count + ' from LocalMachine'" % sha1)


def add_user(cert_path):
    """会弹「证书存储」确认框，需要人点『是』。"""
    return _run(["certutil", "-user", "-addstore", "Root", cert_path])


def remove_user(sha1):
    """同样会弹框。先确认物理存在再动，避免对合并视图里的机器库副本下手。"""
    if not physical("user", sha1=sha1):
        return 0, "用户库物理上没有这张（PowerShell 的 CU 视图会假报有），未做任何动作"
    return _run(["certutil", "-delstore", "-user", "Root", sha1])


# ---------------- 本地归属记录 ----------------
# 名称正则是粗筛，这张才是"是不是我签的"的真相：只记本机自己 make 过的那张指纹。
# 它落在 state/（已被 .gitignore 排除），换一台机器就是另一张，不会跨机互相认领。

def _ensure_dirs():
    STATE.mkdir(parents=True, exist_ok=True)


def record_write(sha1, cn="", extra=""):
    _ensure_dirs()
    lines = ["sha1=%s" % sha1]
    if cn:
        lines.append("cn=%s" % cn)
    if extra:
        lines.append(extra.strip())
    my_ca_record().write_text("\n".join(lines) + "\n", encoding="utf-8")
    return my_ca_record()


def record_read():
    try:
        txt = my_ca_record().read_text(encoding="utf-8")
    except Exception:
        return ""
    m = re.search(r"sha1=(\w+)", txt or "")
    return m.group(1).lower().replace(":", "") if m else ""


def belongs_to_us(sha1):
    """删除前的唯一许可条件：这张的指纹 == 本机记录的那张。

    反向断言用例：库里塞一张**同名但不同指纹**的 CA，本函数必须返回 False，
    于是 purge/uninstall 不许动它。只测"我的删得掉"证不出"它会不会多删"。
    """
    want = record_read()
    if not want:
        return False
    return str(sha1 or "").lower().replace(":", "") == want


def installed_anywhere(sha1):
    """跨两个库找这张，返回命中的库列表。传指纹就绕开名称这一层。"""
    hits = []
    for where in ("user", "machine"):
        if physical(where, sha1=sha1):
            hits.append(where)
    return hits
