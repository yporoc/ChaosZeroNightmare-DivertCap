# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
ca_tool.py — 根证书与内核残留管理（唯一入口）

  make        在仓库 ca/ 下签一张全新的 CA（已存在则只报告，绝不覆盖）
  install     装进 Root 库 + 正向断言（默认机器库=所有进程与所有用户都认；需管理员）
  uninstall   撤掉**本机自己签的那张** + 反向断言（默认两个库都查、都撤）
  list        打印库里的自建 CA
  snapshot    把当前自建 CA 现状存进 state/（取证，不是备份）
  purge       清理自建 CA；默认只清自己的，别家的一律不动
  throwaway   签一张永不安装的对照 CA（给 tls_trust_probe 当负对照）
  kernel      报告/清理 WinDivert 服务残留

归属判定用**指纹**，不用名称：名称只能证明"这张是同类工具自造的"，不能证明"这张是我签的"。
按名称删会把别的机器/别的项目装的同类根证书一起删掉。退出码：0=通过，非 0=有 RED。
"""
import argparse
import ctypes
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402
import ca_store  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CA_DIR = ncenv.CA_DIR
STATE = ncenv.STATE
THROWAWAY = STATE / "throwaway_ca"
CA_PEM = CA_DIR / "mitmproxy-ca.pem"
CERT_PEM = CA_DIR / "mitmproxy-ca-cert.pem"
CERT_CER = CA_DIR / "mitmproxy-ca-cert.cer"

MY_ORG = ncenv.CA_ORG
MY_CN = ncenv.CA_CN
STORES = ("user", "machine")


def sh(argv):
    import subprocess
    p = subprocess.run(argv, capture_output=True, shell=False)
    return p.returncode, ncenv.decode_mixed(p.stdout or b"") + ncenv.decode_mixed(p.stderr or b"")


def ps(script):
    return sh(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def fingerprint(cert_path):
    """用 PowerShell 取指纹，不依赖 openssl 是否在 PATH 上（那是台机器上的巧合）。"""
    rc, out = ps("$c=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('%s');"
                 "'SHA1='+$c.Thumbprint;'SUBJ='+$c.Subject;'FROM='+$c.NotBefore.ToString('yyyy-MM-dd');"
                 "'TIL='+$c.NotAfter.ToString('yyyy-MM-dd');'SER='+$c.SerialNumber" % cert_path)
    if rc != 0 or "SHA1=" in out:
        pass
    try:
        sha1 = out.split("SHA1=")[1].splitlines()[0].strip()
    except Exception:
        return "", out
    return sha1, out


def owned_sha1():
    """这张 CA 到底是不是我的：优先看**我手里有没有它的证书文件**（有文件=我持有），
    其次看本机记录。两个都没有就回答"不知道"，调用方必须因此什么都不删。"""
    if CERT_PEM.exists():
        sha1, _ = fingerprint(CERT_PEM)
        if sha1:
            return sha1.upper()
    return (ca_store.record_read() or "").upper()


def generate(dest, basename, org, cn):
    py, _mitm, hint = ncenv.resolve_python()
    if not py:
        print("[RED] %s" % hint)
        return False
    code = ("from pathlib import Path\n"
            "from mitmproxy.certs import CertStore\n"
            "CertStore.create_store(Path(r'%s'),'%s',2048,organization='%s',cn='%s')\n"
            % (dest, basename, org, cn))
    rc, out = sh([str(py), "-c", code])
    print(out.strip()[-300:] or "(生成完成，无输出)")
    if rc != 0:
        print("[RED] 生成失败：这个 Python 里可能没有 mitmproxy。先跑 00_run.bat 选 9 装依赖。")
        return False
    return True


# ---------- 库的视图（一律物理视图，见 ca_store 的三条实测教训） ----------
def list_cas(verbose=True):
    hits = []
    for where in STORES:
        for e in ca_store.physical(where):
            hits.append("%s|%s|%s|%s|%s|%s" % (
                where, str(e.get("sha1", "?")).replace(":", "").upper(), e.get("serial", "?"),
                e.get("notbefore", "?")[:16], e.get("notafter", "?")[:10],
                e.get("subject", e.get("issuer", "?"))))
    if verbose:
        print("\n".join(hits) if hits else "(两个库里都没有自建 CA)")
    return hits


def snapshot():
    STATE.mkdir(parents=True, exist_ok=True)
    fp = STATE / ("ca_snapshot_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt")
    lines = ["# snapshot %s admin=%s" % (datetime.now().isoformat(timespec="seconds"), is_admin())]
    for tag in STORES:
        lines.append("== %s Root: 自建 CA ==" % tag)
        lines.append("\n".join(list_cas(verbose=False)))
    lines.append("== 本机持有的 CA 指纹 ==")
    lines.append(owned_sha1() or "(无：ca/ 里没有证书，state 里也没有记录)")
    rc, out = sh(["sc", "query", "WinDivert"])
    lines.append("== WinDivert ==")
    lines.append(out.strip() or "(无输出 rc=%s)" % rc)
    fp.write_text("\n".join(lines), encoding="utf-8")
    print("[snapshot] ->", fp)
    return fp


def _delete(where, sha1):
    if where == "machine":
        return ca_store.remove_machine(sha1)
    rc, out = ca_store.remove_user(sha1)
    print("   ", str(out)[:140].replace("\n", " "))
    return rc, out


def _ask(verb, what):
    """删除是对外部系统的不可逆动作，跨归属的那一类必须现场要人确认。"""
    try:
        ans = input("      %s %s ？输入 y 才动手: " % (verb, what)).strip().lower()
    except Exception:
        return False
    return ans == "y"


def purge(dry_run=False, all_selfbuilt=False):
    """默认只清本机自己签的那张。--all-selfbuilt 会把**别人装的**同类根证书也一并清掉，
    那会撤掉别的项目的信任链，所以逐条要人确认。"""
    mine = owned_sha1()
    hits = list_cas(verbose=False)
    if not hits:
        print("[purge] 库里没有自建 CA，无需动作")
        return 0
    touched, skipped, bad = 0, 0, 0
    for h in hits:
        p = h.split("|")
        where, sha1, subject = p[0], p[1], p[5]
        is_mine = bool(mine) and sha1 == mine
        tag = "我的" if is_mine else "不是我的"
        print("[purge] %s %s [%s] %s" % (where, sha1, tag, subject[:48]))
        if not is_mine and not all_selfbuilt:
            print("       跳过：归属判据不认这张。要连别人装的一起清，加 --all-selfbuilt（会逐条确认）")
            skipped += 1
            continue
        if not is_mine and all_selfbuilt and not _ask("删除", "%s 库里的 %s" % (where, subject[:40])):
            print("       未确认，跳过")
            skipped += 1
            continue
        if dry_run:
            continue
        rc, out = _delete(where, sha1)
        touched += 1
        if rc != 0:
            print("   !! 删除失败:", str(out)[:140])
            bad += 1
    if dry_run:
        print("[purge] DRY-RUN，未改动")
        return 0
    left = list_cas(verbose=False)
    mine_left = [l for l in left if mine and l.split("|")[1] == mine]
    if mine_left:
        print("[purge] RED: 反向断言失败，我那张仍在库:", mine_left)
        return 1
    print("[purge] OK：删了 %d 条，跳过 %d 条（别人装的、未确认的），我那张已确认不在库里"
          % (touched, skipped))
    if left:
        print("[purge] 库里还剩这些自建 CA，都不是本机持有的，本工具不动它们：")
        for l in left:
            print("   ", l)
    return bad


# ---------- 我自己的 CA ----------
def make_ca():
    CA_DIR.mkdir(parents=True, exist_ok=True)
    if CA_PEM.exists() and CERT_PEM.exists():
        print("[make] CA 已存在，未重新生成:", CA_PEM)
    else:
        if not generate(CA_DIR, "mitmproxy", MY_ORG, MY_CN):
            return 1
        if not CERT_PEM.exists():
            print("[make] RED: 生成完找不到证书文件")
            return 1
    sha1, detail = fingerprint(CERT_PEM)
    print(detail.strip())
    if not sha1:
        print("[make] RED: 取不到指纹，后面所有归属判定都会失效")
        return 1
    STATE.mkdir(parents=True, exist_ok=True)
    ca_store.record_write(sha1, MY_CN, detail.strip())
    print("[make] 本机 CA SHA1 =", sha1, "->", ncenv.my_ca_record())
    return 0


def install(where="machine"):
    if not CERT_CER.exists() and not CERT_PEM.exists():
        print("[install] RED: 先跑 make（ca/ 里没有证书）")
        return 1
    if where in ("machine", "both") and not is_admin():
        print("[install] RED: 装机器库需要管理员。以管理员身份重跑，或 --where user（会弹框要点『是』）")
        return 1
    locs = {"machine": ["machine"], "user": ["user"],
            "both": ["machine", "user"], "all": ["machine", "user"]}[where]
    src = str(CERT_CER if CERT_CER.exists() else CERT_PEM)
    my_sha, _ = fingerprint(CERT_PEM) if CERT_PEM.exists() else ("", "")
    if not my_sha:
        my_sha = ca_store.record_read()
    my_sha = (my_sha or "").upper()
    for loc in locs:
        # 逐库存亡检查：同一个库里可能存着多份同指纹条目，也可能是别人的那张。
        if my_sha and ca_store.physical(loc, sha1=my_sha):
            print("   %s 库物理上已经有这张指纹，跳过（未重复添加）" % loc)
            continue
        if loc == "machine":
            rc, out = ca_store.add_machine(src)
        else:
            print("   [提醒] 装用户库走 certutil，会弹一个「证书存储」确认框，请点『是』")
            rc, out = ca_store.add_user(src)
        print("   ", str(out)[:140].replace("\n", " "))
        if rc != 0:
            print("[install] RED: %s 库写入失败" % loc)
            return 1
    # 正向断言按**指纹**，不按名称：名称证明不了是这张。
    got = ca_store.installed_anywhere(my_sha) if my_sha else []
    missing = [l for l in locs if l not in got]
    if not my_sha or missing:
        print("[install] RED: 装完在物理视图里按指纹查不到（缺 %s）。正向断言失败。" % (",".join(missing) or "指纹"))
        return 1
    print("[install] OK 正向断言：%s 库里都能按指纹查到 %s" % (",".join(got), my_sha))
    print("[install] 说明：X509Store('Root','LocalMachine') 不弹框；certutil 对 Root 库会弹"
          "「证书存储」对话框把脚本卡死（实测）。")
    return 0


def uninstall(where="all"):
    """撤掉本机持有的那张。默认两个库都查、都撤 —— 只撤一个库会留下"报告已卸载但系统仍然信任"。"""
    my_sha = owned_sha1()
    if not my_sha:
        print("[uninstall] RED: 无法确定哪张是我的（ca/ 里没有证书文件，state 里也没有记录）。"
              "没有归属依据时本工具不做任何删除。")
        return 1
    locs = ["machine", "user"] if where in ("all", "both") else [where]
    found = ca_store.installed_anywhere(my_sha)
    hits = [l for l in found if l in locs]
    if not hits:
        print("[uninstall] 物理视图里 %s 库没有这张（%s），未做动作" % ("/".join(locs), my_sha[:16] + "…"))
    for loc in hits:
        rc, out = _delete(loc, my_sha)
        if rc != 0:
            print("[uninstall] %s 删除失败:" % loc, str(out)[:140])
    left = ca_store.installed_anywhere(my_sha)
    if left:
        print("[uninstall] RED: 反向断言失败，这张仍物理存在于:", left)
        return 1
    print("[uninstall] OK 反向断言：按指纹 %s 在两个库里都查不到" % my_sha)
    others = [h for h in list_cas(verbose=False) if h.split("|")[1] != my_sha]
    if others:
        print("[uninstall] 提示：库里还有别的自建 CA（不是本工具持有的，未动）：")
        for o in others:
            print("   ", o)
    other_store = [l for l in found if l not in locs]
    if other_store:
        print("[uninstall] 提示：你只撤了 %s，另一库还剩 %s —— 系统仍然信任这张。要撤干净用 --where all"
              % ("/".join(locs), other_store))
    return 0


def throwaway():
    THROWAWAY.mkdir(parents=True, exist_ok=True)
    marker = THROWAWAY / "ca-ca.pem"
    if marker.exists():
        print("[throwaway] 已存在", THROWAWAY)
        return 0
    if not generate(THROWAWAY, "ca", ncenv.THROWAWAY_ORG, ncenv.THROWAWAY_CN):
        return 1
    print("[throwaway] 这张**永远不装进任何库**，只给 tls_trust_probe 当负对照:", THROWAWAY)
    return 0 if marker.exists() else 1


def kernel(action="report"):
    rc, out = sh(["sc", "query", "WinDivert"])
    running = "RUNNING" in out
    first = out.strip().splitlines()[0] if out.strip() else "?"
    print("[kernel] WinDivert:", "RUNNING" if running else first)
    rc, out2 = sh(["sc", "qc", "WinDivert"])
    for l in out2.splitlines():
        if "BINARY_PATH_NAME" in l or "START_TYPE" in l:
            print("   ", l.strip())
    if action == "clean":
        sh(["sc", "stop", "WinDivert"])
        rc, out3 = sh(["sc", "delete", "WinDivert"])
        print("[kernel] delete ->", out3.strip()[-80:])
        rc, out4 = sh(["sc", "query", "WinDivert"])
        if "RUNNING" in out4 or "1060" not in out4:
            print("[kernel] RED: 仍在（或 sc 本身失败），不许绿着退")
            return 1
        print("[kernel] OK 反向断言：服务已消失 (1060)")
    return 0


def main():
    ncenv.utf8_stdout()
    if not ncenv.python_major_ok():
        print("[RED] 需要 Python >= %s，当前 %s" % (".".join(map(str, ncenv.MIN_PY)), sys.version.split()[0]))
        return 1
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("cmd", choices=["snapshot", "list", "purge", "make", "install",
                                    "uninstall", "throwaway", "kernel"])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--all-selfbuilt", action="store_true",
                    help="purge：连别人装的同类自建 CA 也清（逐条确认，会撤掉别的项目的信任链）")
    ap.add_argument("--clean", action="store_true", help="kernel：stop+delete WinDivert")
    ap.add_argument("--where", choices=["machine", "user", "both", "all"], default=None,
                    help="install 默认 machine（需管理员）；uninstall 默认 all（两个库都撤）")
    a = ap.parse_args()
    STATE.mkdir(parents=True, exist_ok=True)
    if a.cmd == "install":
        return install(a.where or "machine")
    if a.cmd == "uninstall":
        return uninstall(a.where or "all")
    return {
        "snapshot": lambda: 0 if snapshot() else 1,
        "list": lambda: 0 if list_cas() is not None else 1,
        "purge": lambda: purge(a.dry_run, a.all_selfbuilt),
        "make": lambda: make_ca(),
        "throwaway": lambda: throwaway(),
        "kernel": lambda: kernel("clean" if a.clean else "report"),
    }[a.cmd]()


if __name__ == "__main__":
    sys.exit(main())
