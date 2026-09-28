# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
qa_release.py — 发版自测：把"这套东西真的能分发"钉成可复跑的多腿对照。

覆盖三件纯靠读代码看不出来的事：
  A. 呈现层出得来文件，且**未收尾的批次必须拒绝落盘**（不污染正在被测的产物）
  B. 快照正文里没有原值身份，身份是加盐哈希形状
  C. 改名之后的归属判定仍然只认指纹：库里那张**同名但不同指纹**的 CA 不许被删；
     没有任何归属依据时 uninstall 拒绝动手

全程不写系统证书库：删除实现被换成"记下调用"，所以本脚本连 Root 库都不会打开。
不联网、不起 mitmdump。纯本地。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402
import ca_store  # noqa: E402
import ca_tool  # noqa: E402
import report  # noqa: E402
import sanitize  # noqa: E402
import verify_run  # noqa: E402

FAILS = []
FAKE_MINE = "BBBB" * 10
FAKE_OTHER = "AAAA" * 10


def t(name, ok, note=""):
    print("%-4s %-56s %s" % ("OK" if ok else "RED", name, note))
    if not ok:
        FAILS.append(name)


def _completed_run():
    run = verify_run._mk("healthy")
    meta = json.loads((run / "meta.json").read_text(encoding="utf-8"))
    meta.update({"ended": "2026-09-28T00:00:00+08:00", "trigger": "qa",
                 "procs_filter": ["target-proc.exe"], "ca_sha1": "ABCDEF0123456789",
                 "build_hint": "1.0", "world_hint": "w1", "user_nation": "xx",
                 "game_user_id": "770000000101", "publisher_uid": "770000000202",
                 "user_access_token_len": 40, "tun_marks": ""})
    (run / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    return run


def leg_report():
    print("\n===== A/B 呈现层 =====")
    run = _completed_run()
    rc = report.build(run)
    snap = run / "snapshot"
    made = sorted(p.name for p in snap.glob("*")) if snap.exists() else []
    t("A1 正常批次出得来 7 个以上文件且 rc=0", rc == 0 and len(made) >= 7, "rc=%s n=%d" % (rc, len(made)))

    busy = verify_run._mk("healthy")
    bm = json.loads((busy / "meta.json").read_text(encoding="utf-8"))
    bm.pop("ended", None)
    (busy / "meta.json").write_text(json.dumps(bm, ensure_ascii=False), encoding="utf-8")
    rc2 = report.build(busy)
    t("A2 未收尾批次拒绝落盘（对照腿：松开才肯写）",
      rc2 == 1 and not (busy / "snapshot").exists(), "rc=%s" % rc2)

    if snap.exists():
        joined = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                           for p in snap.glob("*") if p.is_file())
        leaks = sanitize.audit_text(joined)
        t("B1 快照正文审计无原值命中", not leaks, str(leaks[:2]))
        ov = (snap / "00_overview.md").read_text(encoding="utf-8") if (snap / "00_overview.md").exists() else ""
        t("B2 身份是加盐哈希而不是原值",
          "770000000101" not in ov and "id:" in ov,
          [l.strip() for l in ov.splitlines() if "id:" in l][:2])
        t("B3 原始 meta 含真实身份时，快照里仍查不到原值",
          "770000000202" not in joined and "770000000101" not in joined,
          "这是主路径而不是边缘情形：本机 meta 按设计就是原文")
        # B4 反向腿：本机原始档必须**还是**原文。查不到秘密说明有人把脱敏挪回采集口，
        # 那会同时毁掉分析材料并让 B1 永远通过（没有可审计的东西了）。
        parts = [p.read_text(encoding="utf-8", errors="replace") for p in run.glob("*.jsonl")]
        parts.append((run / "meta.json").read_text(encoding="utf-8"))
        rawdir = chr(10).join(parts)
        raw_hits = sanitize.audit_text(rawdir)
        t("B4 本机 run 仍保持原文（反向腿）", bool(raw_hits),
          "命中 %d 类，样例 %s" % (len(raw_hits), raw_hits[:1]) if raw_hits
          else "本机落盘被擦了：脱敏被挪回了采集口，出舱闸将无从审计")


def leg_ownership():
    print("\n===== C CA 归属 =====")
    saved_phys = ca_store.physical
    saved_rm = ca_store.remove_machine
    saved_ru = ca_store.remove_user
    calls = []
    ca_store.remove_machine = lambda sha1: (calls.append(("machine", sha1)), (0, "fake no-op"))[1]
    ca_store.remove_user = lambda sha1: (calls.append(("user", sha1)), (0, "fake no-op"))[1]
    ca_store.physical = lambda where, sha1=None: (
        [{"sha1": FAKE_OTHER, "serial": "1", "notbefore": "2026", "notafter": "2036",
          "issuer": "CN=%s, O=%s" % (ncenv.CA_CN, ncenv.CA_ORG),
          "subject": "CN=%s, O=%s" % (ncenv.CA_CN, ncenv.CA_ORG)}]
        if (sha1 is None or sha1 == FAKE_OTHER) else [])
    rec = ncenv.my_ca_record()
    bak = rec.read_text(encoding="utf-8") if rec.exists() else None
    try:
        ncenv.STATE.mkdir(parents=True, exist_ok=True)
        ca_store.record_write(FAKE_MINE, ncenv.CA_CN, "qa 模拟")
        has_cert_file = ca_tool.CERT_PEM.exists()
        expect = ""
        if has_cert_file:
            expect, _ = ca_tool.fingerprint(ca_tool.CERT_PEM)
            t("C1 ca/ 里有证书时归属取文件指纹（优先于本地记录）",
              ca_tool.owned_sha1().upper() == expect.upper(),
              "%s（ca/ 存在，本地记录被正确让位）" % ca_tool.owned_sha1()[:12])
        else:
            t("C1 没有证书文件时归属退回本地指纹记录",
              ca_tool.owned_sha1() == FAKE_MINE, ca_tool.owned_sha1()[:12])

        buf = []
        real_print = print
        import builtins
        builtins.print = lambda *a, **k: buf.append(" ".join(str(x) for x in a))
        try:
            ca_tool.purge(dry_run=False, all_selfbuilt=False)
        finally:
            builtins.print = real_print
        txt = "\n".join(buf)
        t("C2 purge 未尝试任何删除动作", not calls, str(calls))
        t("C3 同名但不同指纹的 CA 被判非本机持有并跳过", "跳过" in txt and FAKE_OTHER in txt,
          [l for l in buf if "跳过" in l][:1])

        # 无归属依据：ca/ 无证书 且 记录里没有 sha1
        if not has_cert_file:
            rec.write_text("cn=%s\n" % ncenv.CA_CN, encoding="utf-8")
            t("C4 没有任何归属依据时 uninstall 拒绝动手", ca_tool.uninstall("all") == 1, "")
        else:
            t("C4 本机已有 ca/ 证书，跳过'无依据'用例（不是失败，是前提不成立）", True, "ca/ 存在")
    finally:
        if bak is None:
            try:
                rec.unlink()
            except Exception:
                pass
        else:
            rec.write_text(bak, encoding="utf-8")
        ca_store.physical = saved_phys
        ca_store.remove_machine = saved_rm
        ca_store.remove_user = saved_ru


def main():
    ncenv.utf8_stdout()
    ncenv.ensure_dirs()
    leg_report()
    leg_ownership()
    print("\n---- qa_release: RED %d ----" % len(FAILS))
    if FAILS:
        print("不合格：%s" % ", ".join(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
