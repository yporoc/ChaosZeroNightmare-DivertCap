# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
dictgen.py — 自己训练/导入 zstd 字典，并**量化它带来的收益**。

为什么要有这个文件：本仓库不携带任何第三方资产。字典对目标应用是私有产物，
所以把"怎么得到字典"这件事本身作为可分发能力提供，而不是塞一份别人的文件进来。

子命令：
  train        --from <文件或目录> [--size 100KB] [--out dicts/default.dict]
               从明文样本训一张字典。样本 = 你手上已经能读到的那些消息。
  from-capture --run <run目录>
               用某批已解出明文的帧当样本自举训练（先靠无字典能解的部分，训完再回去解剩下的）。
               这是最实用的路径：抓第一批时字典还没有，训完第二批就全解开了。
  eval         --run <run目录> [--dict <路径>]
               现算收益：同一批帧，用这张字典能多解出多少条、剩下多少 undecoded。
               没有这一步，"加了字典"只是一句口头承诺。
  import       --from <路径>
               把你从别处拿到的字典放进来，并记下它的 sha256 与来源声明（provenance）。

字典文件本身落在仓库的 dicts/ 下，被 .gitignore 排除。
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ncenv  # noqa: E402

try:
    import zstandard as zstd
except Exception as e:  # pragma: no cover
    zstd = None
    _ZSTD_ERR = repr(e)[:120]


def _need_zstd():
    if zstd is None:
        print("RED: 这个 Python 里没有 zstandard。跑 00_run.bat 选 9 装依赖。（%s）" % _ZSTD_ERR)
        return False
    return True


def _sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def _samples_from_files(p: Path, limit=200_000):
    """样本粒度：按行切（一条业务消息一行）。整文件当样本会让字典学到的是文件边界而不是词表。"""
    out = []
    files = [p] if p.is_file() else sorted([f for f in p.rglob("*") if f.is_file()])
    for f in files:
        try:
            txt = f.read_bytes()
        except Exception:
            continue
        for line in txt.split(b"\n"):
            line = line.strip()
            if 8 <= len(line) <= 65536:
                out.append(line)
            if len(out) >= limit:
                return out
    return out


def _samples_from_run(run: Path, limit=200_000):
    out = []
    fp = run / "frames.jsonl"
    if not fp.exists():
        return out
    for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except Exception:
            continue
        t = r.get("text")
        if r.get("dec") in ("undecoded",) or not t:
            continue
        b = t.encode("utf-8")
        if 8 <= len(b) <= 65536:
            out.append(b)
        if len(out) >= limit:
            break
    return out


def _write_dict(data: bytes, out: Path, source: str, note=""):
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    man = out.parent / "manifest.json"
    rec = {}
    if man.exists():
        try:
            rec = json.loads(man.read_text(encoding="utf-8"))
        except Exception:
            rec = {}
    rec[out.name] = {"sha256_16": _sha(data), "bytes": len(data),
                     "obtained": source, "note": note,
                     "recorded_at": datetime.now().isoformat(timespec="seconds")}
    man.write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    print("[dict] -> %s (%d B, sha256_16=%s)  来源登记: %s" % (out, len(data), _sha(data), source))


def cmd_train(a):
    if not _need_zstd():
        return 1
    p = Path(a.frm)
    if not p.exists():
        print("RED: --from 指向的东西不存在:", p)
        return 1
    s = _samples_from_files(p)
    if len(s) < 50:
        print("RED: 只收到 %d 条样本，训不出有用的字典（要 >=50）。" % len(s))
        return 1
    out = Path(a.out) if a.out else (ncenv.DICT_DIR / "default.dict")
    d = zstd.train_dictionary(a.size, s, level=a.level)
    _write_dict(d.as_bytes(), out, "trained from %s（%d 条样本，本仓库不携带任何第三方资产）" % (p, len(s)))
    print("     样本 %d 条，字典 %d B" % (len(s), a.size))
    return 0


def cmd_from_capture(a):
    if not _need_zstd():
        return 1
    run = Path(a.run)
    s = _samples_from_run(run)
    if len(s) < 50:
        print("RED: 这批里没有 %d 条可读明文。先不带字典抓一批，能解多少算多少，再回来训。"
              "（当前可读 %d 条）" % (50, len(s)))
        return 1
    out = Path(a.out) if a.out else (ncenv.DICT_DIR / "default.dict")
    d = zstd.train_dictionary(a.size, s, level=a.level)
    _write_dict(d.as_bytes(), out, "自举训练：用 %s 里已解出明文的帧当样本" % run.name)
    print("     样本 %d 条。下一步：python tools\\dictgen.py eval --run <新抓的一批> 看真实收益" % len(s))
    return 0


def cmd_import(a):
    p = Path(a.frm)
    if not p.exists():
        print("RED: %s 不存在" % p)
        return 1
    data = p.read_bytes()
    note = a.note or "未声明来源：这样一份文件是否有权使用由你自己判断并负责"
    if data[:4] == b"\x28\xb5\x2f\xfd":
        # 真实分发形态之一就是"被 zstd 压缩过的字典"，net_catch_addon._load_dict() 就是这么读的
        # （先判帧 magic、解压、再 ZstdCompressionDict）。这里绝不把它当非法输入拒掉 ——
        # 上一版就是这么把你自备的字典挡在门外的。存**解压后的**字典本体，加载更快也少一层依赖。
        if not _need_zstd():
            return 1
        try:
            inner = zstd.ZstdDecompressor().decompressobj().decompress(data)
        except Exception as e:
            print("RED: 带 zstd 帧 magic，但解不出来：%r" % (e,))
            return 1
        dcheck = zstd.ZstdCompressionDict(inner)      # 让 zstandard 自己判这是不是字典
        data, note = dcheck.as_bytes(), note + "（导入时从 zstd 帧里解出字典本体）"
    out = Path(a.out) if a.out else (ncenv.DICT_DIR / "default.dict")
    _write_dict(data, out, "外部导入 %s" % p.name, note=note)
    return 0


def cmd_eval(a):
    if not _need_zstd():
        return 1
    run = Path(a.run)
    fp = run / "frames.jsonl"
    if not fp.exists():
        print("RED: %s 里没有 frames.jsonl" % run)
        return 1
    dp = Path(a.dict) if a.dict else ncenv.dict_path()
    ok, dp = ncenv.dict_status() if not a.dict else (dp.exists(), dp)
    if not ok:
        print("RED: 没有可测的字典（%s）" % dp)
        return 1
    raw = dp.read_bytes()
    if raw[:4] == b"\x28\xb5\x2f\xfd":
        raw = zstd.ZstdDecompressor().decompressobj().decompress(raw)
    cd = zstd.ZstdCompressionDict(raw)
    bodies = run / "bodies"
    before, after, still = 0, 0, 0
    for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except Exception:
            continue
        dec = r.get("dec")
        if dec == "undecoded":
            before += 1
            rf = r.get("raw_file")
            data = None
            if rf and (run / rf).exists():
                data = (run / rf).read_bytes()
            elif dec == "undecoded" and r.get("hex"):
                h = r["hex"].split("...")[0]
                try:
                    data = bytes.fromhex(h)
                except Exception:
                    data = None
            if data:
                try:
                    zstd.ZstdDecompressor(dict_data=cd).decompressobj().decompress(data)
                    after += 1
                    continue
                except Exception:
                    pass
            still += 1
        elif dec in ("text", "utf8", "zstd-dict", "gzip", "zlib15", "zlib-15", "zlib31", "zlib47", "zstd-plain"):
            pass
    total_und = before
    print("字典: %s (%d B, sha256_16=%s)" % (dp, dp.stat().st_size, _sha(dp.read_bytes())))
    print("本批 undecoded: %d 条 -> 换用这张字典后预计可解 %d 条，仍解不出 %d 条"
          % (total_und, after, still))
    if total_und == 0:
        print("（这批本来就没有未解码帧，收益无从衡量。要测收益就抓一批带压缩帧的。）")
    elif after == 0:
        print("RED: 字典对这批零收益 —— 大概率不是同一张（目标换了字典/版本，或样本不是同一条协议）")
        return 1
    return 0


def main():
    ncenv.utf8_stdout()
    ncenv.ensure_dirs()
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train")
    t.add_argument("--from", dest="frm", required=True, help="明文样本文件或目录")
    t.add_argument("--size", type=int, default=100 * 1024)
    t.add_argument("--level", type=int, default=19)
    t.add_argument("--out", default="")
    t.set_defaults(func=cmd_train)
    fc = sub.add_parser("from-capture")
    fc.add_argument("--run", required=True)
    fc.add_argument("--size", type=int, default=100 * 1024)
    fc.add_argument("--level", type=int, default=19)
    fc.add_argument("--out", default="")
    fc.set_defaults(func=cmd_from_capture)
    im = sub.add_parser("import")
    im.add_argument("--from", dest="frm", required=True)
    im.add_argument("--note", default="")
    im.add_argument("--out", default="")
    im.set_defaults(func=cmd_import)
    ev = sub.add_parser("eval")
    ev.add_argument("--run", required=True)
    ev.add_argument("--dict", default="")
    ev.set_defaults(func=cmd_eval)
    a = ap.parse_args()
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
