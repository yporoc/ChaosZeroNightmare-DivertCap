# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 netcatch contributors
#
# SPDX-License-Identifier: GPL-3.0-only
"""
sanitize.py — 脱敏发生在**出舱时**，不是采集时。

边界在哪：本机 `catchedsample\\run_*` 是**原文**，是分析材料。数据持有者要能看见 token 的真实
形状、要能跨批认出同一个玩家、要能核对 header —— 在采集口擦掉等于把这些权力收走，而那些权力
正是这套工具存在的理由。
唯一可外带的产物是 `report.py` 生成的 `snapshot/`，本模块就是那个出舱口的过滤器：出舱的一切
先过这里，生成后再强制审计一次，命中即拒绝出舱。所以"忘记擦"这个失败模式照样不存在，
只是守门人从采集口换到了出舱口。

分级（策略在代码里，不靠配置文件存在与否来开关）：
  KEEP   原样保留 —— 协议形状才是这套工具的价值：cmd、res、qid、opcode、端口、路径、TLS 参数、长度。
  LEN    只留长度 —— token / cookie 的值。
  ID     加本地随机盐的截断哈希 —— 各类用户/平台 ID。同一盐下同一 ID 得到同一值，
         所以"同一个玩家跨批次是否一致"这个问题仍然可答，而值本身不可反查、不可跨仓关联。
  DROP   整条丢 —— Authorization/Cookie 头值、可定位所在地的属性。

⚠ 本模块**管不到 capture.flows**：那是 mitmdump 自己写的原始档，里面必然是未脱敏的原文。
   所以可外带产物只有 report.py 产出的 snapshot/；run 目录整体外带是错的。
   verify_run 会把这条钉成判据。
"""
import json
import re

import ncenv

# 键名匹配（大小写不敏感，整串匹配优先，再退到子串）
_LEN_KEYS = re.compile(
    r"(access_token|user_access_token|refresh_token|id_token|auth_?token|"
    r"cookie|_cookie|cheetah_cookie|session_?id|signature|secret)", re.I)
_ID_KEYS = re.compile(
    r"(^(publisher_?uid|uuid|user_?id|server_?user_?id|game_?user_?id|account_?id|uid|"
    r"custom_?user_?id|auth_?id|open_?id|union_?id)$|"
    r"uid$|user_id$|_uuid$)", re.I)
# 裸 `id` 太宽（关卡 id、道具 id、回合 id 都叫 id），一律 hash 会破坏协议保真。
# 所以按路径判定：只有身处 用户/账号/玩家/资料 这类对象里的 id 才算身份。
_ID_PATH = re.compile(r"[.\[][^.\]]*\b(user|account|player|profile|publisher|member)\b"
                      r"[.\]\[][^\[\]]*\.?(id|auth_?id|uuid|user_?id|uid|guid)$", re.I)
_DROP_KEYS = re.compile(
    r"(^(user_?nation|nation|country|language_?code|device_?id|imei|oaid|advertising_?id|"
    r"mac|serial_?number|ip_?addr|client_?ip|ip)$|Authorization|Proxy-Authorization|WWW-Authenticate)", re.I)
# 头名：值一律 DROP，键名保留（这样还能看出"这个接口用了哪种鉴权"）
_SECRET_HEADERS = re.compile(r"^(authorization|cookie|set-cookie|proxy-authorization|"
                             r"www-authenticate|x-api-key|api-key)$", re.I)

# 值形状兜底：未匹配到键名、但明显是凭据的东西
_BEARER = re.compile(r"^\s*(bearer|basic|token)\s+\S{8,}", re.I)
_LONG_B64 = re.compile(r"^[A-Za-z0-9+/_=-]{40,}$")

# ---- 按**值形状**判身份，不按键名 ----
# 实测理由（真目标第一批）：身份藏在 `auth.id`、`friend_list[].search_entity.id` 这种
# 任意名字的容器里，而且里面是**别人**的 player id。键名枚举永远会漏新容器，
# 所以出舱口改为：8~12 位纯数字（真实账号/玩家 id 的长度带）一律 hash，
# 除非这个键名本身表明它是时钟或序号。名字无关 ⇒ 新容器不需要改策略表。
_ID_DIGITS = re.compile(r"^\d{8,12}$")
_CLOCK_KEYS = re.compile(r"^(cts|ctk|seqnum|qid|seq|sn|count|num|size|len|"
                         r"time|ts|timestamp|.*_at|.*_time|.*_timestamp|"
                         r"server_time|client_time|day|month|year|port|code|status|"
                         r"lv|level|exp|hp|mp|cost|amount|quantity|index|pos|idx)$", re.I)
_RUN8_12 = re.compile(r"(?<!\d)\d{8,12}(?!\d)")
# 展示型身份字段：昵称/角色名是**别人**的可读身份（实测昵称里还带 `#<player_id>`），
# 出舱时整条只留长度，键名保留（这样还能看出"这个对象有昵称这个字段"）。
_NAME_KEYS = re.compile(r"^(nickname|nick_name|player_?name|char(acter)?_?name|"
                        r"user_?name|display_?name|name_tag|guild_?name|team_?name)$", re.I)


def mask_identity_runs(s):
    """把字符串里任意 8~12 位数字串换成 id:… 哈希。
    昵称、URL 参数值、自由文本里的身份都靠这一条兜住 —— 键名枚举追不上它们。"""
    return _RUN8_12.sub(lambda m: fingerprint_id(m.group(0)), s)


def looks_like_identity_number(key, v):
    if isinstance(v, bool) or _CLOCK_KEYS.search(str(key)):
        return False
    if isinstance(v, int):
        return bool(_ID_DIGITS.match(str(v)))
    if isinstance(v, str):
        return bool(_ID_DIGITS.match(v.strip()))
    return False


def _looks_like_json(s):
    s = (s or "").strip()
    return len(s) > 12 and ((s[0] == "{" and s[-1] == "}") or (s[0] == "[" and s[-1] == "]"))


def _redact_embedded_json(s):
    """值本身是一段 JSON 文本时：解析→递归脱敏→重排。解析不了返回 None，交回上层当普通字符串。"""
    try:
        obj = json.loads(s)
    except Exception:
        return None
    if not isinstance(obj, (dict, list)):
        return None
    return json.dumps(redact_obj(obj), ensure_ascii=False, separators=(",", ":"))


def fingerprint_id(value):
    raw = ("%s|%s" % (ncenv.local_salt().hex(), str(value))).encode("utf-8")
    import hashlib
    return "id:" + hashlib.sha256(raw).hexdigest()[:10]


def _len_note(value):
    """只留长度。不留任何前缀字符 —— 3 个字符的 token 前缀也是原文片段，
    攒够批次就能拼东西。"""
    s = "" if value is None else (value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
    return {"redacted": "len", "len": len(s)}


def keep_secrets_out_headers(h):
    """headers 修好后凭据就会立刻开始落盘，所以脱敏必须先于 _hdrs 修复上线。"""
    out = {}
    for k, v in (h or {}).items():
        if _SECRET_HEADERS.match(str(k).lower()) or _BEARER.match(str(v or "")):
            out[str(k)] = "[redacted %d B]" % len(str(v or ""))
        else:
            out[str(k)] = str(v)[:400]
    return out


def redact_obj(o, path=""):
    """递归处理任意 JSON 结构，返回新对象。ID/LEN/DROP 三档都在键名上做。"""
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            key = str(k)
            p = "%s.%s" % (path, key)
            if _ID_PATH.search(p) and not isinstance(v, (dict, list)) and v not in (None, ""):
                out[key] = fingerprint_id(v)
                continue
            if _DROP_KEYS.search(key):
                out[key] = "[redacted]"
                continue
            if _ID_KEYS.search(key) and not isinstance(v, (dict, list)):
                out[key] = fingerprint_id(v) if v not in (None, "") else v
                continue
            if _LEN_KEYS.search(key) and not isinstance(v, dict):
                out[key] = _len_note(v)
                continue
            if isinstance(v, str) and _BEARER.match(v):
                out[key] = "[redacted bearer]"
                continue
            if isinstance(v, str) and _LONG_B64.match(v.strip()):
                out[key] = "[redacted %d chars]" % len(v)
                continue
            if looks_like_identity_number(key, v):
                # 名字无关的一道：8~12 位纯数字一律当身份 hash（时钟/序号键名除外）
                out[key] = fingerprint_id(v)
                continue
            if _NAME_KEYS.search(key) and isinstance(v, str) and v:
                out[key] = "[redacted %d chars]" % len(v)
                continue
            if isinstance(v, str) and _RUN8_12.search(v) and not _looks_like_json(v):
                # 串在自由文本里的身份：昵称 `<handle>#<player_id>`、
                # URL 参数值里的 userID、各种 device 指纹串。键名追不上，只能按值形状兜。
                out[key] = mask_identity_runs(v)
                continue
            if isinstance(v, str) and _looks_like_json(v):
                # 二次编码载荷：值本身是一段 JSON 文本（真实语料里就有 patch_version、
                # 整块 client_data）。不走这条，藏在里面的 "user":{"id":"…"} 会原样出海。
                inner = _redact_embedded_json(v)
                if inner is not None:
                    out[key] = inner
                    continue
            out[key] = redact_obj(v, p)
        return out
    if isinstance(o, list):
        return [redact_obj(x, "%s[]" % path) for x in o]
    return o


def redact_text(text):
    """帧内文本：先按 JSON 走（协议就是这样），解析不了再做正则兜底。
    解析不了不等于安全 —— 未识别的密文同样要落进 snapshot，所以标 json:false 由 report 决定展示方式。"""
    if not text:
        return text, "none"
    try:
        obj = json.loads(text)
    except Exception:
        obj = None
    if obj is not None:
        return json.dumps(redact_obj(obj), ensure_ascii=False, separators=(",", ":")), "json"
    # 正则兜底：键名后面直接跟值的形状
    t = re.sub(r'("((?:user_access|refresh|id|auth)_?token|cookie|[a-z_]*_cookie)"\s*:\s*)"((?:[^"\\]|\\.)*)"',
               lambda m: '"%s":"[redacted len=%d]"' % (m.group(1), len(m.group(3))), text, flags=re.I)
    t = re.sub(r'("(publisher_uid|uuid|user_?id|server_user_id|uid|user_id)"\s*:\s*)("?[^,"}\s]+"?)',
               lambda m: '%s"%s"' % (m.group(1), fingerprint_id(m.group(3).strip('"'))), t, flags=re.I)
    t = re.sub(r'("(user_?nation|device_?id|imei|mac|ip_?addr|client_?ip)"\s*:\s*)"?[^",}\s]+"?',
               r'"\1[redacted]', t, flags=re.I)
    return t, "regex" if t != text else "none"


def redact_frame(rec):
    """出舱时用：frames.jsonl 的一行原文 -> 可外带形态。保留 size/opcode/dir/dec/tag，
    text 走 redact_text。采集口不调用它。"""
    rec = dict(rec)
    if "text" in rec:
        t, how = redact_text(rec["text"])
        rec["text"] = t
        if how != "none":
            rec["red"] = how
    for k in ("text_truncated",):
        if k in rec:
            rec[k], _ = redact_text(rec[k])
    return rec


def redact_event(rec):
    """events.jsonl 的一行。host/port/path/status/len 是协议事实，一律留。

    顺序：先摘出需要特殊形状的两个字段，其余**整条按键名规则走结构化脱敏**，
    再把 headers 压成"只留键名与长度"、证书压成"只留摘要不留 PEM"。
    只处理 headers/证书是不够的 —— 插件自证 probe 第一次真跑就发现 publisher_uid 原样落盘，
    因为那时键名规则没有作用到记录的其余部分。"""
    rec = dict(rec)
    hdr = rec.pop("headers", None)
    cert = rec.pop("server_cert", None)
    rec = redact_obj(rec)
    if hdr is not None:
        rec["headers"] = keep_secrets_out_headers(hdr)
    if cert is not None:
        c = dict(cert)
        for drop in ("pem", "raw", "public_key"):
            c.pop(drop, None)
        rec["server_cert"] = c
    _Q = (r"(access_token|refresh_token|id_token|user_access_token|token|session_?id|session|sig|"
          r"signature|api_?key|key|auth|authorization|cookie|password|passwd|secret|"
          r"uid|user_?id|custom_?user_?id|publisher_?uid|guid|uuid|auth_?id|open_?id|union_?id|"
          r"device_?id|imei|oaid|mac|ip)")
    for k in ("path", "url"):
        if rec.get(k):
            v = str(rec[k])
            # 先解码再遮：埋点参数 e= 的值是百分号编码的 JSON，里面就写着 "userID"。
            # 上一版这里写了 `for src in (dec, v)` 却在每轮重新赋值 src，
            # 循环结束时留下的是**原始未解码串**的处理结果 —— 等于解码白做，泄漏照旧出海。
            try:
                from urllib.parse import unquote_plus
                src = unquote_plus(v)
            except Exception:
                src = v
            src = re.sub(_Q + r"=([^&;]{4,})", lambda m: "%s=[redacted]" % m.group(1),
                         src, flags=re.I)
            src = re.sub(r"=([^&;]*" + r"\d{8,12}" + r"[^&;]*)",
                         lambda m: "=[redacted len=%d]" % len(m.group(1)), src)
            rec[k] = src[:400]
    return rec


def redact_meta(meta):
    """meta.json 里的身份/环境字段。ca_sha1 是可跨批关联的指纹，换成随机 run id。"""
    m = dict(meta)
    for k in ("game_user_id", "server_user_id", "publisher_uid"):
        if m.get(k) not in (None, ""):
            m[k] = fingerprint_id(m[k])
    for k in ("user_nation", "tun_marks"):
        if k in m:
            m[k] = "[redacted]" if m[k] else m[k]
    if m.get("ca_sha1"):
        m["ca_sha1"] = "ca:" + str(m["ca_sha1"])[:8] + "(truncated)"
    m["redaction"] = "on"
    return m


# ---------------- 泄漏审计：尺子本身 ----------------
_LEAK_PATTERNS = (
    ("原值 uid", re.compile(r'"(game_user_id|publisher_uid|server_user_id|uuid)"\s*:\s*"?(\d{8,})')),
    ("token 值", re.compile(r'"user_access_token"\s*:\s*"[A-Za-z0-9+/=_-]{16,}"')),
    ("鉴权头", re.compile(r'"(authorization|cookie|set-cookie)"\s*:\s*"(?! ?\[redacted)[^"]{12,}', re.I)),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("CA 全指纹", re.compile(r'"ca_sha1"\s*:\s*"[0-9a-fA-F]{24,}"')),
    ("国家码", re.compile(r'"user_nation"\s*:\s*"(?! ?\[redacted)[a-zA-Z]{2,}"')),
    # 下面三条对应"出舱物里真出现过"的漏法（2026-09-28 第一次真目标跑就抓到前两条）：
    # ① 值本身是 JSON 文本的嵌套载荷里有 "user":{"id":"…"}  ② URL 查询参数带 uid
    ("嵌套对象裸 id", re.compile(r'"(id|auth_?id|guid|uuid)"\s*:\s*"?(\d{8,})')),
    ("URL 参数带 uid", re.compile(r"(?i)(custom_?user_?id|user_?id|publisher_?uid|auth_?id|uid|guid)=(\d{6,})")),
    ("URL 参数带凭据", re.compile(r"(?i)(access_?token|token|session_?id|api_?key|sig|secret)=([A-Za-z0-9%+/_=-]{12,})")),
)
# snapshot 里明确允许出现的形状：报告写这些不算泄漏
_EXEMPT = re.compile(r"^(id:[0-9a-f]{10}|\[redacted.*|ca:[0-9a-f]{8}\(truncated\)|\{.*redacted.*\}"
                     r"|.*[?&;]\w+=\[redacted.*)")


def audit_text(text):
    """返回 [(类别, 片段), ...]。空列表 = 这一份里没有可关联的个人数据。

    CSV 会把引号翻倍（`""id"":""123""`），所以同一份文本要按**还原引号后的形状**
    再过一遍 —— 只按 JSON 形状写判据的话，CSV 里的真实泄漏会绕过去（实测发生过）。"""
    hits = []
    probes = [text or ""]
    if '""' in (text or ""):
        probes.append(text.replace('""', '"'))
    for label, pat in _LEAK_PATTERNS:
        for src in probes:
            for m in pat.finditer(src):
                frag = m.group(0)[:90]
                if _EXEMPT.match(frag):
                    continue
                hits.append((label, frag))
    seen, uniq = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def audit_tree(path, skip=("capture.flows",)):
    from pathlib import Path
    p = Path(path)
    bad = []
    for f in sorted(p.rglob("*")):
        if not f.is_file() or f.name in skip:
            continue
        if f.suffix.lower() in (".pcapng", ".bin", ".p12", ".key"):
            continue  # 密文/二进制原件不参与文本审计，README 规定这些一律不外带
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for label, frag in audit_text(txt):
            bad.append((str(f.relative_to(p)), label, frag))
    return bad


def selftest_probe():
    """两腿都要立：
      正腿 = 喂进已知秘密，出来必须查不到；
      反腿 = 把已知秘密原样放进"待审"文本，audit 必须报出来（否则尺子不咬东西）。
    返回 (ok, detail)。"""
    probe = {
        "cmd": "auth", "qid": 7,
        "params": {"cmd": "auth_with_platform", "user_access_token": "A" * 40,
                   "uuid": "770000000101", "publisher_uid": "770000000202",
                   "user_nation": "xx", "world_id": "world-test-1"},
    }
    out, how = redact_text(json.dumps(probe, ensure_ascii=False))
    keep_ok = ('"world_id":"world-test-1"' in out.replace(" ", "") and '"qid":7' in out.replace(" ", ""))
    leak = audit_text(out)
    if how not in ("json",):
        return False, "帧内 JSON 没走结构化脱敏（how=%s）" % how
    if not keep_ok:
        return False, "协议形状被误伤（world_id/qid 没留下），脱敏不能破坏读数"
    if leak:
        return False, "正腿失败：脱敏后仍审计得到泄漏 %s" % (leak[:2],)
    # 反腿：原值直接给审计，必须报
    poisoned = json.dumps(probe, ensure_ascii=False)
    got = audit_text(poisoned)
    if not got:
        return False, "反腿失败：audit 对原样未脱敏的内容不报（尺子不咬东西）"
    kinds = {k for k, _ in got}
    if not {"原值 uid", "token 值", "国家码"} <= kinds:
        return False, "反腿只报了 %s，uid/token/nation 三项没报全" % (kinds,)
    hid = fingerprint_id("770000000101")
    if not re.match(r"^id:[0-9a-f]{10}$", hid):
        return False, "ID 哈希形状不对: %s" % hid
    if hid != fingerprint_id("770000000101"):
        return False, "同一盐下同一 ID 必须得同一值（否则跨批次无法关联）"

    # 第二组毒腿：真目标第一次真跑就漏出去的形状。两向都要测 ——
    # 只测"遮住了"会放过"把无害字段一起遮光"这种更隐蔽的坏法。
    # 键名故意用 auth / search_entity：证明判据不依赖容器叫什么。
    nested = {"cmd": "load", "params": {"client_data": json.dumps(
        {"auth": {"id": "770000000101", "auth_id": "87654321"},
         "friend_list": [{"search_entity": {"id": "770000000303", "lv": 53}}],
         "stage_id": 123, "cts_ms": 1577836800000}),
        "seqnum": 619283740, "cts": 1577836800000}}
    # 夹具卫生闸：泄漏样本与"必须原样保留"样本不许互为子串。
    # 真实教训：seqnum 一度写成 987654321，把泄漏样本 87654321 包在里面 ⇒
    # "值形状判据漏了 87654321"指的其实是那个本该保留的序号，报错指向错的地方。
    _leaks = {"770000000101", "87654321", "770000000303", "770000000202",
              "770000000404", "770000000505"}
    _keeps = set(re.findall(r"\d{7,}", json.dumps(nested))) - _leaks
    clash = [(a, b) for a in sorted(_leaks) for b in sorted(_keeps) if a in b or b in a]
    if clash:
        return False, "夹具自撞：%s —— 泄漏值与保留值互为子串，判据会把无辜字段误读成漏网" % (clash,)
    out2, _ = redact_text(json.dumps(nested, ensure_ascii=False))
    flat = out2.replace(" ", "").replace('\\"', '"')
    for leak in ("770000000101", "87654321", "770000000303"):
        if leak in flat:
            return False, "值形状判据漏了 %s（auth/search_entity 这类任意容器名）" % leak
    if audit_text(out2) or audit_text(flat):
        return False, "已遮但审计仍命中，形状不自洽 %s" % (audit_text(out2)[:1],)
    # 不许过度脱敏：时钟与序号必须原样（它们是可对齐的协议事实，不是身份）
    for keep in ('"seqnum":619283740', '"cts":1577836800000', '"lv":53', '"stage_id":123'):
        if keep not in flat:
            return False, "过度脱敏：%s 被一起遮掉了" % keep
    if flat.count("id:") < 3:
        return False, "身份值没被 hash 成 id:… 形状（只见到 %d 处）" % flat.count("id:")

    u = redact_event({"event": "req",
                      "path": "/api/x?custom_user_id=770000000202&app_v=1.0.0.464&e=%7B%22a%22%3A1%7D"})
    if "770000000202" in u["path"]:
        return False, "URL 查询参数里的 uid 没被遮"
    if "app_v=1.0.0.464" not in u["path"]:
        return False, "过度脱敏：URL 里的版本号参数被连带遮掉（那是协议事实）"
    if audit_text(u["path"]):
        return False, "URL 遮了仍被审计命中 %s" % (audit_text(u["path"])[:1],)
    csv_probe = '"a","load.user","x","","{""auth"":{""id"":""770000000101""}}","y"'
    if not audit_text(csv_probe):
        return False, "审计看不见 CSV 引号翻倍后的形状（这就是当初放过它的原因）"

    # 第三组毒腿：真语料第二轮才暴露的两种形状
    enc = redact_event({"event": "req", "path":
                        "/t?app_v=1.0.0.464&n=touch&e=%7B%22userID%22%3A%20%22770000000404%22%7D"})
    if "770000000404" in enc["path"]:
        return False, "百分号编码的 JSON 参数值里的 userID 没被遮（解码那一层没生效）"
    if "app_v=1.0.0.464" not in enc["path"]:
        return False, "过度脱敏：编码路径里的版本号被遮了"
    nm = redact_obj({"friend_list": [{"search_entity":
                                     {"nickname": "user#770000000505", "lv": 60}}],
                     "friend_count": 1})
    s = json.dumps(nm, ensure_ascii=False)
    if "770000000505" in s or "user#" in s:
        return False, "昵称整条没被遮（展示型身份字段）"
    if '"lv": 60' not in s and '"lv":60' not in s:
        return False, "过度脱敏：昵称旁边那个无辜的 lv 被连带删了"
    return True, ("OK(两腿立；uid->%s；原值审计命中 %d 条；时钟/序号/版本号/lv 未被误伤；"
                  "嵌套/URL/编码URL/昵称/CSV 五形全覆盖)" % (hid, len(got)))
