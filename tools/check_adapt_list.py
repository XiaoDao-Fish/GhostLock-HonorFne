#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
核对 / 自动同步 `D:\\xa\\下载\\适配机型.txt` 与 App 的两份提权白名单。

白名单来源（都以源码/assets 为准，不靠人工维护的 txt）：
  链路 A  EngineCatalog.kt 的 GHOSTLOCK_KERNELS（ghostlock 二进制逐字 strcmp）
  链路 B  extractkit/profiles.tsv（CVE-2026-98260 的 76+ 条内置 profile）

用法：
  python3 tools/check_adapt_list.py          # 只核对，报告越界/遗漏/重复
  python3 tools/check_adapt_list.py --fix    # 缺的补进 txt（会重排整份文件）
  python3 tools/check_adapt_list.py --target <其它txt路径>

约定：txt 只写「可临时 root」的内核（= 白名单全集），不写系统版本号。
新增内核适配后必须跑一次 --fix，否则清单会与 App 实际能力脱节。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE_KT = ROOT / "GhostLockApp/app/src/main/java/com/ghostlock/honorfne/EngineCatalog.kt"
PROFILES_TSV = ROOT / "GhostLockApp/app/src/main/assets/extractkit/profiles.tsv"
DEFAULT_TXT = Path(r"D:\xa\下载\适配机型.txt")
WORKSPACE_TXT = ROOT / "适配机型.txt"

GROUPS = [(6, 18), (6, 12), (6, 6), (6, 1), (5, 15), (5, 10), (5, 4)]

# 链路 A 独有内核的机型名（profiles.tsv 里没有，需要人工维护；新增时在此登记）
# 2026-11-20：只保留荣耀机型。原 OPPO / 一加 / 小米 / vivo / 索尼 的
# 14 条链路 A 独有内核已从 EngineCatalog.GHOSTLOCK_KERNELS 移除，对应机型
# 注释一并删除，避免适配名单再列出非荣耀机子。
EXTRA_MODELS = {
    "5.4.289-qgki-g7fd5b29213eb": "FNE-AN00 / NTH-AN00（荣耀 70 / 荣耀 50）",
    "5.4.295-g0fb2656b2b50": "NTH-AN00（荣耀 Magic5 Pro）",
}


def kkey(s: str) -> str:
    """与 App EngineCatalog.kernelKey 同款归一化：主版本号 + g<hash 前12>。"""
    s = (s or "").strip().lower()
    if not s:
        return ""
    m = re.match(r"\d+\.\d+\.\d+", s)
    ver = m.group() if m else s[:8]
    h = re.search(r"g([0-9a-f]{8,40})", s)
    return ver + "-g" + h.group(1)[:12] if h else ver


def load_whitelist():
    """返回 ({kkey: (release, model)}, {kkey: (release, model)})。

    分两组，因为「可临时 root」有两条路径：
      builtin —— 内置 profile / 链路 A 二进制，**开箱即用**。
      selfadapt —— 内置 profile 是 offsets-only（缺 STATIC_TIMER_SITE /
        TIMER_SITE_LOW21，payload 会强制 fake_stage=0、!g_slide 直接
        park_forever），开箱跑不通；但 App 的「自助适配」能让用户导入本机
        boot.img 现场生成 symbols 模式的 profile，之后可以 root。
        所以不能删除，要标注清楚。
    """
    text = ENGINE_KT.read_text(encoding="utf-8", errors="ignore")
    block = re.search(r"val GHOSTLOCK_KERNELS = listOf\((.*?)\)", text, re.S)
    ghostlock = re.findall(r'"([^"]+)"', block.group(1)) if block else []

    builtin, selfadapt = {}, {}
    for release in ghostlock:
        k = kkey(release)
        builtin[k] = (release, EXTRA_MODELS.get(k, "—"))
    for ln in PROFILES_TSV.read_text(encoding="utf-8", errors="ignore").splitlines():
        c = ln.split("\t")
        if len(c) >= 5:
            name = c[5] if len(c) > 5 else ""
            k = c[1]
            if k in builtin:
                continue
            row = (c[2], c[4] or "—")
            if "offsets-only" in name:
                selfadapt[k] = row
            else:
                builtin[k] = row
    return builtin, selfadapt


def load_txt(path: Path):
    if not path.is_file():
        return {}
    out = {}
    for ln in path.read_text(encoding="utf-8-sig").splitlines():
        m = re.search(r"(\d+\.\d+\.\d+[0-9A-Za-z._+\-]*)", ln)
        if m:
            k = kkey(m.group())
            out[k] = out.get(k, 0) + 1
    return out


def vtuple(k):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", k)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def render(builtin, selfadapt) -> str:
    lines, total = [], 0

    def emit(rows, header):
        nonlocal total
        lines.append("=" * 107)
        lines.append(header)
        for maj, mnr in GROUPS:
            items = [(k, v) for k, v in rows.items() if vtuple(k)[:2] == (maj, mnr)]
            if not items:
                continue
            items.sort(key=lambda kv: (kv[1][1], kv[0]))
            lines.append("-" * 107)
            for k, (release, model) in items:
                model = model.replace("|", " / ")
                # 机型列补到 36 字符对齐；超长时至少留一个空格，别和内核串粘连
                col = model.ljust(36) if len(model) < 36 else model + " "
                lines.append(col + release)
                total += 1

    emit(builtin, "内置 profile / 链路 A —— 开箱即用，直接点「一键 Root」")
    if selfadapt:
        emit(selfadapt,
             "内置 profile 仅结构偏移（offsets-only）—— 需在 App 内「自助适配」"
             "导入本机 boot.img 后才能 Root")
    lines.append("=" * 107)
    return "\n".join(lines) + "\n", total


def main():
    args = sys.argv[1:]
    do_fix = "--fix" in args
    target = DEFAULT_TXT
    if "--target" in args:
        target = Path(args[args.index("--target") + 1])

    builtin, selfadapt = load_whitelist()
    wl = {**builtin, **selfadapt}
    have = load_txt(target)

    over = sorted(k for k in have if k not in wl)
    miss = sorted(k for k in wl if k not in have)
    dup = {k: v for k, v in have.items() if v > 1}

    print(f"白名单内核: {len(wl)}（开箱即用 {len(builtin)} + 需自助适配 {len(selfadapt)}）")
    print(f"{target} 唯一内核: {len(have)}")
    print()
    if over:
        print(f"[越界] txt 里有、白名单没有（应删）{len(over)} 条:")
        for k in over:
            print("   ", k)
    if miss:
        print(f"[遗漏] 白名单有、txt 没有（应补）{len(miss)} 条:")
        for k in miss:
            print("   ", k, "->", wl[k][0])
    if dup:
        print(f"[重复] {dup}")
    if not (over or miss or dup):
        print("双向一致 ✓ 无越界 / 无遗漏 / 无重复")
        if not do_fix:
            return 0
        # --fix 即使一致也重写，用于应用最新排版（分段 / 对齐）
        print()

    if do_fix:
        body, total = render(builtin, selfadapt)
        target.write_text(body, encoding="utf-8-sig")
        print()
        print(f"已重写 {target}：{total} 条内核")
        if target != WORKSPACE_TXT:
            WORKSPACE_TXT.write_text(body, encoding="utf-8-sig")
            print(f"已同步工作区副本 {WORKSPACE_TXT}")
    else:
        print()
        print("加 --fix 自动重写（按「开箱即用 / 需自助适配」分段）")
    return 0 if do_fix or not (over or miss or dup) else 1


if __name__ == "__main__":
    raise SystemExit(main())
