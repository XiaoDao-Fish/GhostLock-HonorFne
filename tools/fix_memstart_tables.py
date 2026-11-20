#!/usr/bin/env python3
"""Re-derive the exploit's memstart-probe tables for a new kernel build.

The exploit (root/exploit/src/core/memstart.c) picks a *hard-coded* table of
kernel addresses per build:

    ms_spans_289[]  adjacent-symbol bounds, used to derive the KASLR slide
    ms_wins_289[]   tiny instruction windows where a register still holds the
                    vmemmap base (kind 0) or the physvirt base (kind 1)

Both are absolute kernel VAs of the build they were written for
(5.4.289-qgki-gf6cb1f712a6e).  A different commit of the same kernel moves
text around, so the tables go stale: the slide is then derived from wrong
spans (bogus slide) and the windows match nothing, so the probe reports
"no consensus" and the DM path falls back to a hard-coded linear-map base
that is wrong -> the walker dereferences garbage -> the device reboots.

This tool re-derives both tables for any boot.img whose kallsyms we can
read, and patches them into a copy of the *prebuilt* exploit, so no NDK and
no source rebuild is needed.

  boot.img -> kallsyms (BASE_RELATIVE) -> globals page (vmemmap /
  physvirt_offset) -> per-function "ldr xR,[xB,#off]" sites -> new tables
  -> byte-patch into the prebuilt ELF

Usage:
  python tools/fix_memstart_tables.py <boot.img> \
      --binary  GhostLockApp/app/src/main/assets/ghostlock \
      --out     GhostLockApp/app/src/main/assets/ghostlock_g7fd5b \
      --memstart-c root/exploit/src/core/memstart.c \
      --old-boot 5.4.289-qgki-gc1fab518d5f6.boot.img \
      --entry-out tools/out/g7fd5b_memstart_tables.h

`--old-boot` is the build the current table was written for; it is used to
(1) self-test the derivation and (2) map the old windows onto the new build.
"""
from __future__ import annotations

import argparse
import bisect
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import add_boot_img_kernel as atk  # noqa: E402

KIMAGE = atk.KIMAGE

# ---------------------------------------------------------------------------
# window role overrides: old host function -> new host function to use.
#
# The old table's windows live in specific functions.  When the new build
# re-lays-out the MM code the same function may no longer load the globals
# (or may not exist with that body), so we pick a function that plays the
# same role: it sits on the page-fault / free path and loads the vmemmap
# base, so a faulting IP inside it still has the value in the register.
#
# "kind" is decided automatically from the global that is actually loaded
# (vmemmap -> 0, physvirt_offset -> 1); "reg" likewise comes from the
# instruction, so a register-number change in the new build is picked up.
WINDOW_OVERRIDES = {
    # old function            -> new functions, one per old window of it
    "pagemap_pmd_range":     ["pagemap_pte_hole", "smaps_pte_hole"],
    "free_unref_page":       ["vm_insert_page"],
    "get_page_from_freelist": ["walk_page_vma"],
    "handle_mm_fault":       ["handle_pte_fault"],
    "follow_page_mask":      ["follow_pte"],
    "pte_map_lock":          ["follow_invalidate_pte"],
}

# old function -> which of its globals-loads to use (index into the list
# ordered by address).  Needed when a function has several candidate loads.
WINDOW_LOAD_INDEX = {
    "pagemap_pmd_range": [0, 1],
    "free_unref_page": [0],
    "get_page_from_freelist": [0],
    "handle_mm_fault": [0],
    "follow_page_mask": [0],
    "pte_map_lock": [0],
}

SPAN_RE = re.compile(
    r"\{\s*(0x[0-9a-fA-F]+)ULL\s*,\s*(0x[0-9a-fA-F]+)ULL\s*\}", re.M)
WIN_RE = re.compile(
    r"\{\s*(0x[0-9a-fA-F]+)ULL\s*,\s*(0x[0-9a-fA-F]+)ULL\s*,\s*"
    r"(\d+)\s*,\s*(\d+)\s*\}")


def adrp_target(word: int, pc: int):
    """Decode an ADRP: return the absolute page it points at, else None."""
    if (word & 0x9F000000) != 0x90000000:
        return None
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


class Kernel:
    """One kernel build: kallsyms + the globals page + globals-load sites."""

    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        self.kernel = atk.read_boot_kernel(path)
        self.sym, self.entries = atk.parse_kallsyms_all(self.kernel, None)
        # arm64 Image header ("ARM\x64") locates the Image inside the file
        hdr = self.raw.find(b"ARM\x64")
        if hdr < 0:
            sys.exit(f"{path}: no arm64 Image header")
        self.img = hdr - 0x38
        self.va_text = KIMAGE + self.sym["_text"]
        self.gp = (KIMAGE + self.sym["vmemmap"]) & ~0xFFF
        self.off_v = (KIMAGE + self.sym["vmemmap"]) & 0xFFF
        self.off_p = (KIMAGE + self.sym["physvirt_offset"]) & 0xFFF
        self.addrs = [KIMAGE + a for a, _ in self.entries]
        self._loads = None

    def va_to_file(self, va: int) -> int:
        return self.img + (va - self.va_text)

    def func_of(self, va: int) -> str:
        i = bisect.bisect_right(self.addrs, va) - 1
        return self.entries[i][1] if i >= 0 else "?"

    def next_symbol_va(self, va: int) -> int:
        """VA of the next symbol after `va` (adjacent-symbol bound)."""
        i = bisect.bisect_right(self.addrs, va)
        return self.addrs[i] if i < len(self.addrs) else va + 0x1000

    def loads(self):
        """{(func, rt, kind): [ldr_va, ...]} for every globals-page load.

        A load qualifies when the preceding ADRP points at the globals page
        (within 8 instructions - the compiler may interleave).
        """
        if self._loads is not None:
            return self._loads
        res = {}
        end = min(len(self.raw), self.img + 0x2C00000)
        for off in range(self.img + 0x40, end, 4):
            w = struct.unpack_from("<I", self.raw, off)[0]
            if (w & 0xFFC00000) != 0xF9400000:
                continue
            byteoff = ((w >> 10) & 0xFFF) * 8
            if byteoff not in (self.off_v, self.off_p):
                continue
            rn = (w >> 5) & 0x1F
            ok = False
            for back in range(1, 9):
                o2 = off - 4 * back
                if o2 < self.img:
                    break
                w2 = struct.unpack_from("<I", self.raw, o2)[0]
                if (w2 & 0x9F000000) == 0x90000000 and (w2 & 0x1F) == rn:
                    pc = self.va_text + (o2 - self.img)
                    if adrp_target(w2, pc) == self.gp:
                        ok = True
                    break
            if not ok:
                continue
            va = self.va_text + (off - self.img)
            kind = 0 if byteoff == self.off_v else 1
            res.setdefault((self.func_of(va), w & 0x1F, kind), []).append(va)
        for v in res.values():
            v.sort()
        self._loads = res
        return res


class SymRef:
    """A /proc/kallsyms dump: the *exact* build a table was written for.

    The boot.img we happen to have may be a different commit, where a few
    symbols drifted.  The dumped kallsyms gives us the original addresses,
    so the old table can be attributed to symbols exactly.
    """

    def __init__(self, path: Path):
        self.path = path
        self.sym = {}
        for line in path.read_text(encoding="latin1").splitlines():
            p = line.split()
            if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]):
                self.sym.setdefault(p[2].split("$")[0], int(p[0], 16))
        self.entries = sorted((v, k) for k, v in self.sym.items())
        self.addrs = [v for v, _ in self.entries]

    def func_of(self, va: int) -> str:
        i = bisect.bisect_right(self.addrs, va) - 1
        return self.entries[i][1] if i >= 0 else "?"


def parse_memstart_c(path: Path, tag: str = "289"):
    """Pull ms_spans_<tag>[] and ms_wins_<tag>[] out of the C source.

    `tag` names the table set: 289 (5.4.289-qgki), 224 (5.4.295 slot, see
    ms_select_tables()) or g7fd5b.  All sets carry the same 28 spans / 7
    windows, so one can be re-derived into any slot.
    """
    txt = path.read_text(encoding="utf-8", errors="replace")
    out = {}
    for name in (f"ms_spans_{tag}", f"ms_wins_{tag}"):
        m = re.search(rf"{name}\[\][^=]*=\s*\{{(.*?)\n\}};", txt, re.S)
        if not m:
            sys.exit(f"{path}: {name} not found")
        out[name] = ([tuple(int(x, 0) for x in g) for g in SPAN_RE.findall(m.group(1))]
                     if name.startswith("ms_spans") else
                     [tuple(int(x, 0) for x in g) for g in WIN_RE.findall(m.group(1))])
    return out[f"ms_spans_{tag}"], out[f"ms_wins_{tag}"]


def derive_spans(old: Kernel, new: Kernel, old_spans):
    """New span table: [symbol_start, next_symbol_start) in the new build."""
    out = []
    for lo, hi in old_spans:
        name = old.func_of(lo)
        if name not in new.sym:
            print(f"[span] 跳过 {name}: 新内核无此符号")
            continue
        nlo = KIMAGE + new.sym[name]
        nhi = nlo + (hi - lo)
        out.append((name, nlo, nhi))
    return out


def derive_windows(old: Kernel, new: Kernel, old_wins):
    """New window table.

    For every old window we know (host function, reg, kind, length).  We look
    for the same function in the new build; if it no longer loads the globals
    we fall back to WINDOW_OVERRIDES, which points at the function that plays
    the same role on the fault path.  The new register and kind are taken
    from the instruction that is actually there, so a register-number or
    global change in the new build is picked up automatically.
    """
    new_loads = new.loads()
    out = []
    used = set()
    # how many old windows each host function contributed (in order)
    seq = {}
    for lo, hi, reg, kind in old_wins:
        host = old.func_of(lo)
        seq[host] = seq.get(host, 0)
    for lo, hi, reg, kind in old_wins:
        host = old.func_of(lo)
        idx = seq[host]
        seq[host] += 1
        length = hi - lo
        cands = []
        if host in new.sym:
            cands.append(host)
        ov = WINDOW_OVERRIDES.get(host, [])
        if idx < len(ov):
            cands.append(ov[idx])
        pick = None
        for c in cands:
            hits = []
            for (f, rt, k), vas in new_loads.items():
                if f == c:
                    hits += [(rt, k, v) for v in vas]
            hits.sort(key=lambda t: t[2])
            if not hits:
                continue
            # prefer same register + same kind, then same kind, then same reg
            for pred in (lambda h: h[0] == reg and h[1] == kind,
                         lambda h: h[1] == kind,
                         lambda h: h[0] == reg):
                for h in hits:
                    if h[2] not in used and pred(h):
                        pick = (c, h)
                        break
                if pick:
                    break
            if not pick:
                for h in hits:
                    if h[2] not in used:
                        pick = (c, h)
                        break
            if pick:
                break
        if pick is None:
            print(f"[win] 警告: {host} 在新内核找不到可用载入点，跳过该窗口")
            continue
        c, (rt, k, ldr_va) = pick
        used.add(ldr_va)
        out.append((c, ldr_va + 4, ldr_va + 4 + length, rt, k))
    return out


def verify_windows(new: Kernel, wins):
    """Each window must start right after a globals-page ldr."""
    loads = new.loads()
    by_va = {}
    for (f, rt, k), vas in loads.items():
        for v in vas:
            by_va[v] = (f, rt, k)
    bad = 0
    for (f, lo, hi, rt, k) in wins:
        ldr = lo - 4
        if ldr not in by_va:
            print(f"[verify] ✘ {f}: lo-4={ldr:#x} 不是 globals 载入点")
            bad += 1
            continue
        gf, grt, gk = by_va[ldr]
        if gf != f or grt != rt or gk != k:
            print(f"[verify] ✘ {f}: 载入点归属不符 ({gf},x{grt},k{gk})")
            bad += 1
        else:
            print(f"[verify] ✔ {f}: lo={lo:#x} hi={hi:#x} x{rt} kind={k}")
    return bad == 0


def patch_binary(src: Path, dst: Path, old_spans, new_spans, old_wins, new_wins,
                 slot: str = "289"):
    """Overwrite the two tables inside the prebuilt exploit.

    `old_spans`/`old_wins` are the values *currently compiled into* the
    target slot and are only used to locate the arrays; the values written
    are the freshly derived ones.  Keeping them separate is what lets a new
    build be derived from the well-understood 289 table and still land in
    the slot the runtime actually selects (5.4.295 -> ms_*_224).
    """
    data = bytearray(src.read_bytes())

    # --- spans: 28 * (lo,hi) u64 pairs -------------------------------
    old_bytes = b"".join(struct.pack("<QQ", lo, hi) for lo, hi in old_spans)
    idx = data.find(old_bytes)
    if idx < 0:
        sys.exit(f"在二进制里找不到 ms_spans_{slot} 表")
    if data.find(old_bytes, idx + 1) >= 0:
        sys.exit(f"ms_spans_{slot} 表在二进制里不唯一，拒绝盲改")
    if len(new_spans) != len(old_spans):
        sys.exit(f"span 条目数变了（{len(new_spans)} vs {len(old_spans)}），"
                 "二进制里是定长表，不能原地改")
    new_bytes = b"".join(struct.pack("<QQ", lo, hi) for _n, lo, hi in new_spans)
    data[idx:idx + len(new_bytes)] = new_bytes
    print(f"[patch] ms_spans_{slot} @ {idx:#x}: {len(old_spans)} 条已更新")

    # --- windows: 7 * (lo,hi,reg,kind) --------------------------------
    old_bytes = b"".join(struct.pack("<QQii", lo, hi, reg, kind)
                         for lo, hi, reg, kind in old_wins)
    idx = data.find(old_bytes)
    if idx < 0:
        sys.exit(f"在二进制里找不到 ms_wins_{slot} 表")
    if data.find(old_bytes, idx + 1) >= 0:
        sys.exit(f"ms_wins_{slot} 表在二进制里不唯一，拒绝盲改")
    new_bytes = b"".join(struct.pack("<QQii", lo, hi, rt, k)
                         for _f, lo, hi, rt, k in new_wins)
    if len(new_bytes) != len(old_bytes):
        sys.exit(f"window 条目数变了（{len(new_wins)} vs {len(old_wins)}），"
                 "二进制里是定长表，不能原地改")
    data[idx:idx + len(new_bytes)] = new_bytes
    print(f"[patch] ms_wins_{slot} @ {idx:#x}: {len(old_wins)} 条已更新")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(bytes(data))
    print(f"[patch] 写出 {dst} ({len(data)} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("boot", type=Path)
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--memstart-c", type=Path, default=Path(
        "root/exploit/src/core/memstart.c"))
    ap.add_argument("--old-boot", type=Path, default=None,
                    help="构建 memstart 表的那个 boot.img（用于自检 + 窗口映射）")
    ap.add_argument("--old-syms", type=Path, default=Path(
        "GhostLockApp/app/src/main/assets/ksu_fne/fne_syms.txt"),
        help="表对应构建的 /proc/kallsyms dump（精确地址来源）")
    ap.add_argument("--entry-out", type=Path, default=None)
    ap.add_argument("--slot", default="289", choices=("289", "224", "g7fd5b"),
                    help="要覆盖二进制里的哪套表（运行时按 uname 选："
                         "5.4.289-* -> 289，5.4.295-* -> 224）")
    ap.add_argument("--from-slot", default=None, choices=("289", "224", "g7fd5b"),
                    help="用哪套 C 表做语义参照（地址必须属于 --old-syms 的构建；"
                         "默认与 --slot 相同）")
    ap.add_argument("--self-test", action="store_true",
                    help="只用 --old-boot 跑一遍，验证推导能复现原表")
    a = ap.parse_args()

    from_slot = a.from_slot or a.slot
    # 参照表：符号名/长度从这里取（必须与 --old-syms 是同一个构建）
    ref_spans, ref_wins = parse_memstart_c(a.memstart_c, from_slot)
    # 槽位表：二进制里要定位并覆盖的那套（条目数必须一致）
    old_spans, old_wins = parse_memstart_c(a.memstart_c, a.slot)
    print(f"[table] 参照 ms_*_{from_slot} ({len(ref_spans)} spans/{len(ref_wins)} wins)"
          f"  →  覆盖 ms_*_{a.slot} ({len(old_spans)}/{len(old_wins)})")
    if (len(ref_spans), len(ref_wins)) != (len(old_spans), len(old_wins)):
        sys.exit("两套表条目数不同，二进制里是定长数组，不能这样搬")

    ref = SymRef(a.old_syms)
    print(f"[ref] {a.old_syms}: {len(ref.sym)} 个符号（表对应构建的精确地址）")
    new = Kernel(a.boot)
    print(f"[new] globals 页={new.gp:#x} "
          f"vmemmap@{new.off_v:#x} physvirt@{new.off_p:#x}")

    # --- self test ------------------------------------------------------
    # Re-derive the table against the build it was written for.  The
    # reference kallsyms gives that build's exact addresses; the boot.img
    # gives the code (and therefore the load sites).  Every entry must come
    # out identical, except spans whose symbol moved between the two
    # commits - that difference is exactly what the tool exists to fix.
    if a.old_boot:
        oldk = Kernel(a.old_boot)
        st_spans = derive_spans(ref, oldk, ref_spans)
        st_wins = derive_windows(ref, oldk, ref_wins)
        bad = 0
        for (name, lo, hi), (olo, ohi) in zip(st_spans, ref_spans):
            if (lo, hi) != (olo, ohi):
                moved = ref.sym.get(name) != (KIMAGE + oldk.sym.get(name, 0))
                tag = "符号在两个构建间移动过（预期差异）" if moved else "✘ 无法解释的差异"
                print(f"[selftest] span {name}: 推导 ({lo:#x},{hi:#x}) != "
                      f"原表 ({olo:#x},{ohi:#x})  {tag}")
                if not moved:
                    bad += 1
        for (f, lo, hi, rt, k), (olo, ohi, oreg, okind) in zip(st_wins, ref_wins):
            if lo != olo or rt != oreg or k != okind:
                print(f"[selftest] win {f}: 推导 ({lo:#x},x{rt},k{k}) != "
                      f"原表 ({olo:#x},x{oreg},k{okind})")
                bad += 1
        print(f"[selftest] {'通过 ✔（表可被完整复现）' if bad == 0 else f'失败 ✘ {bad} 处'}")
        if bad:
            sys.exit("自检失败：推导逻辑与原表不一致，拒绝产出")
    if a.self_test:
        return

    new_spans = derive_spans(ref, new, ref_spans)
    new_wins = derive_windows(ref, new, ref_wins)
    print(f"\n[table] 新 span {len(new_spans)} 条 / 新 window {len(new_wins)} 条")
    for name, lo, hi in new_spans:
        print(f"   span  {name:24s} [{lo:#x},{hi:#x})")
    for f, lo, hi, rt, k in new_wins:
        print(f"   win   {f:24s} [{lo:#x},{hi:#x}) x{rt} kind={k}")

    if not verify_windows(new, new_wins):
        sys.exit("窗口校验失败，拒绝产出")

    if a.entry_out:
        lines = ["/* memstart probe tables re-derived by tools/fix_memstart_tables.py",
                 f" * from {a.boot.name}; 语义参照 ms_*_{from_slot} -> 覆盖 ms_*_{a.slot}. */",
                 f"static struct ms_win ms_wins_{a.slot}[] = {{"]
        for f, lo, hi, rt, k in new_wins:
            lines.append(f"    {{0x{lo:016x}ULL, 0x{hi:016x}ULL, {rt}, {k}}},"
                         f"  /* {f} */")
        lines.append("};")
        lines.append(f"static const uint64_t ms_spans_{a.slot}[][2] = {{")
        for name, lo, hi in new_spans:
            lines.append(f"    {{0x{lo:016x}ULL, 0x{hi:016x}ULL}},   /* {name} */")
        lines.append("};")
        a.entry_out.parent.mkdir(parents=True, exist_ok=True)
        a.entry_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[out] {a.entry_out}")

    patch_binary(a.binary, a.out, old_spans, new_spans, old_wins, new_wins, a.slot)


if __name__ == "__main__":
    main()
