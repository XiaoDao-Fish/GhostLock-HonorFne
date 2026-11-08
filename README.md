# GhostLock-HonorFne

[中文文档](README.zh-CN.md) · [Build guide / 构建教程](BUILD.md) · [Categories](#repository-categories) · [Supported devices](#supported-devices)

Temporary, **per-boot root** for the HONOR 70 (FNE-AN00), built on
**CVE-2026-43499** (a futex PI-waiter use-after-free) plus a custom
**KernelSU late-load** chain. A Shizuku-based companion app reproduces the
host-script flow on-device without a PC.

> **Scope and disclaimer**
> This is security research for a device you own. The exploit writes directly
> into kernel memory using offsets that are hard-coded per kernel build.
> Running it on a different model, a different firmware, or an unlisted kernel
> build can corrupt unrelated kernel memory and cause a panic / boot loop.
> Root is **not persistent** — it is lost on every reboot and must be re-run.
> Never write to `system`, `vendor` or `vbmeta` partitions.

---

## Repository categories

The tree is organised by **role in the root pipeline**, not by file type.
`✅` = commit to the repository, `📦` = better placed in GitHub Releases,
`⛔` = local-only, exclude before uploading.

| # | Category | Path | Contents | |
|---|----------|------|----------|---|
| 1 | **Entry points** | `run_root.bat`, `run_root.command` | One-click host scripts for Windows / macOS: dependency check → USB connection → deploy → grind → install managers | ✅ |
| 2 | **Exploit core** | `root/exploit/` | CVE-2026-43499 PoC: C sources, `src/devices/*/offsets.h` per-device kernel offset tables, prebuilt `e` binary, build tooling | ✅ |
| 3 | **Host drivers** | `root/host-scripts/` | `run_forever.sh` (outer loop), `run_w2.sh` (W1→W2 runner), `install_managers.sh`, `wait_ksu.sh`, `gl_cycle.sh`, `uninstall.sh`, settle / reboot recovery logic | ✅ |
| 4 | **KernelSU late-load chain** | `root/ksu-late-load/` | `chain_hook.sh`, `kernelsu.ko`, `ksud`, `magiskpolicy`, `load_ko`, `kmsg_dumper`, `fne_syms.txt`, kallsyms tables and build scripts | ✅ |
| 5 | **Runtime KSU modules** | `root/ksu-modules/netfix_packet/` | `sepolicy.rule` (network / hwservice fix), `post-fs-data.sh` + `service.sh` (status-bar, nav-bar, AOD / RRO fix) | ✅ |
| 6 | **Shizuku companion app** | `GhostLockApp/` | Android app (Kotlin, AGP 8.5.2): Shizuku shell privileges replace `adb shell`, deploys payloads, drives W1/W2/KSU, installs managers; adaptive launcher icon, bilingual crash logging to `Download/XiaoDao` | ✅ |
| 7 | **LSPosed hook module** | `hooks/launcher/` | `HnLauncherPort` — desktop / SystemUI animation, gesture and small-window tweaks | ✅ |
| 8 | **Install payloads** | `deploy/` | `KernelSU-manager.apk`, `ZygiskNext.zip`, `LSPosed-zygisk.zip` (installed through `ksud module install`, never bare-unzipped) | 📦 |
| 9 | **Documentation** | `README.md`, `docs/` | Setup guide, exploit analysis, milestone notes, desktop-hook rationale | ✅ |
| 10 | **Auxiliary tools** | `tools/` | Third-party reference APK, kernel-offset helpers | ⚠️ review licenses |
| — | **Local build toolchain** | `cmdline-tools/`, `gradle-8.6/`, `gradle-*-bin.zip`, `jdk-*/` | Android SDK cmdline tools, Gradle distributions, JDK — ~400 MB, downloaded locally | ⛔ |
| — | **Upstream source snapshots** | `KernelSU-main/`, `Shizuku-API-master/` | Vendored copies of third-party projects. Reference them as upstream links / submodules instead of committing | ⛔ |
| — | **Local state / artifacts** | `.workbuddy/`, `*.log`, `app-debug.apk`, `.gradle/`, `build/` | Session notes, grind logs, compiled APKs | ⛔ |

> The provided `.gitignore` and `.gitattributes` implement this split.
> `.gitattributes` is important: `*.sh` / `*.command` must stay **LF**,
> `*.bat` must stay **CRLF**, and kernel binaries must stay untouched.

---

## Supported devices

The bundled `kernelsu.ko` declares
`vermagic=5.4.289-qgki-gf6cb1f712a6e SMP preempt mod_unload modversions aarch64`,
so the module only loads on that exact kernel.

| Source | Claimed range |
|--------|---------------|
| Root `README.md` | HONOR 70 / 60 / 60 Pro (FNE / LSA / TNA), MagicOS 8.0.221 / 8.0.224, kernels `5.4.289-qgki-gf6cb1f712a6e` and `5.4.295-qgki-g0fb2656b2b50` |
| `docs/README_1.md` (strict) | **FNE-AN00 only**: `5.4.289-qgki-gf6cb1f712a6e` (MagicOS 8.0.214–221), or `5.4.295-qgki-*` (MagicOS 8.0.2xx, 10 known builds including 8.0.224) |

`root/exploit/src/devices/fne/offsets.h` lists **11 exact kernel builds**
(one 5.4.289 plus ten 5.4.295 variants, grouped into clusters A–D).
There is no `lsa/` or `tna/` offset table — those models are listed as a
same-lineage assumption, not as tested configurations.

The exploit source itself carries offset tables for additional devices
(OnePlus 13/15, OPPO Find X9 series, Reno10 Pro+, Pad 4 Pro, vivo T4 /
X Fold3 Pro / X200 Ultra, Sony Xperia 1 IV, Ace 6T, and others; kernels
5.4 → 6.12). Those cover the **privilege-escalation stage only**. The
KernelSU late-load chain, symbol tables and modules in this repository are
FNE-specific, so the full pipeline is not portable as-is.

Check your kernel with `adb shell uname -r` (or Settings → About phone →
Kernel version) and match the string exactly.

---

## How it works

```
[1/5] Dependency check      platform-tools / Git Bash
[2/5] Connect device        USB (wireless adb removed from host scripts)
[3/5] Root state check      skip this boot if kernelsu.ko is already loaded
[4/5] Deploy                push e, ksu_fne/, netfix_packet/ to /data/local/tmp
[5/5] Grind                 run_forever.sh: settle → W1 → W2 → KSU late-load
[+]   Wrap-up               install KSU Manager / ZygiskNext / LSPosed
```

1. **settle** — kill background app storms, wait for real CPU idle ≥ 85 %
   (`/proc/stat` based; load average is misleading because of D-state kworkers).
   W1/W2 are extremely timing-sensitive.
2. **W1** — `env $SYNC e --write1`: corrupt `selinux_state` → Permissive.
   Historically ~8 % landing rate per invocation; kernel panics and
   protective reboots are expected, not a tool failure.
3. **W2** — cred write (`GL_W2_ROUNDS=2`, ladder on `GL_W2_CRED_ADJ`) →
   root child process → detached `chain_hook.sh`.
4. **KSU late-load** — fake kallsyms rebased to this boot's slide,
   `magiskpolicy` injects KSU rules, `load_ko` insmods `kernelsu.ko`,
   `ksud` runs post-fs-data / services / boot-completed / install stages,
   then SELinux enforcing is restored.

**Never run two grinds concurrently.** `run_forever.sh` and the Shizuku app
both kill stale `e` processes (`pkill -9 -x e`) before starting; two
`slab_drain` fork storms will trigger a protective reboot.

---

## Getting started

### Host script (recommended for unattended runs)

Requirements: Windows + Git Bash + platform-tools, or macOS + platform-tools.
USB connection only. From the repository root:

```cmd
run_root.bat
```

```bash
bash run_root.command
```

The host script can survive device reboots via `adb wait-for-device` and run
the 8-round loop overnight.

### Shizuku app (PC-free)

1. Install Shizuku and start it through **Wireless debugging** (Android 11+).
2. Install `GhostLockApp`, grant Shizuku permission, tap **Deploy payloads**.
3. Tap **One-tap temporary Root**, then **Install managers** after `KSU READY`.

Caveat: wireless-debugging Shizuku dies on every reboot and must be restarted
and re-authorised manually, which makes repeated W1 attempts tedious.

Build the app with JDK 17 + Android SDK 34 + Gradle 8.7 (AGP 8.5.2 requires
Gradle ≥ 8.7). Project paths must be ASCII on Windows. See the
**[Build guide](BUILD.md)** for full instructions, version matrix, native
exploit / `kernelsu.ko` rebuild steps and troubleshooting.

---

## Upload checklist

- [ ] Keep `LICENSE` (Apache-2.0) and add explicit notices for the vendored
      GPL-2.0 KernelSU material and MIT-licensed Shizuku API.
- [ ] Remove `gradle-8.6-bin.zip` / `gradle-8.7-bin.zip` — each exceeds
      GitHub's 100 MB per-file limit.
- [ ] Remove local toolchain and upstream source snapshots (see ⛔ rows).
- [ ] Move large APK / ZIP payloads to **GitHub Releases** rather than the
      git history.
- [ ] Verify `git check-attr -a -- root/host-scripts/*.sh` and `*.bat`.
- [ ] Do not commit `*.log` or `.workbuddy/`.

### Suggested GitHub topics

`android-root` `kernelsu` `shizuku` `cve-2026-43499` `kernel-exploit`
`security-research` `poc` `honor` `magicos` `lsposed` `zygisk` `temporary-root`

---

## Built-in modules

**netfix_packet** fixes two side effects of the root process: SELinux SID loss
(16 `sepolicy.rule` lines injected during late-load) and status-bar /
navigation-bar / AOD breakage caused by LSPosed daemon repeatedly mounting
tmpfs over `/data/resource-cache` (post-fs-data + service.sh patch + idmap2d
keep-alive).

**HnLauncherPort** (`hooks/launcher/`) enables advanced blur / icon entrance
animations, rebuilds gesture inertia, adds small-window threshold tuning and
cleans redundant controls.

---

## Credits & license

- [GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT)
- [KernelSU](https://github.com/tiann/KernelSU)
- [Shizuku-API](https://github.com/RikkaApps/Shizuku-API)

`root/exploit/` — Apache-2.0 (see `LICENSE`).
KernelSU-derived material — GPL-2.0.
Shizuku API — MIT.
