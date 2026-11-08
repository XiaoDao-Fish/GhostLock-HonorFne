# Building GhostLock-HonorFne

[中文构建教程](BUILD.zh-CN.md) · [English README](README.md) · [Categories](CATEGORIES.md)

This guide covers **how to compile every buildable component in this repository**,
on Windows, Linux and macOS. It documents the toolchain versions that were
actually used to produce a working `app-debug.apk`, plus the pitfalls found
while building it.

> **Most users do not need to build anything.** `run_root.bat` / `run_root.command`
> are plain scripts and run as-is. The Shizuku app, the exploit binary and
> `kernelsu.ko` are shipped prebuilt. Build only when you change source code.

> **Device scope:** the bundled `kernelsu.ko` has vermagic
> `5.4.289-qgki-gf6cb1f712a6e`. A rebuilt binary with different offsets or a
> different kernel build can panic the device. See
> [Supported devices](README.md#supported-devices).

---

## 0. What actually needs building

| # | Component | Toolchain | Build required? | Output |
|---|-----------|-----------|-----------------|--------|
| 1 | `run_root.bat`, `run_root.command`, `root/host-scripts/*.sh` | Git Bash + `adb` | **No** — plain scripts | — |
| 2 | `GhostLockApp/` (Shizuku app) | JDK 17 + Android SDK 34 + Gradle 8.7 | **Yes, if you edit Kotlin** | `app/build/outputs/apk/debug/app-debug.apk` (~40 MB) |
| 3 | `root/exploit/` (CVE-2026-43499 PoC) | Android NDK, `aarch64-linux-android35-clang` | Optional — `ghostlock` is prebuilt | `root/exploit/ghostlock` |
| 4 | `root/ksu-late-load/kernelsu.ko` | arm64 Linux container + FNE kernel source | Advanced only — `.ko` is prebuilt | `.build/kernelsu.ko` |
| 5 | `hooks/launcher/` (LSPosed module) | AGP 9.3.0 + Gradle 9.5.0 + JDK 17+ | Optional | `hooks/launcher/out/HnLauncherPort.apk` |
| 6 | `deploy/`, `GhostLockApp/app/src/main/assets/`, `tools/` | — | **No** — binary payloads | — |

Components 2 and 5 use **different Gradle/AGP generations**. Do not try to
build both with one Gradle installation.

---

## 1. Version matrix (verified working)

| Item | Version | Where it is pinned |
|------|---------|--------------------|
| JDK | **17** (17.0.12 used) | `compileOptions` / `kotlinOptions.jvmTarget = "17"` |
| Android Gradle Plugin | **8.5.2** | `GhostLockApp/build.gradle.kts` |
| Kotlin | **1.9.24** | `GhostLockApp/build.gradle.kts` |
| Gradle | **8.7** | `gradle/wrapper/gradle-wrapper.properties` |
| Android SDK Platform | **34** (`compileSdk = 34`) | `app/build.gradle.kts` |
| Build-Tools | **34.0.0** | installed via `sdkmanager` |
| Platform-Tools | current | supplies `adb` |
| `minSdk` / `targetSdk` | 24 / 34 | `app/build.gradle.kts` |
| Shizuku | **11.0.2** (`api` + `provider`) | `app/build.gradle.kts` |
| NDK (exploit only) | r27+ / API 35 clang | `root/exploit/Makefile` (`API ?= 35`) |
| Launcher module | AGP 9.3.0 / Kotlin 2.2.10 / Gradle 9.5.0 | `hooks/launcher/gradle/libs.versions.toml` |

> **AGP 8.5.2 requires Gradle ≥ 8.7.** Gradle 8.6 fails immediately with
> "Minimum supported Gradle version is 8.7". The wrapper properties are already
> set to 8.7.

---

## 2. Path A — Android Studio (simplest)

1. Install [Android Studio](https://developer.android.com/studio) (bundles JDK 17).
2. **SDK Manager → SDK Platforms**: tick **Android SDK Platform 34**.
3. **SDK Manager → SDK Tools**: tick **Android SDK Build-Tools 34.x** and
   **Android SDK Platform-Tools**.
4. Open the `GhostLockApp/` directory (not the repository root) as a project.
5. Wait for Gradle Sync. `settings.gradle.kts` already lists Aliyun mirrors
   first, then `google()` / `mavenCentral()`.
6. **Build → Build Bundle(s) / APK(s) → Build APK(s)**, or:

   ```bash
   cd GhostLockApp
   ./gradlew clean assembleDebug          # macOS / Linux
   ```

   ```cmd
   cd GhostLockApp
   gradlew.bat clean assembleDebug        &:: Windows
   ```

7. Output: `GhostLockApp/app/build/outputs/apk/debug/app-debug.apk`.

> The Gradle wrapper JAR is now committed at
> `GhostLockApp/gradle/wrapper/gradle-wrapper.jar`, so `gradlew` works on a
> fresh clone with no Android Studio at all.

---

## 3. Path B — command line only (no Android Studio)

This is the path actually used to produce the released APK. It needs only a
JDK, the SDK command-line tools and the Gradle wrapper.

### 3.1 Put the project on an ASCII-only path (Windows, critical)

AGP hard-rejects project paths containing non-ASCII characters:

```
Your project path contains non-ASCII characters.
```

A path such as `D:\xa\下载\GhostLock-HonorFne\GhostLockApp` **will fail**.
Use `D:\src\GhostLock-HonorFne\GhostLockApp` instead. This applies to the
project, the SDK (`D:\android-sdk`) and the JDK (`D:\jdk-17.0.12`) — `aapt2`
also fails to locate `android.jar` when the SDK path contains Chinese
characters.

`android.overridePathCheck=true` in `gradle.properties` can suppress the check,
but it does **not** fix `aapt2`. Move the files instead.

### 3.2 Install JDK 17

[Temurin JDK 17](https://adoptium.net/temurin/releases/?version=17), then:

```bash
export JAVA_HOME=/path/to/jdk-17
export PATH="$JAVA_HOME/bin:$PATH"
java -version
```

```cmd
set "JAVA_HOME=D:\jdk-17.0.12"
set "PATH=%JAVA_HOME%\bin;%PATH%"
java -version
```

### 3.3 Install Android SDK command-line tools

Download **Command line tools only** from
<https://developer.android.com/studio#command-line-tools-only> and unpack it so
that `sdkmanager` is at `cmdline-tools/bin/sdkmanager` (create that nesting if
the zip unpacks as `cmdline-tools/` directly).

```bash
export ANDROID_HOME="$HOME/android-sdk"       # ASCII path on Windows
export PATH="$ANDROID_HOME/cmdline-tools/bin:$PATH"

# Older cmdline-tools builds do not know --accept-licenses; pipe "y" instead.
yes | sdkmanager --licenses
sdkmanager --sdk_root="$ANDROID_HOME" "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

On Windows PowerShell:

```powershell
$env:ANDROID_HOME = "D:\android-sdk"
1..200 | ForEach-Object { "y" } | & "$env:ANDROID_HOME\cmdline-tools\bin\sdkmanager.bat" --licenses
& "$env:ANDROID_HOME\cmdline-tools\bin\sdkmanager.bat" --sdk_root=$env:ANDROID_HOME "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

Verify that `$ANDROID_HOME/platforms/android-34/android.jar` exists.

### 3.4 Point Gradle at the SDK

Either set `ANDROID_HOME` (above), or add one line to
`GhostLockApp/local.properties` (this file is git-ignored):

```properties
sdk.dir=D\:\\android-sdk
```

### 3.5 Build

```bash
cd GhostLockApp
./gradlew clean assembleDebug --no-daemon
```

```cmd
cd GhostLockApp
gradlew.bat clean assembleDebug --no-daemon
```

The wrapper downloads Gradle 8.7 on first run. If `services.gradle.org` is
unreachable, download `gradle-8.7-bin.zip` from a mirror
(e.g. `https://mirrors.cloud.tencent.com/gradle/`) and either place it in the
Gradle wrapper cache or call a local Gradle directly:

```cmd
D:\gradle-8.7\bin\gradle.bat clean assembleDebug --no-daemon
```

### 3.6 Install on the device

```bash
adb install -r GhostLockApp/app/build/outputs/apk/debug/app-debug.apk
```

The APK uses the default **debug** signature. Reinstalls with the same
signature keep Shizuku authorisation and the payloads already deployed in
`/data/local/tmp`.

### 3.7 Optional Windows helper scripts

`GhostLockApp/build_debug.bat` and `build_minimal.bat` are convenience
wrappers. `build_minimal.bat` expects `jdk-17.0.12/` and `cmdline-tools/` in the
**parent** directory and installs SDK components into `../android-sdk`. Those
directories are local toolchain downloads and are deliberately git-ignored.
For a clean checkout, use the commands in 3.2–3.6 instead.

---

## 4. Constraints you must not "modernise"

These are deliberate, not stale. Changing them breaks the app at runtime.

| Constraint | Reason |
|------------|--------|
| `rikka.shizuku:api:11.0.2` **and** `rikka.shizuku:provider:11.0.2` | 13.x moves to group `dev.rikka.shizuku` and makes `Shizuku.newProcess()` private. All `exec()` / `writeFile()` calls rely on it. Upgrading requires rewriting the command channel as a UserService/AIDL bridge. |
| `rikka.shizuku.ShizukuProvider` in `AndroidManifest.xml`, authority `${applicationId}.shizuku` | Shizuku delivers the Binder through this ContentProvider. Without it the app never receives the Binder, never appears in Shizuku's app list and never shows a permission dialog. The provider AAR does **not** declare the component for you. |
| `androidResources { noCompress += listOf("ko","zip","apk","bin") }` | `aapt2` must not compress / align the prebuilt kernel module and payloads. |
| `env` argument of `Shizuku.newProcess` must be `null` | `emptyArray()` gives the child an **empty** environment. The exploit reads many `getenv()` knobs (`GL_*`, `MMSTRIDE`, `KPHYS`, …). `null` inherits the shell environment, matching `adb shell`. |
| `buildFeatures { viewBinding = true }`, no AIDL | The UserService/AIDL bridge was removed; `IRootService.aidl` no longer exists. |
| Assets kept in the repository (`assets/*.apk`, `*.zip`, `*.ko`) | `.gitignore` excludes only `app-debug.apk` / `app-release.apk`. A global `*.apk` rule would silently remove required payloads from a fresh clone. |

---

## 5. Rebuilding the native exploit (optional)

`root/exploit/ghostlock` (aarch64, ~216 KB) is already shipped and copied into
`GhostLockApp/app/src/main/assets/ghostlock` at app build time. Rebuild it only
when you change the C sources or the offset tables.

Requirements: Android NDK r27+ (contains `aarch64-linux-android35-clang`).

```bash
cd root/exploit
make NDK_ROOT=/path/to/android-ndk API=35 HOST_TAG=linux-x86_64
```

> **`HOST_TAG` matters.** The Makefile only auto-detects `darwin-arm64` /
> `darwin-x86_64`. On Linux pass `HOST_TAG=linux-x86_64`, on Windows
> `HOST_TAG=windows-x86_64`, or the compiler path will be wrong.

Alternatively invoke clang directly (from `root/exploit/README.md`):

```bash
NDK=/path/to/android-ndk
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
  -O2 -Wall -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\" \
  src/core/main.c src/core/util.c src/core/slide.c \
  src/core/fops.c src/core/pipe_physrw.c src/core/root.c \
  src/core/miniadb.c src/core/umh_root.c src/core/memstart.c \
  -o ./ghostlock -fPIE -pie -pthread
```

Then copy the result over `GhostLockApp/app/src/main/assets/ghostlock` and
re-run `assembleDebug`. Device offset tables live in
`src/devices/fne/offsets.h` (11 exact kernel builds). A wrong offset does not
"fail gracefully" — it writes to unrelated kernel memory.

---

## 6. Rebuilding `kernelsu.ko` (advanced, usually unnecessary)

The shipped module targets the FNE-AN00 5.4.289 kernel exactly. The build
scripts require a **native arm64 Linux container** (Docker / colima on Apple
Silicon, or an arm64 host), the HONOR 70 open-source kernel tree, and the
device's real `/proc/config.gz`.

```bash
cd root/ksu-late-load
export KERNEL_SRC=/path/to/fne_src/Code_Opensource/kernel
sh ksu_ko_build.sh          # stages .build/, clones KernelSU v3.3.0, builds in debian:bookworm
sh probe_build.sh           # optional: quantify struct-layout drift
```

`build_inner.sh` forges `UTS_RELEASE` to
`5.4.289-qgki-gf6cb1f712a6e` and bypasses MODVERSIONS. `KSU_VERSION` is
derived from the KernelSU git commit count (manager version code 32601), so
the clone must keep its `.git` directory and stay at the matching tag.
Do **not** casually upgrade the manager or the module — the project README
explicitly warns against it.

---

## 7. Rebuilding the LSPosed module (optional)

`hooks/launcher/` is a separate, much newer Gradle build
(AGP 9.3.0 / Kotlin 2.2.10 / Gradle 9.5.0, `compileSdk` 37). Use its own
wrapper; do not reuse Gradle 8.7.

```bash
cd hooks/launcher
./gradlew assembleRelease
# or: bash build.sh   → copies to out/HnLauncherPort.apk
```

`app/build.gradle.kts` signs the release build with the committed
`debug.keystore` (`alias launcherport`, password `android`). Keep that file
in the repository, or `assembleRelease` will fail.

---

## 8. Verifying the build

```bash
# application label, package and icon
aapt2 dump badging app/build/outputs/apk/debug/app-debug.apk | grep -E "^package:|application-label:"
# provider must be present, or Shizuku will never see the app
aapt2 dump xmltree --file AndroidManifest.xml app-debug.apk | grep -i ShizukuProvider
# uncompressed payloads really made it into the APK
unzip -l app-debug.apk | grep -E "kernelsu.ko|ghostlock|KernelSU-manager.apk"
```

Expected: `application-label:'FNE-AN00'`, package `com.ghostlock.honorfne`,
and `rikka.shizuku.ShizukuProvider` in the manifest.

Line endings (`.gitattributes` enforces this):

```bash
git check-attr -a -- root/host-scripts/*.sh run_root.bat
```

`*.sh` / `*.command` must be **LF** (CRLF causes `bad interpreter`), `*.bat`
must stay **CRLF in the blob** (LF breaks `goto :label` in `cmd.exe` and the
script closes immediately).

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `Your project path contains non-ASCII characters` | Move project, JDK and SDK to ASCII-only paths (§3.1). |
| `Minimum supported Gradle version is 8.7` | Wrapper is on 8.6; use `gradle-8.7-bin.zip`. |
| `Could not find gradle-wrapper.jar` / `gradlew` exits immediately | The JAR was missing from earlier snapshots; it is now committed. If your copy lacks it, run `gradle wrapper --gradle-version 8.7 --no-validate-url`. |
| `aapt2` cannot find `android.jar` | SDK path contains non-ASCII characters, or Platform 34 is not installed. |
| `Could not resolve rikka.shizuku:api:13.1.5` | Version does not exist under that group. This project pins `11.0.2`; v13 uses `dev.rikka.shizuku`. |
| `Unresolved reference: newProcess` after upgrading Shizuku | 13.x makes it private. Stay on 11.0.2 or rewrite with UserService. |
| `Unknown argument --accept-licenses` | Old `sdkmanager`; pipe `y` into `--licenses` instead (§3.3). |
| Downloads from GitHub raw / `repo1.maven.org` time out | `settings.gradle.kts` already prefers `maven.aliyun.com`; Gradle itself can come from `mirrors.cloud.tencent.com/gradle/`. |
| `aaptOptions` / `noCompress` deprecation | Already migrated to `androidResources { noCompress += … }`. |
| App missing from Shizuku's authorised-app list | `ShizukuProvider` absent from the manifest, or the app has not yet called `requestPermission()` (open it and tap **Connect Shizuku**). |
| `BUILD SUCCESSFUL` but APK has no payloads | A global `*.apk` / `*.zip` ignore rule removed the assets. See §4. |

---

## 10. What not to commit

`.gitignore` excludes: local toolchain (`cmdline-tools/`, `gradle-8.*/`,
`jdk-*/`, `gradle-*-bin.zip`), upstream source snapshots (`KernelSU-main/`,
`Shizuku-API-master/`), build output (`build/`, `.gradle/`, `*.apk` at the app
level), logs and `.workbuddy/`. Two Gradle ZIPs in the original workspace each
exceed GitHub's 100 MB per-file limit. Put large payload APK/ZIP files in
**GitHub Releases** instead of git history.

---

## 11. Disclaimer

Security research for a device you own. The exploit writes to kernel memory at
hard-coded per-build offsets; an unsupported kernel can panic or boot-loop.
Root is temporary and lost on reboot. Never write to `system`, `vendor` or
`vbmeta`. See [LICENSE](LICENSE) and the upstream GPL-2.0 / MIT notices.
