# GhostLock-HonorFne 构建教程

[English build guide](BUILD.md) · [中文 README](README.zh-CN.md) · [分类索引](CATEGORIES.md)

本教程说明**仓库里每个可编译组件该怎么构建**，覆盖 Windows、Linux、macOS。
所列版本是实际打出可用 `app-debug.apk` 的组合，并附上构建过程中踩过的坑。

> **多数用户不需要构建任何东西。** `run_root.bat` / `run_root.command` 是纯脚本，
> 直接运行即可；Shizuku App、exploit 二进制和 `kernelsu.ko` 都是随仓库附带的预编译产物。
> 只有改了源码才需要重编。

> **机型范围**：内置 `kernelsu.ko` 的 vermagic 为
> `5.4.289-qgki-gf6cb1f712a6e`。用错偏移或换了内核构建重编，可能导致设备 panic。
> 详见[支持机型](README.zh-CN.md#支持机型)。

---

## 0. 哪些东西需要构建

| # | 组件 | 工具链 | 需要构建吗 | 产物 |
|---|------|--------|-----------|------|
| 1 | `run_root.bat`、`run_root.command`、`root/host-scripts/*.sh` | Git Bash + `adb` | **不需要**，纯脚本 | — |
| 2 | `GhostLockApp/`（Shizuku 应用） | JDK 17 + Android SDK 34 + Gradle 8.7 | **改 Kotlin 才需要** | `app/build/outputs/apk/debug/app-debug.apk`（约 40 MB） |
| 3 | `root/exploit/`（CVE-2026-43499 PoC） | Android NDK、`aarch64-linux-android35-clang` | 可选，`ghostlock` 已预编译 | `root/exploit/ghostlock` |
| 4 | `root/ksu-late-load/kernelsu.ko` | arm64 Linux 容器 + FNE 内核源码 | 进阶专用，`.ko` 已预编译 | `.build/kernelsu.ko` |
| 5 | `hooks/launcher/`（LSPosed 模块） | AGP 9.3.0 + Gradle 9.5.0 + JDK 17+ | 可选 | `hooks/launcher/out/HnLauncherPort.apk` |
| 6 | `deploy/`、`GhostLockApp/app/src/main/assets/`、`tools/` | — | **不需要**，二进制物料 | — |

组件 2 和 5 用的是**两代不同的 Gradle/AGP**，不要拿同一个 Gradle 去编两者。

---

## 1. 版本对照表（已实测可用）

| 项目 | 版本 | 固定位置 |
|------|------|---------|
| JDK | **17**（实测 17.0.12） | `compileOptions` / `kotlinOptions.jvmTarget = "17"` |
| Android Gradle Plugin | **8.5.2** | `GhostLockApp/build.gradle.kts` |
| Kotlin | **1.9.24** | `GhostLockApp/build.gradle.kts` |
| Gradle | **8.7** | `gradle/wrapper/gradle-wrapper.properties` |
| Android SDK Platform | **34**（`compileSdk = 34`） | `app/build.gradle.kts` |
| Build-Tools | **34.0.0** | 由 `sdkmanager` 安装 |
| Platform-Tools | 当前版本 | 提供 `adb` |
| `minSdk` / `targetSdk` | 24 / 34 | `app/build.gradle.kts` |
| Shizuku | **11.0.2**（`api` + `provider`） | `app/build.gradle.kts` |
| NDK（仅 exploit） | r27+ / API 35 clang | `root/exploit/Makefile`（`API ?= 35`） |
| 桌面 Hook 模块 | AGP 9.3.0 / Kotlin 2.2.10 / Gradle 9.5.0 | `hooks/launcher/gradle/libs.versions.toml` |

> **AGP 8.5.2 要求 Gradle ≥ 8.7**。用 8.6 会直接报
> "Minimum supported Gradle version is 8.7"。wrapper 配置已指向 8.7。

---

## 2. 路径 A：Android Studio（最简单）

1. 安装 [Android Studio](https://developer.android.com/studio)（自带 JDK 17）。
2. **SDK Manager → SDK Platforms**：勾选 **Android SDK Platform 34**。
3. **SDK Manager → SDK Tools**：勾选 **Android SDK Build-Tools 34.x** 与
   **Android SDK Platform-Tools**。
4. 打开 `GhostLockApp/` 目录（**不是仓库根目录**）作为工程。
5. 等待 Gradle Sync。`settings.gradle.kts` 已把阿里云镜像排在
   `google()` / `mavenCentral()` 前面。
6. **Build → Build Bundle(s) / APK(s) → Build APK(s)**，或：

   ```bash
   cd GhostLockApp
   ./gradlew clean assembleDebug          # macOS / Linux
   ```

   ```cmd
   cd GhostLockApp
   gradlew.bat clean assembleDebug        &:: Windows
   ```

7. 产物：`GhostLockApp/app/build/outputs/apk/debug/app-debug.apk`。

> Gradle Wrapper 的 JAR 现已随仓库提交在
> `GhostLockApp/gradle/wrapper/gradle-wrapper.jar`，全新 clone 后不装 Android Studio
> 也能直接跑 `gradlew`。

---

## 3. 路径 B：纯命令行（不装 Android Studio）

发布用的 APK 就是这条路打出来的，只需要 JDK、SDK 命令行工具和 Gradle Wrapper。

### 3.1 工程必须放在纯 ASCII 路径（Windows 关键）

AGP 会硬性拒绝含非 ASCII 字符的工程路径：

```
Your project path contains non-ASCII characters.
```

像 `D:\xa\下载\GhostLock-HonorFne\GhostLockApp` 这种路径**必然失败**，
请改用 `D:\src\GhostLock-HonorFne\GhostLockApp`。工程、SDK（`D:\android-sdk`）
和 JDK（`D:\jdk-17.0.12`）都要满足 —— SDK 路径带中文时 `aapt2` 同样找不到
`android.jar`。

在 `gradle.properties` 里加 `android.overridePathCheck=true` 只能绕过检查，
**修不了 `aapt2` 的问题**，正确做法是挪目录。

### 3.2 安装 JDK 17

下载 [Temurin JDK 17](https://adoptium.net/temurin/releases/?version=17)，然后：

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

### 3.3 安装 Android SDK 命令行工具

从 <https://developer.android.com/studio#command-line-tools-only> 下载
**Command line tools only**，解压后保证 `sdkmanager` 位于
`cmdline-tools/bin/sdkmanager`（若 zip 直接解出 `cmdline-tools/`，需自己套一层）。

```bash
export ANDROID_HOME="$HOME/android-sdk"       # Windows 上务必 ASCII 路径
export PATH="$ANDROID_HOME/cmdline-tools/bin:$PATH"

# 旧版 cmdline-tools 不认识 --accept-licenses，改用管道喂 y
yes | sdkmanager --licenses
sdkmanager --sdk_root="$ANDROID_HOME" "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

Windows PowerShell：

```powershell
$env:ANDROID_HOME = "D:\android-sdk"
1..200 | ForEach-Object { "y" } | & "$env:ANDROID_HOME\cmdline-tools\bin\sdkmanager.bat" --licenses
& "$env:ANDROID_HOME\cmdline-tools\bin\sdkmanager.bat" --sdk_root=$env:ANDROID_HOME "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

确认 `$ANDROID_HOME/platforms/android-34/android.jar` 存在。

### 3.4 让 Gradle 找到 SDK

设置上面的 `ANDROID_HOME` 即可；也可以在
`GhostLockApp/local.properties`（该文件已 git-ignore）里写一行：

```properties
sdk.dir=D\:\\android-sdk
```

### 3.5 执行构建

```bash
cd GhostLockApp
./gradlew clean assembleDebug --no-daemon
```

```cmd
cd GhostLockApp
gradlew.bat clean assembleDebug --no-daemon
```

首次运行 wrapper 会下载 Gradle 8.7。若 `services.gradle.org` 不通，可从镜像
（如 `https://mirrors.cloud.tencent.com/gradle/`）下载 `gradle-8.7-bin.zip`，
放进 wrapper 缓存，或直接调用本地 Gradle：

```cmd
D:\gradle-8.7\bin\gradle.bat clean assembleDebug --no-daemon
```

### 3.6 安装到设备

```bash
adb install -r GhostLockApp/app/build/outputs/apk/debug/app-debug.apk
```

APK 用默认 **debug 签名**。同签名覆盖安装不会丢 Shizuku 授权，也不会丢已部署到
`/data/local/tmp` 的物料。

### 3.7 可选的 Windows 便捷脚本

`GhostLockApp/build_debug.bat` 与 `build_minimal.bat` 只是封装。
`build_minimal.bat` 要求 `jdk-17.0.12/` 和 `cmdline-tools/` 放在**父目录**下，
并把 SDK 组件装到 `../android-sdk`。这些目录属于本地工具链，已被 git 忽略。
干净 clone 出来的仓库请直接用 3.2–3.6 的命令。

---

## 4. 不要"顺手升级"的几处约束

以下都是刻意保留的，不是遗忘。改动会让 App 在运行时直接失效。

| 约束 | 原因 |
|------|------|
| `rikka.shizuku:api:11.0.2` **和** `rikka.shizuku:provider:11.0.2` | 13.x 换了 group 到 `dev.rikka.shizuku`，且把 `Shizuku.newProcess()` 改成 private。所有 `exec()` / `writeFile()` 都依赖它；升级就必须用 UserService/AIDL 重写命令通道。 |
| `AndroidManifest.xml` 里的 `rikka.shizuku.ShizukuProvider`，authority 为 `${applicationId}.shizuku` | Shizuku 通过这个 ContentProvider 下发 Binder。缺了它 App 收不到 Binder、不会出现在 Shizuku 应用列表、也弹不出授权框。provider AAR **不会**自动声明该组件。 |
| `androidResources { noCompress += listOf("ko","zip","apk","bin") }` | 不能让 `aapt2` 压缩 / 对齐预编译内核模块和物料。 |
| `Shizuku.newProcess` 的 env 参数必须是 `null` | 传 `emptyArray()` 等于给子进程一个**空环境**。exploit 大量读取 `getenv()` 旋钮（`GL_*`、`MMSTRIDE`、`KPHYS`…）；`null` 才是继承 shell 环境，与 `adb shell` 一致。 |
| `buildFeatures { viewBinding = true }`，无 AIDL | UserService/AIDL 桥接已移除，`IRootService.aidl` 不再存在。 |
| assets 里的 APK/ZIP/KO 必须入库 | `.gitignore` 只排除 `app-debug.apk` / `app-release.apk`。若写全局 `*.apk`，全新 clone 会悄悄丢掉必需物料。 |

---

## 5. 重编 native exploit（可选）

`root/exploit/ghostlock`（aarch64，约 216 KB）已预编译，并作为
`GhostLockApp/app/src/main/assets/ghostlock` 随 App 打包。只有改了 C 源码或偏移表
才需要重编。

要求：Android NDK r27+（含 `aarch64-linux-android35-clang`）。

```bash
cd root/exploit
make NDK_ROOT=/path/to/android-ndk API=35 HOST_TAG=linux-x86_64
```

> **`HOST_TAG` 必须手动指定**：Makefile 只自动识别 `darwin-arm64` /
> `darwin-x86_64`。Linux 要传 `HOST_TAG=linux-x86_64`，Windows 传
> `HOST_TAG=windows-x86_64`，否则编译器路径是错的。

也可以按 `root/exploit/README.md` 直接调 clang：

```bash
NDK=/path/to/android-ndk
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
  -O2 -Wall -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\" \
  src/core/main.c src/core/util.c src/core/slide.c \
  src/core/fops.c src/core/pipe_physrw.c src/core/root.c \
  src/core/miniadb.c src/core/umh_root.c src/core/memstart.c \
  -o ./ghostlock -fPIE -pie -pthread
```

编完覆盖 `GhostLockApp/app/src/main/assets/ghostlock`，再跑一次 `assembleDebug`。
设备偏移表在 `src/devices/fne/offsets.h`（11 个精确内核构建）。偏移写错不会
"优雅失败"，而是往无关内核内存里写值。

---

## 6. 重编 `kernelsu.ko`（进阶，通常不需要）

随附模块精确匹配 FNE-AN00 的 5.4.289 内核。构建脚本要求**原生 arm64 Linux 容器**
（Apple Silicon 上用 Docker / colima，或直接用 arm64 主机）、荣耀 70 开源内核树，
以及设备真实的 `/proc/config.gz`。

```bash
cd root/ksu-late-load
export KERNEL_SRC=/path/to/fne_src/Code_Opensource/kernel
sh ksu_ko_build.sh          # 准备 .build/、克隆 KernelSU v3.3.0、在 debian:bookworm 内编译
sh probe_build.sh           # 可选：量化结构体布局漂移
```

`build_inner.sh` 会把 `UTS_RELEASE` 伪造成
`5.4.289-qgki-gf6cb1f712a6e` 并绕过 MODVERSIONS。`KSU_VERSION` 由 KernelSU 的
git commit 数推导（管理器 versionCode 32601），所以克隆必须保留 `.git` 并停在
对应 tag。**不要随意升级管理器或模块版本** —— 项目 README 明确警告过。

---

## 7. 重编 LSPosed 模块（可选）

`hooks/launcher/` 是独立的、更新得多的 Gradle 工程
（AGP 9.3.0 / Kotlin 2.2.10 / Gradle 9.5.0，`compileSdk` 37）。用它自己的 wrapper，
不要复用 Gradle 8.7。

```bash
cd hooks/launcher
./gradlew assembleRelease
# 或：bash build.sh   → 复制到 out/HnLauncherPort.apk
```

`app/build.gradle.kts` 用仓库内提交的 `debug.keystore`
（别名 `launcherport`、密码 `android`）给 release 签名。该文件必须保留，
否则 `assembleRelease` 会失败。

---

## 8. 验证构建结果

```bash
# 应用名、包名、图标
aapt2 dump badging app/build/outputs/apk/debug/app-debug.apk | grep -E "^package:|application-label:"
# provider 必须存在，否则 Shizuku 永远看不到这个 App
aapt2 dump xmltree --file AndroidManifest.xml app-debug.apk | grep -i ShizukuProvider
# 未压缩的物料确实打进了 APK
unzip -l app-debug.apk | grep -E "kernelsu.ko|ghostlock|KernelSU-manager.apk"
```

预期：`application-label:'FNE-AN00'`、包名 `com.ghostlock.honorfne`，
manifest 里有 `rikka.shizuku.ShizukuProvider`。

行尾（`.gitattributes` 强制约束）：

```bash
git check-attr -a -- root/host-scripts/*.sh run_root.bat
```

`*.sh` / `*.command` 必须是 **LF**（CRLF 会报 `bad interpreter`）；`*.bat` 必须在
**仓库 blob 里保持 CRLF**（LF 会让 `cmd.exe` 的 `goto :label` 失效、双击直接闪退）。

---

## 9. 故障排查

| 现象 | 原因 / 处理 |
|------|------------|
| `Your project path contains non-ASCII characters` | 工程、JDK、SDK 全挪到纯 ASCII 路径（§3.1）。 |
| `Minimum supported Gradle version is 8.7` | wrapper 还停在 8.6，换 `gradle-8.7-bin.zip`。 |
| 找不到 `gradle-wrapper.jar` / `gradlew` 直接退出 | 早期快照缺这个 JAR，现已入库。若本地副本仍缺，执行 `gradle wrapper --gradle-version 8.7 --no-validate-url`。 |
| `aapt2` 找不到 `android.jar` | SDK 路径含非 ASCII，或没装 Platform 34。 |
| `Could not resolve rikka.shizuku:api:13.1.5` | 该 group 下没有这个版本。本项目锁定 `11.0.2`；v13 的 group 是 `dev.rikka.shizuku`。 |
| 升级 Shizuku 后 `Unresolved reference: newProcess` | 13.x 把方法设为 private。留在 11.0.2，或改用 UserService 重写。 |
| `Unknown argument --accept-licenses` | 旧版 `sdkmanager`；改成向 `--licenses` 管道喂 `y`（§3.3）。 |
| GitHub raw / `repo1.maven.org` 下载超时 | `settings.gradle.kts` 已优先 `maven.aliyun.com`；Gradle 本体可走 `mirrors.cloud.tencent.com/gradle/`。 |
| `aaptOptions` / `noCompress` 弃用警告 | 已改为 `androidResources { noCompress += … }`。 |
| Shizuku 授权列表里看不到 App | manifest 缺 `ShizukuProvider`，或 App 还没调用 `requestPermission()`（打开后点「连接 Shizuku」才会出现）。 |
| `BUILD SUCCESSFUL` 但 APK 里没有物料 | 全局 `*.apk` / `*.zip` 忽略规则把 assets 排掉了，见 §4。 |

---

## 10. 不要提交什么

`.gitignore` 已排除：本地工具链（`cmdline-tools/`、`gradle-8.*/`、`jdk-*/`、
`gradle-*-bin.zip`）、上游源码快照（`KernelSU-main/`、`Shizuku-API-master/`）、
构建产物（`build/`、`.gradle/`、app 级 `*.apk`）、日志与 `.workbuddy/`。
原工作区里两个 Gradle ZIP 都超过 GitHub 单文件 100 MB 上限。大体积物料
APK/ZIP 建议放 **GitHub Releases**，不要进 git 历史。

---

## 11. 免责声明

仅限自有设备的安全研究。漏洞利用按逐内核构建硬编码的偏移直接写内核内存，
不支持的内核可能 panic 或反复重启。Root 是临时的，重启即失效。禁止改写
`system`、`vendor`、`vbmeta` 分区。参见 [LICENSE](LICENSE) 及上游
GPL-2.0 / MIT 许可声明。
