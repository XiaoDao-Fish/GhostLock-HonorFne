# GhostLock HonorFne — Shizuku 临时 Root App（FNE-AN00）

把原 `GhostLock-HonorFne`（电脑 adb + USB 一键脚本）改造成**手机端 App**：通过
[Shizuku](https://github.com/RikkaApps/Shizuku) 取得 `shell`（uid 2000）权限后，
直接在设备上部署预编译物料并驱动提权循环，不再需要电脑和 USB 线
（首次启动 Shizuku 仍需无线调试）。

> 适用设备：**荣耀 70 / FNE-AN00**，内核 `5.4.289-qgki-gf6cb1f712a6e` 或
> `fne/offsets.h` 列出的 5.4.295 构建，锁 bootloader、临时 root、重启失效。
> 原理：CVE-2026-43499（futex PI UAF）自提权 → KernelSU 晚加载。exploit 从
> `shell` 上下文自我提权到 root，因此 Shizuku 的 `shell` 权限等价于原方案的
> `adb shell`。**不要拿本 APK 在其它机型 / 内核上试**，偏移写错会打崩内核。

---

## 1. 构建

完整教程见仓库根目录 **[构建教程（中文）](../BUILD.zh-CN.md)** /
**[Build guide (EN)](../BUILD.md)**，含 Android Studio 与纯命令行两条路径、
版本对照表、NDK / `kernelsu.ko` 重编方法、故障排查。

最短路径（JDK 17 + Android SDK 34，工程路径必须纯 ASCII）：

```bash
cd GhostLockApp
./gradlew clean assembleDebug          # macOS / Linux
```

```cmd
cd GhostLockApp
gradlew.bat clean assembleDebug        &:: Windows
```

产物：`app/build/outputs/apk/debug/app-debug.apk`（约 40 MB，debug 签名）。
安装：`adb install -r app/build/outputs/apk/debug/app-debug.apk`。

关键版本：**JDK 17 / AGP 8.5.2 / Kotlin 1.9.24 / Gradle 8.7 / compileSdk 34 /
Shizuku api+provider 11.0.2**。`gradle-wrapper.jar` 已随仓库提交，全新 clone
可直接用 `gradlew`，不需要先装 Android Studio。

### 不要改的地方

| 约束 | 原因 |
|------|------|
| `rikka.shizuku:api:11.0.2` + `provider:11.0.2` | 13.x 换 group 且把 `Shizuku.newProcess()` 设为 private，会让所有命令执行失效 |
| `AndroidManifest.xml` 的 `rikka.shizuku.ShizukuProvider` | Shizuku 靠它下发 Binder；缺了 App 不会出现在授权列表、也弹不出授权框 |
| `androidResources { noCompress += listOf("ko","zip","apk","bin") }` | 防止 `aapt2` 压缩内核模块与物料 |
| `newProcess` 的 env 参数传 `null` | 传 `emptyArray()` 会给 exploit 一个空环境（它重度依赖 `getenv()`） |
| assets 里的 APK / ZIP / KO 必须入库 | 全局 `*.apk` 忽略规则会让 clone 出来的工程编不出完整功能 |

---

## 2. 工程结构

```
GhostLockApp/
├── settings.gradle.kts          # 阿里云镜像优先 + google()/mavenCentral()
├── build.gradle.kts             # AGP 8.5.2 / Kotlin 1.9.24
├── gradle.properties
├── gradlew / gradlew.bat        # Gradle 8.7 Wrapper（jar 已入库）
├── build_debug.bat              # 可选：一键构建+安装（Windows）
├── build_minimal.bat            # 可选：本地工具链一键构建（需父目录放 JDK / cmdline-tools）
├── gradle/wrapper/              # gradle-wrapper.properties + gradle-wrapper.jar
└── app/
    ├── build.gradle.kts         # Shizuku 11.0.2、AndroidX、协程、noCompress
    └── src/main/
        ├── AndroidManifest.xml  # ShizukuProvider + 启动 Activity + BootNotifyReceiver
        ├── assets/              # ghostlock / ksu_fne / netfix_packet / managers（约 43 MB）
        ├── res/                 # FNE-AN00 应用名 + 自适应图标（5 档密度）
        └── java/com/ghostlock/honorfne/
            ├── MainActivity.kt        # UI、授权、部署、管理器安装
            ├── ShizukuController.kt   # newProcess exec / writeFile、硬超时、清场
            ├── AssetDeployer.kt       # 物料分块写入 /data/local/tmp
            ├── GrindRunner.kt         # settle → W1 → W2 → KSU 轮询与重启判定
            ├── LogStore.kt            # 即时落盘到 下载/XiaoDao + 崩溃会话归档
            ├── RootUserService.kt     # 兼容用 stub Service（运行时不使用）
            └── BootNotifyReceiver.kt  # 开机后提醒重新启动 Shizuku
```

没有 AIDL：`IRootService.aidl` 与 UserService 桥接已移除，命令执行统一走
`Shizuku.newProcess`（等价于 `adb shell`）。

---

## 3. Shizuku 启动（关键前提）

1. 设备安装 **Shizuku** App。
2. 开发者选项 → **无线调试** → 开启。
3. Shizuku App 内通过「无线调试」启动服务。
4. 打开本 App →「连接 Shizuku」→ 在系统弹窗授权。

只有调用过 `requestPermission()` 的应用才会出现在 Shizuku 的「应用管理」列表里，
**光安装不打开是不会出现的**。

---

## 4. 使用流程

| 按钮 | 作用 |
|------|------|
| 连接 Shizuku | 检测 Binder → 申请权限 → 刷新状态 |
| 部署物料 | 把内嵌 exploit / KSU 物料写入 `/data/local/tmp`（约 43 MB，分块流式写入） |
| 一键临时 Root | `settle → W1 → W2 → KSU 晚加载`，每轮前清残留 `e` 进程，最长 8 轮 |
| 查看状态 | `getenforce` / `kernelsu` 模块数 / `boot_completed` / `su 0 id` / 残留进程数 |
| 安装管理器 | root 后装 KSU Manager + 同步 netfix_packet + ksud 装 ZygiskNext / LSPosed |

正确顺序：**连接 Shizuku → 部署物料 → 一键临时 Root →（出现 KSU READY 后）安装管理器**。
「安装管理器」在没有 root 时只会装好管理器 APK 并明确返回，不会空等。

---

## 5. 与原脚本的对应关系

| 原 host 脚本 | App 中的实现 |
|--------------|--------------|
| `run_root.bat/.command` 物料推送 | `AssetDeployer`（`newProcess` + `cat >` 流式写入 + chmod 755） |
| `adb shell <cmd>` | `ShizukuController.exec`（`Shizuku.newProcess`，硬超时 + 并行读流） |
| `gl_cycle.sh` 的 `pkill -9 -x e` | `ShizukuController.killStaleExploits()`（每轮 / W1 前 / W2 前清场） |
| `run_forever.sh` / `run_w2.sh` | `GrindRunner`（settle / 420s W1 / W2 阶梯 / boot_id 判定 / KSU 轮询） |
| `e --write1` / `e` | 后台 detached 启动，低干扰轮询设备端日志（W1 每 30s 一条合并查询） |
| `wait_ksu.sh` | `GrindRunner.waitKsu()` |
| 崩溃后人工取日志 | `LogStore` 即时写 `下载/XiaoDao/ghostlock_latest.txt`，重启后打开 App 自动归档上次会话 |

---

## 6. 日志与取证

日志由 App 自己用 Android 文件 API **逐条即时落盘**，不依赖 Shizuku、不依赖电脑、
不需要存储权限：

- 文件管理器 → **下载 → XiaoDao → `ghostlock_latest.txt`**（最易找）
- `session_时间戳.txt`：上次崩溃 / 重启前会话的归档
- `/storage/emulated/0/XiaoDao/ghostlock_latest.log`，不可写时自动降级到
  `Android/data/com.ghostlock.honorfne/files/XiaoDao/`

关键节点会抓取 `w1.log` / `w2.log` / `chain.log` 尾部、`getenforce`、
`kernelsu` 模块数、`boot_id`、`pstore` / `dmesg` / `logcat`。
排查 W1/W2 崩溃时把这个文件发出来即可。

---

## 7. 已知限制与风险

- **重启后 Shizuku 会掉**：W1/W2 触发的设备重启会让无线调试启动的 Shizuku 失效，
  必须手动重新启用并授权。这是与 PC 脚本（`adb wait-for-device` 自动重连）
  最大的体验差异；挂机跑 8 轮建议用根目录 `run_root.bat`（USB adb）。
- **Root 不持久**，每次重启都要重新跑一遍。
- **设备 / 内核强绑定**：物料只针对 FNE / 5.4.289 及已知 5.4.295 构建。
- **W1/W2 可能触发内核 panic 与保护性重启**，属于该漏洞利用的固有风险。
- 仅限自有设备的安全研究用途；存在保修失效、安全模型改变、变砖风险，
  请自行评估并承担。

---

## 8. 许可证

沿用上游约定：exploit 与文档 Apache-2.0；KernelSU 衍生部分 GPL-2.0；
Shizuku API 集成 MIT。仅供授权安全研究。
