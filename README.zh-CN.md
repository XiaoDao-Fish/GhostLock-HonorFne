# GhostLock-HonorFne

[English](README.md) · [构建教程 / Build guide](BUILD.zh-CN.md) · [项目分类](#项目分类) · [支持机型](#支持机型)

基于 **CVE-2026-43499**（futex PI waiter 释放后重用）与自定义
**KernelSU 晚加载链**的荣耀 70（FNE-AN00）**临时 / 单次开机 Root** 方案。
另附一个基于 **Shizuku** 的安卓端应用，可在不接电脑的情况下复现宿主脚本流程。

> **适用范围与免责声明**
> 本项目仅用于自有设备的安全研究。漏洞利用会按**逐内核构建硬编码的偏移**
> 直接写内核内存，在不同机型、不同固件或未列出的内核版本上运行，可能写坏
> 无关内核内存并导致 panic / 反复重启。**Root 不持久化**，每次重启失效，
> 需重新运行。禁止改写 `system`、`vendor`、`vbmeta` 分区。

---

## 项目分类

目录按**在提权流程中的角色**组织，而不是按文件类型。
`✅` 提交到仓库 · `📦` 建议放 GitHub Releases · `⛔` 本地专用，上传前排除。

| # | 分类 | 路径 | 内容 | |
|---|------|------|------|---|
| 1 | **一键入口** | `run_root.bat`、`run_root.command` | Windows / macOS 宿主脚本：依赖检查 → USB 连接 → 部署 → grind → 安装管理器 | ✅ |
| 2 | **提权核心** | `root/exploit/` | CVE-2026-43499 PoC：C 源码、`src/devices/*/offsets.h` 逐机型内核偏移表、预编译 `e`、构建工具 | ✅ |
| 3 | **宿主驱动脚本** | `root/host-scripts/` | `run_forever.sh`（外循环）、`run_w2.sh`（W1→W2）、`install_managers.sh`、`wait_ksu.sh`、`gl_cycle.sh`、`uninstall.sh`，以及 settle / 崩溃重启恢复逻辑 | ✅ |
| 4 | **KernelSU 晚加载链** | `root/ksu-late-load/` | `chain_hook.sh`、`kernelsu.ko`、`ksud`、`magiskpolicy`、`load_ko`、`kmsg_dumper`、`fne_syms.txt`、kallsyms 符号表与构建脚本 | ✅ |
| 5 | **运行时 KSU 模块** | `root/ksu-modules/netfix_packet/` | `sepolicy.rule`（网络 / hwservice 修复）、`post-fs-data.sh` + `service.sh`（状态栏、导航栏、AOD / RRO 修复） | ✅ |
| 6 | **Shizuku 安卓端** | `GhostLockApp/` | Kotlin + AGP 8.5.2：用 Shizuku 的 shell 权限替代 `adb shell`，部署物料、驱动 W1/W2/KSU、安装管理器；含自适应图标与写入 `下载/XiaoDao` 的崩溃日志 | ✅ |
| 7 | **LSPosed Hook 模块** | `hooks/launcher/` | `HnLauncherPort`：桌面 / SystemUI 动画、手势与小窗优化 | ✅ |
| 8 | **安装物料** | `deploy/` | `KernelSU-manager.apk`、`ZygiskNext.zip`、`LSPosed-zygisk.zip`（走 `ksud module install`，绝不裸解压） | 📦 |
| 9 | **文档资料** | `README.md`、`docs/` | 使用说明、提权原理分析、里程碑记录、桌面模块原理 | ✅ |
| 10 | **辅助工具** | `tools/` | 第三方参考 APK、内核偏移辅助脚本 | ⚠️ 需核对许可证 |
| — | **本地构建工具链** | `cmdline-tools/`、`gradle-8.6/`、`gradle-*-bin.zip`、`jdk-*/` | Android SDK cmdline-tools、Gradle 发行包、JDK，约 400 MB，均为本机下载 | ⛔ |
| — | **上游源码快照** | `KernelSU-main/`、`Shizuku-API-master/` | 第三方项目源码副本。应以上游链接 / submodule 引用，不要直接提交 | ⛔ |
| — | **本地状态与产物** | `.workbuddy/`、`*.log`、`app-debug.apk`、`.gradle/`、`build/` | 会话记录、grind 日志、编译产物 | ⛔ |

> 随附的 `.gitignore` / `.gitattributes` 即按此划分实现。
> `.gitattributes` 很关键：`*.sh` / `*.command` 必须保持 **LF**，
> `*.bat` 必须保持 **CRLF**，内核二进制不得被转换。

---

## 支持机型

内置的 `kernelsu.ko` 声明
`vermagic=5.4.289-qgki-gf6cb1f712a6e SMP preempt mod_unload modversions aarch64`，
因此该模块只能在与之完全一致的内核上 `insmod`。

| 来源 | 声明范围 |
|------|----------|
| 根目录 `README.md` | 荣耀 70 / 60 / 60 Pro（FNE / LSA / TNA），MagicOS 8.0.221 / 8.0.224，内核 `5.4.289-qgki-gf6cb1f712a6e` 与 `5.4.295-qgki-g0fb2656b2b50` |
| `docs/README_1.md`（更严谨） | **仅 FNE-AN00**：`5.4.289-qgki-gf6cb1f712a6e`（MagicOS 8.0.214–221），或 `5.4.295-qgki-*`（MagicOS 8.0.2xx，含 8.0.224 实机，共 10 个已知构建） |

`root/exploit/src/devices/fne/offsets.h` 列出 **11 个精确内核构建**
（1 个 5.4.289 + 10 个 5.4.295，按 A–D 簇分组）。目录中没有 `lsa/`、
`tna/` 的偏移表，因此荣耀 60 / 60 Pro 属于"同一内核血脉推测"，并无实测配置。

exploit 源码本身还带其它机型的偏移表（OnePlus 13/15、OPPO Find X9 系列、
Reno10 Pro+、Pad 4 Pro、vivo T4 / X Fold3 Pro / X200 Ultra、Sony Xperia 1 IV、
Ace 6T 等，内核跨度 5.4 → 6.12），但这些只覆盖**提权阶段**。本仓库的
KSU 晚加载链、符号表和模块均为 FNE 专用，完整流程不能原样移植。

用 `adb shell uname -r`（或 设置 → 关于手机 → 内核版本）查看，
必须与上述字符串**完全匹配**。

---

## 工作流程

```
[1/5] 依赖检查        platform-tools / Git Bash
[2/5] 连接设备        USB（宿主脚本已移除 WiFi / 网络 adb）
[3/5] ROOT 状态检查   本 boot 已加载 kernelsu.ko 则跳过
[4/5] 部署            推送 e、ksu_fne/、netfix_packet/ 到 /data/local/tmp
[5/5] 运行提权        run_forever.sh：settle → W1 → W2 → KSU 晚加载
[+]   成功收尾        安装 KSU Manager / ZygiskNext / LSPosed
```

1. **settle** —— 清理后台应用风暴，按 `/proc/stat` 等待真实 CPU 空闲 ≥ 85 %
   （D 态 kworker 会让 load average 虚高）。W1/W2 对时序极其敏感。
2. **W1** —— `env $SYNC e --write1`：写坏 `selinux_state` → Permissive。
   历史落地率约 **8%/次**，内核崩溃与保护性重启属于预期现象，不是工具故障。
3. **W2** —— cred 写入（`GL_W2_ROUNDS=2`，按 `GL_W2_CRED_ADJ` 阶梯爬坡）→
   root 子进程 → detached 拉起 `chain_hook.sh`。
4. **KSU 晚加载** —— fake kallsyms 按本次开机 slide 重定基，
   `magiskpolicy` 注入 KSU 规则，`load_ko` 加载 `kernelsu.ko`，
   `ksud` 依次执行 post-fs-data / services / boot-completed / install，
   最后恢复 SELinux enforcing。

**绝不要并发跑两个 grind。** `run_forever.sh` 与 Shizuku 应用启动前都会
`pkill -9 -x e` 清理残留；两个 `slab_drain` fork 风暴叠加会触发保护性重启。

---

## 使用方法

### 宿主脚本（挂机跑推荐）

依赖：Windows + Git Bash + platform-tools，或 macOS + platform-tools；仅 USB 连接。
在仓库根目录执行：

```cmd
run_root.bat
```

```bash
bash run_root.command
```

宿主脚本可借助 `adb wait-for-device` 熬过设备重启，整夜跑完 8 轮外循环。

### Shizuku 应用（无需电脑）

1. 安装 Shizuku，通过**无线调试**（Android 11+）启动。
2. 安装 `GhostLockApp`，授予 Shizuku 权限，点「部署物料」。
3. 点「一键临时 Root」，出现 `KSU READY` 后再点「安装管理器」。

局限：无线调试启动的 Shizuku 每次重启都会失效，需手动重新启用并授权，
因此反复尝试 W1 会比较繁琐。

应用构建：JDK 17 + Android SDK 34 + Gradle 8.7（AGP 8.5.2 要求 Gradle ≥ 8.7）；
Windows 下工程路径必须为纯 ASCII。完整步骤、版本对照、native exploit /
`kernelsu.ko` 重编方法与故障排查见 **[构建教程](BUILD.zh-CN.md)**。

---

## 上传前检查清单

- [ ] 保留 `LICENSE`（Apache-2.0），并为引入的 KernelSU（GPL-2.0）
      与 Shizuku API（MIT）补充明确的许可证声明。
- [ ] 删除 `gradle-8.6-bin.zip` / `gradle-8.7-bin.zip` —— 两者均超过
      GitHub **单文件 100 MB** 限制。
- [ ] 删除本地工具链与上游源码快照（见上表 ⛔ 行）。
- [ ] 大体积 APK / ZIP 物料放到 **GitHub Releases**，不要进 git 历史。
- [ ] 用 `git check-attr -a -- root/host-scripts/*.sh` 与 `*.bat` 核对行尾规则。
- [ ] 不要提交 `*.log` 与 `.workbuddy/`。

### 建议的 GitHub Topics

`android-root` `kernelsu` `shizuku` `cve-2026-43499` `kernel-exploit`
`security-research` `poc` `honor` `magicos` `lsposed` `zygisk` `temporary-root`

---

## 内置模块

**netfix_packet** 修复 Root 过程引入的两个独立问题：SELinux SID 丢失
（晚加载时注入的 16 行 `sepolicy.rule`），以及 LSPosed daemon 反复把 tmpfs
挂到 `/data/resource-cache` 造成的状态栏 / 导航栏 / AOD 失效
（`post-fs-data.sh` + `service.sh` 补丁、清理叠层、保活 idmap2d）。

**HnLauncherPort**（`hooks/launcher/`）：高级模糊与图标入场动画、
手势惯性重构、小窗阈值优化、冗余控件清理。

---

## 致谢与许可证

- [GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT)
- [KernelSU](https://github.com/tiann/KernelSU)
- [Shizuku-API](https://github.com/RikkaApps/Shizuku-API)

`root/exploit/` —— Apache-2.0（见 `LICENSE`）。
KernelSU 衍生部分 —— GPL-2.0。
Shizuku API —— MIT。
