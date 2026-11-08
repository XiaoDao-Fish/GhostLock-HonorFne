# Repository Categories / 项目分类

> One-page bilingual index for publishing to GitHub.
> 上传到 GitHub 用的一页式双语分类索引。
>
> Full documentation: [English](README.md) · [中文](README.zh-CN.md)
> Build guide / 构建教程: [English](BUILD.md) · [中文](BUILD.zh-CN.md)

**Legend / 图例**：`✅` Commit / 提交 · `📦` GitHub Releases / 发布附件 ·
`⛔` Exclude / 排除 · `⚠️` Review license / 核对许可证

| # | Category / 分类 | Path / 路径 | Role / 作用 | Upload / 上传 |
|---|-----------------|-------------|-------------|:---:|
| 1 | Entry points<br>一键入口 | `run_root.bat`<br>`run_root.command` | One-click host scripts (Windows / macOS)<br>Windows / macOS 一键宿主脚本 | ✅ |
| 2 | Exploit core<br>提权核心 | `root/exploit/` | CVE-2026-43499 PoC, C sources, per-kernel offset tables, prebuilt `e`<br>漏洞 PoC、C 源码、逐内核偏移表、预编译 `e` | ✅ |
| 3 | Host drivers<br>宿主驱动脚本 | `root/host-scripts/` | `run_forever.sh`, `run_w2.sh`, `install_managers.sh`, settle & reboot recovery<br>外循环、W1/W2 runner、管理器安装、静默与重启恢复 | ✅ |
| 4 | KernelSU late-load chain<br>KSU 晚加载链 | `root/ksu-late-load/` | `chain_hook.sh`, `kernelsu.ko`, `ksud`, `magiskpolicy`, symbol tables<br>加载链脚本、内核模块、符号表 | ✅ |
| 5 | Runtime KSU modules<br>运行时模块 | `root/ksu-modules/netfix_packet/` | SELinux / network / status-bar / AOD fixes<br>SELinux、网络、状态栏、AOD 修复 | ✅ |
| 6 | Shizuku companion app<br>Shizuku 安卓端 | `GhostLockApp/` | PC-free Android client (Kotlin, AGP 8.5.2)<br>无需电脑的安卓客户端 | ✅ |
| 7 | LSPosed hook module<br>桌面 Hook 模块 | `hooks/launcher/` | `HnLauncherPort`: desktop / SystemUI tweaks<br>桌面与 SystemUI 动效、手势优化 | ✅ |
| 8 | Install payloads<br>安装物料 | `deploy/` | KernelSU Manager, ZygiskNext, LSPosed (APK / ZIP)<br>管理器与模块安装包 | 📦 |
| 9 | Documentation<br>文档资料 | `README.md`<br>`README.zh-CN.md`<br>`BUILD.md`<br>`BUILD.zh-CN.md`<br>`CATEGORIES.md`<br>`docs/` | Setup, bilingual build guide, exploit analysis, milestone notes<br>使用说明、双语构建教程、原理分析、里程碑 | ✅ |
| 10 | Auxiliary tools<br>辅助工具 | `tools/` | Third-party reference APK, kernel-offset helpers<br>第三方参考 APK、偏移辅助脚本 | ⚠️ |
| — | Local toolchain<br>本地工具链 | `cmdline-tools/`<br>`gradle-8.6/`<br>`gradle-*-bin.zip`<br>`jdk-*/` | Downloaded SDK / Gradle / JDK, ~400 MB, two ZIPs exceed GitHub 100 MB limit<br>本机下载的 SDK / Gradle / JDK，两个 ZIP 超 GitHub 100 MB 限制 | ⛔ |
| — | Upstream snapshots<br>上游源码快照 | `KernelSU-main/`<br>`Shizuku-API-master/` | Vendored third-party sources; use upstream links or submodules<br>第三方源码副本，改用上游链接或 submodule | ⛔ |
| — | Local state / artifacts<br>本地状态与产物 | `.workbuddy/`<br>`*.log`<br>`app-debug.apk`<br>`.gradle/`, `build/` | Session notes, grind logs, build output<br>会话记录、grind 日志、编译产物 | ⛔ |

---

## Topics / 建议标签

`android-root` · `kernelsu` · `shizuku` · `cve-2026-43499` · `kernel-exploit` ·
`security-research` · `poc` · `honor` · `magicos` · `lsposed` · `zygisk` ·
`temporary-root`

## License split / 许可证划分

| Material / 内容 | License / 许可证 |
|-----------------|------------------|
| `root/exploit/` | Apache-2.0 (`LICENSE`) |
| KernelSU-derived files / KernelSU 衍生部分 | GPL-2.0 |
| Shizuku API integration / Shizuku API 集成 | MIT |

## Pre-upload checklist / 上传前清单

- [ ] Remove / 删除 `gradle-8.6-bin.zip`、`gradle-8.7-bin.zip`（>100 MB）
- [ ] Exclude / 排除 ⛔ rows above（见 `.gitignore`）
- [ ] Move APK / ZIP payloads to Releases / 大体积安装包放 Releases
- [ ] Verify line endings / 核对行尾：`git check-attr -a -- root/host-scripts/*.sh`、`*.bat`
- [ ] Add third-party license notices / 补充第三方许可证声明
- [ ] Keep / 保留 `GhostLockApp/gradle/wrapper/gradle-wrapper.jar`（fresh clone 可直接 `gradlew`）
