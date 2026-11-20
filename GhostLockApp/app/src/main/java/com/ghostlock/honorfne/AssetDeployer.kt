package com.ghostlock.honorfne

import android.content.Context
import android.content.res.AssetManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Pushes the prebuilt exploit + KernelSU material from the APK's assets into
 * /data/local/tmp using shell-privileged [ShizukuController.writeFile] / exec.
 *
 * Layout on device (mirrors the original host-script deploy step):
 *   assets/ghostlock             -> /data/local/tmp/e               (chmod 755)
 *
 * 【老版配方回归】三份补丁二进制（ghostlock_gc1fab / _g7fd5b / _g0fb2656）
 * 仍留在 assets 里供对照，但不再下发：老版一次成功日志推的就是原版 ghostlock，
 * 而这台 5.4.295 内核的 uname 字符串本来就在原版二进制的 offsets 表里。
 *   assets/ksu_fne/  (all files) -> /data/local/tmp/ksu_fne/
 *   assets/netfix_packet/ (all)  -> /data/local/tmp/netfix_packet/
 *   assets/managers/ (all files) -> /data/local/tmp/managers/       (post-root install)
 *
 * 2026-11-14 fix: the old ensurePayloads() only tested whether the files
 * EXISTED. After an APK upgrade the device kept the previous ksu_lateload.sh
 * (2072 B, insmod only) while the new APK shipped 4439 B (with ksud install +
 * three boot stages). The chain therefore reported "module Live" but
 * `su` stayed at code=127. verify() now compares the payload version stamp
 * AND every critical file's byte size, so stale material is always replaced.
 */
object AssetDeployer {

    private const val TMP = "/data/local/tmp"
    private const val STAMP_PATH = "$TMP/ksu_fne/.payload_stamp"

    /** Bump on ANY change to assets/ghostlock, assets/ksu_fne or these scripts. */
    // 3.0.0.0：老版配方回归。设备端 /data/local/tmp/e 目前是
    // ghostlock_g0fb2656（精确偏移 + 重推 224 表 + force-light 补丁），必须换戳
    // 强制覆盖回原版 assets/ghostlock（老版一次成功日志里推的就是这一份）。
    // 3.1.0.0：新增荣耀 Magic3 / g2312a84fef60 精确适配资产；资产名进戳，
    // 只有这颗内核会拿到 ghostlock_g2312a84，其余内核戳不变、仍用原版。
    // 3.1.1.0：g7fd5b / gc1fab 从「一律推原版」改回推最小补丁版，且 g7fd5b
    // 资产本身换掉了带 force-light 的旧版（cmp x8,#60 从 4095 改回 60）。
    // 戳不变则设备端仍拿着旧物料，exploit 一启动就 no offsets 退出。
    // 3.1.2.0：ksu_lateload.sh 改为从 .manager_pkg 读管理器包名（LAUNCHER 拉起），
    // 支持第三方分支；脚本内容变了必须换戳，否则设备端继续跑写死官方包名的旧脚本。
    private const val PAYLOAD_VERSION = "3.1.2.0"

    private val KSU_EXECUTABLES = setOf(
        "chain_hook.sh", "ksu_lateload.sh", "restore_enforce.sh",
        "magiskpolicy", "ksud", "load_ko", "kmsg_dumper"
    )

    /** Files whose exact byte size is compared on every run. */
    private val CRITICAL = listOf(
        "$TMP/e",
        "$TMP/ksu_fne/kernelsu.ko",
        "$TMP/ksu_fne/ksu_lateload.sh",
        "$TMP/ksu_fne/restore_enforce.sh",
        "$TMP/ksu_fne/chain_hook.sh",
        "$TMP/ksu_fne/ksud"
    )

    @Volatile
    private var sizeCacheKey = ""
    @Volatile
    private var sizeCache: List<Int> = emptyList()

    /**
     * 老版配方：原版已收录的内核一律下发原版 assets/ghostlock；
     * 仅原版未收录且已精确适配的 Magic3 / g2312a84fef60 走新资产。
     * 与 EngineCatalog.exploitAssetFor() 保持同一数据源。
     * 版本戳仍包含资产名（stamp = PAYLOAD_VERSION|资产名），换戳即可强制重推。
     */
    fun exploitAssetFor(kernel: String): String = EngineCatalog.exploitAssetFor(kernel)

    private fun assetSize(context: Context, path: String): Int =
        context.assets.open(path).use { it.readBytes().size }

    /** Expected on-device byte sizes, cached because reading 9 MB of assets is slow. */
    private fun expectedSizes(context: Context, kernel: String): List<Int> {
        val key = "$PAYLOAD_VERSION|${exploitAssetFor(kernel)}"
        if (sizeCacheKey == key && sizeCache.size == CRITICAL.size) return sizeCache
        val v = listOf(
            assetSize(context, exploitAssetFor(kernel)),
            assetSize(context, "ksu_fne/kernelsu.ko"),
            assetSize(context, "ksu_fne/ksu_lateload.sh"),
            assetSize(context, "ksu_fne/restore_enforce.sh"),
            assetSize(context, "ksu_fne/chain_hook.sh"),
            assetSize(context, "ksu_fne/ksud")
        )
        sizeCache = v
        sizeCacheKey = key
        return v
    }

    private fun stampFor(kernel: String): String =
        "$PAYLOAD_VERSION|${exploitAssetFor(kernel)}"

    /**
     * True only when BOTH the stamp and every critical file size match this APK.
     * Cheap (one short shell command), so it can be called before every W1.
     */
    suspend fun verify(
        context: Context, kernel: String, log: (String) -> Unit
    ): Boolean = withContext(Dispatchers.IO) {
        val expected = expectedSizes(context, kernel)
        val files = CRITICAL.joinToString(" ") { "'$it'" }
        val cmd = "for f in $files; do wc -c < \"\$f\" 2>/dev/null || echo -1; done; " +
            "echo ---; cat '$STAMP_PATH' 2>/dev/null || echo NO_STAMP"
        val r = ShizukuController.exec(cmd, 20_000)
        val lines = r.out.lines().map { it.trim() }.filter { it.isNotEmpty() }
        val sep = lines.indexOf("---")
        if (sep < 0) {
            log("[deploy] 版本校验无有效输出（code=${r.code} ${r.err.trim().take(120)}）")
            return@withContext false
        }
        val actual = lines.take(sep).mapNotNull { it.toIntOrNull() }
        val stamp = lines.getOrNull(sep + 1).orEmpty()
        val wantStamp = stampFor(kernel)
        if (stamp != wantStamp) {
            log("[deploy] 设备端物料版本 '$stamp' ≠ 本 APK '$wantStamp'，将强制覆盖")
            return@withContext false
        }
        if (actual.size != expected.size || actual != expected) {
            CRITICAL.forEachIndexed { i, path ->
                val a = actual.getOrNull(i) ?: -1
                val e = expected[i]
                if (a != e) log("[deploy][差异] $path：设备 $a B / 本 APK $e B")
            }
            return@withContext false
        }
        true
    }

    /**
     * 把当前选择的管理器包名同步到 `/data/local/tmp/ksu_fne/.manager_pkg`。
     *
     * `ksu_lateload.sh` 收尾时要拉起「用户选的那个」管理器，不能写死官方包名；
     * 切换管理器后即使其它物料一字未改（verify 直接通过），也要重写这个文件，
     * 否则脚本仍会去 am start 上一个管理器。
     */
    suspend fun syncManager(context: Context): Boolean = withContext(Dispatchers.IO) {
        val pkg = ManagerSelection.selected(context)
        ShizukuController.writeFile(
            pkg.toByteArray(Charsets.US_ASCII), "$TMP/ksu_fne/.manager_pkg"
        )
    }

    suspend fun deploy(
        context: Context, log: (String) -> Unit, kernel: String = ""
    ): Boolean = withContext(Dispatchers.IO) {
        val asset = exploitAssetFor(kernel)
        log("[deploy] 开始推送物料到 $TMP ... (exploit=$asset, 内核=${kernel.ifBlank { "未读取" }})")

        // 1) exploit binary (renamed to `e`)
        writeAsset(context, asset, "$TMP/e", log)
        ShizukuController.exec("chmod 755 $TMP/e", 15_000)

        // 2) KSU late-load chain — ALWAYS overwrite, never trust "file exists".
        ShizukuController.exec("mkdir -p $TMP/ksu_fne", 15_000)
        deployDir(context, "ksu_fne", "$TMP/ksu_fne", log)
        KSU_EXECUTABLES.forEach {
            ShizukuController.exec("chmod 755 $TMP/ksu_fne/$it", 15_000)
        }
        // 管理器包名：ksu_lateload.sh 收尾时按这个包名拉起 App。
        // 必须写在 deployDir 之后（否则会被 assets 里的同名文件覆盖），
        // 且每次切换管理器都要重新同步 —— 见 syncManager()。
        syncManager(context)

        // 启用「HONOR50-KernelSU晚加载提权实现记录」验证过的交接链路：
        // chain_hook.sh 见到该标记后只建立常驻 root FIFO 通道就退出，
        // 由 App 通过 rs.in 投递 ksu_lateload.sh + restore_enforce.sh。
        // 删掉 /data/local/tmp/ksu_fne/handoff 即可回退到旧的 load_ko 链路。
        ShizukuController.exec(
            "rm -f $TMP/rs.in $TMP/rs.out $TMP/ksu_fne/.payload_stamp; " +
                ": > $TMP/ksu_fne/handoff",
            15_000
        )

        // 3) netfix_packet module
        ShizukuController.exec("mkdir -p $TMP/netfix_packet", 15_000)
        deployDir(context, "netfix_packet", "$TMP/netfix_packet", log)

        // 4) manager material (post-root)
        ShizukuController.exec("mkdir -p $TMP/managers", 15_000)
        deployDir(context, "managers", "$TMP/managers", log)

        // 5) 版本戳：以后只要 APK 物料变了，verify() 就会强制重新部署。
        val wrote = ShizukuController.writeFile(
            stampFor(kernel).toByteArray(Charsets.US_ASCII), STAMP_PATH
        )
        if (!wrote) log("[deploy][警告] 版本戳写入失败，下次会重复全量部署（不影响本轮）")

        // `cat` 退出码为 0 不等于文件真的落地：Shizuku.newProcess 静默失效时
        // 所有命令都会返回空，旧版会谎报「全部部署成功」，随后 W1 却报
        // "No such file or directory"。这里按字节数逐项复检。
        val ok = verify(context, kernel, log)
        if (ok) {
            log("[deploy] 完成并校验通过 ✔ 路径：$TMP/e + $TMP/ksu_fne + $TMP/netfix_packet + $TMP/managers")
        } else {
            log("[deploy][错误] 关键文件写入后校验失败，多为 Shizuku 命令通道失效")
            log("[deploy][错误] 请重新连接 Shizuku 后重试，绝不带着旧物料启动 exploit")
        }
        ok
    }

    private suspend fun deployDir(
        context: Context, assetDir: String, destDir: String, log: (String) -> Unit
    ) {
        val am = context.assets
        val entries = am.list(assetDir) ?: return
        for (entry in entries) {
            val assetPath = "$assetDir/$entry"
            val destPath = "$destDir/$entry"
            if (isAssetDir(am, assetPath)) {
                ShizukuController.exec("mkdir -p '$destPath'", 15_000)
                deployDir(context, assetPath, destPath, log)
            } else {
                writeAsset(context, assetPath, destPath, log)
            }
        }
    }

    private suspend fun writeAsset(
        context: Context, assetPath: String, destPath: String, log: (String) -> Unit
    ) {
        val data = context.assets.open(assetPath).use { it.readBytes() }
        val ok = ShizukuController.writeFile(data, destPath)
        if (!ok) log("[deploy] 失败: $assetPath -> $destPath")
        else log("[deploy] $assetPath -> $destPath (${data.size} bytes)")
    }

    /** A file returns an opened stream; a directory throws on open. */
    private fun isAssetDir(am: AssetManager, path: String): Boolean {
        val listed = am.list(path)
        if (listed != null && listed.isNotEmpty()) return true
        return try {
            am.open(path).close()
            false
        } catch (_: IOException) {
            true
        }
    }
}
