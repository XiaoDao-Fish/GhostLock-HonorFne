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
 *   assets/ksu_fne/  (all files) -> /data/local/tmp/ksu_fne/
 *   assets/netfix_packet/ (all)  -> /data/local/tmp/netfix_packet/
 *   assets/managers/ (all files) -> /data/local/tmp/managers/       (post-root install)
 */
object AssetDeployer {

    private const val TMP = "/data/local/tmp"

    private val KSU_EXECUTABLES = setOf("chain_hook.sh", "magiskpolicy", "ksud", "load_ko", "kmsg_dumper")

    suspend fun deploy(context: Context, log: (String) -> Unit) = withContext(Dispatchers.IO) {
        log("[deploy] 开始推送物料到 $TMP ...")

        // 1) exploit binary (renamed to `e`)
        writeAsset(context, "ghostlock", "$TMP/e", log)
        ShizukuController.exec("chmod 755 $TMP/e", 15_000)

        // 2) KSU late-load chain
        ShizukuController.exec("mkdir -p $TMP/ksu_fne", 15_000)
        deployDir(context, "ksu_fne", "$TMP/ksu_fne", log)
        KSU_EXECUTABLES.forEach {
            ShizukuController.exec("chmod 755 $TMP/ksu_fne/$it", 15_000)
        }

        // 3) netfix_packet module
        ShizukuController.exec("mkdir -p $TMP/netfix_packet", 15_000)
        deployDir(context, "netfix_packet", "$TMP/netfix_packet", log)

        // 4) manager material (post-root)
        ShizukuController.exec("mkdir -p $TMP/managers", 15_000)
        deployDir(context, "managers", "$TMP/managers", log)

        log("[deploy] 完成。设备端路径：$TMP/e + $TMP/ksu_fne + $TMP/netfix_packet + $TMP/managers")
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
