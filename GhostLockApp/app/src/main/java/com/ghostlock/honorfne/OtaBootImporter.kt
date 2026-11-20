package com.ghostlock.honorfne

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream
import java.util.zip.ZipFile

/**
 * 全量包链接 → boot.img（移植月虹 1.7.0 的远程 OTA 取包思路，离线实现）。
 *
 * 月虹用服务端签名接口解析 ota_url，再对远程 ZIP 做区间读取、取 payload.bin。
 * 本项目没有那套服务端配置，所以改为用户直接粘链接：
 *  - https 链接、512 MiB 上限、跟随跳转但拒绝跳到明文 http；
 *  - 链接直接是 boot.img → 原样保存；
 *  - 链接是 OTA ZIP → 优先取 boot.img 条目；
 *  - ZIP 里只有 payload.bin → 解析 Android payload 头/最小 protobuf manifest，
 *    提取 boot 分区的 REPLACE / REPLACE_GZ 操作（XZ/Brotli/ZSTD 需要设备侧
 *    解压器，明确报错并提示先提取 boot.img，绝不静默拿错镜像去适配）。
 */
object OtaBootImporter {
    data class Result(val ok: Boolean, val file: File? = null, val message: String = "", val bytes: Long = 0)

    private const val MAX_BYTES = 512L * 1024 * 1024
    private const val CONNECT_MS = 15_000
    private const val READ_MS = 90_000

    suspend fun fetch(context: Context, rawUrl: String, onProgress: (Int, String) -> Unit): Result =
        withContext(Dispatchers.IO) {
            var connection: HttpURLConnection? = null
            val tmp = File.createTempFile("honorroot-ota-", ".bin", context.cacheDir)
            try {
                val url = runCatching { URL(rawUrl.trim()) }
                    .getOrElse { return@withContext Result(false, message = "链接格式不对：${it.message}") }
                if (!url.protocol.equals("https", true)) {
                    return@withContext Result(false, message = "出于安全考虑只接受 https 链接")
                }
                onProgress(0, "连接全量包服务器…")
                val active = url.openConnection() as HttpURLConnection
                connection = active
                active.requestMethod = "GET"
                active.instanceFollowRedirects = true
                active.connectTimeout = CONNECT_MS
                active.readTimeout = READ_MS
                active.setRequestProperty("Accept", "application/octet-stream")
                val code = active.responseCode
                if (code !in 200..299) {
                    return@withContext Result(false, message = "下载失败：HTTP $code")
                }
                if (!active.url.protocol.equals("https", true)) {
                    return@withContext Result(false, message = "服务器跳转到了非加密链接，已中止")
                }
                val total = active.contentLengthLong
                if (total > MAX_BYTES) {
                    return@withContext Result(false, message = "全量包超过 512 MiB（${total / 1048576} MiB），请本机提取 boot.img 后导入")
                }
                var written = 0L
                var lastPct = -1
                FileOutputStream(tmp).use { out ->
                    active.inputStream.use { input ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            written += n
                            if (written > MAX_BYTES) throw IOException("全量包超过 512 MiB")
                            out.write(buf, 0, n)
                            if (total > 0) {
                                val pct = (written * 100 / total).toInt().coerceIn(0, 100)
                                if (pct != lastPct && pct % 5 == 0) {
                                    lastPct = pct
                                    onProgress(pct, "已下载 ${written / 1048576} / ${total / 1048576} MiB")
                                }
                            }
                        }
                    }
                    out.fd.sync()
                }
                if (written == 0L) return@withContext Result(false, message = "下载到 0 字节")

                onProgress(96, "识别镜像格式…")
                val magic = ByteArray(8)
                tmp.inputStream().use { it.read(magic) }
                val boot = when {
                    magic.copyOf(4).contentEquals("ANDROID!".toByteArray()) -> tmp
                    magic[0] == 'P'.code.toByte() && magic[1] == 'K'.code.toByte() ->
                        extractFromZip(tmp, onProgress)
                    magic.copyOf(4).contentEquals("CrAU".toByteArray()) ->
                        extractBootFromPayload(tmp, onProgress)
                    else -> {
                        tmp.delete()
                        return@withContext Result(false, message = "链接既不是 boot.img，也不是 OTA ZIP / payload.bin")
                    }
                }
                if (boot == null) {
                    tmp.delete()
                    return@withContext Result(false, message = "全量包里找不到可用的 boot 镜像")
                }
                val dest = File(context.cacheDir, "honorroot-ota-boot.img")
                if (boot.absolutePath != dest.absolutePath) {
                    boot.copyTo(dest, overwrite = true)
                }
                onProgress(99, "boot.img 已就绪（${dest.length() / 1048576} MiB）")
                Result(true, dest, "已从全量包提取 boot.img", written)
            } catch (e: Exception) {
                Result(false, message = "下载/解析全量包失败：${e.message ?: e.javaClass.simpleName}")
            } finally {
                connection?.disconnect()
                if (tmp.exists() && (!tmp.name.contains("boot.img"))) tmp.delete()
            }
        }

    /** ZIP 里优先 boot.img；只有 payload.bin 时再走 payload 解析。 */
    private fun extractFromZip(zip: File, onProgress: (Int, String) -> Unit): File? {
        ZipFile(zip).use { zf ->
            val entries = zf.entries().toList()
            val bootEntry = entries.firstOrNull { it.name == "boot.img" }
                ?: entries.firstOrNull { it.name.endsWith("/boot.img") }
            if (bootEntry != null) {
                onProgress(97, "从 OTA ZIP 取 boot.img…")
                val out = File(zip.parentFile, "honorroot-zip-boot.img")
                zf.getInputStream(bootEntry).use { input ->
                    FileOutputStream(out).use { output -> input.copyTo(output, 64 * 1024) }
                }
                val head = ByteArray(8)
                out.inputStream().use { it.read(head) }
                if (!head.copyOf(4).contentEquals("ANDROID!".toByteArray())) {
                    out.delete()
                    return null
                }
                return out
            }
            val payloadEntry = entries.firstOrNull { it.name == "payload.bin" }
                ?: entries.firstOrNull { it.name.endsWith("/payload.bin") }
                ?: return null
            onProgress(97, "从 OTA ZIP 流式取 payload.bin…")
            val out = File(zip.parentFile, "honorroot-ota-payload.bin")
            zf.getInputStream(payloadEntry).use { input ->
                FileOutputStream(out).use { output -> input.copyTo(output, 64 * 1024) }
            }
            return extractBootFromPayload(out, onProgress)
        }
    }

    /**
     * payload.bin：CrAU + major(8) + manifest_size(8) + signature_size(4) + manifest(pb)。
     * 只解 boot 分区的 REPLACE(1) / REPLACE_GZ(3)；其它压缩方式明确失败。
     */
    private fun extractBootFromPayload(payload: File, onProgress: (Int, String) -> Unit): File? {
        val all = payload.readBytes()
        if (all.size < 24 || !all.copyOfRange(0, 4).contentEquals("CrAU".toByteArray())) return null
        // manifestSize 是 u64，直接 toInt() 会截断成负/溢出值；先按 Long 校验
        // 范围再收窄，避免绕过下面的边界检查。
        val manifestSizeL = le64(all, 12)
        val sigSize = le32(all, 20).toLong() and 0xffffffffL
        if (manifestSizeL <= 0 || manifestSizeL > Int.MAX_VALUE) return null
        val manifestSize = manifestSizeL.toInt()
        if (24L + manifestSizeL + sigSize > all.size) return null
        val dataBase = 24L + manifestSizeL + sigSize
        val fields = parsePb(all, 24, manifestSize)
        val bootPartition = fields[1].orEmpty().mapNotNull { parsePartition(it) }.firstOrNull { it.name == "boot" }
            ?: return null
        for (op in bootPartition.operations) {
            if (op.type == 4L || op.type == 5L) continue // ZERO / DISCARD 不产生数据
            if (op.type != 1L && op.type != 3L) {
                onProgress(98, "boot 分区使用了当前不支持的压缩方式（type=${op.type}）")
                return null
            }
            // dataOffset/dataLength 来自 payload manifest（不可信）；全程用 Long 算，
            // 防止 start+len 溢出绕过边界检查，再确认可安全收窄为 Int。
            val start = dataBase + op.dataOffset
            val end = start + op.dataLength
            if (start < 0 || op.dataLength <= 0 || end < start ||
                end > all.size || end > Int.MAX_VALUE) return null
            val slice = all.copyOfRange(start.toInt(), end.toInt())
            val output = ByteArrayInputStream(slice).use { raw ->
                val src: InputStream = if (op.type == 3L) GZIPInputStream(raw) else raw
                src.use { it.readBytes() }
            }
            val out = File(payload.parentFile, "honorroot-payload-boot.img")
            out.writeBytes(output)
            val head = ByteArray(8)
            out.inputStream().use { it.read(head) }
            if (!head.copyOf(4).contentEquals("ANDROID!".toByteArray())) {
                out.delete()
                return null
            }
            return out
        }
        return null
    }

    private data class Partition(val name: String, val operations: List<Op>)
    private data class Op(val type: Long, val dataOffset: Long, val dataLength: Long)

    private fun parsePartition(bytes: ByteArray): Partition? {
        val f = parsePb(bytes, 0, bytes.size)
        val name = f[1].orEmpty().firstOrNull()?.let { String(it, Charsets.UTF_8) } ?: return null
        val ops = f[2].orEmpty().mapNotNull { raw ->
            val of = parsePb(raw, 0, raw.size)
            Op(
                type = of[1].orEmpty().firstOrNull()?.let { varint(it, 0)?.first ?: 0L } ?: 0L,
                dataOffset = of[2].orEmpty().firstOrNull()?.let { varint(it, 0)?.first ?: 0L } ?: 0L,
                dataLength = of[3].orEmpty().firstOrNull()?.let { varint(it, 0)?.first ?: 0L } ?: 0L,
            )
        }
        return Partition(name, ops)
    }

    /** 最小 protobuf 解析：返回 field number → 原始 value 字节（varint / bytes）。 */
    private fun parsePb(data: ByteArray, from: Int, size: Int): Map<Int, List<ByteArray>> {
        val out = HashMap<Int, MutableList<ByteArray>>()
        var p = from
        val end = from + size
        while (p < end) {
            val tag = varint(data, p) ?: break
            p = tag.second
            val field = (tag.first shr 3).toInt()
            val wire = (tag.first and 7).toInt()
            when (wire) {
                0 -> {
                    val v = varint(data, p) ?: break
                    p = v.second
                    out.getOrPut(field) { ArrayList() }.add(data.copyOfRange(v.first.toInt(), v.second).let { it })
                }
                2 -> {
                    val len = varint(data, p) ?: break
                    p = len.second
                    val n = len.first.toInt()
                    if (n < 0 || p + n > end) break
                    out.getOrPut(field) { ArrayList() }.add(data.copyOfRange(p, p + n))
                    p += n
                }
                1 -> { if (p + 8 > end) break; out.getOrPut(field) { ArrayList() }.add(data.copyOfRange(p, p + 8)); p += 8 }
                5 -> { if (p + 4 > end) break; out.getOrPut(field) { ArrayList() }.add(data.copyOfRange(p, p + 4)); p += 4 }
                else -> break
            }
        }
        return out
    }

    private fun varint(data: ByteArray, from: Int): Pair<Long, Int>? {
        var p = from
        var result = 0L
        var shift = 0
        while (p < data.size && shift < 63) {
            val b = data[p++].toInt() and 0xff
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result to p
            shift += 7
        }
        return null
    }

    private fun le32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or ((b[off + 3].toInt() and 0xff) shl 24)

    private fun le64(b: ByteArray, off: Int): Long =
        (le32(b, off).toLong() and 0xffffffffL) or ((le32(b, off + 4).toLong() and 0xffffffffL) shl 32)
}
