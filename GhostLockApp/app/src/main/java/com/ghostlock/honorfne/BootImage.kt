package com.ghostlock.honorfne

// 移植自 ExtractKit（com.extractkit.app）：只改包名，算法与常量保持原样。

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Android boot image 头解析（v0~v4）+ 内嵌 BTF 抽取。
 *
 * 只需要两件事：
 *   1. 从 boot.img 里把 arm64 的 kernel Image 切出来（KallsymsFinder 要扫它）
 *   2. Image 里通常内嵌 .BTF（magic 9f eb 01 00 18 00 00 00），直接切一段出来
 *
 * 设备上 shell 读不到 /sys/kernel/btf/vmlinux（SELinux），所以走 boot.img 这条路。
 */
object BootImage {

    data class Info(
        val headerVersion: Int,
        val kernelOffset: Long,
        val kernelSize: Int,
        val pageSize: Int,
    )

    private val MAGIC = "ANDROID!".toByteArray(Charsets.US_ASCII)
    private val VENDOR_MAGIC = "VNDRBOOT".toByteArray(Charsets.US_ASCII)
    private val ARM64_MAGIC = byteArrayOf('A'.code.toByte(), 'R'.code.toByte(), 'M'.code.toByte(), 0x64)

    class Unsupported(message: String) : Exception(message)

    /** 返回 null 表示头不合法；抛 Unsupported 表示认得出但走不通（比如 vendor_boot）。 */
    fun parseHeader(head: ByteArray): Info? {
        if (head.size < 64) return null
        val buf = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)

        // 已经是裸 Image（有人直接把 kernel 存成 boot.img）
        if (head[0x38] == ARM64_MAGIC[0] && head[0x39] == ARM64_MAGIC[1] &&
            head[0x3A] == ARM64_MAGIC[2] && head[0x3B] == ARM64_MAGIC[3]
        ) {
            return Info(headerVersion = -1, kernelOffset = 0, kernelSize = head.size, pageSize = 4096)
        }

        if (!head.startsWith(MAGIC)) {
            if (head.startsWith(VENDOR_MAGIC)) throw Unsupported("这是 vendor_boot.img，请选 boot.img")
            return null
        }

        val kernelSize = buf.getInt(8)
        if (kernelSize <= 0) return null

        val headerVersion = buf.getInt(40)
        if (headerVersion in 3..4) {
            // v3/v4：kernel 固定在 4096 之后
            return Info(headerVersion, kernelOffset = 4096L, kernelSize = kernelSize, pageSize = 4096)
        }

        // v0~v2：page_size 在 36
        val pageSize = buf.getInt(36)
        if (pageSize in intArrayOf(2048, 4096, 8192, 16384, 32768, 65536)) {
            return Info(headerVersion, kernelOffset = pageSize.toLong(), kernelSize = kernelSize, pageSize = pageSize)
        }
        // 荣耀/华为的 boot 头是非标的：page_size 字段经常是垃圾（实测 3 / 4），
        // kernel_addr / ramdisk 也全是 0。但 kernel 仍然从 4096 开始，所以按 4096 兜底，
        // 真正的判据交给 [toRawImage] 的 magic 校验。
        return Info(headerVersion, kernelOffset = 4096L, kernelSize = kernelSize, pageSize = 4096)
    }

    /** 从输入流里按 Info 切出 kernel Image（只读需要的那一段，boot.img 整体可能有 100 MB）。 */
    fun readKernel(stream: java.io.FileInputStream, info: Info, maxBytes: Int = 64 * 1024 * 1024): ByteArray {
        val size = minOf(info.kernelSize, maxBytes)
        val out = ByteArray(size)
        stream.channel.position(info.kernelOffset)
        var read = 0
        while (read < size) {
            val n = stream.read(out, read, size - read)
            if (n <= 0) break
            read += n
        }
        return if (read == size) out else out.copyOf(read)
    }

    /**
     * 内核段不一定是裸 Image：荣耀/华为的 boot.img 里 kernel 常常是压缩的
     * （实测 `5.15.104-android13` 的镜像是 legacy LZ4 帧，26 MiB → 58 MiB）。
     * 这里把它还原成裸 Image，后面 kallsyms / BTF / call site 全按裸 Image 处理。
     *
     * 支持：裸 ARM64 Image、LZ4 legacy 帧（magic 02 21 4C 18）、
     *       LZ4 现代帧（04 22 4D 18）、gzip。其余（zstd/bzip2/xz）明确报错，
     *       不猜——猜错会拿着随机字节去扫符号表，只会给出误导性的结果。
     */
    data class Raw(val image: ByteArray, val codec: String)

    private val LZ4_LEGACY = byteArrayOf(0x02, 0x21, 0x4C, 0x18)
    private val LZ4_FRAME = byteArrayOf(0x04, 0x22, 0x4D, 0x18)
    private val GZIP_MAGIC = byteArrayOf(0x1F, 0x8B.toByte())

    /** 头部偏移不准时的兜底候选：0 以及前 1 MiB 内所有 4 KiB 对齐位置。 */
    private fun candidates(b: ByteArray): IntArray {
        val out = ArrayList<Int>(260)
        out.add(0)
        var o = 0x1000
        val limit = minOf(b.size, 1 shl 20)
        while (o < limit) {
            out.add(o)
            o += 0x1000
        }
        return out.toIntArray()
    }

    /**
     * 把 [payload]（readKernel 切出来的那段）还原成裸 Image。
     * 返回 null 表示认不出格式——调用方应当直接报错，不要拿原字节继续跑。
     */
    fun toRawImage(payload: ByteArray, onProgress: (String) -> Unit = {}): Raw? {
        val maxOut = 128 shl 20
        for (off in candidates(payload)) {
            if (isArm64Image(payload, off)) {
                return Raw(if (off == 0) payload else payload.copyOfRange(off, payload.size), "raw")
            }
            if (startsWithAt(payload, off, LZ4_LEGACY) || startsWithAt(payload, off, LZ4_FRAME)) {
                val legacy = startsWithAt(payload, off, LZ4_LEGACY)
                onProgress(if (legacy) "LZ4 legacy 帧解压…" else "LZ4 帧解压…")
                val img = decompressLz4(payload, off, legacy, maxOut) ?: continue
                if (isArm64Image(img, 0)) return Raw(img, if (legacy) "lz4-legacy" else "lz4")
                onProgress("! LZ4 解出来了但不是 arm64 Image（${img.size} B），继续找")
            }
            if (startsWithAt(payload, off, GZIP_MAGIC)) {
                onProgress("gzip 解压…")
                val img = gunzip(payload, off, maxOut) ?: continue
                if (isArm64Image(img, 0)) return Raw(img, "gzip")
                onProgress("! gzip 解出来了但不是 arm64 Image（${img.size} B），继续找")
            }
        }
        return null
    }

    private fun isArm64Image(b: ByteArray, off: Int): Boolean =
        off >= 0 && off + 0x3C <= b.size &&
            b[off + 0x38] == ARM64_MAGIC[0] && b[off + 0x39] == ARM64_MAGIC[1] &&
            b[off + 0x3A] == ARM64_MAGIC[2] && b[off + 0x3B] == ARM64_MAGIC[3]

    private fun startsWithAt(b: ByteArray, off: Int, m: ByteArray): Boolean {
        if (off < 0 || off + m.size > b.size) return false
        for (i in m.indices) if (b[off + i] != m[i]) return false
        return true
    }

    private fun u32(b: ByteArray, p: Int): Int =
        (b[p].toInt() and 0xFF) or ((b[p + 1].toInt() and 0xFF) shl 8) or
            ((b[p + 2].toInt() and 0xFF) shl 16) or ((b[p + 3].toInt() and 0xFF) shl 24)

    /** 可增长缓冲区：LZ4 需要回引用（写之前读），ByteArrayOutputStream 做不到。 */
    private class Growable(capacity: Int) {
        var buf = ByteArray(capacity.coerceAtLeast(1 shl 16))
            private set
        var len = 0
            private set

        private fun ensure(n: Int) {
            if (len + n <= buf.size) return
            var cap = buf.size
            while (cap < len + n) cap = cap shl 1
            buf = buf.copyOf(cap)
        }

        fun put(src: ByteArray, off: Int, n: Int) {
            ensure(n)
            System.arraycopy(src, off, buf, len, n)
            len += n
        }

        fun copyBack(dist: Int, n: Int) {
            ensure(n)
            var s = len - dist
            var i = 0
            while (i < n) {
                buf[len++] = buf[s++]
                i++
            }
        }

        fun toArray(): ByteArray = buf.copyOf(len)
    }

    private fun decompressLz4(src: ByteArray, start: Int, legacy: Boolean, maxOut: Int): ByteArray? {
        var p = start + 4
        var flg = 0
        if (!legacy) {
            if (p + 3 > src.size) return null
            flg = src[p].toInt() and 0xFF
            p += 2                                   // FLG + BD
            if (flg and 0x08 != 0) p += 8            // content size
            if (flg and 0x01 != 0) p += 4            // dict id
            p += 1                                   // header checksum
        }
        val cap = minOf(maxOut, maxOf(1 shl 23, src.size * 3))
        val out = Growable(cap)
        while (p + 4 <= src.size) {
            var bs = u32(src, p)
            p += 4
            if (bs == 0) break
            if (bs == 0x184C2102) continue           // 下一个 legacy 帧
            var plain = false
            if (!legacy && (bs and 0x80000000.toInt()) != 0) {
                plain = true
                bs = bs and 0x7FFFFFFF
            }
            if (bs <= 0 || p + bs > src.size) break
            if (out.len + bs > maxOut) return null
            if (plain) out.put(src, p, bs)
            else if (!lz4Block(src, p, p + bs, out, maxOut)) return null
            p += bs
            if (!legacy && (flg and 0x10) != 0) p += 4   // block checksum
        }
        return if (out.len > 0) out.toArray() else null
    }

    private fun lz4Block(src: ByteArray, from: Int, to: Int, out: Growable, maxOut: Int): Boolean {
        var i = from
        while (i < to) {
            val token = src[i].toInt() and 0xFF
            i++
            var ll = token ushr 4
            if (ll == 15) {
                while (i < to) {
                    val b = src[i].toInt() and 0xFF
                    i++
                    ll += b
                    if (b != 255) break
                }
            }
            // ll 由 0xFF 链累加，可溢出为负 → arraycopy 负长度崩溃。
            if (ll < 0 || i > to - ll) return false
            out.put(src, i, ll)
            i += ll
            if (i >= to) break
            if (i + 2 > to) return false
            val dist = (src[i].toInt() and 0xFF) or ((src[i + 1].toInt() and 0xFF) shl 8)
            i += 2
            if (dist == 0 || dist > out.len) return false
            var ml = token and 0x0F
            if (ml == 15) {
                while (i < to) {
                    val b = src[i].toInt() and 0xFF
                    i++
                    ml += b
                    if (b != 255) break
                }
            }
            // copyBack 走 Growable.ensure 会无限倍增容量；ml 由 0xFF 链累加，
            // 恶意镜像可构造超大匹配长度触发 GB 级分配甚至 Int 溢出 → OOM 崩溃。
            // put 路径在 210 行有 maxOut 校验，copyBack 必须同样受限。
            val add = ml + 4
            if (add < 0 || out.len > maxOut - add) return false
            out.copyBack(dist, add)
        }
        return true
    }

    private fun gunzip(src: ByteArray, start: Int, maxOut: Int): ByteArray? = runCatching {
        java.io.ByteArrayInputStream(src, start, src.size - start).use { bin ->
            java.util.zip.GZIPInputStream(bin).use { gz ->
                val out = java.io.ByteArrayOutputStream(1 shl 23)
                val chunk = ByteArray(1 shl 20)
                var total = 0
                while (true) {
                    val n = gz.read(chunk)
                    if (n <= 0) break
                    total += n
                    if (total > maxOut) return null
                    out.write(chunk, 0, n)
                }
                out.toByteArray()
            }
        }
    }.getOrNull()

    /**
     * Image 里的内核版本串，找不到就返回 null。
     *
     * 注意不能只取第一个 "Linux version "：镜像里还有别的地方会写这个前缀
     * （实测 5.4.295 上第一个命中就是格式串 `Linux version %s`），
     * 那样解出来的 release 是字面量 "%s"，后面 kallsyms / 匹配全废。
     * 所以逐个候选往后扫，只接受形如 `5.4.295-qgki-g0fb2656b2b50` 的 token。
     */
    fun kernelRelease(image: ByteArray): String? {
        val needle = "Linux version ".toByteArray(Charsets.US_ASCII)
        val versionLike = Regex("^\\d+\\.\\d+\\.\\d+[A-Za-z0-9._+\\-]*$")
        var from = 0
        var tried = 0
        while (tried < 64) {
            val at = indexOf(image, needle, from, image.size) ?: return null
            val body = at + needle.size
            var end = body
            while (end < image.size && end - body < 200 && image[end] != 0.toByte()) end++
            val line = String(image, body, end - body, Charsets.ISO_8859_1)
            val token = line.substringBefore(' ').trim()
            if (token.isNotEmpty() && versionLike.matches(token)) return token
            from = at + 1
            tried++
        }
        return null
    }

    /** 在 Image 里找内嵌 BTF 并切出完整 BTF blob（header + types + strings）。 */
    fun extractBtf(image: ByteArray): ByteArray? {
        val magic = byteArrayOf(0x9f.toByte(), 0xeb.toByte(), 0x01, 0x00, 0x18, 0x00, 0x00, 0x00)
        val at = indexOf(image, magic, 0, image.size) ?: return null
        if (at + 24 > image.size) return null
        val buf = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        val hdrLen = buf.getInt(at + 4)
        val typeOff = buf.getInt(at + 8)
        val typeLen = buf.getInt(at + 12)
        val strOff = buf.getInt(at + 16)
        val strLen = buf.getInt(at + 20)
        // 偏移全来自不可信镜像；typeOff/typeLen 为 Int，相加可溢出为负或超大，
        // 用 Long 计算再收窄，避免绕过边界检查后在 copyOfRange 越界崩溃。
        if (hdrLen <= 0 || typeLen <= 0 || strLen <= 0 ||
            typeOff < 0 || strOff < 0) return null
        val typeEnd = typeOff.toLong() + typeLen
        val strEnd = strOff.toLong() + strLen
        val totalL = hdrLen.toLong() + maxOf(typeEnd, strEnd)
        if (totalL <= 0 || totalL > Int.MAX_VALUE) return null
        val total = totalL.toInt()
        if (at > image.size - total) return null
        return image.copyOfRange(at, at + total)
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray, from: Int, to: Int): Int? {
        val limit = minOf(to, hay.size) - needle.size
        var i = from
        outer@ while (i <= limit) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) {
                    i++
                    continue@outer
                }
            }
            return i
        }
        return null
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        for (i in prefix.indices) if (this[i] != prefix[i]) return false
        return true
    }
}
