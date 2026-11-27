package com.ghostlock.honorfne



import java.nio.ByteBuffer
import java.nio.ByteOrder

   
                                            
  
          
                                                                  
                                                               
  
                                                                   
   
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

                                                                  
    fun parseHeader(head: ByteArray): Info? {
        if (head.size < 64) return null
        val buf = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)

        
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
            
            return Info(headerVersion, kernelOffset = 4096L, kernelSize = kernelSize, pageSize = 4096)
        }

        
        val pageSize = buf.getInt(36)
        if (pageSize in intArrayOf(2048, 4096, 8192, 16384, 32768, 65536)) {
            return Info(headerVersion, kernelOffset = pageSize.toLong(), kernelSize = kernelSize, pageSize = pageSize)
        }
        
        
        
        return Info(headerVersion, kernelOffset = 4096L, kernelSize = kernelSize, pageSize = 4096)
    }

                                                                       
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

       
                                                     
                                                                   
                                                                 
      
                                                        
                                                             
                                           
       
    data class Raw(val image: ByteArray, val codec: String)

    private val LZ4_LEGACY = byteArrayOf(0x02, 0x21, 0x4C, 0x18)
    private val LZ4_FRAME = byteArrayOf(0x04, 0x22, 0x4D, 0x18)
    private val GZIP_MAGIC = byteArrayOf(0x1F, 0x8B.toByte())

                                                   
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
            p += 2                                   
            if (flg and 0x08 != 0) p += 8            
            if (flg and 0x01 != 0) p += 4            
            p += 1                                   
        }
        val cap = minOf(maxOut, maxOf(1 shl 23, src.size * 3))
        val out = Growable(cap)
        while (p + 4 <= src.size) {
            var bs = u32(src, p)
            p += 4
            if (bs == 0) break
            if (bs == 0x184C2102) continue           
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
            if (!legacy && (flg and 0x10) != 0) p += 4   
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
