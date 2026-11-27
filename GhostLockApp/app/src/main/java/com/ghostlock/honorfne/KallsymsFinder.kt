package com.ghostlock.honorfne



import java.nio.ByteBuffer
import java.nio.ByteOrder

   
                                                                             
  
          
  
                 
                                                                                             
  
                       
                                                                                               
                                                                 
                                           
  
                                       
  
          
                                                             
                                                     
                                                                          
   
object KallsymsFinder {

    data class Result(
        val symbols: Map<String, Long>,
        val numSyms: Int,
        val relativeBase: Long,
        val markersOffset: Int,
        val namesOffset: Int,
    )

    private const val MIN_MARKERS = 128
    private const val MAX_MARKERS = 4096
    private const val STEP_MIN = 32
    private const val STEP_MAX = 20000
    private const val NAME_WINDOW = 8 * 1024 * 1024
    private const val TOKEN_SCAN_WINDOW = 4 * 1024 * 1024
    private val IDENT = Regex("^[A-Za-z_.$][A-Za-z0-9_.$]*$")

    private fun align(v: Int, a: Int) = (v + a - 1) and (a - 1).inv()

    fun find(image: ByteArray, onProgress: (String) -> Unit = {}): Result? {
        val buf = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)

        onProgress("扫描 markers…")
        val markerCandidates = findMarkers(buf, image.size)
        if (markerCandidates.isEmpty()) return null
        onProgress("markers 候选 ${markerCandidates.size} 组")

        for ((markersOff, mCount) in markerCandidates) {
            val markers = IntArray(mCount) { buf.getInt(markersOff + 4 * it) }

            
            modernLayout(buf, image, markersOff, markers, onProgress)?.let { return it }
            
            onProgress("新布局不匹配，尝试旧布局（6.1/5.15）…")
            legacyLayout(buf, image, markersOff, markers, onProgress)?.let { return it }
        }
        return null
    }

    

    private fun modernLayout(
        buf: ByteBuffer,
        image: ByteArray,
        markersOff: Int,
        markers: IntArray,
        onProgress: (String) -> Unit,
    ): Result? {
        val mCount = markers.size
        val tableOff = align(markersOff + 4 * mCount, 8)
        val parsed = parseTokens(image, tableOff) ?: return null
        val tokens = parsed.first
        val tableEnd = parsed.second

        val tiOff = findTokenIndex(buf, tableEnd) ?: return null
        val offsetsOff = align(tiOff + 512, 4)

        val namesStart = findNamesStart(image, tokens, markersOff, markers[1]) ?: run {
            onProgress("旧布局：没找到 names 起点")
            return null
        }

        onProgress("解码符号表…")
        val walked = walkNames(buf, namesStart, markersOff, mCount)
        val count = walked.first
        if (count <= 0 || walked.second.size < mCount) return null
        if (!markersMatch(walked.second, markers)) return null

        val baseOff = align(offsetsOff + 4 * count, 8)
        if (baseOff + 8 > image.size) return null
        val base = buf.getLong(baseOff)
        if (!plausibleBase(base)) return null

        val symbols = buildSymbols(buf, image, tokens, namesStart, count, offsetsOff, base)
        if (symbols.isEmpty()) return null
        if (!sanityOk(symbols, base)) return null
        onProgress("符号 ${symbols.size} 个，base=${hex(base)}（新布局）")
        return Result(symbols, count, base, markersOff, namesStart)
    }

    

    private fun legacyLayout(
        buf: ByteBuffer,
        image: ByteArray,
        markersOff: Int,
        markers: IntArray,
        onProgress: (String) -> Unit,
    ): Result? {
        val mCount = markers.size

        
        onProgress("旧布局：扫描 token 表（从 0x${(markersOff + 4 * mCount).toString(16)} 起）")
        val tokens = scanTokenTable(buf, image, markersOff + 4 * mCount) ?: run {
            onProgress("旧布局：没找到 token 表")
            return null
        }
        
        val namesStart = findNamesStart(image, tokens, markersOff, markers[1]) ?: run {
            onProgress("旧布局：没找到 names 起点")
            return null
        }
        onProgress("旧布局：names @ 0x${namesStart.toString(16)}")

        val walked = walkNames(buf, namesStart, markersOff, mCount)
        val count = walked.first
        if (count <= 0) { onProgress("旧布局：names 走不通"); return null }
        if (!markersMatch(walked.second, markers)) {
            onProgress("旧布局：markers 对不上（count=$count）")
            return null
        }

        
        
        
        onProgress("旧布局：回溯定位 offsets/base…")
        val located = findOffsetsAndBase(buf, namesStart, count) ?: run {
            onProgress("旧布局：没找到 offsets/base")
            return null
        }
        val (offsetsOff, base) = located

        val symbols = buildSymbols(buf, image, tokens, namesStart, count, offsetsOff, base)
        if (symbols.isEmpty()) return null
        if (!sanityOk(symbols, base)) {
            onProgress("旧布局：_text 与 base 对不上")
            return null
        }
        onProgress("符号 ${symbols.size} 个，base=${hex(base)}（旧布局）")
        return Result(symbols, count, base, markersOff, namesStart)
    }

                                                                         
    private fun scanTokenTable(buf: ByteBuffer, image: ByteArray, from: Int): Array<ByteArray>? {
        val end = minOf(from + TOKEN_SCAN_WINDOW, image.size - 1024)
        var p = maxOf(0, from)
        while (p < end) {
            val parsed = parseTokens(image, p)
            if (parsed != null) {
                val tokens = parsed.first
                val tableEnd = parsed.second
                
                for (delta in 0..32) {
                    val ti = tableEnd + delta
                    if (ti + 512 > image.size) continue
                    if (buf.getShort(ti) != 0.toShort()) continue
                    var ok = true
                    var prev = -1
                    for (i in 0 until 256) {
                        val v = buf.getShort(ti + 2 * i).toInt() and 0xFFFF
                        if (v < prev) { ok = false; break }
                        prev = v
                    }
                    
                    if (ok) {
                        var startsOk = 0
                        var q = p
                        for (i in 0 until 256) {
                            val v = buf.getShort(ti + 2 * i).toInt() and 0xFFFF
                            if (p + v == q) startsOk++
                            var z = q
                            while (z < image.size && image[z] != 0.toByte()) z++
                            q = z + 1
                        }
                        if (startsOk >= 250) return tokens
                    }
                }
            }
            p++
        }
        return null
    }

       
                                                                   
                                                             
                                                       
       
    private fun findOffsetsAndBase(
        buf: ByteBuffer,
        namesStart: Int,
        count: Int,
    ): Pair<Int, Long>? {
        val span = minOf(namesStart, 24 * 1024 * 1024)
        var off = namesStart - 8
        val limit = namesStart - span
        var checked = 0
        while (off >= limit && off >= 8) {
            val base = buf.getLong(off)
            if (plausibleBase(base)) {
                checked++
                
                
                for (delta in 0..64 step 4) {
                    val oo = off - 4 * count - delta
                    if (oo < 0) break
                    if (buf.getInt(oo) != 0) continue
                    if (!looksMonotonic(buf, oo, count)) continue
                    val last = buf.getInt(oo + 4 * (count - 1)).toLong() and 0xFFFFFFFFL
                    if (last in 0x1000..0x4000_0000L) return oo to base
                }
            }
            off -= 8
        }
        return null
    }

                                      
    private fun looksMonotonic(buf: ByteBuffer, off: Int, count: Int): Boolean {
        if (count < 16) return false
        val step = maxOf(1, count / 64)
        var prev = buf.getInt(off)
        var i = step
        while (i < count) {
            val v = buf.getInt(off + 4 * i)
            if (v < prev) return false
            prev = v
            i += step
        }
        return true
    }

    private fun markersMatch(positions: IntArray, markers: IntArray): Boolean {
        if (positions.size < markers.size) return false
        for (i in 0 until markers.size) if (positions[i] != markers[i]) return false
        return true
    }

    private fun plausibleBase(base: Long): Boolean {
        val u = base.toULong()
        return u >= 0xFFFFFF8000000000uL && (base and 0xFFF) == 0L
    }

                                                 
    private fun sanityOk(symbols: Map<String, Long>, base: Long): Boolean {
        val text = symbols["_text"] ?: symbols["_stext"] ?: return true
        return text == base || (text - base) in 0..0x200000
    }

    private fun buildSymbols(
        buf: ByteBuffer,
        image: ByteArray,
        tokens: Array<ByteArray>,
        namesStart: Int,
        count: Int,
        offsetsOff: Int,
        base: Long,
    ): Map<String, Long> {
        val symbols = HashMap<String, Long>(count * 2)
        var q = namesStart
        for (i in 0 until count) {
            val hdr = readRecordHeader(image, q)
            val len = hdr.second
            if (len <= 0 || hdr.first + len > image.size) break
            q = hdr.first
            val raw = ByteArray(len)
            System.arraycopy(image, q, raw, 0, len)
            q += len
            val name = decodeName(tokens, raw)
            if (name.length >= 2) {
                val off = buf.getInt(offsetsOff + 4 * i)
                val uoff = off.toUInt().toLong()
                val addr = if (uoff >= 0x80000000L) base - (0x100000000L - uoff) else base + uoff
                symbols.putIfAbsent(name.substring(1), addr)
            }
        }
        return symbols
    }

    

    private fun findMarkers(buf: ByteBuffer, size: Int): List<Pair<Int, Int>> {
        val out = ArrayList<Pair<Int, Int>>()
        var o = 0
        while (o + 8 <= size) {
            if (buf.getInt(o) == 0 && buf.getInt(o + 4) > STEP_MIN) {
                var run = 1
                var prev = 0
                var p = o + 4
                while (p + 4 <= size && run < MAX_MARKERS) {
                    val v = buf.getInt(p)
                    val d = v - prev
                    if (d <= STEP_MIN || d > STEP_MAX) break
                    run++
                    prev = v
                    p += 4
                }
                if (run >= MIN_MARKERS) {
                    out.add(o to run)
                    o = p
                    continue
                }
            }
            o += 4
        }
        return out
    }

                                                         
    private fun parseTokens(img: ByteArray, start: Int): Pair<Array<ByteArray>, Int>? {
        if (start <= 0 || start >= img.size) return null
        val tokens = Array(256) { ByteArray(0) }
        var p = start
        for (i in 0 until 256) {
            var q = p
            val limit = minOf(p + 512, img.size)
            while (q < limit && img[q] != 0.toByte()) q++
            if (q >= limit) return null
            val tok = img.copyOfRange(p, q)
            for (b in tok) {
                val c = b.toInt() and 0xFF
                if (c < 0x20 || c > 0x7E) return null
            }
            tokens[i] = tok
            p = q + 1
        }
        return tokens to p
    }

    private fun findTokenIndex(buf: ByteBuffer, tableEnd: Int): Int? {
        for (delta in 0..32) {
            val cand = tableEnd + delta
            if (cand + 512 > buf.capacity()) continue
            if (buf.getShort(cand) != 0.toShort()) continue
            var prev = -1
            var ok = true
            for (i in 0 until 256) {
                val v = buf.getShort(cand + 2 * i).toInt() and 0xFFFF
                if (v <= prev || v > 8192) { ok = false; break }
                prev = v
            }
            if (ok) return cand
        }
        return null
    }

       
                                               
                                            
       
    private fun findNamesStart(
        img: ByteArray,
        tokens: Array<ByteArray>,
        markersOff: Int,
        marker1: Int,
    ): Int? {
        var p = maxOf(0, markersOff - NAME_WINDOW)
        while (p < markersOff) {
            val hdr = readRecordHeader(img, p)
            val len = hdr.second
            val nameAt = hdr.first
            if (len in 1..64 && nameAt + len <= markersOff) {
                val name = decodeName(tokens, img.copyOfRange(nameAt, nameAt + len))
                if (name.length >= 2 && IDENT.matches(name.substring(1))) {
                    var q = p
                    var ok = true
                    for (i in 0 until 256) {
                        val h = readRecordHeader(img, q)
                        if (h.second !in 1..512 || h.first + h.second > img.size) { ok = false; break }
                        q = h.first + h.second
                    }
                    if (ok && q - p == marker1) return p
                }
            }
            p++
        }
        return null
    }

                                                    
    private fun walkNames(buf: ByteBuffer, start: Int, markersOff: Int, mCount: Int): Pair<Int, IntArray> {
        val positions = IntArray(mCount) { -1 }
        var q = start
        var count = 0
        while (q < markersOff && q + 2 < buf.capacity()) {
            val hdr = readRecordHeader(buf, q)
            val len = hdr.second
            if (len !in 1..512) {
                
                if (markersOff - q <= 8) break
                return -1 to positions
            }
            if (count % 256 == 0 && count / 256 < mCount) positions[count / 256] = q - start
            q = hdr.first + len
            count++
        }
        return count to positions
    }

                                                          
    private fun readRecordHeader(buf: ByteBuffer, q: Int): Pair<Int, Int> {
        var pos = q
        var len = buf.get(pos).toInt() and 0xFF
        pos++
        if (len and 0x80 != 0) {
            len = (len and 0x7F) or ((buf.get(pos).toInt() and 0xFF) shl 7)
            pos++
        }
        return pos to len
    }

    private fun readRecordHeader(img: ByteArray, q: Int): Pair<Int, Int> {
        var pos = q
        var len = img[pos].toInt() and 0xFF
        pos++
        if (len and 0x80 != 0) {
            len = (len and 0x7F) or ((img[pos].toInt() and 0xFF) shl 7)
            pos++
        }
        return pos to len
    }

    private fun decodeName(tokens: Array<ByteArray>, raw: ByteArray): String {
        val sb = StringBuilder(raw.size * 4)
        for (b in raw) {
            val t = tokens[b.toInt() and 0xFF]
            for (x in t) sb.append((x.toInt() and 0xFF).toChar())
        }
        return sb.toString()
    }

    private fun hex(v: Long) = "0x" + java.lang.Long.toHexString(v)
}
