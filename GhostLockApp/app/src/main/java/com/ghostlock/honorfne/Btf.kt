package com.ghostlock.honorfne



   
                        
  
                                                         
                                                  
                                          
   
class Btf private constructor(private val raw: ByteArray) {

    data class Member(val name: String, val typeId: Int, val byteOffset: Int)

    data class Type(
        val id: Int,
        val name: String,
        val kind: Int,
        val size: Int,
        val members: List<Member>,
    )

    val types = ArrayList<Type>()

    companion object {
        private const val MAGIC = 0xEB9F

        fun parse(raw: ByteArray): Btf {
            val btf = Btf(raw)
            btf.read()
            return btf
        }

        private fun u16(b: ByteArray, o: Int): Int =
            (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

        private fun u32(b: ByteArray, o: Int): Int =
            (b[o].toInt() and 0xFF) or
                ((b[o + 1].toInt() and 0xFF) shl 8) or
                ((b[o + 2].toInt() and 0xFF) shl 16) or
                ((b[o + 3].toInt() and 0xFF) shl 24)
    }

    private fun read() {
        require(raw.size > 24) { "BTF 太小" }
        require(u16(raw, 0) == MAGIC) { "不是 BTF（magic=${u16(raw, 0)}）" }
        val hdrLen = u32(raw, 4)
        val typeOff = u32(raw, 8)
        val typeLen = u32(raw, 12)
        val strOff = u32(raw, 16)
        val strLen = u32(raw, 20)

        val typesStart = hdrLen + typeOff
        val typesEnd = typesStart + typeLen
        val strStart = hdrLen + strOff
        val strEnd = minOf(strStart + strLen, raw.size)
        require(typesEnd <= raw.size) { "BTF 类型区越界" }

        fun name(off: Int): String {
            if (off == 0) return ""
            var i = strStart + off
            if (i < 0 || i >= strEnd) return ""
            val sb = StringBuilder()
            while (i < strEnd && raw[i] != 0.toByte()) {
                sb.append((raw[i].toInt() and 0xFF).toChar())
                i++
            }
            return sb.toString()
        }

        var off = typesStart
        var id = 1
        val result = ArrayList<Type>()
        while (off + 12 <= typesEnd) {
            val nameOff = u32(raw, off)
            val info = u32(raw, off + 4)
            val sizeOrType = u32(raw, off + 8)
            off += 12
            val kind = (info ushr 24) and 0x1F
            val vlen = info and 0xFFFF
            val kflag = (info ushr 31) and 1

            val members = ArrayList<Member>()
            when (kind) {
                4, 5 -> {                       
                    for (m in 0 until vlen) {
                        if (off + 12 > typesEnd) break
                        val mo = u32(raw, off)
                        val mt = u32(raw, off + 4)
                        val mof = u32(raw, off + 8)
                        off += 12
                        val bitOff = if (kflag == 1) mof and 0xFFFFFF else mof
                        members.add(Member(name(mo), mt, bitOff / 8))
                    }
                }
                6, 13 -> off += vlen * 8   
                15, 19 -> off += vlen * 12 
                1 -> off += 4              
                3 -> off += 12             
                14 -> off += 4             
                17 -> off += 4             
                else -> Unit               
            }
            result.add(Type(id, name(nameOff), kind, sizeOrType, members))
            id++
        }
        types.addAll(result)
    }

                                                     
    private fun typeById(id: Int): Type? = types.getOrNull(id - 1)

    fun struct(name: String): Type? =
        types.firstOrNull { (it.kind == 4 || it.kind == 5) && it.name == name }

       
                                   
                                                        
       
    fun memberOffset(structName: String, member: String): Int? {
        val root = struct(structName) ?: return null
        var frontier = listOf(root.id to 0)
        val seen = HashSet<Int>()
        repeat(6) {
            val next = ArrayList<Pair<Int, Int>>()
            for ((tid, base) in frontier) {
                if (!seen.add(tid)) continue
                val t = typeById(tid) ?: continue
                if (t.kind != 4 && t.kind != 5) continue
                for (m in t.members) {
                    val off = base + m.byteOffset
                    if (m.name == member) return off
                    next.add(m.typeId to off)
                }
            }
            frontier = next
            if (frontier.isEmpty()) return null
        }
        return null
    }

    fun sizeOf(structName: String): Int? = struct(structName)?.size
}
