package com.ghostlock.honorfne



   
                               
  
                                                                    
                                        
  
            
  
                                                                          
                                                                         
                                                                         
  
                                                                 
                                                                        
  
                                                        
   
object CallSiteFinder {

    data class Result(
                                                                               
        val timerOffset: Int,
        val timerLow21: Int,
        val credLow21: Int,
        val taskLow21: Int,
                                          
        val timerAbs: Long = 0,
        val credAbs: Long = 0,
        val taskAbs: Long = 0,
                                 
        val detail: List<String>,
    )

    
    private const val BL_MASK = -0x04000000
    private const val BL_OP = -0x6C000000
    private const val SPAN = 0x1200      
    private const val THUNK_WINDOW = 0x80L   

       
                                                        
                                               
                                                
       
    fun find(image: ByteArray, syms: Map<String, Long>, textVa: Long): Result? {
        
        
        
        
        val wantedAt = ArrayList<Long>()
        val wantedName = ArrayList<String>()
        for ((rawName, a) in syms) {
            
            
            if (rawName.contains(".cold")) continue
            val n = canonicalName(rawName) ?: continue
            if (n == "kmem_cache_alloc" || n == "kmem_cache_alloc_node" || n == "__kasan_slab_alloc") {
                wantedAt.add(a)
                wantedName.add(n)
            }
        }
        if (wantedAt.isEmpty()) return null
        val order = wantedAt.indices.sortedBy { wantedAt[it] }
        val allocAddrs = LongArray(order.size) { wantedAt[order[it]] }
        val allocNames = Array(order.size) { wantedName[order[it]] }

        
        
        
        
        val sortedSyms = syms.values.asSequence()
            .filter { it >= textVa }
            .distinct().sorted().toList().toLongArray()

        val timer = syms["do_timer_create"] ?: return null
        val cred = syms["prepare_creds"] ?: return null
        val task = syms["copy_process"] ?: return null

        val detail = ArrayList<String>(3)

        
        val timerHit = firstBl(image, timer, funcEnd(timer, sortedSyms), textVa, allocAddrs, allocNames, "kmem_cache_alloc")
        timerHit?.let { detail.add("do_timer_create +0x${(it.first - timer).toString(16)} → ${it.second}") }
            ?: detail.add("do_timer_create ✗ 没找到 kmem_cache_alloc 调用")

        
        
        
        val credEnd = funcEnd(cred, sortedSyms)
        val credHit = firstBl(image, cred, credEnd, textVa, allocAddrs, allocNames, "kmem_cache_alloc")
            ?: firstBl(image, cred, credEnd, textVa, allocAddrs, allocNames, "__kasan_slab_alloc")
        credHit?.let { detail.add("prepare_creds   +0x${(it.first - cred).toString(16)} → ${it.second}") }
            ?: detail.add("prepare_creds   ✗ 没找到 kmem_cache_alloc / __kasan_slab_alloc 调用")

        val hasNode = allocNames.any { it.startsWith("kmem_cache_alloc_node") }
        val taskCallee = if (hasNode) "kmem_cache_alloc_node" else "kmem_cache_alloc"
        val taskHit = firstBl(image, task, funcEnd(task, sortedSyms), textVa, allocAddrs, allocNames, taskCallee)
        taskHit?.let { detail.add("copy_process    +0x${(it.first - task).toString(16)} → ${it.second}") }
            ?: detail.add("copy_process    ✗ 没找到 $taskCallee 调用")

        return Result(
            timerOffset = timerHit?.let { (it.first - timer).toInt() } ?: 0,
            timerLow21 = timerHit?.let { (it.first and 0x1FFFFF).toInt() } ?: 0,
            timerAbs = timerHit?.first ?: 0,
            credLow21 = credHit?.let { (it.first and 0x1FFFFF).toInt() } ?: 0,
            credAbs = credHit?.first ?: 0,
            taskLow21 = taskHit?.let { (it.first and 0x1FFFFF).toInt() } ?: 0,
            taskAbs = taskHit?.first ?: 0,
            detail = detail,
        )
    }

       
                                       
      
                                                               
                                                          
                                                              
       
       
                               
      
                                                              
                                                   
                                                    
                             
       
    private fun funcEnd(fnVa: Long, sorted: LongArray): Long {
        var lo = 0
        var hi = sorted.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (sorted[mid] <= fnVa) lo = mid + 1 else hi = mid
        }
        return if (lo < sorted.size) sorted[lo] else fnVa + SPAN
    }

    private fun firstBl(
        image: ByteArray,
        fnVa: Long,
        fnEndVa: Long,
        textVa: Long,
        allocAddrs: LongArray,
        allocNames: Array<String>,
        callee: String,
    ): Pair<Long, String>? {
        val start = fnVa - textVa
        if (start < 0 || start >= image.size) return null
        var off = start
        
        
        val byFunc = if (fnEndVa > fnVa + 0x40) fnEndVa - textVa else start + SPAN
        val end = minOf(start + SPAN, byFunc, (image.size - 4).toLong())
        while (off <= end) {
            val insn = readU32(image, off.toInt())
            if ((insn and BL_MASK) == BL_OP) {
                var imm = insn and 0x03FFFFFF
                if ((imm and 0x02000000) != 0) imm -= 0x04000000     
                val pcVa = fnVa + (off - start)
                val target = pcVa + (imm.toLong() shl 2)
                val name = resolveCallee(target, allocAddrs, allocNames, callee)
                if (name != null) return (pcVa + 4) to name
            }
            off += 4
        }
        return null
    }

                                          
    private fun resolveCallee(
        target: Long,
        allocAddrs: LongArray,
        allocNames: Array<String>,
        callee: String,
    ): String? {
        var lo = 0
        var hi = allocAddrs.size - 1
        var pos = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (allocAddrs[mid] <= target + THUNK_WINDOW) { pos = mid; lo = mid + 1 } else hi = mid - 1
        }
        if (pos < 0) return null
        val addr = allocAddrs[pos]
        if (target > addr + THUNK_WINDOW) return null
        val name = allocNames[pos]
        
        
        if (kotlin.math.abs(target - addr) > THUNK_WINDOW) return null
        val okName = if (callee == "kmem_cache_alloc") {
            name == "kmem_cache_alloc"
        } else {
            name == callee
        }
        return if (okName) name else null
    }

       
              
      
                                                                        
                                                                         
                                                                          
                                          
                                       
       
    private fun canonicalName(raw: String): String? {
        var n = raw
        n = n.substringBefore(".cfi_jt")
        for (suffix in listOf(".cold", ".isra", ".part", ".constprop", ".lto_priv")) {
            n = n.substringBefore(suffix)
        }
        if (n.endsWith("_noprof")) n = n.removeSuffix("_noprof")
        return n.takeIf { it.isNotEmpty() }
    }

    private fun readU32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or
            ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or
            ((b[o + 3].toInt() and 0xFF) shl 24)
}
