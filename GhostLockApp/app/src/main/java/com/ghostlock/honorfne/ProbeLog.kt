package com.ghostlock.honorfne

   
                               
  
                                                   
                                                 
                                                       
                                           
   
object ProbeLog {

                                                    
    private const val MAX_PLAUSIBLE_SLIDE = 0x1_0000_0000L   

                                          
    fun slide(text: String): Long? {
        if (text.isBlank()) return null
        val m = Regex("memstart probe: slide=0x([0-9a-fA-F]+)").findAll(text).lastOrNull() ?: return null
        return m.groupValues[1].toLongOrNull(16)
    }

                                               
    fun impossibleSlide(text: String): Long? =
        slide(text)?.takeIf { it >= MAX_PLAUSIBLE_SLIDE }

    fun hex(v: Long): String = "0x" + java.lang.Long.toHexString(v)
}
