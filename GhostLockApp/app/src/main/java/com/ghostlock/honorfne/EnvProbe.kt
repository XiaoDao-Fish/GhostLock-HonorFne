package com.ghostlock.honorfne

/**
 * 与具体提权链无关的只读环境探测。
 *
 * 链路 B 能不能跑，第一道门不是 profile，而是 shell 有没有权限写 tracefs。
 * Honor 6.1.157 的 /sys/kernel/tracing/events/kmem 是 0750 root:readtracefs，
 * shell（uid 2000）不在组里，profile 再准也没用。这个探测不需要内核白名单，
 * 任何机型都能先点一下看结论，避免为了一颗注定跑不了的内核去做 boot.img。
 */
object EnvProbe {

    data class TraceFs(val usable: Boolean, val summary: String, val detail: List<String>)

    /**
     * 只写 "0"（关闭状态），不改任何几何/偏移，也不留残余触发规则。
     * 返回的 detail 原样进日志，summary 是一句人话结论。
     */
    suspend fun tracefs(): TraceFs {
        val r = ShizukuController.exec(
            """
            if [ -d /sys/kernel/tracing/events/kmem ]; then echo "root=ok"; else echo "root=missing"; fi
            if [ -d /sys/kernel/debug/tracing/events/kmem ]; then echo "debug-root=ok"; else echo "debug-root=missing"; fi
            ls -ld /sys/kernel/tracing /sys/kernel/tracing/events/kmem /sys/kernel/tracing/events/kmem/mm_page_alloc/enable 2>&1
            printf 0 > /sys/kernel/tracing/tracing_on 2>/dev/null && echo "tracing_on=write-ok" || echo "tracing_on=deny"
            printf 0 > /sys/kernel/tracing/events/kmem/mm_page_alloc/enable 2>/dev/null && echo "enable=write-ok" || echo "enable=deny"
            printf 0 > /sys/kernel/tracing/events/sched/sched_switch/trigger 2>/dev/null && echo "trigger=write-ok" || echo "trigger=deny"
            if [ -r /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw ]; then echo "raw=read-ok"; else echo "raw=deny"; fi
            getenforce 2>/dev/null
            if id -Gn 2>/dev/null | grep -q readtracefs; then echo "kmem-group=member"; else echo "kmem-group=not-member"; fi
            echo "enable-mode=$(stat -c '%a %U %G' /sys/kernel/tracing/events/kmem/mm_page_alloc/enable 2>/dev/null || echo unreadable)"
            echo "kmem-events=$(ls /sys/kernel/tracing/events/kmem 2>/dev/null | grep -E '^(kmem_cache_alloc|kmem_cache_free|mm_page_)' | tr '\n' ',')"
            """.trimIndent(),
            15_000
        )
        val lines = r.out.lines().map { it.trim() }.filter { it.isNotEmpty() }
        fun flag(k: String) = lines.firstOrNull { it.startsWith("$k=") }?.substringAfter('=')
        val root = flag("root")
        val debug = flag("debug-root")
        val enable = flag("enable")
        val trigger = flag("trigger")
        val member = flag("kmem-group")
        val usable = enable == "write-ok" || trigger == "write-ok"

        // 目录权限是判断「DAC 还是 SELinux」的关键：0750 root:readtracefs 说明
        // shell 根本不在可读组里，不是 SELinux 策略问题，换 sepolicy 也救不了。
        val kmemLine = lines.lastOrNull {
            it.contains("/sys/kernel/tracing/events/kmem") && !it.contains("/enable")
        }
        val kmemParts = kmemLine?.split(Regex("\\s+"))
        val kmemPerm = if (kmemParts != null && kmemParts.size >= 4) {
            "${kmemParts[0]} ${kmemParts[2]} ${kmemParts[3]}"
        } else null
        val mode = flag("enable-mode")
        // 6.18 上 payload 只认到 2 个 kmem 事件候选（enable ok=6 fail=0 反推），
        // 说明它的事件名白名单与新内核不匹配。这里把内核实际暴露的名字列出来，
        // 不用等 payload 日志就能看清是「没有这个事件」还是「名字变了」。
        val kmemEvents = (flag("kmem-events") ?: "").split(',').filter { it.isNotBlank() }
        val kmemListed = lines.any { it.startsWith("kmem-events=") }
        val kmemNote = when {
            !kmemListed -> ""
            kmemEvents.isEmpty() -> "；events/kmem 目录不可读，读不到事件名"
            kmemEvents.size < 4 -> "；内核只暴露 ${kmemEvents.size} 个 kmem 事件：${kmemEvents.joinToString(", ")}"
            else -> ""
        }
        // 别再断言「是 SELinux」：shell 在 readtracefs 组里、目录可读，但 enable
        // 文件通常属于 root 且不带组写位，单看这两个事实分不出是文件属主（DAC）
        // 还是 SELinux。写清楚「两种都可能是、且都不是免 root 能改的」才准确。
        val groupNote = when (member) {
            "member" -> "shell 在 readtracefs 组内（目录可读），但 enable/trigger 写入被拒；" +
                "文件属主/DAC 与 SELinux 二者都可能，均需 root 才能改"
            "not-member" -> "shell 不在 readtracefs 组（DAC 权限）"
            else -> "shell 组信息读不到"
        }
        val summary = when {
            root != "ok" && debug == "ok" ->
                "payload 只认 /sys/kernel/tracing，本机该路径没有 tracefs"
            root != "ok" -> "本机没有 tracefs（/sys/kernel/tracing 不存在）"
            usable -> "tracefs 可写（enable=$enable，trigger=$trigger）$kmemNote"
            else -> "events/kmem 权限 ${kmemPerm ?: "未知"}" +
                (if (mode.isNullOrBlank()) "" else "，enable 文件 $mode") +
                "，enable=$enable，trigger=$trigger，$groupNote$kmemNote"
        }
        val detail = lines + listOfNotNull(
            if (!kmemListed) null
            else "kmem 事件 ${kmemEvents.size} 个（payload 只匹配 kmem_cache_alloc*/kmem_cache_free/mm_page_*）：" +
                kmemEvents.joinToString(", ").ifBlank { "（目录不可读）" }
        )
        return TraceFs(usable, summary, detail)
    }
}
