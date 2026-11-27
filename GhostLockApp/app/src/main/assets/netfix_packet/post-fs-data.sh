#!/system/bin/sh











MODDIR=${0%/*}
LOG=$MODDIR/netfix.log
ts() { date '+%m-%d %H:%M:%S'; }




for LSPD in /data/adb/modules/zygisk_lsposed/daemon /data/adb/modules_update/zygisk_lsposed/daemon; do
    if [ -f "$LSPD" ]; then
        
        
        if grep -q '^\[netfix_packet\] patched:' "$LSPD"; then
            sed -i 's|^\[netfix_packet\] patched:|# [netfix_packet] patched:|' "$LSPD" \
                && echo "$(ts) post-fs-data: fixed bare-text patch line in $LSPD" >> "$LOG"
        fi
        if grep -q '^mount tmpfs -t tmpfs /data/resource-cache' "$LSPD"; then
            sed -i 's|^mount tmpfs -t tmpfs /data/resource-cache|# [netfix_packet] patched: stacked tmpfs shadows all RRO idmaps|' "$LSPD" \
                && echo "$(ts) post-fs-data: patched $LSPD (tmpfs on /data/resource-cache)" >> "$LOG"
        fi
    fi
done

n=0
while grep -q " /data/resource-cache " /proc/1/mountinfo 2>/dev/null; do
    umount /data/resource-cache 2>/dev/null \
        || umount -l /data/resource-cache 2>/dev/null \
        || break
    n=$((n + 1))
done
[ "$n" -gt 0 ] && echo "$(ts) post-fs-data: unmounted $n stacked tmpfs on /data/resource-cache" >> "$LOG"
exit 0
