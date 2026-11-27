#!/system/bin/sh

























D=/data/local/tmp/ksu_fne
export PATH=$D:/system/bin:/system/xbin:/vendor/bin:$PATH



MGR=$(cat $D/.manager_pkg 2>/dev/null | tr -d '\r\n')
[ -n "$MGR" ] || MGR=me.weishu.kernelsu
echo "manager=$MGR"

echo "=== KSU late-load start $(date) ==="
echo "uid=$(id -u) enforce=$(getenforce) ctx=$(cat /proc/self/attr/current 2>/dev/null)"


po=$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null); echo "panic_on_oops=$po -> 0"
echo 0 > /proc/sys/kernel/panic_on_oops 2>/dev/null
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null


[ -s $D/pristine_policy ] || cat /sys/fs/selinux/policy > $D/pristine_policy
echo "pristine_policy: $(wc -c < $D/pristine_policy 2>/dev/null) bytes"


$D/magiskpolicy --apply $D/ksu_rules --live >/dev/null 2>&1
echo "magiskpolicy rc=$?"


if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
  echo "--- ksud insmod: module already loaded, skip ---"
else
  echo "--- ksud insmod ---"
  $D/ksud insmod $D/kernelsu.ko "allow_shell=1 pristine_policy=$D/pristine_policy" 2>&1
  echo "ksud insmod rc=$?"
  sleep 2
fi
grep '^kernelsu ' /proc/modules 2>&1


echo "--- ksud install ---"
$D/ksud install 2>&1
echo "ksud install rc=$?"


echo "--- ksud stages ---"
$D/ksud post-fs-data 2>&1; echo "post-fs-data rc=$?"
$D/ksud services 2>&1; echo "services rc=$?"
$D/ksud boot-completed 2>&1; echo "boot-completed rc=$?"





echo "--- restart manager (non-blocking) ---"
am force-stop $MGR >/dev/null 2>&1
am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p $MGR >/dev/null 2>&1 &
sleep 1



echo "--- readiness ---"
MODULE_OK=0
grep -q '^kernelsu ' /proc/modules 2>/dev/null && MODULE_OK=1
USERSPACE_OK=0
if [ -e /data/adb/ksud ] || [ -e /data/adb/ksu/bin/ksud ]; then
  USERSPACE_OK=1
fi
echo "module_loaded=$MODULE_OK userspace_installed=$USERSPACE_OK"
ls -l /data/adb/ksud /data/adb/ksu/bin/ksud 2>&1
echo "--- su entry (informational, may be invisible in kernel ctx) ---"
ls -l /system/bin/su 2>&1
if [ "$MODULE_OK" = "1" ] && [ "$USERSPACE_OK" = "1" ]; then
  echo "KSU_READY"
else
  echo "KSU_NOT_READY"
fi
echo "KSUTRY_DONE"
