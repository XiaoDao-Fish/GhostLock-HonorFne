#!/system/bin/sh
# 通过常驻 root FIFO 通道执行的 KernelSU 晚加载脚本。
# 依据：HONOR50-KernelSU-Root-main/scripts/device/ksu_lateload.sh（NTH-AN00 实测成功）
#       + HONOR50-KernelSU晚加载提权实现记录 S3。
# 运行上下文：uid=0，u:r:kernel:s0，SELinux Permissive。
#
# 完整晚加载三步，缺一不可：
#   1) ksud insmod                     把 kernelsu.ko 加载进内核
#   2) ksud install                   把用户态组件装到 /data/adb/ksud、/data/adb/ksu/bin
#   3) post-fs-data/services/boot-completed  三个启动阶段
#   4) 拉起管理器 App                 让它重新拿 KSU 驱动 fd
# 只做第 1 步会出现「模块 Live 但 su 不可用」的假成功状态。
#
# 为什么不用 load_ko + fake kallsyms：
#   静态符号表 fne_syms.txt 与运行内核大面积不一致（实测 57154 个差 0x30、
#   41699 个差 0x180），且厂商把 commit_creds / prepare_kernel_cred 从
#   kallsyms 过滤掉，手工补地址会让模块 init 跳飞并 panic。
#   官方 ksud 3.3.0 的 insmod 子命令自带运行时符号解析与重定位。
#
# /system/bin/su 是 sucompat 注册的虚拟路径（内核把 execve 重定向到
# KSUD_PATH=/data/adb/ksud）。在 u:r:kernel:s0 通道里 test -x / ls 可能看不到，
# 所以这里绝不用它当就绪判据；真正的 uid=0 验证由 App 在 shell 域完成。
#
# 不要手工 cp ksud 到 /data/adb/ksud：由 kernel 域直接创建的文件会带上错误
# SELinux 上下文，shell 域执行时得到 "Permission denied"（2026-11-12 实测）。
# 交给官方 ksud install 原子部署。
D=/data/local/tmp/ksu_fne
export PATH=$D:/system/bin:/system/xbin:/vendor/bin:$PATH
# 管理器包名由 App 部署物料时写进 .manager_pkg（跟随工作台选择，
# 见 ManagerSelection / AssetDeployer）。读不到就回退官方：
# 第三方分支的入口类名各不相同，这里绝不能写死官方 Activity。
MGR=$(cat $D/.manager_pkg 2>/dev/null | tr -d '\r\n')
[ -n "$MGR" ] || MGR=me.weishu.kernelsu
echo "manager=$MGR"

echo "=== KSU late-load start $(date) ==="
echo "uid=$(id -u) enforce=$(getenforce) ctx=$(cat /proc/self/attr/current 2>/dev/null)"

# 1) 让 insmod 期间的任何 oops 变成可观察日志，而不是直接重启
po=$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null); echo "panic_on_oops=$po -> 0"
echo 0 > /proc/sys/kernel/panic_on_oops 2>/dev/null
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null

# 2) 快照原始 SELinux 策略（供模块的 selinux_hide 备份使用）
[ -s $D/pristine_policy ] || cat /sys/fs/selinux/policy > $D/pristine_policy
echo "pristine_policy: $(wc -c < $D/pristine_policy 2>/dev/null) bytes"

# 3) late-load 不会自己应用规则，必须预先注入 ksu 域规则
$D/magiskpolicy --apply $D/ksu_rules --live >/dev/null 2>&1
echo "magiskpolicy rc=$?"

# 4) 加载内核模块（幂等：已 Live 则跳过 insmod，但用户态收尾必须继续）
if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
  echo "--- ksud insmod: module already loaded, skip ---"
else
  echo "--- ksud insmod ---"
  $D/ksud insmod $D/kernelsu.ko "allow_shell=1 pristine_policy=$D/pristine_policy" 2>&1
  echo "ksud insmod rc=$?"
  sleep 2
fi
grep '^kernelsu ' /proc/modules 2>&1

# 5) 官方用户态部署：由 ksud 自己生成 /data/adb/ksud 并设好权限与上下文
echo "--- ksud install ---"
$D/ksud install 2>&1
echo "ksud install rc=$?"

# 6) 三个启动阶段（PC 实测脚本要求，之前缺这三步）
echo "--- ksud stages ---"
$D/ksud post-fs-data 2>&1; echo "post-fs-data rc=$?"
$D/ksud services 2>&1; echo "services rc=$?"
$D/ksud boot-completed 2>&1; echo "boot-completed rc=$?"

# 7) 重启管理器：官方 late_load.rs 的收尾动作，让它重新拿 KSU 驱动 fd。
#    非阻塞，且必须在 restore_enforce 之前做（flip 会杀掉 kernel:s0 通道 shell）。
#    用 LAUNCHER intent 而不是 -n 固定类名：官方是 .ui.MainActivity，
#    7kimisu / SukiSU / BakaSU 的入口类各不相同。
echo "--- restart manager (non-blocking) ---"
am force-stop $MGR >/dev/null 2>&1
am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p $MGR >/dev/null 2>&1 &
sleep 1

# 8) 就绪判据：内核模块已 Live + ksud 用户态已安装。
#    /system/bin/su 只做信息输出，不作为判据（kernel 域看不见虚拟路径）。
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
