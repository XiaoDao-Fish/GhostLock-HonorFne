#!/system/bin/sh
# 通过常驻 root FIFO 通道执行的 KernelSU 晚加载脚本。
# 依据：HONOR50-KernelSU晚加载提权实现记录 S3 / 10.4（NTH-AN00 实测成功）。
# 运行上下文：uid=0，u:r:kernel:s0，SELinux Permissive。
#
# 为什么不用 load_ko + fake kallsyms：
#   静态符号表 fne_syms.txt 与运行内核大面积不一致（实测 57154 个差 0x30、
#   41699 个差 0x180），且厂商把 commit_creds / prepare_kernel_cred 从
#   kallsyms 过滤掉，手工补地址会让模块 init 跳飞并 panic。
#   官方 ksud 3.3.0 的 insmod 子命令自带运行时符号解析与重定位，
#   不需要任何手工地址表。
D=/data/local/tmp/ksu_fne
export PATH=/system/bin:$D:$PATH

echo "=== KSU late-load start $(date) ==="
echo "uid=$(id -u) enforce=$(getenforce) ctx=$(cat /proc/self/attr/current 2>/dev/null)"

# 幂等：chain_hook 若已自行加载成功，绝不能第二次 insmod
if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
  echo "kernelsu already loaded - skip insmod"
  echo "KSUTRY_DONE"
  exit 0
fi

# 1) insmod 期间的 oops 变成可观察日志，而不是直接重启
po=$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null); echo "panic_on_oops=$po -> 0"
echo 0 > /proc/sys/kernel/panic_on_oops
echo 0 > /proc/sys/kernel/kptr_restrict

# 2) 快照原始 SELinux 策略，供模块的 selinux_hide 备份使用
[ -s $D/pristine_policy ] || cat /sys/fs/selinux/policy > $D/pristine_policy
echo "pristine_policy: $(wc -c < $D/pristine_policy 2>/dev/null) bytes"

# 3) late-load 不会自己应用规则，必须预先注入 ksu 域规则
$D/magiskpolicy --apply $D/ksu_rules --live >/dev/null 2>&1
echo "magiskpolicy rc=$?"

# 4) 官方 ksud insmod
echo "--- ksud insmod ---"
$D/ksud insmod $D/kernelsu.ko "allow_shell=1 pristine_policy=$D/pristine_policy" 2>&1
echo "ksud insmod rc=$?"
sleep 3

# 5) 收尾检查
echo "--- /proc/modules ---"
grep kernelsu /proc/modules 2>&1
echo "--- su 入口 ---"
ls -l /system/bin/su 2>&1
echo "--- su 自检 ---"
/system/bin/su -c id 2>&1
echo "KSUTRY_DONE"
