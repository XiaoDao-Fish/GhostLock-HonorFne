#!/system/bin/sh
# 最后一步：把 SELinux 从 Permissive 切回 Enforcing。
# 依据：HONOR50-KernelSU晚加载提权实现记录 S4 / 10.5。
#
# 本脚本由 u:r:kernel:s0 的 root 通道 shell 执行；切换 enforcing 会杀掉
# kernel:s0 进程（包括执行它的这个 shell 自己），所以必须是整个流程的
# 最后一条命令 —— 上面所有工作都已落盘、KSU 模块已经 Live。
#
# 切换后 root 依然可用：/system/bin/su 是 sucompat 虚拟入口，内核把它
# 重定向到 /data/adb/ksud 并套用 u:r:ksu:s0 root profile，
# 不再依赖 kernel 上下文，也不再依赖 Permissive。
#
# ⚠️ 本脚本运行在 exploit 注入的 root 通道里：PATH 可能为空，且 SELinux
# 还可能挡掉 toybox 外部小程序（旧版 getenforce / sleep 会报
# 「inaccessible or not found」）。故一律用 shell 内建完成，避免依赖外部
# 二进制：
#   - 读 enforcing 状态：read < /sys/fs/selinux/enforce（0=Permissive / 1=Enforcing）
#   - 写 enforcing：echo 1 > /sys/fs/selinux/enforce（内建 echo + 重定向）
#   - 短暂延时：纯内建 busy-loop，不依赖外部 sleep

read -r BEFORE < /sys/fs/selinux/enforce 2>/dev/null
echo "before: enforce=${BEFORE:-?}"

# 切回 Enforcing（会杀掉 kernel:s0 自身，故必须放最后）
echo 1 > /sys/fs/selinux/enforce 2>&1

# 纯内建短暂等待 SELinux 状态生效（避免外部 sleep 缺失报「inaccessible」）
i=0
while [ "$i" -lt 30 ]; do i=$((i + 1)); done

read -r AFTER < /sys/fs/selinux/enforce 2>/dev/null
echo "after: enforce=${AFTER:-?}"

echo "RESTORE_ENFORCE_DONE"
