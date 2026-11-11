#!/system/bin/sh
# 最后一步：把 SELinux 从 Permissive 切回 Enforcing。
# 依据：HONOR50-KernelSU晚加载提权实现记录 S4 / 10.5。
#
# 本脚本由 u:r:kernel:s0 的 root 通道 shell 执行；切换 enforcing 会杀掉
# kernel:s0 进程（包括执行它的这个 shell 自己），所以必须是整个流程的
# 最后一条命令 —— 上面所有工作都已落盘、KSU 模块已经 Live。
#
# 切换后 root 依然可用：/system/bin/su 走 KernelSU 的 u:r:ksu:s0 域，
# 不再依赖 kernel 上下文，也不再依赖 Permissive。
echo "before: enforce=$(getenforce)"
echo 1 > /sys/fs/selinux/enforce 2>&1
sleep 1
echo "after: enforce=$(getenforce)"
echo "RESTORE_ENFORCE_DONE"
