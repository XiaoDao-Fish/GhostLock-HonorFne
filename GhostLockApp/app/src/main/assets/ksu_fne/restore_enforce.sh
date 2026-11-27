#!/system/bin/sh



















read -r BEFORE < /sys/fs/selinux/enforce 2>/dev/null
echo "before: enforce=${BEFORE:-?}"


echo 1 > /sys/fs/selinux/enforce 2>&1


i=0
while [ "$i" -lt 30 ]; do i=$((i + 1)); done

read -r AFTER < /sys/fs/selinux/enforce 2>/dev/null
echo "after: enforce=${AFTER:-?}"

echo "RESTORE_ENFORCE_DONE"
