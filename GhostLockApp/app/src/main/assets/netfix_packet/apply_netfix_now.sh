#!/bin/bash










set -e
KSU=/data/adb/ksu/bin/ksud

echo "=== Attempt 1: ksud sepolicy patch ==="
$KSU sepolicy patch "allow domain unlabeled:packet send" || true
$KSU sepolicy patch "allow domain unlabeled:packet recv" || true

echo "=== Attempt 2: check load mtime (should change if patch worked) ==="
stat -c '%y %s' /sys/fs/selinux/load || ls -la /sys/fs/selinux/load

echo "=== Attempt 3: verify netdev SIDs (need netif, not unlabeled) ==="

ping -c 1 -W 2 192.168.1.1 && echo PING_OK || echo PING_FAIL_still_broken

echo "=== Done. If PING_FAIL: reboot, re-run grind (run_forever.sh), ==="
echo "=== KSU will load modules including netfix_packet sepolicy.rule. ==="
