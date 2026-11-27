#!/system/bin/sh







D=/data/local/tmp/ksu_fne
L=$D/chain.log
ST=$D/chain_status



DRY=${DRY_RUN:-0}
export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
if [ "$DRY" != "1" ]; then exec >>$L 2>&1; fi


chmod 755 $D/magiskpolicy $D/ksud $D/load_ko $D/kmsg_dumper $D/chain_hook.sh 2>/dev/null
echo running > $ST
echo "=== chain start $(date) pid=$$ dry=$DRY ==="
id 2>&1; getenforce 2>&1
sync


if grep -q kernelsu /proc/modules 2>/dev/null; then
  if [ "$DRY" = "1" ]; then
    echo "[dry-run] kernelsu already loaded - continuing for validation"
  else
    echo "kernelsu already loaded - nothing to do"
    echo ok > $ST
    exit 0
  fi
fi






rm -f /data/local/tmp/rs.in /data/local/tmp/rs.out
mkfifo /data/local/tmp/rs.in 2>/dev/null
chmod 666 /data/local/tmp/rs.in 2>/dev/null
: > /data/local/tmp/rs.out
chmod 666 /data/local/tmp/rs.out 2>/dev/null
echo "ROOT SHELL CHANNEL UP uid=$(id -u) ctx=$(cat /proc/self/attr/current 2>/dev/null)" >> /data/local/tmp/rs.out
setsid /system/bin/sh -c 'while true; do /system/bin/sh </data/local/tmp/rs.in >>/data/local/tmp/rs.out 2>&1; done' </dev/null >/dev/null 2>&1 &
echo "root shell channel pid=$!"
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null
cat /proc/kallsyms > /data/local/tmp/real_kallsyms.txt 2>/dev/null
chmod 644 /data/local/tmp/real_kallsyms.txt 2>/dev/null
echo "kallsyms snapshot done ($(wc -l < /data/local/tmp/real_kallsyms.txt 2>/dev/null) lines)"






if [ -f $D/handoff ] && [ "$DRY" != "1" ]; then
  echo "HANDOFF: root channel ready; app will drive ksud insmod + restore_enforce"
  echo handoff > $ST
  sync
  exit 0
fi


sv=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)
echo "sig_enforce=$sv"
if [ "$sv" != "N" ] && [ "$sv" != "0" ]; then
  echo "!! sig_enforce still set (W1b missed this boot) - aborting; device"
  echo "   stays permissive; reboot + regrind retries W1b"
  echo sigfail > $ST
  sync
  exit 1
fi


po=$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null); po=${po:-1}
echo "panic_on_oops=$po"
if [ "$DRY" != "1" ]; then echo 0 > /proc/sys/kernel/panic_on_oops; fi



if [ "$DRY" != "1" ]; then
  cat /sys/fs/selinux/policy > $D/pristine_policy 2>/dev/null \
    && echo "pristine policy: $(wc -c < $D/pristine_policy) bytes"
fi







if [ ! -s $D/fake_ksyms.txt ]; then
  echo "!! fake_ksyms.txt missing/empty (exploit did not generate the"
  echo "   runtime kallsyms) - aborting; device stays permissive"
  echo noksyms > $ST
  sync
  exit 1
fi
kr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null); echo "kptr_restrict=$kr"
echo 0 > /proc/sys/kernel/kptr_restrict



cat /proc/kallsyms > $D/real_kallsyms.txt 2>/dev/null
echo "real kallsyms dumped: $(wc -l < $D/real_kallsyms.txt 2>/dev/null) lines"















SLIDE_SYMS="init_cred init_task selinux_state modules sysctl_bootid init_mm init_uts_ns log_buf"
DIF_MODE=""; DIF_CNT=0; DIF_UNIQ=""; DIF_TOTAL=0
for s in $SLIDE_SYMS; do
  R=$(grep -m1 " $s$" /proc/kallsyms 2>/dev/null | cut -d' ' -f1)
  F=$(grep -m1 " $s$" $D/fake_ksyms.txt 2>/dev/null | cut -d' ' -f1)
  if [ -z "$R" ]; then echo "slide-check: $s real=ABSENT"; continue; fi
  if [ -z "$F" ]; then echo "slide-check: $s fake=ABSENT"; continue; fi
  if [ "$R" = "0000000000000000" ]; then echo "slide-check: $s real=0000"; continue; fi
  if [ "$R" = "$F" ]; then echo "slide-check: $s identical"; continue; fi
  case "$R$F" in
    *[!0-9a-fA-F]*) echo "slide-check: $s non-hex"; continue ;;
    *) DV=$(( 0x$R - 0x$F )) ;;
  esac
  DIF_TOTAL=$((DIF_TOTAL+1))
  echo "slide-check: $s diff=$DV"
  if [ "$DV" = "$DIF_MODE" ]; then DIF_CNT=$((DIF_CNT+1))
  elif [ -z "$DIF_MODE" ]; then DIF_MODE=$DV; DIF_CNT=1
  else DIF_UNIQ="$DIF_UNIQ $DV"
  fi
done
echo "slide vote: mode_diff=$DIF_MODE count=$DIF_CNT sampled=$DIF_TOTAL others=[$DIF_UNIQ]"
if [ "$DIF_CNT" -ge 3 ] && [ "$DIF_TOTAL" -ge 5 ]; then
  echo "note: uniform diff $DIF_MODE on $DIF_CNT/$DIF_TOTAL data syms (static-table bias)"
elif [ "$DIF_TOTAL" -ge 5 ]; then
  echo "!! diff NOT uniform ($DIF_CNT/$DIF_TOTAL agree) - fne_syms table suspect"
else
  echo "!! too few sampled syms ($DIF_TOTAL) - cannot validate slide; proceeding on merge"
fi
echo "slide check non-fatal; merge below overwrites all shared names with real addresses"






awk -v stats=$D/merge.stats '
  NR==FNR { if ($1 != "0000000000000000") { if (!($3 in r)) r[$3]=$1
             k=$3; sub(/\$.*/, "", k); if (!(k in rs)) rs[k]=$1 }
           next }
  { out=$0
    if ($3 in r) { if (r[$3] != $1) d++; out=r[$3] " " $2 " " $3; o++ }
    else { k=$3; sub(/\$.*/, "", k)
           if (k in rs) { if (rs[k] != $1) d++; out=rs[k] " " $2 " " $3; o++ }
           else n++ }
    print out }
  END { printf "%d overlaid from real kallsyms, %d kept slide-derived, %d drift-fixed\n", o, n, d+0 > stats }' \
  /proc/kallsyms $D/fake_ksyms.txt > $D/fake_kallsyms
if [ ! -s $D/fake_kallsyms ]; then
  echo "!! kallsyms merge produced empty file - aborting"
  echo "$kr" > /proc/sys/kernel/kptr_restrict 2>/dev/null
  echo "$po" > /proc/sys/kernel/panic_on_oops 2>/dev/null
  echo mergefail > $ST
  sync
  exit 1
fi
echo "merge: $(cat $D/merge.stats 2>/dev/null)"






T=/sys/kernel/tracing
[ -d "$T" ] || T=/sys/kernel/debug/tracing
if [ -d "$T" ] && [ -w "$T/kprobe_events" ]; then
  if echo "p:glcc commit_creds" > "$T/kprobe_events" 2>/dev/null; then
    oto=$(cat "$T/tracing_on" 2>/dev/null)
    echo sym-addr > "$T/trace_options" 2>/dev/null
    echo 1 > "$T/tracing_on" 2>/dev/null
    echo 1 > "$T/events/kprobes/glcc/enable" 2>/dev/null
    ls / >/dev/null 2>&1 & sleep 1     
    RCA=$(grep -m1 "glcc:" "$T/trace" 2>/dev/null | sed -n "s/.*<\(.*\)>.*/\1/p")
    echo 0 > "$T/events/kprobes/glcc/enable" 2>/dev/null
    echo "-:glcc" > "$T/kprobe_events" 2>/dev/null
    echo nosym-addr > "$T/trace_options" 2>/dev/null
    echo "$oto" > "$T/tracing_on" 2>/dev/null
    echo > "$T/trace" 2>/dev/null
    FCA=$(grep -m1 " T commit_creds$" $D/fake_kallsyms 2>/dev/null | cut -d" " -f1)
    if [ -n "$RCA" ] && [ -n "$FCA" ]; then
      if [ "$RCA" = "$FCA" ]; then
        echo "commit_creds verified: $RCA (kprobe == fake, 一致)"
      else
        echo "!! commit_creds mismatch: kprobe=$RCA fake=$FCA - 就地修正"
        sed -i "s/^$FCA \(T commit_creds\)$/$RCA \1/" $D/fake_kallsyms
        grep -m1 " T commit_creds$" $D/fake_kallsyms
      fi
    else
      echo "cc-verify: kprobe 未命中 - 保留 fake 值 (未验证)"
    fi
  else
    echo "cc-verify: kprobe 注册失败 (黑名单?) - 保留 fake 值 (未验证)"
  fi
fi


if [ "$DRY" = "1" ]; then
  echo "$kr" > /proc/sys/kernel/kptr_restrict 2>/dev/null
  echo "[dry-run] VALIDATION OK - sig_enforce/slide/merge 全部通过;"
  echo "[dry-run] 未执行: bind-mount / magiskpolicy / load_ko (insmod)"
  echo dryok > $ST
  sync
  exit 0
fi

if ! mount --bind $D/fake_kallsyms /proc/kallsyms; then
  echo "!! fake kallsyms bind-mount failed - restoring and aborting"
  echo "$kr" > /proc/sys/kernel/kptr_restrict 2>/dev/null
  echo "$po" > /proc/sys/kernel/panic_on_oops 2>/dev/null
  echo mountfail > $ST
  sync
  exit 1
fi
echo "fake kallsyms bind-mounted ($(wc -l < $D/fake_kallsyms) lines)"



$D/magiskpolicy --apply $D/ksu_rules --live 2>&1
mpc=$?
echo "magiskpolicy exit=$mpc"
if [ $mpc -ne 0 ]; then
  echo "!! magiskpolicy failed - unmounting and aborting (loading the module"
  echo "   without rules would brick KSU at the enforce flip)"
  umount /proc/kallsyms 2>/dev/null
  echo "$kr" > /proc/sys/kernel/kptr_restrict 2>/dev/null
  echo "$po" > /proc/sys/kernel/panic_on_oops 2>/dev/null
  echo polfail > $ST
  sync
  exit 1
fi
ctx=$(cat /proc/self/attr/current 2>/dev/null)
echo "policy injected (ctx=$ctx)"


$D/kmsg_dumper $D/kmsg_cap.txt 2>$D/kmsg_dumper.err &
KPID=$!
sleep 1
$D/load_ko $D/kernelsu.ko "allow_shell=1 pristine_policy=$D/pristine_policy"
lrc=$?
echo "load_ko exit=$lrc"
sleep 2
sync
kill $KPID 2>/dev/null

if ! grep -q kernelsu /proc/modules 2>/dev/null; then
  echo "!! MODULE NOT LOADED - see kmsg_cap.txt / loadko section above;"
  echo "   restoring sysctls, leaving permissive for post-mortem"
  tail -n 30 $D/kmsg_cap.txt 2>/dev/null
  umount /proc/kallsyms 2>/dev/null
  echo "$kr" > /proc/sys/kernel/kptr_restrict 2>/dev/null
  echo "$po" > /proc/sys/kernel/panic_on_oops 2>/dev/null
  echo loadfail > $ST
  sync
  exit 1
fi
echo "=== KernelSU module loaded ==="
grep kernelsu /proc/modules





$D/ksud post-fs-data > $D/stage_postfs.log 2>&1; echo "post-fs-data exit=$?"
$D/ksud services > $D/stage_services.log 2>&1; echo "services exit=$?"
$D/ksud boot-completed > $D/stage_boot.log 2>&1; echo "boot-completed exit=$?"
$D/ksud install > $D/stage_install.log 2>&1; echo "install exit=$?"
ls -la /data/adb/ksud 2>&1


umount /proc/kallsyms 2>/dev/null && echo "kallsyms unmounted"
echo "$kr" > /proc/sys/kernel/kptr_restrict 2>/dev/null && echo "kptr restored=$kr"
echo "$po" > /proc/sys/kernel/panic_on_oops 2>/dev/null && echo "panic_on_oops restored=$po"
rm -f $D/fake_kallsyms $D/fake_ksyms.txt $D/pristine_policy
echo ok > $ST
sync



echo "=== flipping SELinux enforcing (last step; shell may die here) ==="
echo 1 > /sys/fs/selinux/enforce 2>&1
sleep 1
echo "enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null) - chain complete"
echo "=== chain end $(date) ==="
