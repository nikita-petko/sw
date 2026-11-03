#!/usr/bin/env bash
# Runs inside the VM of test_kmod_localhost_vm.sh: the lagsw feature harness against the swdivert module backend. lagsw loads the module
# itself (LAGSW_KMOD_PATH), which is the load policy of the PoC document's section 9.3 as it runs in production.
#
# usage: test_kmod_localhost.sh LAGSW HARNESS PROFILE KO [ONLY]
lagsw="$1"; harness="$2"; profile="$3"; ko="$4"
[ -n "${5:-}" ] && export ONLY="$5"

# lagsw runs on a pseudo-terminal, as it does for a user
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
export LAGSW_KMOD_PATH="$ko"
dmesg_before="$(dmesg | wc -l)"
python3 "$harness" "$lagsw" "$profile"
code=$?

echo "== module"
if lsmod | awk '$1 == "swdivert" {found = 1} END {exit !found}'; then
	echo "ok   lagsw loaded the module and left it loaded (a normal exit never unloads it)"
else
	echo "FAIL the module is not loaded after the run"; code=1
fi
for i in $(seq 1 40); do refs="$(lsmod | awk '$1 == "swdivert" {print $3}')"; [ "$refs" = 0 ] && break; sleep 0.05; done
if [ "$refs" = 0 ]; then echo "ok   no handle is left open after lagsw exited"; else echo "FAIL $refs references to the module remain"; code=1; fi
rmmod swdivert 2> /tmp/rmmod.err && echo "ok   rmmod succeeded" || { echo "FAIL rmmod failed: $(cat /tmp/rmmod.err)"; code=1; }
if dmesg | tail -n +"$((dmesg_before + 1))" | grep -E 'BUG[: ]|WARNING:|Oops|KASAN|lockdep|Call Trace|general protection|kmem_cache_destroy|Slab cache|Poison|Redzone|refcount_t|use-after-free' > /tmp/dmesg.txt; then
	echo "FAIL the kernel log shows a problem:"; head -20 /tmp/dmesg.txt; code=1
else
	echo "ok   no BUG/WARNING/Oops/slab error in the kernel log"
fi
exit "$code"
