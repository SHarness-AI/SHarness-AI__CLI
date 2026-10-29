#!/bin/sh
# E09, third form: the same guest rootfs, the same i386 binaries, on the HOST kernel through
# chroot. No emulator: this is Landlock on the real kernel, called through the i386 syscall
# table. Needs root (chroot, mount). Leaves nothing behind: /proc is unmounted at the end.
#   sudo sh experiments/browser/chroot_native.sh [out-dir]
set -eu
OUT=${1:-$(dirname "$0")/out}
ROOT=$OUT/rootfs
[ -d "$ROOT/usr/lib" ] || { echo "no rootfs at $ROOT: run build_guest.py first" >&2; exit 2; }
trap 'umount "$ROOT/proc" 2>/dev/null || true' EXIT
mount -t proc proc "$ROOT/proc"
# uname(2) answers for the host, so the guest's architecture is read from busybox's ELF header:
# e_machine is the little-endian half-word at offset 18; bytes "03 00" are 0x0003, EM_386.
ELF=$(chroot "$ROOT" /bin/busybox od -An -tx1 -j18 -N2 /bin/busybox | tr -d ' ')
echo "SHARNESS-CHROOT-UP host $(uname -r) $(uname -m), guest binaries ELF e_machine bytes $ELF ($([ "$ELF" = 0300 ] && echo "0x0003, i386" || echo "not i386"))"
echo "--- E01 probe:"
chroot "$ROOT" /bin/sh -c 'export PATH=/usr/bin:/bin:/usr/sbin:/sbin; cd /work && sharness-ai probe'
echo "--- E04 hello:"
chroot "$ROOT" /bin/sh -c 'export PATH=/usr/bin:/bin:/usr/sbin:/sbin; cd /work && sharness-ai hello'
echo "SHARNESS-HELLO-EXIT $?"
echo "SHARNESS-DONE"
