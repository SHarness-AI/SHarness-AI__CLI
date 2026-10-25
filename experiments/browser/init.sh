#!/bin/busybox sh
# PID 1 of the E09 guest. Runs E01, E04 and E03 and the example policies, then powers off;
# with sharness.mode=shell on the kernel command line, gives a shell on the serial line instead.
# Every line goes to the serial console; the runners read the SHARNESS-* markers.
/bin/busybox --install -s
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts /tmp /sys/fs/cgroup
mount -t devpts devpts /dev/pts 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
echo
echo "SHARNESS-GUEST-UP $(uname -r) $(uname -m)"
echo "--- landlock in dmesg:"
dmesg | grep -i landlock
if grep -q 'sharness.mode=shell' /proc/cmdline; then
    # The playground: a shell on the serial line instead of the scripted run. The page types into
    # it; a new shell starts if the old one exits, so PID 1 never returns.
    cd /work
    export PS1='sharness:\w# '
    echo "sharness-ai is installed ($(python3 -I -m sharness_ai --version)); the example policies are in /work/policies"
    echo "SHARNESS-SHELL-READY"
    # setsid then opening ttyS0 makes it the shell's controlling terminal, so Ctrl-C reaches the command
    while true; do setsid sh -c 'exec </dev/ttyS0 >/dev/ttyS0 2>&1; stty cols 160 rows 48; exec /bin/sh -i'; sleep 1; done
fi
echo "--- E01 probe:"
cd /work && sharness-ai probe
echo "--- E04 hello:"
cd /work && sharness-ai hello
echo "SHARNESS-HELLO-EXIT $?"
echo "--- E03 run under P1: port 443 allowed by the policy, port 80 refused (the guest has no network backend, so 443 fails with ENETUNREACH, not EACCES)"
sharness-ai run --policy /work/policies/p1-agent-session.json -- python3 -I -c "import socket,errno
for port in (443, 80):
    try:
        socket.create_connection(('1.1.1.1', port), timeout=3); print(port, 'connected')
    except OSError as e:
        print(port, 'refused:', errno.errorcode.get(e.errno, e.errno), e.strerror)"
echo "--- E03 run under P2: write refused, read allowed"
sharness-ai run --policy /work/policies/p2-tool-server.json -- sh -c 'touch /work/x 2>&1 || echo "write to /work refused"; echo "read allowed: $(ls /usr/bin | wc -l) entries in /usr/bin"'
echo "--- E02 the example policies: shape and hash, in one interpreter"
python3 -I -c "
import glob, sharness_ai.policy as P
for f in sorted(glob.glob('/work/policies/*.json')):
    p = P.load(f); bad = P.check(p)
    print('  ', 'ok ' if not bad else 'BAD', P.policy_hash(p), f.split('/')[-1], *bad)"
echo "--- E03 run: P0 hello world (the caps) and P2 tool server (read-only, no network)"
sharness-ai run --policy /work/policies/p0-hello-world.json -- python3 -I -c "
try:
    bytearray(200 << 20); print('200 MiB allocated: cap not applied')
except MemoryError:
    print('200 MiB refused under a 64 MiB cap: MemoryError')"
sharness-ai run --policy /work/policies/p2-tool-server.json -- sh -c 'echo x > /work/out.txt 2>&1 || echo "write to /work refused"; echo "read allowed: $(head -c 4 /etc/passwd)..."'
echo "SHARNESS-DONE"
poweroff -f
