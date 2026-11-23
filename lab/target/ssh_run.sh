# For the throwaway lab only (QEMU with -snapshot): it writes an authorized_keys file for root.
# Runs on the QNX target. Checks the image's sshd on loopback: config test, which key
# exchange it lists, and a real SSH login that asks for mlkem768x25519-sha256.
# Also runs the probe on the sshd process. Used for the stock image and the upgraded one.
D=/data/lab
echo "=== uname -a"; uname -a
echo "=== openssl version (image)"; /system/bin/openssl version
echo "=== sshd -t (config test)"; /system/bin/sshd -f /system/etc/ssh/sshd_config -t; echo "exit $?"
echo "=== sshd -T, key exchange line"; /system/bin/sshd -f /system/etc/ssh/sshd_config -T 2>&1 | grep -i -E "^kexalgorithms|error|fatal"
echo "=== host keys present"; ls -l /data/var/ssh 2>&1
cd /tmp
/system/bin/ssh-keygen -q -t ed25519 -N "" -f /tmp/id
mkdir -p /data/home/root/.ssh
cat /tmp/id.pub >> /data/home/root/.ssh/authorized_keys
echo "=== start sshd in debug mode on 127.0.0.1:2222"
/system/bin/sshd -f /system/etc/ssh/sshd_config -D -e -d -p 2222 -o ListenAddress=127.0.0.1 -o StrictModes=no > /tmp/sshd.log 2>&1 &
sleep 4
echo "=== sshd log so far"; cat /tmp/sshd.log | head -20
echo "=== sshd running?"; pidin -p sshd 2>&1 | head -3
echo "=== probe"; $D/cbom_probe
echo "=== ssh login asking only for mlkem768x25519-sha256"
/system/bin/ssh -v -p 2222 -i /tmp/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
    -o KexAlgorithms=mlkem768x25519-sha256 root@127.0.0.1 echo LOGIN-OK 2>&1 | grep -a -E "kex: algorithm|no matching|Authenticated|LOGIN-OK|Connection (closed|refused)|Permission denied|fatal|error" | head -8
echo "=== sshd log (last lines)"; tail -n 14 /tmp/sshd.log
echo "=== the way the boot script starts sshd (config test only, no extra options)"
/system/bin/sshd -f /system/etc/ssh/sshd_config -t; echo "exit $?"
echo "=== same test with the OpenSSL 3.5.9 library from the payload disk in front (LD_LIBRARY_PATH)"
LD_LIBRARY_PATH=$D/o35:$LD_LIBRARY_PATH /system/bin/sshd -f /system/etc/ssh/sshd_config -t; echo "exit $?"
