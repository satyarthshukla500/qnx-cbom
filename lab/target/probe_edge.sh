# Runs on the QNX target. Odd situations for the probe: a very long program name,
# a library file deleted while a process still has it mapped, and processes that
# start and end while the probe reads /proc.
D=/data/lab
O=$D/o35
export OPENSSL_CONF=$O/openssl.cnf
cd /tmp
echo "=== long program name (200 characters) with a library from a directory that is removed afterwards"
mkdir -p /tmp/gone
cp $O/libcrypto.so.3 $O/libssl.so.3 /tmp/gone/
LONG=/tmp/$(printf 'n%.0s' $(seq 1 200))
cp /system/bin/openssl $LONG
LD_LIBRARY_PATH=/tmp/gone $LONG s_server -accept 4435 -www -naccept 1 -cert /tmp/none.pem > /tmp/e1.log 2>&1 &
sleep 1
/system/bin/openssl req -x509 -newkey ed25519 -nodes -keyout /tmp/k2.pem -out /tmp/c2.pem -subj /CN=edge -days 1 > /dev/null 2>&1
LD_LIBRARY_PATH=/tmp/gone $LONG s_server -accept 4436 -cert /tmp/c2.pem -key /tmp/k2.pem -www > /tmp/e2.log 2>&1 &
E2=$!
sleep 4
echo "=== state before deleting the library files"; ls -l /tmp/gone; echo "log e2:"; head -3 /tmp/e2.log; echo "log e1:"; head -3 /tmp/e1.log
$D/cbom_probe | grep -c "/tmp/gone"
rm -f /tmp/gone/libcrypto.so.3 /tmp/gone/libssl.so.3
echo "=== probe after the library files were deleted"
$D/cbom_probe
echo "exit $?"
echo "=== probe 15 times while short-lived processes start and end"
( i=0; while [ $i -lt 60 ]; do /system/bin/openssl version > /dev/null 2>&1; i=$((i+1)); done ) &
LOOP=$!
n=0; bad=0
while [ $n -lt 15 ]; do
    $D/cbom_probe > /tmp/p.out 2>&1 || bad=$((bad+1))
    n=$((n+1))
done
echo "runs $n, failed runs $bad"
grep -c CBOM-END /tmp/p.out
kill $E2 $LOOP 2>/dev/null
echo "=== -o attacks: a hard link to another file, a fifo, an existing world-readable file"
echo "victim-content" > /tmp/victim
ln /tmp/victim /tmp/hardlink
$D/cbom_probe -o /tmp/hardlink; echo "exit $?"
cat /tmp/victim
mkfifo /tmp/fifo
$D/cbom_probe -o /tmp/fifo; echo "exit $?"
echo "{}" > /tmp/public.json; chmod 666 /tmp/public.json
$D/cbom_probe -o /tmp/public.json; echo "exit $?"
ls -l /tmp/public.json
head -c 60 /tmp/public.json; echo
