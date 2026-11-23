# Runs on the QNX target. Starts the probe as a resource manager and reads /dev/cbom.
D=/data/lab
echo "=== uname -a"; uname -a
$D/cbom_probe -s &
RM=$!
sleep 3
echo "=== ls -l /dev/cbom"; ls -l /dev/cbom
echo "=== cat /dev/cbom (first 400 bytes)"; cat /dev/cbom | head -c 400; echo
echo "=== read twice: both are complete JSON"
cat /dev/cbom | wc -c; cat /dev/cbom | wc -c
kill $RM
