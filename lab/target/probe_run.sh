# Runs on the QNX target. Starts two TLS servers, one with the image's own OpenSSL
# libraries and one with the OpenSSL 3.5.9 libraries from the payload disk
# (LD_LIBRARY_PATH), and runs the probe after each one.
D=/data/lab
O=$D/o35
export OPENSSL_CONF=$O/openssl.cnf
echo "=== uname -a"; uname -a
echo "=== probe with nothing crypto-related started by this script"
$D/cbom_probe
cd /tmp
echo "=== throwaway key and certificate in /tmp (target RAM only)"
/system/bin/openssl req -x509 -newkey ed25519 -nodes -keyout k.pem -out c.pem -subj /CN=lab -days 1 2>&1 | tail -1
echo "=== start a TLS server with the image's OpenSSL (port 4433)"
/system/bin/openssl s_server -accept 4433 -cert c.pem -key k.pem -www > /tmp/s1.log 2>&1 &
P1=$!
sleep 5
echo "=== probe 1: image library in use"
$D/cbom_probe
echo "=== start a TLS server with OpenSSL 3.5.9 from the payload disk through LD_LIBRARY_PATH (port 4434)"
LD_LIBRARY_PATH=$O:$LD_LIBRARY_PATH /system/bin/openssl s_server -accept 4434 -cert c.pem -key k.pem -www > /tmp/s2.log 2>&1 &
P2=$!
sleep 5
echo "=== probe 2: both servers running"
$D/cbom_probe
echo "=== probe of one process only (-p) and file output (-o)"
$D/cbom_probe -p 1 -o /tmp/one.json; echo "exit $?"; cat /tmp/one.json; echo
$D/cbom_probe -p 999999 | head -3
$D/cbom_probe -p abc; echo "exit $?"
kill $P1 $P2
