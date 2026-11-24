# Runs the image's sshd config test, then the same test with the OpenSSL 3.5.9 library of the payload disk first.
echo "=== uname -a"; uname -a
echo "=== sshd -t with the image's libcrypto"
/system/bin/sshd -f /system/etc/ssh/sshd_config -t; echo "exit $?"
echo "=== sshd -t with OpenSSL 3.5.9 in front (LD_LIBRARY_PATH)"
LD_LIBRARY_PATH=/data/lab/o35:$LD_LIBRARY_PATH /system/bin/sshd -f /system/etc/ssh/sshd_config -t; echo "exit $?"
echo "=== LAB DONE"
