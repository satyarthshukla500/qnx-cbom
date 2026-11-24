# Lists every regular file of the system and data partitions with its size and checksum (cksum).
echo "=== LIVE-BEGIN"
find /system /data -xdev -type f -exec cksum {} \;
echo "=== LIVE-END"
echo "=== LAB DONE"
