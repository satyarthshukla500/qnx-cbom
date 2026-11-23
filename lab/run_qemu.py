# Boots a throwaway copy of a QNX 8.0 QEMU image (x86_64), mounts a payload disk,
# runs one script from it over the serial console and saves the cleaned console log.
# Nothing is written back to the image (-snapshot) and the guest has no network.
# usage: run_qemu.py PAYLOAD_IMG SCRIPT_NAME LOGFILE IFS_BIN DISK
import os
import re
import subprocess
import sys
import threading
import time

payload, script, logfile, ifs, disk = sys.argv[1:6]
cmd = ["qemu-system-x86_64", "-snapshot", "-smp", "2", "-cpu", "max", "-m", "1G",
       "-display", "none", "-monitor", "none", "-serial", "stdio", "-nic", "none",
       "-drive", f"file={disk},if=ide,index=0" + ("" if disk.endswith(".vmdk") else ",format=raw"),
       "-drive", f"file={payload},if=ide,index=1,format=raw",
       "-object", "rng-random,filename=/dev/urandom,id=rng0", "-device", "virtio-rng-pci,rng=rng0",
       "-kernel", ifs]
# the -snapshot overlay file goes next to the log, not into a system folder
env = dict(os.environ, TMPDIR=os.path.dirname(os.path.abspath(logfile)))
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
buf = bytearray()


def reader():
    while True:
        chunk = proc.stdout.read1(4096)
        if not chunk:
            break
        buf.extend(chunk)


threading.Thread(target=reader, daemon=True).start()


def wait_for(text, timeout):
    end = time.time() + timeout
    while time.time() < end and proc.poll() is None:
        if text.encode() in buf:
            return True
        time.sleep(1)
    return False


def send(line):
    proc.stdin.write((line + "\r").encode())
    proc.stdin.flush()


try:
    booted = wait_for("Startup complete", 900)
    time.sleep(8)
    send("")
    send("mkdir -p /data/lab && mount -t qnx6 -r /dev/hd1 /data/lab && echo MOUNT-DONE && ls /data/lab")
    mounted = wait_for("MOUNT-DONE\r\n", 120) or wait_for("MOUNT-DONE\n", 1)
    send(f"sh /data/lab/{script}")
    finished = mounted and wait_for("=== LAB DONE\r", 1500)
    time.sleep(2)
finally:
    proc.kill()
text = buf.decode("utf-8", "replace")
text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace("\r", "")
with open(logfile, "w", encoding="utf-8") as handle:
    handle.write(text)
print("booted", booted, "finished", finished, "log bytes", len(text))
sys.exit(0 if booted and finished else 1)
