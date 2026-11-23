# Builds the probe with qcc for both targets. Needs the QNX SDP environment (source qnxsdp-env.sh).
CFLAGS = -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -DCBOM_WITH_RESMGR

all: build/x86_64/cbom_probe build/aarch64le/cbom_probe

build/x86_64/cbom_probe: cbom_probe.c cbom_resmgr.h
	mkdir -p build/x86_64
	qcc -Vgcc_ntox86_64 $(CFLAGS) -o $@ cbom_probe.c

build/aarch64le/cbom_probe: cbom_probe.c cbom_resmgr.h
	mkdir -p build/aarch64le
	qcc -Vgcc_ntoaarch64le $(CFLAGS) -o $@ cbom_probe.c

clean:
	rm -rf build

.PHONY: all clean
