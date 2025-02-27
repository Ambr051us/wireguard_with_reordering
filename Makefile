WORKDIR := $(shell readlink -f .)
HEADERS_PATH := /usr/src/linux-headers-$(shell uname -r)
INSTALL_PATH := /lib/modules/$(shell uname -r)/kernel/drivers/net/wireguard/wireguard.ko.zst

ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
ccflags-$(CONFIG_WIREGUARD_DEBUG) += -DDEBUG
wireguard-y := main.o
wireguard-y += noise.o
wireguard-y += device.o
wireguard-y += peer.o
wireguard-y += timers.o
wireguard-y += queueing.o
wireguard-y += send.o
wireguard-y += receive.o
wireguard-y += socket.o
wireguard-y += peerlookup.o
wireguard-y += allowedips.o
wireguard-y += ratelimiter.o
wireguard-y += cookie.o
wireguard-y += netlink.o
obj-$(CONFIG_WIREGUARD) := wireguard.o

.DEFAULT_GOAL: wireguard.ko

.PHONY: clean install

wireguard.ko:
	$(MAKE) -C $(HEADERS_PATH) M=$(WORKDIR)

clean:
	$(MAKE) -C $(HEADERS_PATH) M=$(WORKDIR) clean

install: $(WORKDIR)/wireguard.ko
	zstd -fo $(INSTALL_PATH) $(WORKDIR)/wireguard.ko
