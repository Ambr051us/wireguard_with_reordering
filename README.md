# Wireguard kernel module for Linux with RX packet order correction
This is a modified version of the Wireguard kernel module, which processes received packets in the order they were sent by peers. It is fully compatible with peers running unmodified Wireguard.

## Operating principles
Order correction is done by making use of the 64-bit counter that the Wireguard protocol already includes for data packets, and originally uses as a cryptographic nonce. The counter resets on every new key exchange, so the reordering code makes sure to keep track of resets and create a contiguous sequence numbering by adding an offset to counters read from received packets.

Instead of the original code's linked list implementation, this module puts incoming packets into a ring buffer. The buffer index is selected based on the sequence number (modulo the buffer size, which is defined as 2048 in `device.h`), so the thread that enqueues incoming packets writes them into the buffer in the correct order.

The RX polling thread then looks for the next packet in sequence, and takes it from the buffer if it's there. If it still isn't there after the pre-defined maximum delay (set to 5 milliseconds in `device.h`), it looks for the next valid one and processes it.

With this implementation, tunneled packets either arrive in the correct order or get dropped (if they miss the time window), out-of-order delivery never happens. When a packet is lost in transit from the remote peer, there is a sudden pause in the incoming tunneled stream due to waiting for the correct packet. TCP seems to tolerate this way better than out-of-order segments, so this module can improve TCP throughput on reordering-prone links.

## Compilation
### Prerequisites
- Have the toolchain required for kernel compilation installed on your system (`sudo apt install build-essentials` on Ubuntu)
- Have the appropriate kernel header package installed (`sudo apt install linux-headers-$(uname -r)` on Ubuntu)
  - Other distributions may install the headers in a different directory. In this case, make a symlink to the header directory from `/usr/src/linux-headers-$(uname -r)` for the Makefile to work as intended

### What to do
Just run `make` in the root of this repo

## Installation
Run `make install` in the root of this repo. **Make sure to back up the original kernel module, or be prepared to reinstall your kernel package if you wish to revert to the original version of Wireguard.**
