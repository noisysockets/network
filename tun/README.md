# TUN Interface For Linux

In general Noisy Sockets uses a userspace network stack, however on Linux with
user namspaces it is possible to create an in-kernel TUN interface without
elevated priviliges.

The userspace network stack, while optimized, is still slower than the kernel
network stack. So on Linux hosts where performance (and not portability) is
the primary concern, it is recommended to use the TUN interface.

**Note:** This is explicitly a Linux only feature, and we have no plans to
support other OS's (as the complexity is not worth it, and we aren't trying to
build a general purpose VPN, just use upstream WireGuard instead).

