# Latency-conn-XDP-LB
Latency-conn-XDP-LB is an eBPF/XDP-based L4 load balancer that extends Katran by selecting backends using both packet-level RTT estimation and accurate active connection tracking. It operates entirely in the XDP fast path with DSR-style forwarding, bypassing the Linux networking stack, and is evaluated against Katran and IPVS.
