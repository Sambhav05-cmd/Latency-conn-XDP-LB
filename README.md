## XDP Least-Connections Load Balancer

This repository contains an XDP-based least-connections load balancer.

The implementation is derived from and inspired by the hashing-based XDP load balancer lab published on iximiuz (by Teodor Podobnik).  
The LC logic is implemented as an alternative backend-selection strategy on top of the same structure.

### Relevant files
- lb.c 
- main.go

### Notes
- Designed to run fully in XDP (no userspace daemon)
- Connection counts updated on TCP SYN / FIN / RST
- Known limitations: no timeout-based cleanup, relies on FIN/RST
