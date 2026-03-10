# XDP Least-Connections Load Balancer

A NAT-based TCP load balancer implemented in eBPF at the XDP layer. Distributes incoming connections across backend servers using the **least-connections** scheduling algorithm, with backends manageable at runtime via an interactive CLI.

> **Why XDP?** Packets are processed before entering the Linux networking stack — minimal CPU overhead, maximum throughput.

---

## Table of Contents

- [Overview](#overview)
- [Connection Tracking Modes](#connection-tracking-modes)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Building](#building)
- [Running](#running)
- [Runtime CLI](#runtime-cli)
- [Testing](#testing)
- [Customization](#customization)
- [References](#references)

---

## Overview

Each incoming TCP connection is assigned to the backend with the fewest active connections. The XDP eBPF program tracks connection state by inspecting TCP flags and maintaining lightweight per-connection structures in eBPF maps. Because everything runs at the XDP layer, packets are intercepted on arrival — before the kernel's normal network stack — keeping overhead very low.

---

## Connection Tracking Modes

Two builds are provided, differing only in *when* a connection is counted:

| Mode | Counts on | Pros | Cons |
|------|-----------|------|------|
| **Established** | First non-SYN packet (after handshake completes) | Counters reflect only fully established connections | Under burst load, multiple SYNs may see stale counters before they update |
| **SYN** | SYN packet arrival | Reserves backend immediately; more even distribution during bursts | Incomplete handshakes are briefly counted until cleaned up |

---

## Repository Structure

```
.
├── bpf/            # eBPF/XDP load balancer program (C)
├── cmd/lb/         # Go user-space loader and CLI
├── configs/        # Backend configuration file
└── scripts/        # Utility scripts
```

---

## Prerequisites

Install LLVM and required toolchain dependencies:

```bash
sudo ./scripts/llvm.sh
```

> **Requirements:** Root privileges, a modern Linux kernel with eBPF and XDP support.

---

## Configuration

Initial backends are defined in `configs/backends.json`:

```json
{
  "backends": [
    "10.0.0.2",
    "10.0.0.3"
  ]
}
```

Edit this file before starting, or manage backends live via the CLI (see below).

---

## Building

Both binaries are built from the same source using build tags.

**Established-connections version:**

```bash
go generate -tags established ./cmd/lb
go build -tags established -o lb_established ./cmd/lb
```

**SYN-connections version:**

```bash
go generate -tags syn ./cmd/lb
go build -tags syn -o lb_syn ./cmd/lb
```

---

## Running

```bash
# Established-connections version
sudo ./lb_established -i <network-interface> -config configs/backends.json

# SYN-connections version
sudo ./lb_syn -i <network-interface> -config configs/backends.json
```

Replace `<network-interface>` with the interface you want to attach the XDP program to (e.g. `eth0`).

---

## Runtime CLI

After starting, an interactive prompt becomes available:

```
lb>
```

| Command | Description |
|---------|-------------|
| `add <ip>` | Add a backend server |
| `del <ip>` | Remove a backend server |
| `list` | List backends and their current connection counts |

**Example session:**

```
lb> add 10.0.0.4
lb> del 10.0.0.3
lb> list
```

---

### Verifying the XDP Program is Attached

```bash
sudo bpftool prog show
```

---

## Testing

### 1. Start backend servers

Run this on each backend machine:

```bash
python3 -m http.server 8000
```

### 2. Send a single request

From a client machine:

```bash
curl -v --http1.1 http://<load-balancer-ip>:8000
```

> Using `--http1.1` keeps the connection open briefly, making it easier to observe connection counters.

### 3. Simulate high concurrency

Launch 100 parallel requests simultaneously:

```bash
seq 100 | xargs -n1 -P100 -I{} curl -s --http1.1 http://<load-balancer-ip>:8000 > /dev/null
```

### 4. Check active kernel TCP connections

While the test is running:

```bash
ss -tan '( sport = :8000 )' | wc -l
```

### 5. Observe backend distribution

Inside the load balancer CLI:

```
lb> list
```

This prints the connection count per backend in real time. Under burst load you may notice the **established** version distributes less evenly than the **SYN** version, because SYN-counting reserves backends at handshake start.

---

## Customization

The load balancer currently filters on **TCP port 8000**. To change this, edit the port filter in the eBPF program:

```
bpf/lb.c
```

---

## References

- [Teodor Podobnik – XDP Load Balancer Tutorial](https://labs.iximiuz.com/tutorials/xdp-load-balancer-700a1d74)
- [iximiuz Labs – Practical Linux networking and eBPF tutorials](https://labs.iximiuz.com/)
