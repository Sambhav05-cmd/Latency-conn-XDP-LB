 # XDP Weighted Least-Connections Load Balancer

High-performance L4 load balancer implemented in XDP/eBPF
supporting stateful least-connections scheduling with in-datapath
connection tracking.

A NAT-based TCP load balancer implemented in eBPF at the XDP layer. Supports two scheduling algorithms — **Least Connections (LC)** and **Weighted Least Connections (WLC)** — each available in two connection-tracking modes. Backends are manageable at runtime via an interactive CLI. The load balancer filters traffic based on a configurable set of service VIP–port pairs, allowing multiple services to be handled simultaneously while ensuring unrelated network traffic passes through unaffected.

> **Why XDP?** Packets are processed before entering the Linux networking stack — minimal CPU overhead, maximum throughput.

---

## Table of Contents

- [Overview](#overview)
- [Why least connections instead of hashing](#Why-least-connections-instead-of-hashing)
- [Scheduling Algorithms](#scheduling-algorithms)
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

This project implements a stateful Layer-4 load balancer with full network address translation (NAT) in the eBPF/XDP fast path.
Incoming TCP flows destined for configured virtual service endpoints (VIP–port pairs) are intercepted at the earliest point in the Linux receive path and dynamically steered to backend servers using adaptive connection-aware scheduling.

Unlike stateless hashing-based dataplane designs, the load balancer maintains per-connection state directly inside eBPF maps, enabling real-time backend selection based on active connection counts and configurable backend weights.
Both forward and reverse packet paths are rewritten entirely in the XDP layer, providing complete NAT semantics including source-port translation, symmetric return routing, and deterministic connection teardown handling.

The dataplane supports multiple concurrent virtual services, dynamic backend pool updates at runtime, and two scheduling strategies — Least Connections and Weighted Least Connections — each with selectable connection accounting modes.
Because all packet classification, scheduling, connection tracking, and address rewriting occur before socket buffer allocation, the design achieves very low processing latency and high throughput under connection-heavy workloads.

This architecture allows the load balancer to adapt to skewed or persistent traffic patterns while retaining the performance advantages of early-ingress packet processing.

---

## Why Least-Connections instead of Hash-Based Load Balancing

High-performance L4 load balancers in fast datapaths (including most XDP-based designs) commonly rely on **stateless flow hashing** (e.g., 5-tuple hashing) for backend selection.  
Hashing offers constant-time scheduling decisions and minimal per-packet overhead, making it attractive for high-throughput environments.

However, this approach has important practical limitations.

- Hashing assumes that traffic load is **evenly distributed across connections**, which is often not true in real deployments.
- Long-lived or high-throughput persistent connections (such as WebSockets, database sessions, or streaming RPC workloads) can create **significant load imbalance**, even when flow counts appear uniform.
- Stateless hashing cannot adapt to runtime backend load conditions because flow-to-backend mapping is deterministic for the lifetime of the connection.

A further challenge arises when **backend capacity changes dynamically**.

- Adjusting backend weights in a hashing-based scheduler typically requires **rehashing or remapping flows**, which can lead to:
  - sudden traffic shifts
  - connection churn
  - cache and state disruption on backends
- Incremental or fine-grained runtime weight updates are therefore difficult to apply without affecting existing traffic distribution.

This project explores **stateful least-connections scheduling implemented directly in the XDP datapath**, enabling adaptive backend selection based on live connection counts and configurable backend weights.

By maintaining lightweight per-connection state in eBPF maps, the load balancer:

- reacts to real-time load imbalance instead of relying on static flow distribution  
- supports dynamic backend addition, removal, and weight updates without rehashing existing connections  
- performs scheduling entirely in the fast path without requiring backend-side load reporting  

This design trades modest state-management overhead for **improved utilisation fairness, smoother weight transitions, and better handling of persistent or skewed workloads**, while still benefiting from the high throughput of XDP-based packet processing.

---

## Scheduling Algorithms

| Algorithm | Description |
|-----------|-------------|
| **Least Connections (LC)** | Assigns each new connection to the backend with the fewest active connections. All backends are treated equally. |
| **Weighted Least Connections (WLC)** | Assigns connections based on `active_connections / weight`. Backends with higher weights receive a proportionally larger share of traffic. |

---

## Connection Tracking Modes

Both algorithms are available in two builds, differing only in *when* a connection is counted:

| Mode | Counts on | Pros | Cons |
|------|-----------|------|------|
| **SYN** | SYN packet arrival | Reserves backend immediately; more even distribution during bursts | Incomplete handshakes are briefly counted until cleaned up |
| **Established** | First non-SYN packet (after handshake completes) | Counters reflect only fully established connections | Under burst load, multiple SYNs may see stale counters before they update |

---

## Repository Structure

```
.
├── bpf/                  # eBPF/XDP load balancer program (C)
├── cmd/lb/               # Go user-space loader and CLI
├── configs/
│   ├── backends_lc.json  # Backend config for LC (no weights)
│   └── backends_wlc.json # Backend config for WLC (with weights)
└── scripts/
    └── build.sh          # Builds all four binaries
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

The load balancer is configured using a **virtual service endpoint (VIP + port)** and a pool of backend servers.
### LC — `configs/backends_lc.json`

```json
{
  "service": {
    "vip": "10.45.179.173",
    "port": 8000
  },
  "backends": [
    {
      "ip": "10.45.179.166",
      "port": 8000
    },
    {
      "ip": "10.45.179.99",
      "port": 8000
    }
  ]
}
```

### WLC — `configs/backends_wlc.json`

```json
{
  "service": {
    "vip": "10.45.179.173",
    "port": 8000
  },
  "backends": [
    {
      "ip": "10.45.179.166",
      "port": 8000,
      "weight": 80
    },
    {
      "ip": "10.45.179.99",
      "port": 8000,
      "weight": 20
    }
  ]
}
```

Backends can also be added, removed, or reweighted live via the CLI after startup.

---

## Building

Build all four binaries at once:

```bash
./build.sh
```

This produces:

| Binary | Algorithm | Tracking mode |
|--------|-----------|---------------|
| `lb_lc_syn` | Least Connections | SYN |
| `lb_lc_est` | Least Connections | Established |
| `lb_wlc_syn` | Weighted Least Connections | SYN |
| `lb_wlc_est` | Weighted Least Connections | Established |

---

## Running
Choose whichever mode load balancer to run.
Recommended mode is the "syn" mode over the "est" mode for burst of connections, however, you can use "est" for experiment or more stable connection requests

**LC binaries:**

```bash
sudo ./lb_lc_syn -i <network-interface> -config configs/backends_lc.json
sudo ./lb_lc_est -i <network-interface> -config configs/backends_lc.json
```

**WLC binaries:**

```bash
sudo ./lb_wlc_syn -i <network-interface> -config configs/backends_wlc.json
sudo ./lb_wlc_est -i <network-interface> -config configs/backends_wlc.json
```

Replace `<network-interface>` with the interface to attach the XDP program to (e.g. `eth0`).

---

## Runtime CLI

After starting, an interactive prompt becomes available:

```
lb>
```

### LC commands

| Command | Description |
|---------|-------------|
| `add <ip> <port>` | Add a backend server |
| `del <ip> <port>` | Remove a backend server |
| `list` | List backends and their current connection counts |
| `addsvc <ip> <port>` | Add a service endpoint |
| `delsvc <ip> <port>` | Remove a service endpoint |
| `list` | List service endpoints |

### WLC commands

| Command | Description |
|---------|-------------|
| `add <ip> <port> <weight>` | Add a backend server with a given weight |
| `del <ip> <port>` | Remove a backend server |
| `update <ip> <port> <weight>` | Update the weight of an existing backend |
| `list` | List backends with their weights and connection counts |
| `addsvc <ip> <port>` | Add a service endpoint |
| `delsvc <ip> <port>` | Remove a service endpoint |
| `list` | List service endpoints |

**Example session (WLC):**

```
lb> add 10.0.0.4 8000 20
lb> update 10.0.0.2 30
lb> del 10.0.0.3 8001
lb> list
```

---

### Verifying the XDP program is attached

```bash
sudo bpftool prog show
```

---

## Testing
To test the connection tracking the connections should persist for some time, you can either try large downloads which take time, or use the socat tool which keeps connections alive without sending alot of data

### 1. Start backend servers

Run this on each backend machine:

```bash
socat TCP-LISTEN:8000,reuseaddr,fork EXEC:/bin/cat
```

### 2. Send a single request

From a client machine:

```bash
socat - TCP:<load_balancer_ip>:8000
```

### 3. Simulate high concurrency

Launch 100 parallel requests simultaneously:

```bash
for i in $(seq 1 100); do
socat - TCP:<load_balancer_ip>:8000 &
done
```

### 4. Check active kernel TCP connections

```bash
ss -tan '( sport = :8000 )' | wc -l
```

### 5. Observe backend distribution

```
lb> list
```

Under burst load, the **SYN** variants distribute more evenly than the **established** variants because counters are incremented immediately on SYN arrival. With WLC, backends with higher weights should absorb a proportionally larger share of connections.

---

## Customization

The load balancer currently handles a maximum of 60000 simultaneous connections. To change this, you can modify the maximum connections and the maximum port to be 1024+maximum connections
in the bpf program , change the following constants to your desired values:
```c
#define MAX_CONNECTIONS 60000
#define MAX_PORT 61024
```

and in the corresponding main go file:
```go
const maxPort = 61024
```
---

## References

- [Teodor Podobnik – XDP Load Balancer Tutorial](https://labs.iximiuz.com/tutorials/xdp-load-balancer-700a1d74)
- [iximiuz Labs – Practical Linux networking and eBPF tutorials](https://labs.iximiuz.com/)
