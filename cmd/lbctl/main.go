package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"

	pb "lb/proto"

	"github.com/cilium/ebpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	pinDir  = "/sys/fs/bpf/lbxdp"
	wlcSock = "/var/run/lbxdp-wlc.sock"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "add", "del", "list", "addsvc", "delsvc", "listsvc":
		runMapMode()
	case "weight":
		runGRPCCmd()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `lbctl — XDP load balancer control

Backend commands (pinned map access, works with lc and wlc):
  lbctl add    <ip> <port> [weight]   add backend (weight ignored in lc mode)
  lbctl del    <ip> <port>            remove backend (refused if active conns > 0)
  lbctl list                          list backends with connection counts

Service commands (pinned map access, works with lc and wlc):
  lbctl addsvc  <vip> <port>          register a virtual IP
  lbctl delsvc  <vip> <port>          deregister a virtual IP
  lbctl listsvc                       list registered VIPs

Weight command (gRPC, wlc daemon only):
  lbctl weight <ip> <port> <weight>   update a backend's weight live`)
}

// ── gRPC path (wlc weight updates) ───────────────────────────────────────────

func runGRPCCmd() {
	if len(os.Args) < 5 {
		fatalf("usage: lbctl weight <ip> <port> <weight>")
	}
	ip     := os.Args[2]
	port   := mustPort(os.Args[3])
	weight := mustUint16(os.Args[4], "weight")

	conn, err := grpc.NewClient("unix://"+wlcSock,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fatalf("connect to wlc daemon: %v", err)
	}
	defer conn.Close()

	c := pb.NewWeightControlClient(conn)
	_, err = c.UpdateWeight(context.Background(), &pb.WeightRequest{
		Ip:     ip,
		Port:   uint32(port),
		Weight: uint32(weight),
	})
	if err != nil {
		fatalf("UpdateWeight: %v", err)
	}
	fmt.Printf("weight updated: %s:%d → %d\n", ip, port, weight)
}

// ── pinned map path (backends + services) ────────────────────────────────────

// lcBackend matches lbBackend/lb2Backend — no Weight field.
// Padding field keeps Go struct layout aligned with C struct.
type lcBackend struct {
	Ip    uint32
	Port  uint16
	Pad  uint16 // matches C struct padding; remove if your C struct has no padding
	Conns uint32
}

// wlcBackend matches lb3Backend/lb4Backend — has Weight field.
type wlcBackend struct {
    Ip     uint32
    Port   uint16
    Pad1   uint16
    Conns  uint32
    Weight uint16
    Pad2   uint16
}

// serviceKey matches lbIpPort/lb2IpPort/lb3IpPort/lb4IpPort.
// All four variants have the same layout.
type serviceKey struct {
	Ip   uint32
	Port uint16
	Pad  uint16 // matches C struct padding; remove if your C struct has no padding
}

func runMapMode() {
	mode := readMode()

	backendsMap, err := ebpf.LoadPinnedMap(pinDir+"/backends", nil)
	if err != nil {
		fatalf("open backends map: %v\n(is the daemon running?)", err)
	}
	defer backendsMap.Close()

	countMap, err := ebpf.LoadPinnedMap(pinDir+"/backend_count", nil)
	if err != nil {
		fatalf("open backend_count map: %v", err)
	}
	defer countMap.Close()

	servicesMap, err := ebpf.LoadPinnedMap(pinDir+"/services", nil)
	if err != nil {
		fatalf("open services map: %v", err)
	}
	defer servicesMap.Close()

	switch os.Args[1] {

	// ── backend commands ──────────────────────────────────────────────────────

	case "add":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl add <ip> <port> [weight]")
		}
		ip     := parseIPv4(os.Args[2])
		port   := mustPort(os.Args[3])
		weight := uint16(1)
		if len(os.Args) >= 5 {
			weight = mustUint16(os.Args[4], "weight")
		}
		addBackend(backendsMap, countMap, ip, port, weight, mode)

	case "del":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl del <ip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		delBackend(backendsMap, countMap, ip, port, mode)

	case "list":
		listBackends(backendsMap, countMap, mode)

	// ── service commands ──────────────────────────────────────────────────────

	case "addsvc":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl addsvc <vip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		key  := serviceKey{Ip: ip, Port: htons(port)}
		val  := true
		if err := servicesMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			fatalf("addsvc: %v", err)
		}
		fmt.Printf("service added: %s:%d\n", os.Args[2], port)

	case "delsvc":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl delsvc <vip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		key  := serviceKey{Ip: ip, Port: htons(port)}
		if err := servicesMap.Delete(&key); err != nil {
			fatalf("delsvc: %v", err)
		}
		fmt.Printf("service deleted: %s:%d\n", os.Args[2], port)

	case "listsvc":
		iter := servicesMap.Iterate()
		var k serviceKey
		var v bool
		found := false
		for iter.Next(&k, &v) {
			fmt.Printf("service: %s  port: %d\n", ipToStr(k.Ip), ntohs(k.Port))
			found = true
		}
		if err := iter.Err(); err != nil {
			fatalf("iterate services: %v", err)
		}
		if !found {
			fmt.Println("no services registered")
		}
	}
}

// readMode reads the sentinel written by the daemon at startup.
// Returns "lc" or "wlc". Defaults to "lc" if the file is missing.
func readMode() string {
    data, err := os.ReadFile("/run/lbxdp.mode")
	if err != nil {
		return "lc"
	}
	return string(data)
}

// ── backend operations ────────────────────────────────────────────────────────

func addBackend(m, countMap *ebpf.Map, ip uint32, port, weight uint16, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}
	if findBackend(m, count, ip, port, mode) >= 0 {
		fatalf("backend %s:%d already exists", ipToStr(ip), ntohs(port))
	}
	var err error
	if mode == "wlc" {
		be := wlcBackend{Ip: ip, Port: ntohs(port), Weight: weight, Conns: 0}
		err = m.Update(count, &be, ebpf.UpdateAny)
	} else {
		be := lcBackend{Ip: ip, Port: ntohs(port), Conns: 0}
		err = m.Update(count, &be, ebpf.UpdateAny)
	}
	if err != nil {
		fatalf("insert backend: %v", err)
	}
	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		fatalf("update count: %v", err)
	}
	fmt.Printf("backend added: %s:%d\n", ipToStr(ip), ntohs(port))
}

func delBackend(m, countMap *ebpf.Map, ip uint32, port uint16, mode string) {
    var count uint32
    if err := countMap.Lookup(uint32(0), &count); err != nil {
        fatalf("lookup count: %v", err)
    }
    idx := findBackend(m, count, ip, port, mode)
    if idx < 0 {
        fatalf("backend %s:%d not found", ipToStr(ip), ntohs(port))
    }
    if conns := getConns(m, uint32(idx), mode); conns != 0 {
        fatalf("backend has %d active connections — refusing delete", conns)
    }
    last := count - 1
    if uint32(idx) != last {
        // Swap last entry into the deleted slot.
        if mode == "wlc" {
            var b wlcBackend
            if err := m.Lookup(last, &b); err != nil {
                fatalf("lookup last: %v", err)
            }
            if err := m.Update(uint32(idx), &b, ebpf.UpdateExist); err != nil {
                fatalf("swap: %v", err)
            }
        } else {
            var b lcBackend
            if err := m.Lookup(last, &b); err != nil {
                fatalf("lookup last: %v", err)
            }
            if err := m.Update(uint32(idx), &b, ebpf.UpdateExist); err != nil {
                fatalf("swap: %v", err)
            }
        }
    }
    // Zero out the last slot — array maps don't support Delete.
    if mode == "wlc" {
        zero := wlcBackend{}
        if err := m.Update(last, &zero, ebpf.UpdateExist); err != nil {
            fatalf("zero last slot: %v", err)
        }
    } else {
        zero := lcBackend{}
        if err := m.Update(last, &zero, ebpf.UpdateExist); err != nil {
            fatalf("zero last slot: %v", err)
        }
    }
    count--
    if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
        fatalf("update count: %v", err)
    }
    fmt.Printf("backend deleted: %s:%d\n", ipToStr(ip), ntohs(port))
}

func listBackends(m, countMap *ebpf.Map, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}
	if count == 0 {
		fmt.Println("no backends registered")
		return
	}
	for i := uint32(0); i < count; i++ {
		if mode == "wlc" {
			var b wlcBackend
			if err := m.Lookup(i, &b); err != nil {
				continue
			}
			fmt.Printf("%d: %s:%d  weight=%d  conns=%d\n",
				i, ipToStr(b.Ip), ntohs(b.Port), b.Weight, b.Conns)
		} else {
			var b lcBackend
			if err := m.Lookup(i, &b); err != nil {
				continue
			}
			fmt.Printf("%d: %s:%d  conns=%d\n",
				i, ipToStr(b.Ip), ntohs(b.Port), b.Conns)
		}
	}
}

func findBackend(m *ebpf.Map, count uint32, ip uint32, port uint16, mode string) int {
	for i := uint32(0); i < count; i++ {
		if mode == "wlc" {
			var b wlcBackend
			if err := m.Lookup(i, &b); err != nil {
				continue
			}
			if b.Ip == ip && b.Port == htons(port) {
				return int(i)
			}
		} else {
			var b lcBackend
			if err := m.Lookup(i, &b); err != nil {
				continue
			}
			if b.Ip == ip && b.Port == htons(port) {
				return int(i)
			}
		}
	}
	return -1
}

func getConns(m *ebpf.Map, idx uint32, mode string) uint32 {
	if mode == "wlc" {
		var b wlcBackend
		m.Lookup(idx, &b)
		return b.Conns
	}
	var b lcBackend
	m.Lookup(idx, &b)
	return b.Conns
}

// ── net / parse helpers ───────────────────────────────────────────────────────

func parseIPv4(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		fatalf("invalid IP address: %q", s)
	}
	return binary.LittleEndian.Uint32(ip)
}

func ipToStr(i uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return net.IP(b).String()
}

func htons(p uint16) uint16 { return (p<<8)&0xff00 | p>>8 }
func ntohs(p uint16) uint16 { return htons(p) }

func mustPort(s string) uint16 {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		fatalf("invalid port: %q", s)
	}
	return uint16(p)
}

func mustUint16(s, name string) uint16 {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v > 65535 {
		fatalf("invalid %s: %q", name, s)
	}
	return uint16(v)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lbctl: "+format+"\n", args...)
	os.Exit(1)
}