package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb ../../bpf/lb.c

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"bufio"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// network interface name and backend list string
var (
	ifname   string
	backends string
)

// configuration structure for parsing backend config file
type Config struct {
	Backends []string `json:"backends"`
}

// converts IPv4 string into uint32 representation used in BPF maps
func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

// add a new backend dynamically
func addBackend(objs *lbObjects, ip string) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	// read current backend count from map
	err = objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	// prevent duplicate backends
	for i := uint32(0); i < count; i++ {

		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err == nil && b.Ip == backIP {
			log.Println("backend already exists:", ip)
			return
		}
	}

	// create backend entry
	backEp := lbBackend{
		Ip:    backIP,
		Conns: 0,
	}

	// insert backend at next available index
	err = objs.lbMaps.Backends.Put(count, &backEp)
	if err != nil {
		log.Println("failed adding backend:", err)
		return
	}

	// increment backend count
	count++
	err = objs.lbMaps.BackendCount.Put(key, count)
	if err != nil {
		log.Println("failed updating backend count:", err)
		return
	}

	log.Println("backend added:", ip)
}

// delete backend dynamically (only allowed if no active connections)
func deleteBackend(objs *lbObjects, ip string) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	// read backend count
	err = objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	// search backend to delete
	for i := uint32(0); i < count; i++ {

		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		if b.Ip == backIP {

			// prevent deletion if backend still has active connections
			if b.Conns != 0 {
				log.Println("cannot delete backend, active connections:", b.Conns)
				return
			}

			last := count - 1

			// keep array compact by moving last backend into deleted slot
			if i != last {

				var lastBackend lbBackend
				err := objs.lbMaps.Backends.Lookup(last, &lastBackend)
				if err == nil {
					objs.lbMaps.Backends.Put(i, &lastBackend)
				}
			}

			// remove last entry
			objs.lbMaps.Backends.Delete(last)

			// decrease backend count
			count--
			objs.lbMaps.BackendCount.Put(key, count)

			log.Println("backend deleted:", ip)
			return
		}
	}

	log.Println("backend not found:", ip)
}

// list all configured backends and their connection counts
func listBackends(objs *lbObjects) {

	var count uint32
	key := uint32(0)

	// read backend count
	err := objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		fmt.Println("failed to read backend count")
		return
	}

	// iterate through backend map
	for i := uint32(0); i < count; i++ {

		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		// convert stored uint32 IP back to human readable form
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, b.Ip)

		fmt.Println(i, ip, "conns:", b.Conns)
	}
}

func main() {

	// CLI flag for network interface
	flag.StringVar(&ifname, "i", "lo", "Network interface to attach eBPF programs")

	// config file containing initial backends
	var configFile string
	flag.StringVar(&configFile, "config", "configs/backends.json", "Backend configuration file")
	flag.Parse()

	// read backend configuration file
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		log.Fatalf("Invalid config format: %v", err)
	}

	if len(cfg.Backends) == 0 {
		log.Fatal("No backends defined in config file")
	}

	// context used for graceful shutdown on Ctrl+C
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// remove memlock rlimit so BPF objects can be loaded
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// load compiled eBPF program and maps
	var objs lbObjects
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// convert backend list from config into comma-separated string
	backends = strings.Join(cfg.Backends, ",")

	backendList := strings.Split(backends, ",")

	if len(backendList) == 0 {
		log.Fatalf("No backend IPs found")
	}

	// populate BPF backend map
	for i, backend := range backendList {

		backend = strings.TrimSpace(backend)

		backIP, err := parseIPv4(backend)
		if err != nil {
			log.Fatalf("Invalid backend IP %q: %v", backend, err)
		}

		backEp := lbBackend{
			Ip:    backIP,
			Conns: 0,
		}

		if err := objs.lbMaps.Backends.Put(uint32(i), &backEp); err != nil {
			log.Fatalf("Error adding backend #%d (%s) to eBPF map: %v", i, backend, err)
		}

		log.Printf("Added backend #%d: %s", i, backend)
	}

	// store backend count in BPF map so XDP program knows how many exist
	count := uint32(len(backendList))
	key := uint32(0)

	if err := objs.lbMaps.BackendCount.Put(key, count); err != nil {
		log.Fatalf("Failed to update backend count map: %v", err)
	}

	// find interface index
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// attach XDP program to the interface
	xdplink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()

	log.Println("XDP Load Balancer successfully attached and running")

	// interactive CLI loop running in separate goroutine
	reader := bufio.NewReader(os.Stdin)

	go func() {

		for {

			select {

			case <-ctx.Done():
				return

			default:

				fmt.Print("lb> ")

				line, err := reader.ReadString('\n')
				if err != nil {
					continue
				}

				line = strings.TrimSpace(line)
				parts := strings.Fields(line)

				if len(parts) == 0 {
					continue
				}

				switch parts[0] {

				case "add":

					if len(parts) != 2 {
						fmt.Println("usage: add <ip>")
						continue
					}

					addBackend(&objs, parts[1])

				case "del":

					if len(parts) != 2 {
						fmt.Println("usage: del <ip>")
						continue
					}

					deleteBackend(&objs, parts[1])

				case "list":

					listBackends(&objs)

				default:

					fmt.Println("commands: add <ip>, del <ip>, list")
				}
			}
		}

	}()

	// wait for ControlC
	<-ctx.Done()

	log.Println("Received signal, exiting...")
}
