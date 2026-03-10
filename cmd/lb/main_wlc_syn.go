//go:build wlc_syn
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb4 ../../bpf/lb_wlc_syn.c

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

var (
	ifname   string
	backends string
)

type BackendConfig struct {
	IP     string `json:"ip"`
	Weight uint32 `json:"weight"`
}

type Config struct {
	Backends []BackendConfig `json:"backends"`
}

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func addBackend(objs *lb4Objects, ip string, weight uint32) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lb4Maps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
		if err == nil && b.Ip == backIP {
			log.Println("backend already exists:", ip)
			return
		}
	}

	backEp := lb4Backend{
		Ip:     backIP,
		Conns:  0,
		Weight: weight,
	}

	err = objs.lb4Maps.Backends.Put(count, &backEp)
	if err != nil {
		log.Println("failed adding backend:", err)
		return
	}

	count++
	err = objs.lb4Maps.BackendCount.Put(key, count)
	if err != nil {
		log.Println("failed updating backend count:", err)
		return
	}

	log.Println("backend added:", ip)
}

func deleteBackend(objs *lb4Objects, ip string) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lb4Maps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		if b.Ip == backIP {

			if b.Conns != 0 {
				log.Println("cannot delete backend, active connections:", b.Conns)
				return
			}

			last := count - 1

			if i != last {

				var lastBackend lb4Backend
				err := objs.lb4Maps.Backends.Lookup(last, &lastBackend)
				if err == nil {
					objs.lb4Maps.Backends.Put(i, &lastBackend)
				}
			}

			objs.lb4Maps.Backends.Delete(last)

			count--
			objs.lb4Maps.BackendCount.Put(key, count)

			log.Println("backend deleted:", ip)
			return
		}
	}

	log.Println("backend not found:", ip)
}

func updateBackend(objs *lb4Objects, ip string, weight uint32) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lb4Maps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		if b.Ip == backIP {

			b.Weight = weight

			err = objs.lb4Maps.Backends.Put(i, &b)
			if err != nil {
				log.Println("failed updating backend weight:", err)
				return
			}

			log.Println("backend weight updated:", ip, "weight:", weight)
			return
		}
	}

	log.Println("backend not found:", ip)
}

func listBackends(objs *lb4Objects) {

	var count uint32
	key := uint32(0)

	err := objs.lb4Maps.BackendCount.Lookup(key, &count)
	if err != nil {
		fmt.Println("failed to read backend count")
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, b.Ip)

		fmt.Println(i, ip, "conns:", b.Conns, "weight:", b.Weight)
	}
}

func main() {

	flag.StringVar(&ifname, "i", "lo", "Network interface to attach eBPF programs")

	var configFile string
	flag.StringVar(&configFile, "config", "configs/backends_wlc.json", "Backend configuration file")
	flag.Parse()

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs lb4Objects
	if err := loadLb4Objects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	for i, backend := range cfg.Backends {

		backIP, err := parseIPv4(strings.TrimSpace(backend.IP))
		if err != nil {
			log.Fatalf("Invalid backend IP %q: %v", backend.IP, err)
		}

		backEp := lb4Backend{
			Ip:     backIP,
			Conns:  0,
			Weight: backend.Weight,
		}

		if err := objs.lb4Maps.Backends.Put(uint32(i), &backEp); err != nil {
			log.Fatalf("Error adding backend #%d (%s) to eBPF map: %v", i, backend.IP, err)
		}

		log.Printf("Added backend #%d: %s weight=%d", i, backend.IP, backend.Weight)
	}

	count := uint32(len(cfg.Backends))
	key := uint32(0)

	if err := objs.lb4Maps.BackendCount.Put(key, count); err != nil {
		log.Fatalf("Failed to update backend count map: %v", err)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

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

					if len(parts) != 3 {
						fmt.Println("usage: add <ip> <weight>")
						continue
					}

					var w uint32
					fmt.Sscanf(parts[2], "%d", &w)

					addBackend(&objs, parts[1], w)

				case "del":

					if len(parts) != 2 {
						fmt.Println("usage: del <ip>")
						continue
					}

					deleteBackend(&objs, parts[1])

				case "update":

					if len(parts) != 3 {
						fmt.Println("usage: update <ip> <weight>")
						continue
					}

					var w uint32
					fmt.Sscanf(parts[2], "%d", &w)

					updateBackend(&objs, parts[1], w)

				case "list":

					listBackends(&objs)

				default:

					fmt.Println("commands: add <ip> <weight>, del <ip>, update <ip> <weight>, list")
				}
			}
		}

	}()

	<-ctx.Done()

	log.Println("Received signal, exiting...")
}
