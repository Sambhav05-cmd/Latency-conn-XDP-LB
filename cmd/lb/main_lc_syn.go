//go:build lc_syn

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb2 ../../bpf/lb_lc_syn.c

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

type Config struct {
	Backends []string `json:"backends"`
}

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func addBackend(objs *lb2Objects, ip string) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lb2Maps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lb2Backend
		err := objs.lb2Maps.Backends.Lookup(i, &b)
		if err == nil && b.Ip == backIP {
			log.Println("backend already exists:", ip)
			return
		}
	}

	backEp := lb2Backend{
		Ip:    backIP,
		Conns: 0,
	}

	err = objs.lb2Maps.Backends.Put(count, &backEp)
	if err != nil {
		log.Println("failed adding backend:", err)
		return
	}

	count++
	err = objs.lb2Maps.BackendCount.Put(key, count)
	if err != nil {
		log.Println("failed updating backend count:", err)
		return
	}

	log.Println("backend added:", ip)
}

func deleteBackend(objs *lb2Objects, ip string) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lb2Maps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lb2Backend
		err := objs.lb2Maps.Backends.Lookup(i, &b)
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

				var lastBackend lb2Backend
				err := objs.lb2Maps.Backends.Lookup(last, &lastBackend)
				if err == nil {
					objs.lb2Maps.Backends.Put(i, &lastBackend)
				}
			}

			objs.lb2Maps.Backends.Delete(last)

			count--
			objs.lb2Maps.BackendCount.Put(key, count)

			log.Println("backend deleted:", ip)
			return
		}
	}

	log.Println("backend not found:", ip)
}

func listBackends(objs *lb2Objects) {

	var count uint32
	key := uint32(0)

	err := objs.lb2Maps.BackendCount.Lookup(key, &count)
	if err != nil {
		fmt.Println("failed to read backend count")
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lb2Backend
		err := objs.lb2Maps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, b.Ip)

		fmt.Println(i, ip, "conns:", b.Conns)
	}
}

func main() {

	flag.StringVar(&ifname, "i", "lo", "Network interface to attach eBPF programs")

	var configFile string
	flag.StringVar(&configFile, "config", "configs/backends_lc.json", "Backend configuration file")
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

	var objs lb2Objects
	if err := loadLb2Objects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	backends = strings.Join(cfg.Backends, ",")

	backendList := strings.Split(backends, ",")

	if len(backendList) == 0 {
		log.Fatalf("No backend IPs found")
	}

	for i, backend := range backendList {

		backend = strings.TrimSpace(backend)

		backIP, err := parseIPv4(backend)
		if err != nil {
			log.Fatalf("Invalid backend IP %q: %v", backend, err)
		}

		backEp := lb2Backend{
			Ip:    backIP,
			Conns: 0,
		}

		if err := objs.lb2Maps.Backends.Put(uint32(i), &backEp); err != nil {
			log.Fatalf("Error adding backend #%d (%s) to eBPF map: %v", i, backend, err)
		}

		log.Printf("Added backend #%d: %s", i, backend)
	}

	count := uint32(len(backendList))
	key := uint32(0)

	if err := objs.lb2Maps.BackendCount.Put(key, count); err != nil {
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

	<-ctx.Done()

	log.Println("Received signal, exiting...")
}
