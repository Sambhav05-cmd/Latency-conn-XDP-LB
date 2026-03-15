//go:build lc_est
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb ../../bpf/lb_lc_est.c

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
	"strconv"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	ifname   string
	backends string
)

type BackendEntry struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type Config struct {
	Backends []BackendEntry `json:"backends"`
}

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func htons(port uint16) uint16 {
	return (port << 8) | (port >> 8)
}

func addBackend(objs *lbObjects, ip string, port uint16) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {
		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err == nil && b.Ip == backIP && b.Port == htons(port) {
			log.Println("backend already exists:", ip, port)
			return
		}
	}

	backEp := lbBackend{
		Ip:    backIP,
		Port:  htons(port),
		Conns: 0,
	}

	err = objs.lbMaps.Backends.Put(count, &backEp)
	if err != nil {
		log.Println("failed adding backend:", err)
		return
	}

	count++
	err = objs.lbMaps.BackendCount.Put(key, count)
	if err != nil {
		log.Println("failed updating backend count:", err)
		return
	}

	log.Println("backend added:", ip, port)
}

func deleteBackend(objs *lbObjects, ip string, port uint16) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		if b.Ip == backIP && b.Port == htons(port) {

			if b.Conns != 0 {
				log.Println("cannot delete backend, active connections:", b.Conns)
				return
			}

			last := count - 1

			if i != last {
				var lastBackend lbBackend
				err := objs.lbMaps.Backends.Lookup(last, &lastBackend)
				if err == nil {
					objs.lbMaps.Backends.Put(i, &lastBackend)
				}
			}

			objs.lbMaps.Backends.Delete(last)

			count--
			objs.lbMaps.BackendCount.Put(key, count)

			log.Println("backend deleted:", ip, port)
			return
		}
	}

	log.Println("backend not found:", ip, port)
}

func listBackends(objs *lbObjects) {

	var count uint32
	key := uint32(0)

	err := objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		fmt.Println("failed to read backend count")
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, b.Ip)

		fmt.Println(i, ip, "port:", htons(b.Port), "conns:", b.Conns)
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

	var objs lbObjects
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	for i, backend := range cfg.Backends {

		backIP, err := parseIPv4(backend.IP)
		if err != nil {
			log.Fatalf("Invalid backend IP %q: %v", backend.IP, err)
		}

		backEp := lbBackend{
			Ip:    backIP,
			Port:  htons(backend.Port),
			Conns: 0,
		}

		if err := objs.lbMaps.Backends.Put(uint32(i), &backEp); err != nil {
			log.Fatalf("Error adding backend #%d to eBPF map: %v", i, err)
		}

		log.Printf("Added backend #%d: %s:%d", i, backend.IP, backend.Port)
	}

	count := uint32(len(cfg.Backends))
	key := uint32(0)

	if err := objs.lbMaps.BackendCount.Put(key, count); err != nil {
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
						fmt.Println("usage: add <ip> <port>")
						continue
					}

					p, err := strconv.Atoi(parts[2])
					if err != nil {
						fmt.Println("invalid port")
						continue
					}

					addBackend(&objs, parts[1], uint16(p))

				case "del":

					if len(parts) != 3 {
						fmt.Println("usage: del <ip> <port>")
						continue
					}

					p, err := strconv.Atoi(parts[2])
					if err != nil {
						fmt.Println("invalid port")
						continue
					}

					deleteBackend(&objs, parts[1], uint16(p))

				case "list":

					listBackends(&objs)

				default:

					fmt.Println("commands: add <ip> <port>, del <ip> <port>, list")
				}
			}
		}

	}()

	<-ctx.Done()

	log.Println("Received signal, exiting...")
}