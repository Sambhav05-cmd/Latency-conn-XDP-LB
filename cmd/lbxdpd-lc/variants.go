package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
)

type backendCfg struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type serviceCfg struct {
	VIP  string `json:"vip"`
	Port uint16 `json:"port"`
}

type config struct {
	Service  serviceCfg   `json:"service"`
	Backends []backendCfg `json:"backends"`
}

func parseIPv4Cfg(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %q", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func htons(p uint16) uint16 { return (p<<8)&0xff00 | p>>8 }

const (
	pinDir       = "/sys/fs/bpf/lbxdp"
	sentinelPath = "/run/lbxdp.mode"
)

func pinMaps(pins map[string]*ebpf.Map, modeName string) error {
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", pinDir, err)
	}
	for path, m := range pins {
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin %s: %w", path, err)
		}
	}
	return os.WriteFile(sentinelPath, []byte(modeName), 0644)
}

func loadConfig(cfgPath string) (config, error) {
	var cfg config
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", cfgPath, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", cfgPath, err)
	}
	return cfg, nil
}

// lcAddBackend and lcDeleteBackend are shared by both est and syn variants.
// backends is a BPF_MAP_TYPE_ARRAY — no Delete, zero the last slot instead.

func lcAddBackend(backends, countMap *ebpf.Map, ip string, port uint16,
	makeEntry func(ip uint32, port uint16) interface{}) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	// Duplicate check using raw layout (Ip uint32, Port uint16, _pad uint16, Conns uint32).
	type raw struct {
		Ip   uint32
		Port uint16
		_    uint16
		Conns uint32
	}
	for i := uint32(0); i < count; i++ {
		var b raw
		if err := backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			return fmt.Errorf("backend %s:%d already exists", ip, port)
		}
	}
	be := makeEntry(pip, htons(port))
	if err := backends.Update(count, be, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert backend: %w", err)
	}
	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update count: %w", err)
	}
	return nil
}

func lcDeleteBackend(backends, countMap *ebpf.Map, ip string, port uint16,
	zeroEntry func() interface{},
	swapEntry func(m *ebpf.Map, dst, src uint32) error,
	getConns func(m *ebpf.Map, idx uint32) (uint32, error),
	getIPPort func(m *ebpf.Map, idx uint32) (uint32, uint16, error)) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		bip, bport, err := getIPPort(backends, i)
		if err != nil {
			continue
		}
		if bip != pip || bport != htons(port) {
			continue
		}
		conns, err := getConns(backends, i)
		if err != nil {
			return fmt.Errorf("lookup conns: %w", err)
		}
		if conns != 0 {
			return fmt.Errorf("backend %s:%d has %d active connections", ip, port, conns)
		}
		last := count - 1
		if i != last {
			if err := swapEntry(backends, i, last); err != nil {
				return fmt.Errorf("swap: %w", err)
			}
		}
		// Array map — zero the last slot instead of deleting.
		if err := backends.Update(last, zeroEntry(), ebpf.UpdateExist); err != nil {
			return fmt.Errorf("zero last slot: %w", err)
		}
		count--
		if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("update count: %w", err)
		}
		return nil
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

// ── EST variant ───────────────────────────────────────────────────────────────

type estVariant struct {
	objs lbObjects
}

func newEstVariant() (*estVariant, error) {
	v := &estVariant{}
	if err := loadLbObjects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lbMaps.Backends,
		pinDir + "/backend_count": v.objs.lbMaps.BackendCount,
		pinDir + "/services":      v.objs.lbMaps.Services,
	}, "lc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *estVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *estVariant) Close()                 { v.objs.Close() }

func (v *estVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lbMaps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lbBackend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lbMaps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	if err := v.objs.lbMaps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update backend_count: %w", err)
	}
	return nil
}

func (v *estVariant) AddBackend(ip string, port uint16) error {
	return lcAddBackend(v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount, ip, port,
		func(ip uint32, port uint16) interface{} {
			return &lbBackend{Ip: ip, Port: port, Conns: 0}
		})
}

func (v *estVariant) DeleteBackend(ip string, port uint16) error {
	return lcDeleteBackend(v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount, ip, port,
		func() interface{} { return &lbBackend{} },
		func(m *ebpf.Map, dst, src uint32) error {
			var b lbBackend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		})
}

func (v *estVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lbIpPort{Ip: pip, Port: htons(port)}
	val := true
	if err := v.objs.lbMaps.Services.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("add service %s:%d: %w", ip, port, err)
	}
	return nil
}

func (v *estVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lbIpPort{Ip: pip, Port: htons(port)}
	if err := v.objs.lbMaps.Services.Delete(&key); err != nil {
		return fmt.Errorf("delete service %s:%d: %w", ip, port, err)
	}
	return nil
}

// ── SYN variant ───────────────────────────────────────────────────────────────

type synVariant struct {
	objs lb2Objects
}

func newSynVariant() (*synVariant, error) {
	v := &synVariant{}
	if err := loadLb2Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb2Maps.Backends,
		pinDir + "/backend_count": v.objs.lb2Maps.BackendCount,
		pinDir + "/services":      v.objs.lb2Maps.Services,
	}, "lc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *synVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *synVariant) Close()                 { v.objs.Close() }

func (v *synVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb2Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lb2Backend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lb2Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	if err := v.objs.lb2Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update backend_count: %w", err)
	}
	return nil
}

func (v *synVariant) AddBackend(ip string, port uint16) error {
	return lcAddBackend(v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount, ip, port,
		func(ip uint32, port uint16) interface{} {
			return &lb2Backend{Ip: ip, Port: port, Conns: 0}
		})
}

func (v *synVariant) DeleteBackend(ip string, port uint16) error {
	return lcDeleteBackend(v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount, ip, port,
		func() interface{} { return &lb2Backend{} },
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb2Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		})
}

func (v *synVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb2IpPort{Ip: pip, Port: htons(port)}
	val := true
	if err := v.objs.lb2Maps.Services.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("add service %s:%d: %w", ip, port, err)
	}
	return nil
}

func (v *synVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb2IpPort{Ip: pip, Port: htons(port)}
	if err := v.objs.lb2Maps.Services.Delete(&key); err != nil {
		return fmt.Errorf("delete service %s:%d: %w", ip, port, err)
	}
	return nil
}