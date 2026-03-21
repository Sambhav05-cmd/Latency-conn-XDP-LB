package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
)

// ── config types (match the JSON structure exactly) ───────────────────────────

type backendCfg struct {
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
	Weight uint16 `json:"weight"`
}

type serviceCfg struct {
	VIP  string `json:"vip"`
	Port uint16 `json:"port"`
}

type config struct {
	Service  serviceCfg   `json:"service"`
	Backends []backendCfg `json:"backends"`
}

// ── shared helpers ────────────────────────────────────────────────────────────

// NOTE: htons is declared in backend.go — do not redeclare it here.

func parseIPv4Cfg(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %q", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

const (
    pinDir      = "/sys/fs/bpf/lbxdp"
    sentinelPath = "/run/lbxdp.mode"  // outside bpffs, normal file
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
    // Write sentinel outside bpffs — bpffs is mode=700 and rejects
    // regular file writes even from root in some kernel configurations.
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

func defaultWeight(w uint16) uint16 {
	if w == 0 {
		return 1
	}
	return w
}

// ── EST variant (lb3 / lb_wlc_est.c) ─────────────────────────────────────────

type wlcEstVariant struct {
	objs lb3Objects
}

func newWlcEstVariant() (*wlcEstVariant, error) {
	v := &wlcEstVariant{}
	if err := loadLb3Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wlc-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb3Maps.Backends,
		pinDir + "/backend_count": v.objs.lb3Maps.BackendCount,
		pinDir + "/services":      v.objs.lb3Maps.Services,
	}, "wlc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wlcEstVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wlcEstVariant) Close()                 { v.objs.Close() }

func (v *wlcEstVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb3Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	// Register the VIP service from config.
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}

	// Register backends from config.
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lb3Backend{
			Ip:     ip,
			Port:   htons(b.Port),
			Conns:  0,
			Weight: defaultWeight(b.Weight),
		}
		if err := v.objs.lb3Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}

	cnt := uint32(len(cfg.Backends))
	if err := v.objs.lb3Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update backend_count: %w", err)
	}
	return nil
}

func (v *wlcEstVariant) UpdateWeight(ip string, port, weight uint16) error {
	return wlcUpdateWeight(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount, ip, port, weight)
}

func (v *wlcEstVariant) AddBackend(ip string, port, weight uint16) error {
	return wlcAddBackend(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount, ip, port, weight,
		func(ip uint32, port, weight uint16) interface{} {
			return lb3Backend{Ip: ip, Port: port, Conns: 0, Weight: weight}
		})
}

func (v *wlcEstVariant) DeleteBackend(ip string, port uint16) error {
	return wlcDeleteBackend(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount, ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb3Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		})
}

func (v *wlcEstVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb3IpPort{Ip: pip, Port: htons(port)}
	val := true
	if err := v.objs.lb3Maps.Services.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("add service %s:%d: %w", ip, port, err)
	}
	return nil
}

func (v *wlcEstVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb3IpPort{Ip: pip, Port: htons(port)}
	if err := v.objs.lb3Maps.Services.Delete(&key); err != nil {
		return fmt.Errorf("delete service %s:%d: %w", ip, port, err)
	}
	return nil
}

// ── SYN variant (lb4 / lb_wlc_syn.c) ─────────────────────────────────────────

type wlcSynVariant struct {
	objs lb4Objects
}

func newWlcSynVariant() (*wlcSynVariant, error) {
	v := &wlcSynVariant{}
	if err := loadLb4Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wlc-syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb4Maps.Backends,
		pinDir + "/backend_count": v.objs.lb4Maps.BackendCount,
		pinDir + "/services":      v.objs.lb4Maps.Services,
	}, "wlc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wlcSynVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wlcSynVariant) Close()                 { v.objs.Close() }

func (v *wlcSynVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb4Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
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
		be := lb4Backend{
			Ip:     ip,
			Port:   htons(b.Port),
			Conns:  0,
			Weight: defaultWeight(b.Weight),
		}
		if err := v.objs.lb4Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}

	cnt := uint32(len(cfg.Backends))
	if err := v.objs.lb4Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update backend_count: %w", err)
	}
	return nil
}

func (v *wlcSynVariant) UpdateWeight(ip string, port, weight uint16) error {
	return wlcUpdateWeight(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount, ip, port, weight)
}

func (v *wlcSynVariant) AddBackend(ip string, port, weight uint16) error {
	return wlcAddBackend(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount, ip, port, weight,
		func(ip uint32, port, weight uint16) interface{} {
			return lb4Backend{Ip: ip, Port: port, Conns: 0, Weight: weight}
		})
}

func (v *wlcSynVariant) DeleteBackend(ip string, port uint16) error {
	return wlcDeleteBackend(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount, ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb4Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		})
}

func (v *wlcSynVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb4IpPort{Ip: pip, Port: htons(port)}
	val := true
	if err := v.objs.lb4Maps.Services.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("add service %s:%d: %w", ip, port, err)
	}
	return nil
}

func (v *wlcSynVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb4IpPort{Ip: pip, Port: htons(port)}
	if err := v.objs.lb4Maps.Services.Delete(&key); err != nil {
		return fmt.Errorf("delete service %s:%d: %w", ip, port, err)
	}
	return nil
}

// ── generic map helpers ───────────────────────────────────────────────────────

type (
	lookupIPPortFn func(m *ebpf.Map, idx uint32) (ip uint32, port uint16, err error)
	lookupConnsFn  func(m *ebpf.Map, idx uint32) (conns uint32, err error)
	swapFn         func(m *ebpf.Map, dst, src uint32) error
	makeFn         func(ip uint32, port, weight uint16) interface{}
)

func wlcUpdateWeight(backends, countMap *ebpf.Map, ip string, port, weight uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	// lb3Backend and lb4Backend have identical layout so we can use a raw struct.
	type raw struct {
		Ip     uint32
		Port   uint16
		Weight uint16
		Conns  uint32
	}
	for i := uint32(0); i < count; i++ {
		var b raw
		if err := backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			b.Weight = weight
			if err := backends.Update(i, &b, ebpf.UpdateExist); err != nil {
				return fmt.Errorf("update weight: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func wlcAddBackend(backends, countMap *ebpf.Map, ip string, port, weight uint16, make makeFn) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	if weight == 0 {
		weight = 1
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	type raw struct {
		Ip     uint32
		Port   uint16
		Weight uint16
		Conns  uint32
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
	be := make(pip, htons(port), weight)
	if err := backends.Update(count, be, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert backend: %w", err)
	}
	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update count: %w", err)
	}
	return nil
}

func wlcDeleteBackend(backends, countMap *ebpf.Map, ip string, port uint16,
	lookupIPPort lookupIPPortFn, lookupConns lookupConnsFn, swap swapFn) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		bip, bport, err := lookupIPPort(backends, i)
		if err != nil {
			continue
		}
		if bip != pip || bport != htons(port) {
			continue
		}
		conns, err := lookupConns(backends, i)
		if err != nil {
			return fmt.Errorf("lookup conns: %w", err)
		}
		if conns != 0 {
			return fmt.Errorf("backend %s:%d has %d active connections", ip, port, conns)
		}
		last := count - 1
		if i != last {
			if err := swap(backends, i, last); err != nil {
				return fmt.Errorf("swap to fill gap: %w", err)
			}
		}
		if err := backends.Delete(last); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
		count--
		if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("update count: %w", err)
		}
		return nil
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}