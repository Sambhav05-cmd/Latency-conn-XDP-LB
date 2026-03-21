package main

import (
	"encoding/binary"
	"net"
)

func parseIPv4Must(s string) uint32 {
	ip := net.ParseIP(s).To4()
	return binary.LittleEndian.Uint32(ip)
}

func updateBackend(objs any, ip string, port uint16, weight uint16) {

	keyIP := parseIPv4Must(ip)

	switch o := objs.(type) {

	case *lb3Objects:

		var count uint32
		o.lb3Maps.BackendCount.Lookup(uint32(0), &count)

		for i := uint32(0); i < count; i++ {
			var b lb3Backend
			o.lb3Maps.Backends.Lookup(i, &b)
			if b.Ip == keyIP && b.Port == htons(port) {
				b.Weight = weight
				o.lb3Maps.Backends.Update(i, &b, 0)
				return
			}
		}

	case *lb4Objects:

		var count uint32
		o.lb4Maps.BackendCount.Lookup(uint32(0), &count)

		for i := uint32(0); i < count; i++ {
			var b lb4Backend
			o.lb4Maps.Backends.Lookup(i, &b)
			if b.Ip == keyIP && b.Port == htons(port) {
				b.Weight = weight
				o.lb4Maps.Backends.Update(i, &b, 0)
				return
			}
		}
	}
}

func htons(p uint16) uint16 {
	return (p<<8)&0xff00 | p>>8
}
