// +build !appengine

package gx3

import "unsafe"

var le = func() bool { n := uint16(1); return (*(*[2]byte)(unsafe.Pointer(&n)))[0] == 1 }()

func le32(b []byte) uint32 {
	if le {
		return *(*uint32)(unsafe.Pointer(&b[0]))
	}
	return uint32(b[3])<<24 | uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0])
}

func le64(b []byte) uint64 {
	if le {
		return *(*uint64)(unsafe.Pointer(&b[0]))
	}
	return uint64(b[7])<<56 | uint64(b[6])<<48 | uint64(b[5])<<40 | uint64(b[4])<<32 |
		uint64(b[3])<<24 | uint64(b[2])<<16 | uint64(b[1])<<8 | uint64(b[0])
}
