package testdata

// #cgo CFLAGS: -std=gnu99
// #include "xxHash/xxhash.c"
// #include "xxHash/xxhash.h"
// #include "xxHash/xxh3.h"
import "C"

import (
	"reflect"
	"unsafe"
)

func XXH3_64bits_withSeed(data []byte, seed uint64) uint64 {
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&data))
	r := C.XXH3_64bits_withSeed(unsafe.Pointer(header.Data), C.size_t(len(data)), C.ulonglong(seed))
	return uint64(r)
}
