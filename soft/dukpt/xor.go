// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dukpt

import (
	"runtime"
	"unsafe"
)

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "amd64" || runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" || runtime.GOARCH == "s390x"

func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// fastXORWords XORs multiples of 4 or 8 bytes (depending on architecture.)
// The arguments are assumed to be of equal length.
func fastXORWords(dst, a, b []byte) {
	dw := *(*[]uintptr)(unsafe.Pointer(&dst))
	aw := *(*[]uintptr)(unsafe.Pointer(&a))
	bw := *(*[]uintptr)(unsafe.Pointer(&b))
	n := len(b) / wordSize
	for i := 0; i < n; i++ {
		dw[i] = aw[i] ^ bw[i]
	}
}

func xorWords(dst, a, b []byte) {
	if supportsUnaligned {
		fastXORWords(dst, a, b)
	} else {
		safeXORBytes(dst, a, b)
	}
}
