// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dukpt

import (
	"bytes"
	"testing"
	"unsafe"
)

// fastXORBytes xors in bulk. It only works on architectures that
// support unaligned read/writes.
func fastXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}

	w := n / wordSize
	if w > 0 {
		dw := *(*[]uintptr)(unsafe.Pointer(&dst))
		aw := *(*[]uintptr)(unsafe.Pointer(&a))
		bw := *(*[]uintptr)(unsafe.Pointer(&b))
		for i := 0; i < w; i++ {
			dw[i] = aw[i] ^ bw[i]
		}
	}

	for i := (n - n%wordSize); i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}

// xorBytes xors the bytes in a and b. The destination is assumed to have enough
// space. Returns the number of bytes xor'd.
func xorBytes(dst, a, b []byte) int {
	if supportsUnaligned {
		return fastXORBytes(dst, a, b)
	}

	// TODO(hanwen): if (dst, a, b) have common alignment
	// we could still try fastXORBytes. It is not clear
	// how often this happens, and it's only worth it if
	// the block encryption itself is hardware
	// accelerated.
	return safeXORBytes(dst, a, b)
}

func TestXOR(t *testing.T) {
	for alignP := 0; alignP < 2; alignP++ {
		for alignQ := 0; alignQ < 2; alignQ++ {
			for alignD := 0; alignD < 2; alignD++ {
				p := make([]byte, 1024)[alignP:]
				q := make([]byte, 1024)[alignQ:]
				d1 := make([]byte, 1024+alignD)[alignD:]
				d2 := make([]byte, 1024+alignD)[alignD:]
				xorBytes(d1, p, q)
				safeXORBytes(d2, p, q)
				if !bytes.Equal(d1, d2) {
					t.Error("not equal")
				}
			}
		}
	}
}
