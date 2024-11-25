package jwt

import "unsafe"

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

var _K = [...]uint64{
	0x428a2f98d728ae22,
	0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f,
	0xe9b5dba58189dbbc,
	0x3956c25bf348b538,
	0x59f111f1b605d019,
	0x923f82a4af194f9b,
	0xab1c5ed5da6d8118,
	0xd807aa98a3030242,
	0x12835b0145706fbe,
	0x243185be4ee4b28c,
	0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,
	0x80deb1fe3b1696b1,
	0x9bdc06a725c71235,
	0xc19bf174cf692694,
	0xe49b69c19ef14ad2,
	0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5,
	0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,
	0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4,
	0x76f988da831153b5,
	0x983e5152ee66dfab,
	0xa831c66d2db43210,
	0xb00327c898fb213f,
	0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,
	0xd5a79147930aa725,
	0x06ca6351e003826f,
	0x142929670a0e6e70,
	0x27b70a8546d22ffc,
	0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df,
	0x650a73548baf63de,
	0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6,
	0x92722c851482353b,
	0xa2bfe8a14cf10364,
	0xa81a664bbc423001,
	0xc24b8b70d0f89791,
	0xc76c51a30654be30,
	0xd192e819d6ef5218,
	0xd69906245565a910,
	0xf40e35855771202a,
	0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,
	0x1e376c085141ab53,
	0x2748774cdf8eeb99,
	0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,
	0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,
	0x78a5636f43172f60,
	0x84c87814a1f0ab72,
	0x8cc702081a6439ec,
	0x90befffa23631e28,
	0xa4506cebde82bde9,
	0xbef9a3f7b2c67915,
	0xc67178f2e372532b,
	0xca273eceea26619c,
	0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e,
	0xf57d4f7fee6ed178,
	0x06f067aa72176fba,
	0x0a637dc5a2c898a6,
	0x113f9804bef90dae,
	0x1b710b35131c471b,
	0x28db77f523047d84,
	0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,
	0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec,
	0x6c44198c4a475817,
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func reset_64(slice []byte) []byte {
	_ = slice[64]
	slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[16], slice[17], slice[18], slice[19], slice[20], slice[21], slice[22], slice[23] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[24], slice[25], slice[26], slice[27], slice[28], slice[29], slice[30], slice[31] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[32], slice[33], slice[34], slice[35], slice[36], slice[37], slice[38], slice[39] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[40], slice[41], slice[42], slice[43], slice[44], slice[45], slice[46], slice[47] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[48], slice[49], slice[50], slice[51], slice[52], slice[53], slice[54], slice[55] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[56], slice[57], slice[58], slice[59], slice[60], slice[61], slice[62], slice[63] = 0, 0, 0, 0, 0, 0, 0, 0

	return slice
}

func reset_32(slice []byte) []byte {
	_ = slice[32]
	slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[16], slice[17], slice[18], slice[19], slice[20], slice[21], slice[22], slice[23] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[24], slice[25], slice[26], slice[27], slice[28], slice[29], slice[30], slice[31] = 0, 0, 0, 0, 0, 0, 0, 0

	return slice
}

//go:nosplit
func alignArray_32(alignment int) [32]byte {
	var buf [32 + 31]byte // 31 max padding
	base := uintptr(unsafe.Pointer(&buf[0]))
	offset := base % uintptr(alignment)
	var alignedPtr uintptr
	if offset == 0 {
		alignedPtr = base
	} else {
		alignedPtr = base + uintptr(alignment) - offset
	}

	return *(*[32]byte)(unsafe.Pointer(alignedPtr))
}

//go:nosplit
func alignArray_64(alignment int) [64]byte {

	var buf [64 + 31]byte
	base := uintptr(unsafe.Pointer(&buf[0]))
	offset := int(base % uintptr(alignment))

	var alignedPtr uintptr
	if offset == 0 {
		alignedPtr = base
	} else {
		alignedPtr = base + uintptr(alignment-offset)
	}

	return *(*[64]byte)(unsafe.Pointer(alignedPtr))
}

func alignSlice(size int, alignment int) []byte {
	buf := make([]byte, size+alignment)
	offset := int(uintptr(unsafe.Pointer(&buf[0])) % uintptr(alignment))
	if offset == 0 {
		return buf[:size]
	}
	return buf[alignment-offset : alignment-offset+size]
}

func alignGeneric[T any](size int, alignment int) []T {
	buf := make([]T, size+alignment)
	offset := int(uintptr(unsafe.Pointer(&buf[0])) % uintptr(alignment))
	if offset == 0 {
		return buf[:size]
	}

	return buf[alignment-offset : alignment-offset+size]
}

func BePutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func BeUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

func BeAppendUint64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], BeUint64(b)
}
