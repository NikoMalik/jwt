package jwt

import (
	"crypto/subtle"
	"encoding/base64"
	"testing"
	"unsafe"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

const (
	alignment = 32
	paramB    = 256 / 8
)

var (
	_K = [...]uint64{
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
	lowerCase = [256]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}
)

//go:nosplit
//go:noinline
func clamp(k *[64]byte) {
	k[0] &= 248
	k[paramB-1] = (k[paramB-1] & 127) | 64
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func base64Encode(dst, src []byte) {
	base64.RawURLEncoding.Encode(dst, src)
}

func base64Decode(dst, src []byte) (n int, err error) {
	return base64.RawURLEncoding.Decode(dst, src)
}

func base64DecodeLen(n int) int {
	return base64.RawURLEncoding.DecodedLen(n)
}

func base64EncodedLen(n int) int {
	return base64.RawURLEncoding.EncodedLen(n)
}

func constTimeEqual(a, b string) bool {
	aBytes := lowlevelfunctions.StringToBytes(a)
	bBytes := lowlevelfunctions.StringToBytes(b)

	if len(aBytes) != len(bBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(
		aBytes,
		bBytes,
	) == 1
}

func mustOk(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

//go:nosplit
//go:noescape
func MoreStack(size uintptr)

func mustok(err error) {
	if err != nil {
		panic(err)
	}
}

func mustFail(t *testing.T, err error) {
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func mustEqual(t *testing.T, got, want interface{}) {
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func reset_64(slice []byte) []byte {
	_ = slice[63]
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
	_ = slice[31]
	slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[16], slice[17], slice[18], slice[19], slice[20], slice[21], slice[22], slice[23] = 0, 0, 0, 0, 0, 0, 0, 0
	slice[24], slice[25], slice[26], slice[27], slice[28], slice[29], slice[30], slice[31] = 0, 0, 0, 0, 0, 0, 0, 0

	return slice
}

func alignArray_32() [32]byte {
	var buf [32 + 31]byte // 31 max padding
	// base := uintptr(unsafe.Pointer(&buf[0]))
	offset := uintptr(unsafe.Pointer(&buf[0])) % uintptr(alignment)
	var alignedPtr unsafe.Pointer
	if offset == 0 {
		alignedPtr = unsafe.Pointer(&buf[0])
	} else {
		alignedPtr = unsafe.Pointer(uintptr((unsafe.Pointer(&buf[0]))) + uintptr(alignment) - offset)
	}

	return *(*[32]byte)(noescape(unsafe.Pointer(alignedPtr)))
}

func alignArray_64() [64]byte {

	var buf [64 + 32]byte

	offset := uintptr(unsafe.Pointer(&buf[0])) % uintptr(alignment)

	var alignedPtr unsafe.Pointer
	if offset == 0 {
		alignedPtr = unsafe.Pointer(&buf[0])

	} else {
		alignedPtr = unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(alignment) - offset)
	}

	return *(*[64]byte)(noescape(unsafe.Pointer(alignedPtr)))
}

func alignArray_unsafe_32() unsafe.Pointer {
	var buf [32 + 32]byte
	offset := uintptr(unsafe.Pointer(&buf[0])) % uintptr(alignment)

	var alignedPtr unsafe.Pointer
	if offset == 0 {
		alignedPtr = unsafe.Pointer(&buf[0])
	} else {
		alignedPtr = unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(alignment) - offset)
	}

	return noescape(alignedPtr)
}

//go:nosplit
//go:nocheckptr
func noescapeBytes(s *[]byte) []byte {
	return *(*[]byte)(noescape(unsafe.Pointer(s)))
}

//go:nosplit
//go:nocheckptr
func noescapeBytesReturnPointer(s *[]byte) *[]byte {
	return (*[]byte)(noescape(unsafe.Pointer(s)))
}

//go:nosplit
//go:nocheckptr
func noescape_64_array(s *[64]byte) [64]byte {
	return *(*[64]byte)(noescape(unsafe.Pointer(s)))
}

func noescape_64_array_Pointer(s *[64]byte) *[64]byte {
	return (*[64]byte)(noescape(unsafe.Pointer(s)))
}

//go:nosplit
//go:nocheckptr
func noescapeN[T any](s *T) T {
	return *(*T)(noescape(unsafe.Pointer(s)))
}

//go:nosplit
//go:nocheckptr
func noescapeP[T any](s *T) *T {
	return (*T)(noescape(unsafe.Pointer(s)))
}

func alignArray_unsafe_64() unsafe.Pointer {
	var buf [64 + 32]byte
	offset := uintptr(unsafe.Pointer(&buf[0])) % uintptr(alignment)

	var alignedPtr unsafe.Pointer
	if offset == 0 {
		alignedPtr = unsafe.Pointer(&buf[0])
	} else {
		alignedPtr = unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(alignment) - offset)
	}

	return noescape(alignedPtr)
}

//go:nosplit
//go:nocheckptr
func noescape(up unsafe.Pointer) unsafe.Pointer {
	x := uintptr(up)
	return unsafe.Pointer(x ^ 0)
}

type slice_example struct {
	data unsafe.Pointer
	len  int
	cap  int
}

func GuardSlice(buf *[]byte, n int) {
	c := cap(*buf)
	l := len(*buf)
	if c-l < n {
		c = c>>1 + n + l
		if c < 32 {
			c = 32
		}
		tmp := make([]byte, l, c)
		copy(tmp, *buf)
		*buf = tmp
	}
}

func t0_slice(array unsafe.Pointer, lent int) []byte {
	headerSlice := slice_example{
		len:  lent,
		cap:  lent,
		data: array,
	}
	return *(*[]byte)(noescape(unsafe.Pointer(&headerSlice)))
}

//go:noinline
func swap[T any](a, b *T) {
	tmp := *a // Save the value of *a in a temporary variable
	*a = *b   // Assign the value of *b to *a
	*b = tmp  // Assign the saved value of *a to *b
}

func alignSlice(size int, alignment int) []byte {
	buf := lowlevelfunctions.MakeNoZero(size + alignment)
	offset := int(uintptr(unsafe.Pointer(&buf[0])) % uintptr(alignment))
	if offset == 0 {
		return buf[:size]
	}
	return buf[alignment-offset : alignment-offset+size]
}

func alignSliceWithArray_32_2(alignment int) []byte {
	array := alignArray_unsafe_32()
	return unsafe.Slice((*byte)(array), 32)
}

//go:nosplit
func alignSliceWithArray_32(alignment int) []byte {
	array := noescape(alignArray_unsafe_32())
	return t0_slice(array, 32)
}

//go:nosplit
func alignSliceWithArray_64(alignment int) []byte {
	array := noescape(alignArray_unsafe_64())
	return t0_slice(array, 64)
}

func alignSliceWithArray_64_2(alignment int) []byte {
	array := alignArray_unsafe_64()
	return unsafe.Slice((*byte)(array), 64)
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

func _putuint64(p unsafe.Pointer, v uint64) {
	b := (*[8]byte)(p)

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
