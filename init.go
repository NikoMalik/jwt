package jwt

import (
	"crypto"
	"unsafe"

	"github.com/klauspost/cpuid/v2"
)

func init() {

	// possible solution to escape zen1/zen2 (need more tests with zen1/zen2)
	if useAVX2 {
		if isZen1OrZen2(_CPU_) != 0 {
			copyFunc = memmoveCopy
		} else {
			copyFunc = copy_AVX2_32
		}
	} else {
		copyFunc = memmoveCopy
	}

	crypto.RegisterHash(crypto.SHA512, _Newi_)

}

func memmoveCopy(dst, src []byte) int {

	memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))
	return len(src)
}

//go:linkname memmove runtime.memmove
func memmove(dst, src unsafe.Pointer, n uintptr)

var (
	copyFunc func([]byte, []byte) int
	_CPU_    = cpuid.CPU
)
