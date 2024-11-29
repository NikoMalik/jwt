package jwt

import (
	"crypto"
	"fmt"
	"unsafe"

	"github.com/klauspost/cpuid/v2"
)

func init() {
	if !SupportedCPU() {
		fmt.Errorf("unsupported CPU")
		return
	}

	// // possible solution to escape zen1/zen2 (need more tests with zen1/zen2)
	// if useAVX2 {
	// 	if _CPU_.VendorID == cpuid.AMD {
	// 		copyFunc = copy_AMD_AVX2_32
	// 	} else {
	// 		copyFunc = copy_AVX2_32
	// 	}
	// } else {
	// 	copyFunc = memmoveCopy
	// }
	//
	crypto.RegisterHash(crypto.SHA512, _Newi_)

}

func memmoveCopy(dst, src []byte) int {

	memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))
	return len(src)
}

func SupportedCPU() bool {
	return _CPU_.HasAll(wantFeatures)
}

//go:linkname memmove runtime.memmove
func memmove(dst, src unsafe.Pointer, n uintptr)

var (
	_CPU_        = cpuid.CPU
	wantFeatures = cpuid.CombineFeatures(cpuid.AVX2, cpuid.CLMUL, cpuid.BMI2)
)
