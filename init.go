package jwt

import (
	"crypto"
	"fmt"
	"hash"
	"unsafe"

	"github.com/klauspost/cpuid/v2"
)

func init() {
	if !SupportedCPU() {
		fmt.Errorf("unsupported CPU")
		return
	}
	sha512Pool = nObjPool[hash.Hash](1, func() hash.Hash {
		return _Newi_()
	},
	)

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

type HashBorrower[T hash.Hash] struct {
	pool     *objPool[hash.Hash]
	borrowed []hash.Hash
}

func (h *HashBorrower[T]) Borrow() hash.Hash {
	hasher := h.pool.Get()
	h.borrowed = append(h.borrowed, hasher)
	hasher.Reset()
	return hasher
}

func (h *HashBorrower[T]) ReturnAll() {
	for i := 0; i < len(h.borrowed); i++ {
		h.pool.Put(h.borrowed[i])
	}

	h.borrowed = nil
}
