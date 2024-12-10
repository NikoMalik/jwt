package jwt

import (
	"crypto"
	"crypto/sha512"
	"fmt"
	"hash"
	"unsafe"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
	"github.com/klauspost/cpuid/v2"
)

func init() {
	if !SupportedCPU() {
		fmt.Errorf("unsupported CPU")
		return
	}
	sha512Pool = nObjPool[hash.Hash](4, func() hash.Hash {
		return _Newi_()
	},
	)
	base64BufPool = nObjPool[*[]byte](2, func() *[]byte {
		buf := alignSlice(base64BufferSize, 32)
		return &buf

	})

	digestPool = nObjPool[[]byte](4, func() []byte {
		digest := lowlevelfunctions.MakeNoZeroCap(0, sha512.Size)
		return digest
	})

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

const base64BufferSize = 64 * KB

var (
	base64BufPool *objPool[*[]byte]
	_CPU_         = cpuid.CPU
	wantFeatures  = cpuid.CombineFeatures(cpuid.AVX2, cpuid.CLMUL, cpuid.BMI2)
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
