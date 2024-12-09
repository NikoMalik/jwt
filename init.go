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
		buf := []byte{base64BufferSize: 0}
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

const (
	base64BufferSize = 64 * KB
)

var (
	alignedPool = nObjPool[*AlignedBuffer](4, func() *AlignedBuffer {
		buf := NewAlignedBuffer()
		return buf
	})

	bufferPool    *objPool[*[]byte]
	base64BufPool *objPool[*[]byte]
	signaturePool *objPool[[]byte]
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

type AlignedBuffer struct {
	buf []byte
}

func NewAlignedBuffer() *AlignedBuffer {
	buf := lowlevelfunctions.MakeNoZero(128)

	copy_AVX2_64(buf[:64], alignSliceWithArray_64(32))
	copy_AVX2_64(buf[64:], alignSliceWithArray_64(32))

	return &AlignedBuffer{
		buf: buf,
	}

}

func (b *AlignedBuffer) GetInput() []byte {
	if len(b.buf) < 64 {
		panic("buffer too small in GetInput")
	}

	return b.buf[:64]
}
func (b *AlignedBuffer) Reset() {
	reset_64(b.buf[:64])
	reset_64(b.buf[64:])
}

func (b *AlignedBuffer) GetInput32() []byte {
	if len(b.buf) < 32 {
		panic("buffer too small in GetInput32")
	}

	return b.buf[:32]
}

//output

func (b *AlignedBuffer) GetOutput() []byte {
	if len(b.buf) < 64 {
		panic("buffer too small in GetOutput")
	}
	return b.buf[64:]
}

func (b *AlignedBuffer) GetOutput32() []byte {
	if len(b.buf) < 32 {
		panic("buffer too small in GetOutput32")

	}
	return b.buf[96:]
}

func (b *AlignedBuffer) Bytes() []byte {
	return b.buf
}

func (b *AlignedBuffer) Reset64_input() {

	reset_64(b.buf[:64])
}

func (b *AlignedBuffer) Reset32_input() {
	reset_32(b.buf[:32])
}

func (b *AlignedBuffer) Reset64_output() {
	reset_64(b.buf[64:])
}

func (b *AlignedBuffer) Reset32_output() {
	reset_32(b.buf[32:])
}

func (b *AlignedBuffer) WriteToInput(b2 []byte) {
	copy_AVX2_64(b.buf[:64], b2)
}

func (b *AlignedBuffer) WriteToInput32(b2 []byte) {
	copy_AVX2_32(b.buf[:32], b2)
}

func (b *AlignedBuffer) WriteToOutput(b2 []byte) {
	copy_AVX2_64(b.buf[64:], b2)
}

func (b *AlignedBuffer) WriteToOutput32(b2 []byte) {
	copy_AVX2_32(b.buf[96:], b2)
}

func (b AlignedBuffer) WriteResult() []byte {
	result := b.GetOutput()
	copy_AVX2_64(result, b.buf[64:])
	return result
}

func (b AlignedBuffer) WriteResult32() []byte {
	result := b.GetOutput32()
	copy_AVX2_32(result, b.buf[96:])
	return result
}
