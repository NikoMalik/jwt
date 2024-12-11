package jwt

import (
	"testing"
	"unsafe"
)

//go test -bench . -benchmem -gcflags '-l -N'  -cpuprofile cpu.prof -memprofile mem.prof -count 3
//
// func BenchmarkStandardCopy_1024(b *testing.B) {
// 	src := alignSlice(MB, 32)
// 	dst := alignSlice(len(src), 32)
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		copy(src, dst)
// 	}
// 	// fmt.Println(src)
// }
//
// func BenchmarkOptimizedCopy_1024(b *testing.B) {
// 	src := alignSlice(MB, 32)
// 	dst := alignSlice(len(src), 32)
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_copy_(src, dst)
// 	}
// 	// fmt.Println(src)
// }
// func BenchmarkCopy_AVX2_1024(b *testing.B) {
// 	src := alignSlice(MB, 32)
// 	dst := alignSlice(len(src), 32)
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		copy_AVX2_1024(src, dst)
// 	}
// 	// fmt.Println(src)
// }

func BenchmarkCopyStandart_512(b *testing.B) {
	src := alignSlice(512, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkAVX2Copy_512(b *testing.B) {
	src := alignSlice(512, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_512(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkStandartCopy_256(b *testing.B) {
	src := make([]byte, 256)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_256(b *testing.B) {
	src := make([]byte, 256)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkCopyAVX2_256(b *testing.B) {
	src := make([]byte, 256)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_128(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkStandardCopy_64(b *testing.B) {
	src := alignSlice(64, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_64(b *testing.B) {
	src := alignSlice(64, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkCopyAVX2_64(b *testing.B) {
	src := alignSlice(64, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_64(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkZEN1_32(b *testing.B) {
	src := alignSlice(32, 16)
	dst := alignSlice(len(src), 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AMD_AVX2_32(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkStandardCopy_32(b *testing.B) {
	src := alignSlice(32, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		memmoveCopy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_32(b *testing.B) {
	src := make([]byte, 32)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkCopyAVX2_32(b *testing.B) {
	src := alignSlice(32, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkCopyAVX2_32_ALIGNED_ARRAY(b *testing.B) {
	src := alignArray_32(32)
	dst := alignArray_32(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(src[:], dst[:])
	}
	// fmt.Println(src)
}

func BenchmarkCopyAVX2_64_Unsafe(b *testing.B) {
	src := alignArray_unsafe_64(32) // Align to 64-byte boundary
	dst := alignArray_unsafe_64(32) // Align to 64-byte boundary
	s := *(*[64]byte)(src)
	d := *(*[64]byte)(dst)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_64(s[:], d[:])
	}
}

func BenchmarkCopyAVX2_64_UNSAFE_NEWSLICE(b *testing.B) {
	src := alignArray_unsafe_64(32)
	dst := alignArray_unsafe_64(32)
	s := t0_slice(src, 64)
	d := t0_slice(dst, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_64(*s, *d)
	}
}

func BenchmarkCopyAligned_64(b *testing.B) {
	src := alignArray_64(32)
	dst := alignArray_64(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_64(src[:], dst[:])

	}
}

func BenchmarkCopyUneligned_64(b *testing.B) {
	src := [64]byte{}
	dst := [64]byte{}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy_AVX2_64(src[:], dst[:])
	}
}

func BenchmarkUnsafeSlice_32(b *testing.B) {
	src := alignSliceWithArray_32_2(32)
	dst := alignSliceWithArray_32_2(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(src, dst)
	}
}

func BenchmarkMySlice_T0_SLICE_32(b *testing.B) {
	src := alignSliceWithArray_32(32)
	dst := alignSliceWithArray_32(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(src, dst)
	}
}

func BenchmarkDefaultSlice_32(b *testing.B) {
	src := make([]byte, 32)
	dst := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(src, dst)
	}
}

func BenchmarkDefaultSlice_2_32(b *testing.B) {
	src := alignSlice(32, 32)
	dst := alignSlice(32, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(src, dst)
	}
}

func BenchmarkDefaultArray_32(b *testing.B) {
	src := [32]byte{}
	dst := [32]byte{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(src[:], dst[:])
	}
}

func BenchmarkDefaultArray_1_32(b *testing.B) {
	stc := [32]byte{}
	dst := [32]byte{}
	s := t0_slice(unsafe.Pointer(&stc), 32)
	d := t0_slice(unsafe.Pointer(&dst), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(*s, *d)
	}
}

func BenchmarkAlignedArray_2_32(b *testing.B) {
	stc := alignArray_32(32)
	dst := alignArray_32(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_32(stc[:], dst[:])
	}
}

// func BenchmarkStandardCopy_16(b *testing.B) {
// 	src := make([]byte, 16)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		copy(src, dst)
// 	}
// 	// fmt.Println(src)
// }
//
// func BenchmarkOptimizedCopy_16(b *testing.B) {
// 	src := make([]byte, 16)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_copy_(src, dst)
// 	}
// 	// fmt.Println(src)
// }

func BenchmarkStandartCopy_128(b *testing.B) {
	src := alignSlice(128, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_128(b *testing.B) {
	src := alignSlice(128, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkAVX2Copy_128(b *testing.B) {
	src := alignSlice(128, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_AVX2_128(src, dst)
	}
	// fmt.Println(src)
}

// func BenchmarkStandardCopy_8(b *testing.B) {
// 	src := make([]byte, 8)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		copy(src, dst)
// 	}
// 	// fmt.Println(src)
// }
//
// func BenchmarkOptimizedCopy_8(b *testing.B) {
// 	src := make([]byte, 8)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_copy_(src, dst)
// 	}
// 	// fmt.Println(src)
// }
//
// func BenchmarkStandardCopy_4(b *testing.B) {
// 	src := make([]byte, 4)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		copy(src, dst)
// 	}
// 	// fmt.Println(src)
// }
//
// func BenchmarkOptimizedCopy_4(b *testing.B) {
// 	src := make([]byte, 4)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_copy_(src, dst)
// 	}
// 	// fmt.Println(src)
// }
//
// func BenchmarkStandardCopy_2(b *testing.B) {
// 	src := make([]byte, 2)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		copy(src, dst)
// 	}
// 	// fmt.Println(src)
// }
//
// func BenchmarkOptimizedCopy_2(b *testing.B) {
// 	src := make([]byte, 2)
// 	dst := make([]byte, len(src))
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_copy_(src, dst)
// 	}
// 	// fmt.Println(src)
// }
