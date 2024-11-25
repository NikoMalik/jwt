package jwt

import (
	"testing"
)

//go test -bench . -benchmem -gcflags '-l -N'  -cpuprofile cpu.prof -memprofile mem.prof -count 3

func BenchmarkStandardCopy_1024(b *testing.B) {
	src := alignSlice(MB, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_1024(b *testing.B) {
	src := alignSlice(MB, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkAVX2Copy_1024(b *testing.B) {
	src := alignSlice(MB, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy_more_512(src, dst)
	}
	// fmt.Println(src)
}

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
		copy_more_512(src, dst)
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
		copy_AVX2_256(src, dst)
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

func BenchmarkStandardCopy_32(b *testing.B) {
	src := alignSlice(32, 32)
	dst := alignSlice(len(src), 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
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
