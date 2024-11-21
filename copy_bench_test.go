package jwt

import (
	"testing"
)

//go test -bench . -benchmem -gcflags '-l -N'  -cpuprofile cpu.prof -memprofile mem.prof -count 3

func BenchmarkStandardCopy(b *testing.B) {
	src := make([]byte, MB) // 1MB of data
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy(b *testing.B) {
	src := make([]byte, MB)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkStandardCopy_64(b *testing.B) {
	src := make([]byte, 64)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_64(b *testing.B) {
	src := make([]byte, 64)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkStandardCopy_32(b *testing.B) {
	src := make([]byte, 32)
	dst := make([]byte, len(src))

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

func BenchmarkStandardCopy_16(b *testing.B) {
	src := make([]byte, 16)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_16(b *testing.B) {
	src := make([]byte, 16)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkStandardCopy_8(b *testing.B) {
	src := make([]byte, 8)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, dst)
	}
	// fmt.Println(src)
}

func BenchmarkOptimizedCopy_8(b *testing.B) {
	src := make([]byte, 8)
	dst := make([]byte, len(src))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_copy_(src, dst)
	}
	// fmt.Println(src)
}
