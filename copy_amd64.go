//go:build amd64 && !purego

package jwt

//test with gcflags="-S"

//go:noescape
func _copy_(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_32(src []byte, src2 []byte) int

//go:noescape
func copy_AMD_AVX2_32(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_64(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_128(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_256(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_512(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_1024(src []byte, src2 []byte) int

func ExportingAVX2_32(src []byte, src2 []byte) int {
	return copy_AVX2_32(src, src2)
}

func ExportingAVX2_64(src []byte, src2 []byte) int {
	return copy_AVX2_64(src, src2)
}

func ExportingAVX2_128(src []byte, src2 []byte) int {
	return copy_AVX2_128(src, src2)
}

func ExportingAVX2_256(src []byte, src2 []byte) int {
	return copy_AVX2_256(src, src2)
}

func ExportingAVX2_512(src []byte, src2 []byte) int {
	return copy_AVX2_512(src, src2)
}

func ExportingAVX2_1024(src []byte, src2 []byte) int {
	return copy_AVX2_1024(src, src2)
}
