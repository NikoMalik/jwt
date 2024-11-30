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

func cop_32(src []byte, src2 []byte) int {

	return memmoveCopy(src, src2)
}
func cop_64(src []byte, src2 []byte) int {
	if useAVX2 {
		return copy_AVX2_64(src, src2)
	} else {
		return copy(src, src2)
	}
}

func cop_128(src []byte, src2 []byte) int {
	if useAVX2 {
		return copy_AVX2_128(src, src2)
	} else {
		return copy(src, src2)
	}
}
