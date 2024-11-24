//go:build !amd64

package jwt

func _copy_(src []byte, src2 []byte) int {

	return copy(src, src2)
}

func copy_AVX2_32(src []byte, src2 []byte) int {
	return copy(src, src2)
}

func copy_AVX2_64(src []byte, src2 []byte) int {
	return copy(src, src2)
}

func copy_AVX2_128(src []byte, src2 []byte) int {
	return copy(src, src2)
}
