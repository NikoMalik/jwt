//go:build amd64 && !purego

package jwt

//test with gcflags="-S"

//go:noescape
func _copy_(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_32(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_64(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_128(src []byte, src2 []byte) int

//go:noescape
func copy_AVX2_256(src []byte, src2 []byte) int
