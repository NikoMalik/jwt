//go:build amd64 && !purego

package jwt

import "fmt"

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

//go:noescape
func copy_more_512(src []byte, src2 []byte) int

func cop_32(src []byte, src2 []byte) int {
	if useAVX2 {
		return copy_AVX2_32(src, src2)
	}
	if useAVX2 && isZen1() {
		fmt.Println("zen1") // using only for debug delete later
		return copy(src, src2)
	}
	return copy(src, src2)

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
