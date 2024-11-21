//go:build !amd64

package jwt

func _copy_(src []byte, src2 []byte) int {

	return copy(src, src2)
}
