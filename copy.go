//go:build !amd64

package jwt

func _copy_(src1, src2 []byte) {
	copy(src1, src2)

}
