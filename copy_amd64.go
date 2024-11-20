//go:build amd64 && !purego

package jwt

//go:noescape
func _copy_(src []byte, src2 []byte)
