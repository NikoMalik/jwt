package jwt

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestArtem(t *testing.T) {
	name := "artem"

	data := []byte(name)

	hash := _sum512_(data)
	stringHash := hex.EncodeToString(hash[:])

	fmt.Printf("Hash: %s", stringHash)
}
