package jwt

import (
	"fmt"
	"testing"
)

func TestAligns(t *testing.T) {
	randomSeed := make([]byte, 32)
	for i := range randomSeed {
		randomSeed[i] = byte(i)
	}
	newArray := alignArray_32(32)
	copy_AVX2_32(newArray[:], randomSeed)

	fmt.Println(newArray)
	fmt.Println(len(newArray))
}
