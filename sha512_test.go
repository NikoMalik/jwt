package jwt

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestArtem(t *testing.T) {
	name := "artem"

	data := []byte(name)

	sum := _sum512_(data)

	stringHash := hex.EncodeToString(sum[:])

	fmt.Printf("\nHash: %s", stringHash)

	s := sha512.Sum512(data)
	fmt.Printf("\nHash: %s", hex.EncodeToString(s[:]))

	myEdPublic, myEdPrivate, _ := GenerateED25519(cryptorand.Reader)
	fmt.Printf("\nPrivate: %s", hex.EncodeToString(myEdPrivate.key[:]))
	fmt.Printf("\nPublic: %s", hex.EncodeToString(myEdPublic.public[:]))

	res := Sign(myEdPrivate, data, domPrefixPure, "")

	fmt.Printf("\nSignature: %s", hex.EncodeToString(res[:]))

	ed25519Public, ed25519Private, _ := ed25519.GenerateKey(cryptorand.Reader)

	fmt.Printf("\nPrivate: %s", hex.EncodeToString(ed25519Private[:]))
	fmt.Printf("\nPublic: %s", hex.EncodeToString(ed25519Public[:]))

	res2 := ed25519.Sign(ed25519Private, data)

	fmt.Printf("\nSignature: %s", hex.EncodeToString(res2[:]))
}

func BenchmarkSha512(b *testing.B) {

	name := "artem"

	data := []byte(name)

	b.Run("default sha512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sha512.Sum512(data)
		}
	})
	b.Run("sum512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_sum512_(data)
		}
	})
}
