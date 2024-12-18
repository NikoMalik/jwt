package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/NikoMalik/jwt"
)

func main() {
	private, public, _ := jwt.GenerateEDDSARandom(rand.Reader)

	aud := jwt.NewAudience([]string{"test", "some"})

	payload := &jwt.Payload{

		Subject:        "NikoMalik",
		ExpirationTime: jwt.NumericDate(time.Now().Add(time.Hour)),
		Audience:       aud,
	}
	token := jwt.New(jwt.EDDSA, payload)

	signed, err := token.SignedEddsa(private, public)
	if err != nil {
		panic(err)
	}

	verifier, err := token.VerifyEddsa(public)
	if err != nil {
		panic(err)
	}

	// myTok := token.Bytes()

	fmt.Println("\nSigned:", signed)
	fmt.Println("\nVerified:", verifier)

}
