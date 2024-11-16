package main

import (
	"fmt"

	"github.com/NikoMalik/jwt"
)

func main() {
	seedHex := "9d61b19dfffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	eddsa, err := jwt.NewEDDSA(seedHex)
	if err != nil {
		panic(err)
	}
	defer eddsa.Close()
	message := []byte("test message")
	signature, err := eddsa.Sign(message)
	if err != nil {
		panic(err)
	}

	fmt.Println(signature)
	if !eddsa.Verify(message, signature) {
		fmt.Printf("Failed to verify signature for valid message")
	}

}
