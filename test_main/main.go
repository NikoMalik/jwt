package main

import (
	"crypto/rand"
	"fmt"
	"log"

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

	publicKey, privateKey, err := jwt.GenerateED25519(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Private Key: %x\n", privateKey)
	fmt.Printf("Public Key: %x\n", publicKey)

	msg := []byte("Hello, Ed25519!")
	sig := jwt.Sign(privateKey, message)

	valid := jwt.Verify__(publicKey, msg, sig)
	if valid {
		fmt.Println("Signature is valid.")
	}

	publicKey2, privateKey2, err := jwt.GenerateED25519(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Private Key: %x\n", privateKey2)
	fmt.Printf("Public Key: %x\n", publicKey2)

}
