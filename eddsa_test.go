package jwt

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"testing"
)

//
// var (
// 	// See: RFC 8037, appendix A.1
// 	ed25519PrivateKey = PrivateKeyEd([]byte{
// 		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
// 		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
// 		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
// 		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
// 		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
// 		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
// 		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
// 		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
// 	})
// 	ed25519PublicKey = PublicKeyEd(ed25519PrivateKey[32:])
// )

func TestNewSignerEDDSA(t *testing.T) {
	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)
	eddsa, err := NewEddsa(private, public)
	if err != nil {
		t.Fatalf("Failed to create EDDSA signer: %v", err)
	}

	// fmt.Println(eddsa.PrivateKey)
	//
	if len(eddsa.PrivateKey.key) != ed25519.PrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", ed25519.PrivateKeySize, len(eddsa.PrivateKey.key))
	}
	if len(eddsa.PublicKey.public) != ed25519.PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", ed25519.PublicKeySize, len(eddsa.PublicKey.public))
	}
}

func TestEDDSASignAndVerify(t *testing.T) {

	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	eddsa, err := NewEddsa(private, public)
	if err != nil {
		t.Fatalf("Failed to create EDDSA signer: %v", err)
	}

	message := []byte("test message")
	signature, err := eddsa.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !eddsa.Verify(message, signature[:]) {
		t.Errorf("Failed to verify signature for valid message")
	}

	invalidMessage := []byte("modified message")
	if eddsa.Verify(invalidMessage, signature[:]) {
		t.Errorf("Signature verification should have failed for invalid message")
	}

	anotherSignature := []byte("another signature")
	if eddsa.Verify(message, anotherSignature) {
		t.Errorf("Signature verification should have failed for invalid signature")
	}
}

// func TestEDDSAStringVariable(t *testing.T) {
// 	eddsa, err := NewEDDSA("seed")
// 	if err == nil {
// 		t.Errorf("expected error got nil wtf")
// 	}
//
// 	if eddsa.Algorithm().String() != "EDDSA" {
// 		t.Errorf("Expected EDDSA string, got %s", eddsa.Algorithm().String())
// 	}
// }

// func TestNewSignerEDDSAWithInvalidSeed(t *testing.T) {
//
// 	invalidHex := []byte("short")
// 	_, err := NewEDDSA(invalidHex)
// 	if err == nil {
// 		t.Errorf("Expected error for invalid hex length, got nil")
// 	}
//
// 	emptySeed := []byte{}
// 	_, err = NewEDDSA(emptySeed)
//
// 	if err == nil {
// 		t.Errorf("Expected error for empty seed, got nil")
// 	}
//
// }

func TestNewEDDSAWithRandomBytes(t *testing.T) {
	// randomBytes := []byte{
	// 	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	// 	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	// 	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	// 	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	// 	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	// 	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	// 	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	// 	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	// }

	// t.Log(randomBytes)
	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	eddsa, err := NewEddsa(private, public)
	t.Logf("data eddsa :%v, len eddsa: %v", eddsa, len(eddsa.PrivateKey.key))

	if err != nil {
		t.Fatalf("sometimes shit happens again : %v", err)

	}

	// fmt.Println(eddsa.PrivateKey)

	message := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
	}

	sig, err := eddsa.Sign(message)
	if err != nil {
		t.Fatalf("lol :%v", err)
	}
	// fmt.Println(sig)

	valid := eddsa.Verify(message, sig[:])
	if !valid {
		t.Fatalf("Verification failed")
	}
}

//TODO FIX NEW PRIVATE KEY
// func TestNewSignerWithArray(t *testing.T) {
//
// 	private := [privateKeyLen]byte{
// 		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
// 		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
// 		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
// 		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
// 		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
// 		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
// 		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
// 		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
// 	}
// 	//
// 	// var seed [32]byte
// 	//
// 	// if _, err := io.ReadFull(cryptorand.Reader, seed[:]); err != nil {
// 	// 	panic(err)
// 	// }
//
// 	privateKey := NewPrivateKey(private[:])
//
// 	_, err := NewEddsa(privateKey)
// 	mustOk(t, err)
//
// }
