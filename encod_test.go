package jwt

import (
	"crypto"
	"crypto/rand"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"testing"
)

// go test -gcflags '-m' -run=TestName

// TestGenerateKey tests the generation of an Ed25519 key pair.
func TestGenerateKey(t *testing.T) {
	publicKey, privateKey, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(publicKey.public) != publicKeyLen {
		t.Errorf("Expected public key length %d, got %d", publicKeyLen, len(publicKey.public))
	}
	if len(privateKey.key) != privateKeyLen {
		t.Errorf("Expected private key length %d, got %d", privateKeyLen, len(privateKey.key))
	}
}

func TestEmptyMessage(t *testing.T) {
	publicKey, privateKey, err := GenerateED25519(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("") // Empty message

	// Sign the empty message
	signature := Sign(privateKey, message, domPrefixPure, "")

	// Verify the signature of the empty message
	if !Verify__(publicKey, message, signature[:]) {
		t.Errorf("Signature verification failed for empty message")
	}
}

// scalar panic
// func TestInvalidPrivateKey(t *testing.T) {
// 	defer func() {
// 		if r := recover(); r == nil {
// 			t.Errorf("Expected panic for invalid private key")
// 		}
// 	}()
// 	publicKey, _, err := __generateKey__(rand.Reader)
// 	if err != nil {
// 		t.Fatalf("GenerateKey failed: %v", err)
// 	}
//
// 	// Use a different invalid private key
// 	invalidPrivateKey := [64]byte{
// 		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
// 		11, 12, 13, 14, 15, 16, 17, 18,
// 		19, 20, 21, 22, 23, 24, 25, 26,
// 		27, 28, 29, 30, 31, 32, 33, 34,
// 		35, 36, 37, 38, 39, 40, 41, 42,
// 		43, 44, 45, 46, 47, 48, 49, 50,
// 		51, 52, 53, 54, 55, 56, 57, 58,
// 		59, 60, 61, 62, 63,
// 	}
//
// 	message := []byte("Test message")
//
// 	// privateKey := NewPrivateKey(invalidPrivateKey[:])
// 	privateKey := NewKeyFromSeed(invalidPrivateKey[:32])
// 	signature := Sign(privateKey, message, domPrefixPure, "")
//
// 	// Verify with the valid public key
// 	if Verify__(publicKey, message, signature) {
// 		t.Errorf("Signature verification succeeded with invalid private key")
// 	}
// }

func TestPrivateKey(t *testing.T) {
	var privateKey = [64]byte{
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	}

	privateKeyEd := NewPrivateKey(privateKey)
	publicKey := privateKeyEd.Public()
	message := []byte("Test message")
	signature := Sign(privateKeyEd, message, domPrefixPure, "")
	isValid := Verify__(publicKey, message, signature[:])
	if !isValid {
		t.Errorf("Signature verification failed")
	}
}

func TestVerifyWithDifferentPublicKey(t *testing.T) {
	_, privateKey, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	publickey2 := NewPublicKey(&[32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	})

	message := []byte("Test message")

	// Sign the message with the first private key
	signature := Sign(privateKey, message, domPrefixPure, "")

	// Verify the signature with the second public key (should fail)
	isValid := Verify__(publickey2, message, signature[:])
	if isValid {
		t.Errorf("Signature verification succeeded with a different public key")
	} else {
		t.Logf("Signature verification correctly failed with a different public key")
	}
}

func TestAlias(t *testing.T) {
	public, private, _ := __generateKey__(nil)

	message := []byte("test message")
	sig := Sign(private, message, domPrefixPure, "")
	if !Verify__(public, message, sig[:]) {
		t.Errorf("valid signature rejected")
	}
}

func TestMultipleKeyPairs(t *testing.T) {
	// Generate the first key pair
	publicKey1, privateKey1, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Generate the second key pair
	publicKey2, privateKey2, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("Test message")

	// Sign the message with both private keys
	signature1 := Sign(privateKey1, message, domPrefixPure, "")

	signature2 := Sign(privateKey2, message, domPrefixPure, "")

	// Verify the first signature with the first public key
	if !Verify__(publicKey1, message, signature1[:]) {
		t.Errorf("Signature verification failed for first key pair")
	}

	// Verify the second signature with the second public key
	if !Verify__(publicKey2, message, signature2[:]) {
		t.Errorf("Signature verification failed for second key pair")
	}

	// Ensure the signatures don't match with the wrong public keys
	if Verify__(publicKey2, message, signature1[:]) {
		t.Errorf("Signature verification succeeded with wrong public key")
	}
	if Verify__(publicKey1, message, signature2[:]) {
		t.Errorf("Signature verification succeeded with wrong public key")
	}
}

// TestSignAndVerify tests signing a message and verifying the signature.
func TestSignAndVerify(t *testing.T) {
	// Generate a key pair
	publicKey, privateKey, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Define a test message
	message := []byte("Test message for signing")

	// Sign the message
	signature := Sign(privateKey, message, domPrefixPure, "")

	// Verify the signature
	if !Verify__(publicKey, message, signature[:]) {
		t.Errorf("Signature verification failed")
	}
}

func TestTypeAlias(t *testing.T) {
	public, private, _ := __generateKey__(nil)

	message := []byte("test message")
	sig := Sign(private, message, domPrefixPure, "")
	if !Verify__(public, message, sig[:]) {
		t.Errorf("valid signature rejected")
	}
}

// TestSignAndVerifyWithHash tests signing with a hash (Ed25519ph mode).
func TestSignAndVerifyWithHash(t *testing.T) {
	publicKey, privateKey, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	message := []byte("test message")

	hashed := sha512.Sum512(message)
	signature := Sign(privateKey, hashed[:], domPrefixPure, "")

	// Verify the signature using the hashed message
	if !Verify__(publicKey, hashed[:], signature[:]) {
		t.Errorf("SHA-512 signature verification failed")
	}
}

// TestSignAndVerifyWithContext tests signing with a context (Ed25519ctx mode).
func TestSignAndVerifyWithContext(t *testing.T) {
	publicKey, privateKey, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("Test message with context")
	context := "example context"

	signature, err := privateKey.__Sign__(rand.Reader, message, &_Options{Context: context})
	if err != nil {
		t.Fatalf("Signing with context failed: %v", err)
	}

	if !verify(publicKey, message, signature[:], domPrefixCtx, context) {
		t.Errorf("Contextual signature verification failed")
	}
}

// TestTamperedMessage tests that verification fails for a tampered message.
func TestTamperedMessage(t *testing.T) {
	publicKey, privateKey, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("Original message")
	signature := Sign(privateKey, message, domPrefixPure, "")

	// Tamper with the message
	message[0] ^= 0xFF

	if Verify__(publicKey, message, signature[:]) {
		t.Errorf("Signature verification succeeded on tampered message")
	}
}

// TestTamperedSignature tests that verification fails for a tampered signature.
func TestTamperedSignature(t *testing.T) {
	publicKey, privateKey, err := __generateKey__(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("Message for tampered signature test")
	signature, err := privateKey.__Sign__(rand.Reader, message, &_Options{Hash: crypto.Hash(0)})
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// Tamper with the signature
	signature[0] ^= 0xFF

	if Verify__(publicKey, message, signature[:]) {
		t.Errorf("Signature verification succeeded on tampered signature")
	}
}
