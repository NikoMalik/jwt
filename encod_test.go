package jwt

import (
	"crypto"
	"crypto/rand"
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
	if len(publicKey) != publicKeyLen {
		t.Errorf("Expected public key length %d, got %d", publicKeyLen, len(publicKey))
	}
	if len(privateKey) != privateKeyLen {
		t.Errorf("Expected private key length %d, got %d", privateKeyLen, len(privateKey))
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
	signature, err := privateKey.__Sign__(rand.Reader, message, &_Options{Hash: crypto.Hash(0)})
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// Verify the signature
	if !__Verify__(publicKey, message, signature) {
		t.Errorf("Signature verification failed")
	}
}

func TestTypeAlias(t *testing.T) {
	public, private, _ := __generateKey__(nil)

	message := []byte("test message")
	sig := Sign(private, message)
	if !__Verify__(public, message, sig) {
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
	signature := Sign(privateKey, hashed[:])

	// Verify the signature using the hashed message
	if !__Verify__(publicKey, hashed[:], signature) {
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

	if !verify(publicKey, message, signature, domPrefixCtx, context) {
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
	signature := Sign(privateKey, message)

	// Tamper with the message
	message[0] ^= 0xFF

	if __Verify__(publicKey, message, signature) {
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

	if __Verify__(publicKey, message, signature) {
		t.Errorf("Signature verification succeeded on tampered signature")
	}
}
