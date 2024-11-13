package jwt

import (
	"crypto/rand"
	"testing"
)

/// go test -bench . -benchmem -cpuprofile cpu.prof -memprofile mem.prof -count 3

var keySource = "9fd61b19dfffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f6"

func BenchmarkSign(b *testing.B) {

	eddsa, err := NewEDDSA(keySource)
	if err != nil {
		b.Fatalf("Failed to create EDDSA instance: %v", err)
	}
	defer eddsa.Close()

	// Create a random payload to sign
	payload := make([]byte, 1024)

	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eddsa.Sign(payload)
		if err != nil {
			b.Fatalf("Sign failed: %v", err)
		}
	}
}

func BenchmarkSignAndVerify(b *testing.B) {
	key, err := GenerateEDDSARandom(rand.Reader)
	if err != nil {
		b.Fatalf("ffffff: generate failed :%v", err)
	}
	eddsa, err := NewEDDSA(key.Bytes())
	if err != nil {
		b.Fatalf("Failed to create EDDSA instance: %v", err)
	}

	defer eddsa.Close()

	payload := make([]byte, 1024)
	signature, err := eddsa.Sign(payload)
	if err != nil {
		b.Fatalf("Sign failed : %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := eddsa.Verify(payload, signature)
		if !valid {
			b.Fatalf("Verification failed :%v", valid)
		}
	}
}

// Benchmark the Verify method
func BenchmarkVerify(b *testing.B) {
	// Generate a random seed or private key to create EDDSA instance

	eddsa, err := NewEDDSA(keySource)
	if err != nil {
		b.Fatalf("Failed to create EDDSA instance: %v", err)
	}
	defer eddsa.Close()

	// Create a random payload and sign it to generate a valid signature
	payload := make([]byte, 1024)
	signature, err := eddsa.Sign(payload)
	if err != nil {
		b.Fatalf("Sign failed: %v", err)
	}

	// Run the benchmark for Verify
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := eddsa.Verify(payload, signature)
		if !valid {
			b.Fatalf("Verification failed")
		}
	}
}
