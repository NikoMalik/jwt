package jwt

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"runtime"
	"testing"
)

/// go test -bench . -benchmem -cpuprofile cpu.prof -memprofile mem.prof -count 3

func printAllocations(stage string) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fmt.Printf("[%s] Alloc = %v KiB, TotalAlloc = %v KiB, Sys = %v KiB, NumGC = %v\n",
		stage,
		memStats.Alloc/1024,
		memStats.TotalAlloc/1024,
		memStats.Sys/1024,
		memStats.NumGC,
	)
}

func BenchmarkSign(b *testing.B) {
	// Enable allocation reporting
	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	b.ReportAllocs()

	eddsa, err := NewEddsa(private, public)
	if err != nil {
		b.Fatalf("Failed to create EDDSA instance: %v", err)
	}

	// Create a random payload to sign
	payload := make([]byte, 1024)

	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eddsa.Sign(payload)

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignEd(b *testing.B) {
	b.ReportAllocs()

	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	eddsa, err := NewEddsa(private, public)

	if err != nil {
		b.Fatalf("Failed to create EDDSA instance: %v", err)
	}

	payload := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(ed25519.PrivateKey(eddsa.PrivateKey.key[:]), payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignAndVerify(b *testing.B) {

	b.ReportAllocs()

	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	eddsa, err := NewEddsa(private, public)
	if err != nil {
		b.Fatalf("Failed to create EDDSA instance: %v", err)
	}

	payload := make([]byte, 1024)
	signature, err := eddsa.Sign(payload)
	if err != nil {
		b.Fatalf("Sign failed : %v", err)
	}

	for i := 0; i < b.N; i++ {
		valid := eddsa.Verify(payload, signature[:])
		if !valid {
			b.Fatalf("Verification failed :%v", valid)
		}
	}
}

// Benchmark the Verify method
func BenchmarkVerify(b *testing.B) {
	// Generate a random seed or private key to create EDDSA instance

	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	eddsa, err := NewEddsa(private, public)
	if err != nil {
		b.Fatalf("Failed to create EDDSA instance: %v", err)
	}

	// Create a random payload and sign it to generate a valid signature
	payload := make([]byte, 1024)
	signature, err := eddsa.Sign(payload)
	if err != nil {
		b.Fatalf("Sign failed: %v", err)
	}

	// Run the benchmark for Verify
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !eddsa.Verify(payload, signature[:]) {
			b.Fatalf("Verification failed")
		}

	}
}
