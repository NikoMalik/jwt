package jwt

import (
	cryptorand "crypto/rand"
	"testing"
	"time"
)

func BenchmarkSignJwtEddsa(b *testing.B) {
	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	payload := &Payload{
		Issuer:   "darkie",
		Subject:  "sub",
		JWTID:    "jti",
		IssuedAt: &JWTTime{time.Now().Add(time.Hour)},
	}

	token := New(EDDSA, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.SignedEddsa(private, public)
	}
}

func BenchmarkSignTwoEdDSA(b *testing.B) {
	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	payload := &Payload{
		Issuer:   "darkie",
		Subject:  "sub",
		JWTID:    "jti",
		IssuedAt: &JWTTime{(time.Now().Add(time.Second * 5))},
	}
	token := New(EDDSA, payload)
	b.Run("sign-"+EDDSA.String(), func(b *testing.B) {
		var tokenLen int
		for i := 0; i < b.N; i++ {
			_, err := token.SignedEddsa(private, public)
			if err != nil {
				b.Fatal(err)
			}
			tokenLen += len(token.Bytes())
		}
		b.ReportMetric(float64(tokenLen)/float64(b.N), "B/token")

	})

	b.Run("check-"+EDDSA.String(), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := token.VerifyEddsa(public)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
