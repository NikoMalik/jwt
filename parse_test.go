package jwt

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	header := `{"alg":"EDDSA","typ":"JWT"}`
	payload := `{"jti":"1234567890","iss":"John Doe"}`
	signature := "example-signature"

	headerEncoded := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signatureEncoded := base64.RawURLEncoding.EncodeToString([]byte(signature))

	raw := []byte(headerEncoded + "." + payloadEncoded + "." + signatureEncoded)

	re, err := parse(raw, [64]byte{})
	mustOk(t, err)
	t.Log("parsing result", string(re.Bytes()))
}

func TestParsing(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		expectErr bool
	}{
		{
			name:      "Valid Token",
			token:     `eyJhbGciOiAiRUVEU0EiLCAidHlwIjogIkpXVCJ9.eyJqdGkiOiAiaWQiLCAiYXVkIjogImF1ZGllbmNlIn0.signature`,
			expectErr: false,
		},
		{
			name:      "Invalid Prefix",
			token:     `invalidPrefix.eyJqdGkiOiAiaWQiLCAiYXVkIjogImF1ZGllbmNlIn0.signature`,
			expectErr: true,
		},
		{
			name:      "Missing Header",
			token:     `.eyJqdGkiOiAiaWQiLCAiYXVkIjogImF1ZGllbmNlIn0.signature`,
			expectErr: true,
		},
		{
			name:      "Missing Payload",
			token:     `eyJhbGciOiAiRUVEU0EiLCAidHlwIjogIkpXVCJ9..signature`,
			expectErr: true,
		},
		{
			name:      "Malformed Header",
			token:     `eyJhbGciOiAiRUVEU0EiLCAidHlwIjogIkpXVCJ9XXX.eyJqdGkiOiAiaWQiLCAiYXVkIjogImF1ZGllbmNlIn0.signature`,
			expectErr: true,
		},
		{
			name:      "Malformed Payload",
			token:     `eyJhbGciOiAiRUVEU0EiLCAidHlwIjogIkpXVCJ9.eyJqdGkiOiAiaWQiLCAiYXVkIjogImF1ZGllbmNlIn0XXX.signature`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(tt.token)
			_, err := parse(raw, [64]byte{})
			if tt.expectErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("expected no error but got %v", err)
			}
		})
	}
}

func TestSome(t *testing.T) {
	private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

	payload := &Payload{
		Issuer:   "darkie",
		Subject:  "sub",
		JWTID:    "jti",
		IssuedAt: &JWTTime{time.Now().Add(time.Hour)},
	}

	token := New(EDDSA, payload)

	signedResult, err := token.SignedEddsa(private, public)
	mustOk(t, err)

	newToken, err := parse([]byte(signedResult), token.signature)
	mustOk(t, err)

	isValid, err := newToken.VerifyEddsa(public)
	mustOk(t, err)
	if !isValid {
		t.Log("newToken", string(newToken.Bytes()))
		t.Log("oldToken", string(token.Bytes()))

		t.Fatal("Token signature is invalid")
	}
}
