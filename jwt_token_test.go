package jwt

import (
	"testing"
	"time"
	"unsafe"
)

func TestToken_SigningString(t *testing.T) {
	header := &Header{Algorithm: EDDSA}
	payload := &Payload{Issuer: "darkie"}
	token := &Token[any]{
		header:  header,
		payload: payload,
	}

	signingString := token.SigningString()
	if len(signingString) == 0 {
		t.Errorf("Expected SigningString to return a non-empty byte slice")
	}
	t.Log(string(signingString))

}

func TestNew(t *testing.T) {
	payload := &Payload{Issuer: "darkie", Subject: "sub", JWTID: "jti", IssuedAt: &JWTTime{time.Now()}}
	token := New(EDDSA, payload, WithContentType(ContentTypeJWT))

	key := []byte("hajfhajhfaksfkajsflaskfjlasfkj")

	signedString, err := token.SignedString(key) // for eddsa key is not used
	if err != nil {
		t.Errorf("Expected SignedString to succeed, but got error: %v", err)
	}

	t.Log(signedString)
	if len(signedString) == 0 {
		t.Errorf("Expected SignedString to return a non-empty string")
	}
	getSignature := token.Signature()
	t.Log(string(getSignature))
}

func TestToken_SignedString(t *testing.T) {
	header := &Header{Algorithm: EDDSA}
	aud := Audience{
		aud:    unsafe.Pointer(&[]string{"admin"}),
		lenAud: 1,
	}

	payload := &Payload{Issuer: "darkie", Subject: "sub", JWTID: "jti", IssuedAt: &JWTTime{time.Now()}, Audience: aud}
	token := &Token[any]{
		header:  header,
		payload: payload,
	}

	mockKey := []byte("hajfhajhfaksfkajsflaskfjlasfkj")

	signedString, err := token.SignedString(mockKey)
	if err != nil {
		t.Errorf("Expected SignedString to succeed, but got error: %v", err)
	}
	t.Log(signedString)

	if len(signedString) == 0 {
		t.Errorf("Expected SignedString to return a non-empty string")
	}

	getHeaderPart := token.HeaderPart()
	t.Log(string(getHeaderPart))
}
