package jwt

import "testing"

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

func TestToken_SignedString(t *testing.T) {
	header := &Header{Algorithm: EDDSA}
	payload := &Payload{Issuer: "darkie", Subject: "sub"}
	token := &Token[any]{
		header:  header,
		payload: payload,
	}

	mockKey := []byte("test_key")

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
