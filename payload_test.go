package jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestUnmarshalPayload(t *testing.T) {
	payload := &Payload{
		Issuer:   "darkie",
		Subject:  "sub",
		JWTID:    "jti",
		IssuedAt: &JWTTime{time.Now().Add(time.Hour)},
	}

	fmt.Println(string(must(payload.MarshalJSON())))

}
