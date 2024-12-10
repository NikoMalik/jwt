package jwt

import (
	"fmt"
	"testing"
)

func TestHeaders(t *testing.T) {
	hEddsa := &Header{
		Algorithm: EDDSA,
		Type:      TypeJWT,
	}
	predEddsa := unmarshalHeader(hEddsa)

	fmt.Println("eddsa without content type and key id:", predEddsa)

	hEddsaWithContentType := &Header{
		Algorithm:   EDDSA,
		Type:        TypeJWT,
		ContentType: ContentTypeJWT,
	}
	predEddsaWithContentType := unmarshalHeader(hEddsaWithContentType)

	fmt.Println("eddsa with content type and  without key id:", predEddsaWithContentType)
}
