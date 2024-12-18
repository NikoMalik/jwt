package jwt

//RFC8032

//EDDSA +1

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"unsafe"

	"fmt"
	"io"
)

type KeySource interface {
	~[]byte | ~string | ~*[privateKeyLen]byte | ~[privateKeyLen]byte
}

const (
	privateKeyLen = ed25519.PrivateKeySize // 64
	publicKeyLen  = ed25519.PublicKeySize  //32
	signatureSize = ed25519.SignatureSize
	seedLen       = ed25519.SeedSize //32

)

type _EDDSA struct {
	PrivateKey *PrivateKeyEd
	PublicKey  *PublicKeyEd
}

func (e *_EDDSA) Bytes() []byte { return e.PrivateKey.key[:] }

func (e *_EDDSA) SignSize() int { return privateKeyLen }

func (e *_EDDSA) Algorithm() Algorithm { return EDDSA }

func NewEddsa(private *PrivateKeyEd, public *PublicKeyEd) (*_EDDSA, error) {

	switch {
	case private == nil:
		return nil, ErrNil
	default:
		return &_EDDSA{PrivateKey: private, PublicKey: public}, nil
	}

}

func (e *_EDDSA) Sign(payload []byte) ([64]byte, error) {

	if len(payload) == 0 {
		return [64]byte{}, ErrPayloadIsEmpty
	}
	if e.PrivateKey == nil {
		return [64]byte{}, fmt.Errorf("private key is not initialized")
	}
	signature := Sign(e.PrivateKey, payload, domPrefixPure, "")

	return signature, nil // return sign

}
func (e *_EDDSA) Verify(payload []byte, sig []byte) bool { // need sign
	if payload == nil || len(payload) == 0 {
		return false
	}

	return Verify__(e.PublicKey, payload, sig)
}

//
// func (e *_EDDSA) VerifyToken(token *Token[*_EDDSA]) error {
// 	switch {
// 	case !token.isValid():
// 		return ErrTokenIsINVALID
// 	case !constTimeEqual(token.header.Algorithm.String(), EDDSA.String()):
// 		return ErrInvalid
// 	case !e.Verify(token.BeforeSignature(), token.Signature()):
// 		return ErrSignatureInvalid
// 	}
// 	return nil
// }

func GenerateEDDSARandom(rand io.Reader) (*PrivateKeyEd, *PublicKeyEd, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	var seed [32]byte

	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)

	var public [32]byte
	memcopy_avx2_32(unsafe.Pointer(&public[0]), unsafe.Pointer(&privateKey.key[32]))

	return privateKey, NewPublicKey(&public), nil

}
