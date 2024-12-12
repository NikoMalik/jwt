package jwt

//RFC8032

//EDDSA +1

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"

	"fmt"
	"io"
	"reflect"
	"unsafe"
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
	PrivateKey PrivateKeyEd
	PublicKey  PublicKeyEd
}

func (e *_EDDSA) Reset() {
	for i := range e.PrivateKey {
		e.PrivateKey[i] = 0
	}
}

func (e *_EDDSA) Close() {
	if len(e.PrivateKey) > 0 {

	}
	return
}

func (e *_EDDSA) Bytes() PrivateKeyEd { return e.PrivateKey }

func (e *_EDDSA) SignSize() int { return len(e.PrivateKey) }

func (e *_EDDSA) Algorithm() Algorithm { return EDDSA }

func NewEddsa(private []byte) (*_EDDSA, error) {
	var privKey PrivateKeyEd = alignSlice(privateKeyLen, 32)
	if privKey == nil || len(privKey) == 0 {
		return nil, ErrCannotGetObjFromPool
	}

	switch {
	case len(private) == 0:
		return nil, ErrNil
	case len(private) != privateKeyLen:
		return nil, ErrInvalidKeySize

	default:
		copy_AVX2_64(privKey, private)

		return &_EDDSA{PrivateKey: privKey, PublicKey: privKey.Public()}, nil
	}

}

func NewEDDSA[T KeySource](keySource T) (*_EDDSA, error) {
	var privKey PrivateKeyEd = alignSlice(privateKeyLen, 32)
	if privKey == nil || len(privKey) == 0 {
		return nil, ErrCannotGetObjFromPool
	}

	switch v := any(keySource).(type) {

	case string:
		if len(v) == 0 {
			return nil, ErrSeedNil
		}
		if len(v)%2 != 0 {
			return nil, fmt.Errorf("hex string has odd length: %v", len(v))
		}

		decoded, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}
		if len(decoded) == privateKeyLen {
			privKey = *(*PrivateKeyEd)(unsafe.Pointer(&decoded))

		}

		if len(decoded) == seedLen {

			privKey = NewKeyFromSeed(decoded)

		} else {
			return nil, ErrInvalidKeySize
		}

	case []byte:

		// Treat byte slice as a private key or seed based on length
		if len(v) == privateKeyLen {
			privKey = *(*PrivateKeyEd)(unsafe.Pointer(&v))
		} else if len(v) == seedLen {
			privKey = NewKeyFromSeed(v)
		} else {
			return nil, fmt.Errorf("Invalid key length: %v", len(v))
		}

	case [privateKeyLen]byte:
		slice := *(*reflect.SliceHeader)(unsafe.Pointer(&v))
		slice.Data = uintptr(unsafe.Pointer(&v))
		slice.Len = privateKeyLen
		slice.Cap = privateKeyLen

		privKey = *(*PrivateKeyEd)(unsafe.Pointer(&slice))
	case *[privateKeyLen]byte: // pointer to private key

		slice := *(*reflect.SliceHeader)(unsafe.Pointer(&v))
		slice.Data = uintptr(unsafe.Pointer(v))
		slice.Len = privateKeyLen
		slice.Cap = privateKeyLen

		privKey = *(*PrivateKeyEd)(unsafe.Pointer(&slice))

	default:
		return nil, ErrInvalid
	}

	return &_EDDSA{
		PrivateKey: privKey,
		PublicKey:  privKey.Public(),
	}, nil
}

func (e *_EDDSA) Sign(payload []byte) ([]byte, error) {

	if len(payload) == 0 {
		return nil, ErrPayloadIsEmpty
	}
	if e.PrivateKey == nil || len(e.PrivateKey) == 0 {
		return nil, fmt.Errorf("private key is not initialized")
	}
	signature := Sign(e.PrivateKey, payload, domPrefixPure, "")

	return signature, nil
}
func (e *_EDDSA) Verify(payload []byte, sig []byte) bool {
	if payload == nil || len(payload) == 0 {
		return false
	}

	return Verify__(e.PublicKey, payload, sig)
}

func (e *_EDDSA) VerifyToken(token *Token[*_EDDSA]) error {
	switch {
	case !token.isValid():
		return ErrTokenIsINVALID
	case !constTimeEqual(token.header.Algorithm.String(), EDDSA.String()):
		return ErrInvalid
	case !e.Verify(token.PayloadPart(), token.Signature()):
		return ErrSignatureInvalid
	}
	return nil
}

func GenerateEDDSARandom(rand io.Reader) (PrivateKeyEd, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	var seed = alignSliceWithArray_32(32)

	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}

	privateKey := NewKeyFromSeed(seed)

	return privateKey, nil

}

func (p PrivateKeyEd) Bytes() []byte {
	return p
}
