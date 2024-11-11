package jwt

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"unsafe"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

type KeySource interface {
	~[]byte | ~string | ~*[privateKeyLen]byte | ~[privateKeyLen]byte
}

type _PrivateKey []byte

type _PublicKey []byte

const (
	privateKeyLen = ed25519.PrivateKeySize // 64
	publicKeyLen  = ed25519.PublicKeySize  //32
	signatureSize = ed25519.SignatureSize
	seedLen       = ed25519.SeedSize //32
	addressLen    = 20
)

type _EDDSA struct {
	PrivateKey _PrivateKey
	PublicKey  _PublicKey
}

func (e *_EDDSA) Bytes() _PrivateKey { return e.PrivateKey }

func (e *_EDDSA) SignSize() int32 { return 64 }

func (e *_EDDSA) Algorithm() Algorithm { return EDDSA }

func NewEDDSA[T KeySource](keySource T) (*_EDDSA, error) {
	var privKey _PrivateKey = lowlevelfunctions.MakeNoZero(privateKeyLen)

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
			privKey = *(*_PrivateKey)(unsafe.Pointer(&decoded))
		}

		if len(decoded) == seedLen {

			privKey = NewKeyFromSeed(decoded)
		} else {
			return nil, ErrInvalidKeySize
		}

	case []byte:
		// Treat byte slice as a private key or seed based on length
		if len(v) == privateKeyLen {
			privKey = _PrivateKey(v[:])
		}

		if len(v) == seedLen {

			privKey = NewKeyFromSeed(v)
		} else {
			return nil, ErrInvalidKeySize
		}

	case [privateKeyLen]byte:

		privKey = _PrivateKey(v[:])

	case *[privateKeyLen]byte: // pointer to private key

		privKey = _PrivateKey(v[:])

	default:
		return nil, ErrInvalid
	}

	return &_EDDSA{
		PrivateKey: privKey,
		PublicKey:  privKey.Public().(_PublicKey),
	}, nil
}

func (e *_EDDSA) Sign(payload []byte) ([]byte, error) {

	if len(payload) == 0 {
		return nil, ErrPayloadIsEmpty
	}
	signature := Sign(e.PrivateKey, payload)

	return signature, nil
}
func (e *_EDDSA) Verify(payload []byte, sig []byte) bool {
	if payload == nil || len(payload) == 0 {
		return false
	}
	if len(e.PublicKey) != publicKeyLen {
		return false
	}
	return __Verify__(e.PublicKey, payload, sig[:])
}
