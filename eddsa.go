package jwt

//RFC8032

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"unsafe"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

type KeySource interface {
	~[]byte | ~string | ~*[privateKeyLen]byte | ~[privateKeyLen]byte
}

type _PrivateKey []byte

type _PublicKey []byte

var privateKeyPool = oldObjPool[_PrivateKey](INITIAL, func() _PrivateKey {

	return lowlevelfunctions.MakeNoZero(privateKeyLen)
})

const (
	privateKeyLen = ed25519.PrivateKeySize // 64
	publicKeyLen  = ed25519.PublicKeySize  //32
	signatureSize = ed25519.SignatureSize
	seedLen       = ed25519.SeedSize //32

)

type _EDDSA struct {
	PrivateKey _PrivateKey
	PublicKey  _PublicKey
}

func (e *_EDDSA) Reset() {
	_ = e.PrivateKey[:0]
}

func (e *_EDDSA) Close() {
	if len(e.PrivateKey) > 0 {
		n := (*reflect.SliceHeader)(unsafe.Pointer(&e.PrivateKey))

		if n.Data != 0 || n.Cap != 0 {
			// _ = e.PrivateKey[:0]             // Clear the private key (zero out)
			privateKeyPool.put(e.PrivateKey) // Return the private key to the pool
		}

	}
	return
}

func (e *_EDDSA) Bytes() _PrivateKey { return e.PrivateKey }

func (e *_EDDSA) SignSize() int { return len(e.PrivateKey) }

func (e *_EDDSA) Algorithm() Algorithm { return EDDSA }

func NewEDDSA[T KeySource](keySource T) (*_EDDSA, error) {
	var privKey _PrivateKey = privateKeyPool.get()
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
			privKey = *(*_PrivateKey)(unsafe.Pointer(&v))
		} else if len(v) == seedLen {
			privKey = NewKeyFromSeed(v)
		} else {
			return nil, fmt.Errorf("Invalid key length: %v", len(v))
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
	signature := Sign(e.PrivateKey, payload)

	return signature, nil
}
func (e *_EDDSA) Verify(payload []byte, sig []byte) bool {
	if payload == nil || len(payload) == 0 {
		return false
	}

	return __Verify__(e.PublicKey, payload, sig)
}

func GenerateEDDSARandom(rand io.Reader) (_PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	var seed = publicKeyPool.get()
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}

	privateKey := NewKeyFromSeed(seed[:])

	publicKeyPool.put(seed)
	return privateKey, nil

}

func (p _PrivateKey) Bytes() []byte {
	return *(*[]byte)(unsafe.Pointer(&p))
}
