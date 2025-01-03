package jwt

import (
	cryptorand "crypto/rand"
	"fmt"
	"unsafe"
)

// import (
// 	json "github.com/goccy/go-json"
// )
//

// https://datatracker.ietf.org/doc/html/rfc7519

// xxxxx.yyyyy.zzzzz
type Token[T any] struct {
	payload   *Payload // second segment
	header    *Header  // Header is the first segment of the token in decoded form
	raw       []byte
	signature [64]byte
	// signature []byte // HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload).secret)
	//encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.
	sep1, sep2 int32

	valid bool
}

func New(alg Algorithm, payload *Payload, opts ...HeaderOption) *Token[Algorithm] {
	header := &Header{
		Algorithm: alg,
		Type:      TypeJWT,
	}

	for _, opt := range opts {
		opt(header)
	}
	if payload == nil {
		payload = &Payload{}

	}
	return &Token[Algorithm]{
		payload: payload,
		header:  header,
	}

}

func (t *Token[T]) Build()

func (t *Token[T]) Bytes() []byte {
	return t.raw
}

func (t *Token[T]) SetToken(token []byte, sep1, sep2 int32) {
	t.raw = token
	t.sep1 = int32(sep1)
	t.sep2 = sep1 + 1 + sep2

}

func (t *Token[T]) BeforeSignature() []byte {
	return t.raw[:t.sep2]
}
func (t *Token[T]) HeaderPart() []byte {
	return t.raw[:t.sep1]
}

func (t *Token[T]) PayloadPart() []byte {
	return t.raw[t.sep1+1 : t.sep2]
}

func (t *Token[T]) Signature() []byte {
	return t.raw[t.sep2+1:]
}

func (t *Token[T]) Header() *Header {
	return t.header
}

func (t *Token[T]) SigningString() []byte {

	var builder = bufStringPool.Get()

	builder.Write(unmarshalHeader(t.header))
	t.sep1 = int32(builder.Len())
	builder.WriteByte('.')
	builder.Write(unmarshalPayload(t.payload, t.header.Algorithm))
	t.sep2 = int32(builder.Len())

	signingBytes := builder.Bytes()

	builder.Reset()
	bufStringPool.Put(builder)

	return signingBytes
}

func (t *Token[T]) isValid() bool {
	return t != nil && len(t.raw) > 0
}

func (t *Token[T]) SignedString(key []byte) (string, error) {
	sst := t.SigningString()
	var builder = bufStringPool.Get()
	fmt.Println(len(sst))
	// fmt.Println(string(sst))

	switch t.header.Algorithm {
	case EDDSA:

		// TODO
		//
		ss := *(*[]byte)(unsafe.Pointer(&sst))
		private, public, _ := GenerateEDDSARandom(cryptorand.Reader)

		eddsa, err := NewEddsa(private, public)
		if err != nil {
			return "", err
		}
		sig, err := eddsa.Sign(ss)
		if err != nil {
			return "", err
		}

		buf := base64BufPool.Get()
		tt := *buf
		encodedLen := base64EncodedLen(len(sig))
		tt = tt[:encodedLen] // dst := tt[:encodedlen]
		base64Encode(tt, sig[:])
		builder.Write(sst)
		builder.WriteByte('.')
		builder.Write(tt)
		t.raw = builder.Bytes()
		signedString := builder.String()
		builder.Reset()
		bufStringPool.Put(builder)
		base64BufPool.Put(buf)
		return signedString, nil
	}

	return "", nil
}

func (t *Token[T]) SignedEddsa(privateKey *PrivateKeyEd, publicKey *PublicKeyEd) (string, error) {
	sst := t.SigningString()
	var builder = bufStringPool.Get()
	ss := *(*[]byte)(unsafe.Pointer(&sst))
	eddsa, err := NewEddsa(privateKey, publicKey)
	if err != nil {
		return "", err
	}

	sig, err := eddsa.Sign(ss)
	if err != nil {
		return "", err
	}
	t.signature = sig
	buf := base64BufPool.Get()

	encodedLen := base64EncodedLen(len(sig))
	// tt = tt[:encodedLen] // dst := tt[:encodedlen]
	base64Encode((*buf)[:encodedLen], sig[:])
	builder.Write(sst) // header+payload
	builder.WriteByte('.')
	builder.Write((*buf)[:encodedLen])
	t.raw = builder.Bytes()
	signedString := builder.String()
	builder.Reset()
	bufStringPool.Put(builder)
	*buf = (*buf)[:0]
	base64BufPool.Put(buf)
	return signedString, nil

}

func (t *Token[T]) VerifyEddsa(public *PublicKeyEd) (bool, error) {
	// if !t.valid {
	// 	return false, ErrInvalid
	// }
	if public == nil {
		return false, ErrNil
	}

	signingString := t.BeforeSignature()
	// fmt.Println(string(signingString))

	valid := (&_EDDSA{PublicKey: public}).Verify(signingString, t.signature[:])

	return valid, nil

}
