package jwt

import (
	"fmt"
	"unsafe"
)

// import (
// 	json "github.com/goccy/go-json"
// )
//

// https://datatracker.ietf.org/doc/html/rfc7519

type TokenOption func(*Token[any])

// xxxxx.yyyyy.zzzzz
type Token[T any] struct {
	payload   *Payload // second segment
	header    *Header  // Header is the first segment of the token in decoded form
	raw       []byte
	signature []byte // HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload).secret)
	//encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.
	sep1, sep2 int32

	valid bool
}

func (t *Token[T]) Bytes() []byte {
	return t.raw
}

func (t *Token[T]) SetToken(token []byte, sep1, sep2 int32) {
	t.raw = token
	t.sep1 = int32(sep1)
	t.sep2 = sep1 + 1 + sep2

}

func (t *Token[T]) PayloadPart() []byte {
	return t.raw[:t.sep2]
}

func (t *Token[T]) HeaderPart() []byte {
	return t.raw[:t.sep1]
}

func (t *Token[T]) ClaimsPart() []byte {
	return t.raw[t.sep1+1 : t.sep2]
}

func (t *Token[T]) SignaturePart() []byte {
	return t.raw[t.sep2+1:]
}

func (t *Token[T]) Signature() []byte {
	return t.signature
}

func (t *Token[T]) Header() *Header {
	return t.header
}

func (t *Token[T]) SigningString() []byte {

	var builder = bufStringPool.Get()

	builder.Write(unmarshalHeader(t.header))
	t.sep1 = int32(builder.Len())
	builder.WriteByte('.')
	builder.Write(unmarshalPayload(t.payload))
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

	switch t.header.Algorithm {
	case EDDSA:
		ss := *(*_PrivateKey)(unsafe.Pointer(&sst))
		eddsa := &_EDDSA{
			PrivateKey: ss[:64],
		}
		sig, err := eddsa.Sign(key)
		if err != nil {
			return "", err
		}
		dst := alignSlice(base64EncodedLen(len(sig)), 32)
		base64Encode(dst, sig)
		builder.Write(sst)
		builder.WriteByte('.')
		builder.Write(dst)
		t.raw = builder.Bytes()
		signedString := builder.String()
		builder.Reset()
		bufStringPool.Put(builder)
		return signedString, nil
	}

	return "", nil
}
