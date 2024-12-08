package jwt

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
	signature []byte // HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),secret)
	//encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.
	sep1, sep2 int32
	valid      bool
}

func (t *Token[T]) Bytes() []byte {
	return t.raw
}

func (t *Token[T]) SetToken(token []byte, sep1, sep2 int32) {
	t.raw = token
	t.sep1 = int32(sep1)
	t.sep2 = sep1 + 1 + sep2

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

func (t *Token[T]) DecodeHeader() error {
	return nil

}

func (t *Token[T]) isValid() bool {
	return t != nil && len(t.raw) > 0 && t.payload.Valid
}
