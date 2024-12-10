package jwt

import (
	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

//https://datatracker.ietf.org/doc/html/rfc7519#section-5

var bufStringPool = nObjPool[*lowlevelfunctions.StringBuffer](4, func() *lowlevelfunctions.StringBuffer {
	return lowlevelfunctions.NewStringBuffer(64)
})

type HeaderOption func(*Header)

type Header struct {
	KeyID       []byte    `json:"kid,omitempty"`
	ContentType Cyt       `json:"cty,omitempty"`
	Algorithm   Algorithm `json:"alg,omitempty"`
	Type        Typ       `json:"typ,omitempty"`
}

type Cyt uint8

func (c Cyt) String() string {
	switch c {
	case ContentTypeJWT:
		return "application/jwt"
	case ContentTypeJWS:
		return "application/jws"
	case ContentTypeJSON:
		return "application/json"
	case ContentTypeCustom:
		return "custom"

	default:
		return ""

	}
}

const (
	ContentTypeJWT    Cyt = 1
	ContentTypeJWS    Cyt = 2
	ContentTypeJSON   Cyt = 3
	ContentTypeCustom Cyt = 4 //TODO hold custom content type
)

type Typ uint8

const (
	TypeJWT Typ = 1
)

func (t Typ) String() string {
	switch t {
	case TypeJWT:
		return "JWT"
	default:
		return ""

	}

}

func WithKeyID(kid []byte) HeaderOption {
	return func(b *Header) { b.KeyID = kid }
}

func WithContentType(cty Cyt) HeaderOption {
	if cty <= 0 {
		cty = ContentTypeJWT
	}
	return func(b *Header) { b.ContentType = cty }
}

func (h *Header) MarshalJSON() []byte {
	buf := bufStringPool.Get()
	buf.WriteString(`{"alg":"`)
	buf.WriteString(h.Algorithm.String())

	if h.Type != 0 {
		buf.WriteString(`","typ":"`)
		buf.WriteString(h.Type.String())
	}

	if h.ContentType != 0 {
		buf.WriteString(`","cty":"`)
		buf.WriteString(h.ContentType.String())
	}
	if h.KeyID != nil {
		buf.WriteString(`","kid":"`)
		buf.Write(h.KeyID)
	}
	buf.WriteString(`"}`)

	byt := buf.Bytes()
	buf.Reset()
	bufStringPool.Put(buf)

	return byt
}

func unmarshalHeader(header *Header) []byte {
	if header.Type == 0 {
		header.Type = TypeJWT
	}

	if header.Type == TypeJWT && header.ContentType == 0 && header.KeyID == nil {

		if kid, ok := allocatedHeaders[header.Algorithm]; ok {

			return kid
		}
	}

	if header.Type == TypeJWT && header.ContentType == ContentTypeJWT && header.KeyID == nil {

		if kid, ok := allocatedHeadersWithContentTypeJWT[header.Algorithm]; ok {

			return kid
		}
	}

	info := header.MarshalJSON()
	buf := base64BufPool.Get()

	token := *buf
	encodedLen := base64EncodedLen(len(info))

	// encoded := alignSlice(base64EncodedLen(len(info)), 32) // // EncodedLen returns the length in bytes of the base64 encoding  of an input buffer of length n.

	base64Encode(token[:encodedLen], info)

	base64BufPool.Put(buf)

	return token[:encodedLen]
}

var allocatedHeaders = map[Algorithm][]byte{
	EDDSA: []byte{101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 82, 69, 82, 84, 81, 83, 73, 115, 73, 110, 82, 53, 99, 67,
		73, 54, 73, 107, 112, 88, 86, 67, 74, 57},
}

var allocatedHeadersWithContentTypeJWT = map[Algorithm][]byte{
	EDDSA: []byte{
		101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 82, 69, 82, 84, 81, 83, 73, 115, 73, 110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67,
		73, 115, 73, 109, 78, 48, 101, 83, 73, 54, 73, 109, 70, 119, 99, 71, 120, 112, 89, 50, 70, 48, 97, 87, 57, 117, 76, 50, 112, 51, 100, 67, 74, 57,
	},
}
