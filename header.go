package jwt

import lowlevelfunctions "github.com/NikoMalik/low-level-functions"

//https://datatracker.ietf.org/doc/html/rfc7519#section-5

var bufStringPool = nObjPool[*lowlevelfunctions.StringBuffer](1, func() *lowlevelfunctions.StringBuffer {
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
	ContentTypeCustom Cyt = 4
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

	info := header.MarshalJSON()

	encoded := alignSlice(base64EncodedLen(len(info)), 32) // // EncodedLen returns the length in bytes of the base64 encoding  of an input buffer of length n.

	base64Encode(encoded, info)

	return encoded
}
