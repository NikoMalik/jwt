package jwt

type Algorithm int32

type Signer interface {
	Algorithm() Algorithm
	SignSize() int32
	Sign(payload []byte) ([]byte, error)
	Verify(payload []byte, sig []byte) bool
}

const (
	EDDSA Algorithm = iota

	ES256
	ES384
	ES512

	RS256
	RS384
	RS512

	PS256
	PS384
	PS512

	HS256
	HS384
	HS512
)

func (a Algorithm) String() string {
	switch a {
	case EDDSA:
		return "EDDSA"
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	case RS256:
		return "RS256"
	case RS384:
		return "RS384"
	case RS512:
		return "RS512"
	case PS256:
		return "PS256"
	case PS384:
		return "PS384"
	case PS512:
		return "PS512"
	case HS256:
		return "HS256"
	case HS384:
		return "HS384"
	case HS512:
		return "HS512"
	default:
		return "unknown"
	}

}
