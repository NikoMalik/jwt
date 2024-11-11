package jwt

type Token struct {
	Raw    string
	Header *Header
	Valid  bool
}

type Header struct {
	Algorithm   Algorithm `json:"alg"`
	Type        string    `json:"typ"`
	ContentType string    `json:"cty"`
	KeyID       string    `json:"kid"`
}
