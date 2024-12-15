package jwt

import "bytes"

func parse(raw []byte) (*Token[any], error) {
	if !bytes.HasPrefix(raw, []byte("eyJ")) {
		return nil, ErrInvalid
	}
	return nil, nil
}
