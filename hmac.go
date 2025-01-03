package jwt

import (
	"crypto"
)

type Hmac struct {
	selectHm Algorithm
	key      []byte
	hash     crypto.Hash
	pool     *objPool[[]byte]
}

func (h *Hmac) Bytes() []byte {
	return h.key
}

func (h *Hmac) Algorithm() Algorithm {
	return h.selectHm

}

func (h *Hmac) Sign(payload []byte) ([]byte, error) {
	return nil, nil
}
