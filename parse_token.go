package jwt

import (
	"bytes"
	"fmt"
)

func ParseNoVerify(raw []byte) (*Token[any], error) {
	return parse(raw, [64]byte{})
}

func ParseVerifySignature(raw []byte, signature [64]byte) (*Token[any], error) {
	return parse(raw, signature)
}

func parse(raw []byte, signature [64]byte) (*Token[any], error) {
	if !bytes.HasPrefix(raw, []byte("eyJ")) {
		return nil, ErrInvalid
	}

	// first

	sepHeader := bytes.IndexByte(raw, '.')
	if sepHeader == -1 {
		return nil, fmt.Errorf("header not found: %s", raw)
	}

	// bytes.IndexByte(raw, '.')

	//second

	sepPayload := bytes.LastIndexByte(raw, '.')
	if sepPayload == -1 {
		return nil, fmt.Errorf("payload not found: %s", raw)
	}

	header := raw[:sepHeader]
	payload := raw[sepHeader+1 : sepPayload]
	// signature := raw[sepPayload+1:]

	buf := base64BufPool.Get()

	headerN, err := base64Decode((*buf)[:(len(header))], header)
	if err != nil {
		base64BufPool.Put(buf)
		return nil, err
	}
	var headerF Header
	if err := headerF.UnmarshalJSON((*buf)[:headerN]); err != nil {
		base64BufPool.Put(buf)
		return nil, err
	}

	payloadN, err := base64Decode((*buf)[:(len(payload))], payload)
	if err != nil {
		base64BufPool.Put(buf)
		return nil, err
	}
	var payloadF Payload
	if err := payloadF.UnmarshalJSON((*buf)[:payloadN]); err != nil {
		base64BufPool.Put(buf)
		return nil, err
	}

	// signN, err := base64Decode((*buf)[:base64EncodedLen(len(signature))], signature)
	// if err != nil {
	//     base64BufPool.Put(buf)
	//     return nil, err
	// }

	token := &Token[any]{
		raw:       raw,
		payload:   &payloadF,
		header:    &headerF,
		sep1:      int32(sepHeader),
		sep2:      int32(sepPayload),
		signature: signature,
	}

	*buf = (*buf)[:0]

	base64BufPool.Put(buf)

	return token, nil
}
