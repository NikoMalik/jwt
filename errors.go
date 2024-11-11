package jwt

import "errors"

var (
	ErrInvalid          = errors.New("invalid bytes")
	ErrNil              = errors.New("jwt key is nil")
	ErrInvalidToken     = errors.New("invalid token")
	ErrUnknownAlgorithm = errors.New("unknown algorithm")
	ErrInvalidKey       = errors.New("invalid key")
	ErrDateInvalid      = errors.New("invalid date")
	ErrSignatureInvalid = errors.New("invalid signature")
	ErrUnitializedToken = errors.New("unitialized token")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrSeedNil          = errors.New("seed is nil")
	ErrPayloadIsEmpty   = errors.New("payload is empty")
	ErrInvalidSeed      = errors.New("invalid seed")
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrPointerToArray   = errors.New("pointer to array")
)
