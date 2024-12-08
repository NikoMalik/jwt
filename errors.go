package jwt

import "errors"

var (
	ErrInvalid              = errors.New("invalid bytes")
	ErrNil                  = errors.New("jwt key is nil")
	ErrSubjectNil           = errors.New("subject is nil")
	ErrIssuerNil            = errors.New("issuer is nil")
	ErrInvalidToken         = errors.New("invalid token")
	ErrUnknownAlgorithm     = errors.New("unknown algorithm")
	ErrInvalidKey           = errors.New("invalid key")
	ErrDateInvalid          = errors.New("invalid date")
	ErrSignatureInvalid     = errors.New("invalid signature")
	ErrUnitializedToken     = errors.New("unitialized token")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrSeedNil              = errors.New("seed is nil")
	ErrPayloadIsEmpty       = errors.New("payload is empty")
	ErrInvalidSeed          = errors.New("invalid seed")
	ErrInvalidKeySize       = errors.New("invalid key size")
	ErrPointerToArray       = errors.New("pointer to array")
	ErrCannotGetObjFromPool = errors.New("cannot get object from pool")
	ErrSizeNotVald          = errors.New("size not valid")
	ErrCapNotValid          = errors.New("cap not valid")

	ErrTokenExpired     = errors.New("jwt: token is expired")
	ErrTokenNotYetValid = errors.New("jwt: token is not yet valid")
)
