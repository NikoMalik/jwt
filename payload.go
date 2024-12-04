package jwt

import "time"

var now = time.Now()

//https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1

type Payload struct {
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Audience       Audience `json:"aud"` // aud admin
	ExpirationTime *JWTTime `json:"exp"`
	NotBefore      *JWTTime `json:"nbf"`
	IssuedAt       *JWTTime `json:"iat"`
	JWTID          string   `json:"jti,omitempty"`
}

/*
{
  "Issuer": "example.com",
  "Subject": "user123",
  "Audience": ["admin", "co-admin"],
  "ExpirationTime": "2024-12-01T00:00:00Z",
  "NotBefore": "2024-11-01T00:00:00Z",
  "IssuedAt": "2024-11-30T12:00:00Z"
}

*/

func (p *Payload) IsExpired() bool {
	return p.ExpirationTime != nil && p.ExpirationTime.Before(now)
}

func (p *Payload) IsNotBefore() bool {
	return p.NotBefore == nil || p.NotBefore.Before(now)
}

func (p *Payload) IsSubject(subject string) bool {
	return constTimeEqual(p.Subject, subject)
}
