package jwt

import (
	"time"
)

var now = time.Now()

//https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1

type Payload struct {
	JWTID          string   `json:"jti,omitempty"`
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Audience       Audience `json:"aud"` // aud admin
	ExpirationTime *JWTTime `json:"exp"`
	NotBefore      *JWTTime `json:"nbf"`
	IssuedAt       *JWTTime `json:"iat"`
	Valid          bool
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

func (p *Payload) GetIssuer() (string, error) {
	if p.Issuer != "" {
		return p.Issuer, nil
	}
	return "", ErrIssuerNil
}

func (p *Payload) GetSubject() (string, error) {
	if p.Subject != "" {
		return p.Subject, nil
	}
	return "", ErrSubjectNil

}

// get ExpirationTime
func (p *Payload) GetExpiration() *time.Time {
	if p.ExpirationTime != nil {
		t := p.ExpirationTime.Time
		return &t
	}
	return nil
}

// validator processing
func (sc *Payload) IsValidExpiresAt(now time.Time) bool {
	return sc.ExpirationTime == nil || sc.ExpirationTime.After(now)
}

func (sc *Payload) IsID(id string) bool {
	return constTimeEqual(sc.JWTID, id)
}

// IsValidNotBefore reports whether a token isn't used before a given time.
func (sc *Payload) IsValidNotBefore(now time.Time) bool {
	return sc.NotBefore == nil || sc.NotBefore.Before(now)
}

// return issued at timestamp
func (p *Payload) GetIssuedAt() *time.Time {
	if p.IssuedAt != nil {
		t := p.IssuedAt.Time
		return &t
	}
	return nil
}

func (p *Payload) HasAudience(audience string) bool {
	lent := p.Audience.Get()
	for i := 0; i < len(lent); i++ {
		if audience == lent[i] {
			return true
		}
	}

	return false
}

func (p *Payload) IsExpired() bool {
	return p.ExpirationTime != nil && p.ExpirationTime.Before(now)
}

func (p *Payload) IsNotBefore() bool {
	return p.NotBefore == nil || p.NotBefore.Before(now)
}

func (p *Payload) IsSubject(subject string) bool {
	return constTimeEqual(p.Subject, subject)
}

func (p *Payload) Validate() error {
	defer func() {
		p.Valid = true
	}()
	return nil
}

func (p *Payload) IsIssuer(issuer string) bool {
	return constTimeEqual(p.Issuer, issuer)
}
