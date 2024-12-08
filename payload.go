package jwt

import (
	"time"
)

//https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1

type Payload struct { // registered claims
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
func (p *Payload) GetExpiration() *JWTTime {
	if p.ExpirationTime != nil {
		return p.ExpirationTime
	}
	return nil
}

func (sc *Payload) IsID(id string) bool {
	return constTimeEqual(sc.JWTID, id)
}

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
	if p.Audience.lenAud == 0 {
		return false
	}

	for i := 0; i < p.Audience.lenAud; i++ {
		if constTimeEqual(audience, p.Audience.Get()[i]) {
			return true
		}
	}

	return false
}

// valid if token currently not expired but it can be nil
func (sc *Payload) IsValidExpiresAt(now time.Time) bool {
	return sc.ExpirationTime == nil || sc.ExpirationTime.After(now)

}

// check if expired
func (p *Payload) IsExpired(now time.Time) bool {
	return p.ExpirationTime != nil && p.ExpirationTime.Before(now)
}

func (p *Payload) IsNotBefore(now time.Time) bool {
	return p.NotBefore == nil || p.NotBefore.Before(now)
}

func (p *Payload) IsSubject(subject string) bool {
	if subject == "" {
		return false
	}
	return constTimeEqual(p.Subject, subject)
}

func (p *Payload) IsIssuer(issuer string) bool { //iss
	if issuer == "" {
		return false
	}

	return constTimeEqual(p.Issuer, issuer)
}

func (p *Payload) Validate() error {
	now := time.Now()
	errors := make([]uint8, 0, 8)

	if p.IsExpired(now) {
		errors = append(errors, 0x01)
	}
	if !p.IsNotBefore(now) {
		errors = append(errors, 0x02)
	}

	if len(errors) == 0 {
		p.Valid = true
		return nil
	}

	return ErrInvalid
}
