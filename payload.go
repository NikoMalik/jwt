package jwt

import (
	"time"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

//https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1

type Payload struct { // registered claims
	JWTID          string   `json:"jti,omitempty"` // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	Issuer         string   `json:"iss,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Audience       Audience `json:"aud,omitempty"` // aud admin
	ExpirationTime *JWTTime `json:"exp,omitempty"`
	NotBefore      *JWTTime `json:"nbf,omitempty"`
	IssuedAt       *JWTTime `json:"iat,omitempty"`
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

func (sc *Payload) IsValidIssuedAt(now time.Time) bool {
	return sc.IssuedAt == nil || sc.IssuedAt.Before(now)
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

func (p *Payload) HasAudiences(aud []string) bool {
	if p.Audience.lenAud == 0 || len(aud) == 0 {
		return false
	}

	audSet := make(map[string]struct{}, len(aud))
	for a := 0; a < len(aud); a++ {
		audSet[aud[a]] = struct{}{}
	}

	// Check if any audience in p.Audience exists in the set
	for i := 0; i < p.Audience.lenAud; i++ {
		if _, exists := audSet[p.Audience.Get()[i]]; exists {
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

// checks that the current time (now) is later than or equal to the NotBefore value
func (p *Payload) IsNotBefore(now time.Time) bool {
	return p.NotBefore == nil || !p.NotBefore.After(now)
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

func (p *Payload) MarshalJSON() []byte {
	buf := bufStringPool.Get()
	buf.WriteString(`{`)

	if p.JWTID != "" {
		buf.WriteString(`"jti":"`)
		buf.WriteString(p.JWTID)
		buf.WriteString(`",`)
	}
	if p.Issuer != "" {
		buf.WriteString(`"iss":"`)
		buf.WriteString(p.Issuer)
		buf.WriteString(`",`)
	}
	if p.Subject != "" {
		buf.WriteString(`"sub":"`)
		buf.WriteString(p.Subject)
		buf.WriteString(`",`)
	}
	if p.Audience.lenAud > 0 {
		buf.WriteString(`"aud":[`)
		for i := 0; i < p.Audience.lenAud; i++ {
			if i > 0 {
				buf.WriteString(`,`)
			}
			buf.WriteString(`"`)
			buf.WriteString(p.Audience.Get()[i])
			buf.WriteString(`"`)
		}
		buf.WriteString(`],`)
	}
	if p.ExpirationTime != nil {
		buf.WriteString(`"exp":"`)
		buf.WriteString(p.ExpirationTime.Format(time.RFC3339))
		buf.WriteString(`",`)
	}
	if p.NotBefore != nil {
		buf.WriteString(`"nbf":"`)
		buf.WriteString(p.NotBefore.Format(time.RFC3339))
		buf.WriteString(`",`)
	}
	if p.IssuedAt != nil {
		buf.WriteString(`"iat":"`)
		buf.WriteString(p.IssuedAt.Format(time.RFC3339))
		buf.WriteString(`",`)
	}

	// Remove the trailing comma and close the JSON object
	if buf.Len() > 1 && buf.Bytes()[buf.Len()-1] == ',' {
		truncate(buf, buf.Len()-1)
	}
	buf.WriteString(`}`)
	result := buf.Bytes()
	buf.Reset()

	bufStringPool.Put(buf)
	return result
}

func truncate(buffer *lowlevelfunctions.StringBuffer, n int) {
	if n < 0 || n > buffer.Len() {
		n = buffer.Len()
	}
	buf := buffer.Bytes()
	buf = buf[:n]
}

func unmarshalPayload(payload *Payload) []byte {
	info := payload.MarshalJSON()

	encoded := alignSlice(base64EncodedLen(len(info)), 32)

	base64Encode(encoded, info)

	return encoded
}
