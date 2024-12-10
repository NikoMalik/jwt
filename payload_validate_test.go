package jwt

import (
	"testing"
	"time"
	"unsafe"
)

func TestValidPayload(t *testing.T) {
	now := time.Now()
	iat := &JWTTime{now}
	exp := &JWTTime{now.Add(time.Minute)}

	notbefore := &JWTTime{now.Add(time.Millisecond)}

	jtid := "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	iss := "darkie"
	sub := "sub"

	aud := unsafe.Pointer(&[]string{"admin", "user", "furry"})

	audience := Audience{aud: aud, lenAud: 3}

	payload := &Payload{
		JWTID:          jtid,
		Issuer:         iss,
		Subject:        sub,
		Audience:       audience,
		ExpirationTime: exp,
		NotBefore:      notbefore,
		IssuedAt:       iat,
	}

	t.Run("Test GetIssuer", func(t *testing.T) {
		iss, err := payload.GetIssuer()
		if err != nil || iss != "darkie" {
			t.Errorf("expected Issuer to be 'darkie', got '%s', err: %v", iss, err)
		}
	})

	t.Run("Test GetSubject", func(t *testing.T) {
		sub, err := payload.GetSubject()
		if err != nil || sub != "sub" {
			t.Errorf("expected Subject to be 'sub', got '%s', err: %v", sub, err)
		}
	})

	t.Run("Test IsExpired", func(t *testing.T) {
		if payload.IsExpired(now) {
			t.Error("expected payload not to be expired")
		}
	})

	t.Run("Test IsNotBefore", func(t *testing.T) {
		currNow := now.Add(1 * time.Second)

		if !payload.IsNotBefore(currNow) {
			t.Error("expected payload to be valid for not-before")
		}
	})

	t.Run("Test IsID", func(t *testing.T) {
		if payload.IsID("shit") {
			t.Error("expected payload to be valid for ID")
		}
	})

	t.Run("Test iS issuer", func(t *testing.T) {
		if payload.IsIssuer("rick") { // true not correct
			t.Error("expected payload to be valid for issuer")
		}
	})

	t.Run("Test is subject", func(t *testing.T) {
		if payload.IsSubject("rick") { // true not correct
			t.Error("expected payload to be valid for subject")
		}
	})

	t.Run("Test IsExpired", func(t *testing.T) {
		if payload.IsExpired(now) {
			t.Error("expected payload not to be expired")
		}
	})

	t.Run("Test has Audience", func(t *testing.T) {
		if !payload.HasAudience("admin") {
			t.Error("expected payload to have audience")
		}

	})

	t.Run("Test has Audiences", func(t *testing.T) {
		if !payload.HasAudiences([]string{"admin", "user"}) {
			t.Error("expected payload to have audiences")
		}
	})

}

func TestPayload_GetIssuer(t *testing.T) {
	tests := []struct {
		name     string
		payload  Payload
		expected string
		wantErr  bool
	}{
		{
			name:     "Issuer present",
			payload:  Payload{Issuer: "example.com"},
			expected: "example.com",
			wantErr:  false,
		},
		{
			name:     "Issuer missing",
			payload:  Payload{},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := tt.payload.GetIssuer()
			if tt.wantErr {
				mustFail(t, err)
			} else {
				mustOk(t, err)
				mustEqual(t, tt.expected, issuer)
			}
		})
	}
}

func TestPayload_GetSubject(t *testing.T) {
	tests := []struct {
		name     string
		payload  Payload
		expected string
		wantErr  bool
	}{
		{
			name:     "Subject present",
			payload:  Payload{Subject: "user123"},
			expected: "user123",
			wantErr:  false,
		},
		{
			name:     "Subject missing",
			payload:  Payload{},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, err := tt.payload.GetSubject()
			if tt.wantErr {
				mustFail(t, err)
			} else {
				mustOk(t, err)
				mustEqual(t, tt.expected, subject)
			}
		})
	}
}

func TestPayload_IsID(t *testing.T) {
	tests := []struct {
		name     string
		payload  Payload
		id       string
		expected bool
	}{
		{
			name:     "ID matches",
			payload:  Payload{JWTID: "abc123"},
			id:       "abc123",
			expected: true,
		},
		{
			name:     "ID does not match",
			payload:  Payload{JWTID: "abc123"},
			id:       "xyz789",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.payload.IsID(tt.id)
			mustEqual(t, tt.expected, result)
		})
	}
}

func TestPayload_IsValidNotBefore(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		payload  Payload
		now      time.Time
		expected bool
	}{
		{
			name:     "Not before valid",
			payload:  Payload{NotBefore: &JWTTime{Time: now.Add(-1 * time.Hour)}},
			now:      now,
			expected: true,
		},
		{
			name:     "Not before invalid",
			payload:  Payload{NotBefore: &JWTTime{Time: now.Add(1 * time.Hour)}},
			now:      now,
			expected: false,
		},
		{
			name:     "Not before nil",
			payload:  Payload{NotBefore: nil},
			now:      now,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.payload.IsValidNotBefore(tt.now)
			mustEqual(t, tt.expected, result)
		})
	}
}

func TestPayload_IsValidExpiresAt(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		payload  Payload
		now      time.Time
		expected bool
	}{
		{
			name:     "Expiration valid",
			payload:  Payload{ExpirationTime: &JWTTime{Time: now.Add(1 * time.Hour)}},
			now:      now,
			expected: true,
		},
		{
			name:     "Expiration invalid",
			payload:  Payload{ExpirationTime: &JWTTime{Time: now.Add(-1 * time.Hour)}},
			now:      now,
			expected: false,
		},
		{
			name:     "Expiration nil",
			payload:  Payload{ExpirationTime: nil},
			now:      now,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.payload.IsValidExpiresAt(tt.now)
			mustEqual(t, tt.expected, result)
		})
	}
}

func TestPayload_IsExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		payload  Payload
		now      time.Time
		expected bool
	}{
		{
			name:     "Not expired",
			payload:  Payload{ExpirationTime: &JWTTime{Time: now.Add(1 * time.Hour)}},
			now:      now,
			expected: false,
		},
		{
			name:     "Expired",
			payload:  Payload{ExpirationTime: &JWTTime{Time: now.Add(-1 * time.Hour)}},
			now:      now,
			expected: true,
		},
		{
			name:     "Expiration nil",
			payload:  Payload{ExpirationTime: nil},
			now:      now,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.payload.IsExpired(tt.now)
			mustEqual(t, tt.expected, result)
		})
	}
}

func TestPayload_HasAudience(t *testing.T) {
	tests := []struct {
		name     string
		payload  Payload
		audience string
		expected bool
	}{
		{
			name:     "Audience found",
			payload:  Payload{Audience: Audience{lenAud: 2, aud: unsafe.Pointer(&[]string{"admin", "user"})}},
			audience: "admin",
			expected: true,
		},
		{
			name:     "Audience not found",
			payload:  Payload{Audience: Audience{lenAud: 2, aud: unsafe.Pointer(&[]string{"admin", "user"})}},
			audience: "guest",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.payload.HasAudience(tt.audience)
			mustEqual(t, tt.expected, result)
		})
	}
}

func TestPayload_HasAudiences(t *testing.T) {
	tests := []struct {
		name      string
		payload   Payload
		audiences []string
		expected  bool
	}{
		{
			name:      "One common audience",
			payload:   Payload{Audience: Audience{lenAud: 2, aud: unsafe.Pointer(&[]string{"admin", "user"})}},
			audiences: []string{"admin", "guest"},
			expected:  true,
		},
		{
			name:      "No common audience",
			payload:   Payload{Audience: Audience{lenAud: 2, aud: unsafe.Pointer(&[]string{"admin", "user"})}},
			audiences: []string{"guest", "moderator"},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.payload.HasAudiences(tt.audiences)
			mustEqual(t, tt.expected, result)
		})
	}
}

//
// func TestPayload_MarshalJSON(t *testing.T) {
//
// 	now := time.Now()
// 	expirationTime := now.Add(1 * time.Hour)
//
// 	tests := []struct {
// 		name     string
// 		payload  Payload
// 		expected string
// 		wantErr  bool
// 	}{
// 		{
// 			name:     "Valid payload",
// 			payload:  Payload{Issuer: "example.com", Subject: "user123", JWTID: "abc123", ExpirationTime: &JWTTime{Time: expirationTime}},
// 			expected: `{"jti":"abc123","iss":"example.com","sub":"user123","aud":{},"exp":"` + expirationTime.Format(time.RFC3339) + `"}`,
// 			wantErr:  false,
// 		},
// 		{
// 			name:     "Missing optional fields",
// 			payload:  Payload{Issuer: "example.com"},
// 			expected: `{"jti":"","iss":"example.com","sub":"","aud":{},"exp":"","nbf":"","iat":""}`,
// 			wantErr:  false,
// 		},
// 		{
// 			name:     "Empty payload",
// 			payload:  Payload{},
// 			expected: `{"jti":"","iss":"","sub":"","aud":[],"exp":"","nbf":"","iat":""}`,
// 			wantErr:  false,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			result, err := sonic.Marshal(tt.payload)
// 			if tt.wantErr {
// 				mustFail(t, err)
// 			} else {
// 				mustOk(t, err)
//
// 				mustEqual(t, tt.expected, string(result))
// 			}
// 		})
// 	}
// }
