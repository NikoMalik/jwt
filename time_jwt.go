package jwt

import (
	"time"

	"github.com/bytedance/sonic"
)

var since1970 = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

//A JSON numeric value representing the number of seconds from
//      1970-01-01T00:00:00Z UTC until the specified UTC date/time,
//      ignoring leap seconds.  This is equivalent to the IEEE Std 1003.1,
//      2013 Edition [POSIX.1] - https://datatracker.ietf.org/doc/html/rfc7519#ref-POSIX.1

// https://tools.ietf.org/html/rfc7519#section-2
type JWTTime struct { //  NumericDate in rfc
	time.Time
}

func NumericDate(tt time.Time) *JWTTime {
	if tt.Before(since1970) {
		tt = since1970
	}
	return &JWTTime{time.Unix(tt.Unix(), 0)}
}

func (t *JWTTime) MarshalJSON() ([]byte, error) {
	if t.Before(since1970) {
		return []byte("null"), nil
	}

	return sonic.Marshal(t.Unix())
}

func (t *JWTTime) UnmarshalJSON(b []byte) error {
	var unix int64

	if err := sonic.Unmarshal(b, &unix); err != nil {
		return err
	}
	*t = JWTTime{time.Unix(unix, 0).UTC()}
	return nil
}
