package jwt

import (
	"time"
	"unsafe"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
	"github.com/bytedance/sonic"
)

const (
	digits01 = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
	digits10 = "0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999"
)

func formatString(u int, padding int) unsafe.Pointer {
	var neg bool
	if u < 0 {
		neg = true
		u = -u
	} else {
		if u < 10 && padding == 0 {

			switch u {
			case 0:
				return unsafe.Pointer(&[]byte{'0'})
			case 1:
				return unsafe.Pointer(&[]byte{'1'})
			case 2:
				return unsafe.Pointer(&[]byte{'2'})
			case 3:
				return unsafe.Pointer(&[]byte{'3'})
			case 4:
				return unsafe.Pointer(&[]byte{'4'})
			case 5:
				return unsafe.Pointer(&[]byte{'5'})
			case 6:
				return unsafe.Pointer(&[]byte{'6'})
			case 7:
				return unsafe.Pointer(&[]byte{'7'})
			case 8:
				return unsafe.Pointer(&[]byte{'8'})
			case 9:
				return unsafe.Pointer(&[]byte{'9'})
			}
		}
	}

	var q int
	var j uintptr
	var a [20]byte
	i := 20

	for u >= 100 {
		i -= 2
		q = u / 100
		j = uintptr(u - q*100)
		a[i+1] = digits01[j]
		a[i] = digits10[j]
		u = q
	}

	if u >= 10 {
		i--
		q = u / 10
		a[i] = digits01[uintptr(u-q*10)]
		u = q
	}
	i--
	a[i] = digits01[uintptr(u)]

	if padding == 0 {
		if neg {
			i--
			a[i] = '-'
		}
		f := a[i:]
		return noescape(unsafe.Pointer(&f))
	}

	if neg {
		padding = 21 - padding
	} else {
		padding = 20 - padding
	}
	for i > padding {
		i--
		a[i] = '0'
	}
	if neg {
		i--
		a[i] = '-'
	}
	f := a[i:]
	return noescape(unsafe.Pointer(&f))

}

var since1970 = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

//A JSON numeric value representing the number of seconds from
//      1970-01-01T00:00:00Z UTC until the specified UTC date/time,
//      ignoring leap seconds.  This is equivalent to the IEEE Std 1003.1,
//      2013 Edition [POSIX.1] - https://datatracker.ietf.org/doc/html/rfc7519#ref-POSIX.1

// https://tools.ietf.org/html/rfc7519#section-2
type JWTTime struct { //  NumericDate in rfc
	time.Time
}

func (t *JWTTime) Format(layout string) string {
	const bufSize = 64
	max := len(layout) + 10
	var b = lowlevelfunctions.MakeNoZeroCap(0, max)
	if max < bufSize {
		var buf [bufSize]byte
		b = append(b, buf[:0]...)
	} else {
		b = append(b, make([]byte, 0, max)...)
	}
	b = t.AppendFormat(b, layout)
	return lowlevelfunctions.String(b)
}

func NumericDate(tt time.Time) *JWTTime {
	if tt.Before(since1970) {
		tt = since1970
	}
	return &JWTTime{time.Unix(tt.Unix(), 0).UTC()}
}

func (t *JWTTime) GetTime() []byte {

	if t.Before(since1970) {
		return []byte("null")
	}

	g := int(t.Unix())

	b := formatString(g, 0)

	// gh := strconv.FormatInt(int64(g), 10)

	return *(*[]byte)(b)
}

func (t *JWTTime) MarshalJSON() ([]byte, error) {
	if t.Before(since1970) {
		return []byte("null"), nil
	}

	return sonic.ConfigFastest.Marshal(t.Unix())
}

func (t *JWTTime) UnmarshalJSON(b []byte) error {
	var unix int64

	if err := sonic.Unmarshal(b, &unix); err != nil {
		return err
	}
	*t = JWTTime{time.Unix(unix, 0).UTC()}
	return nil
}
