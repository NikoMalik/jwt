package jwt

import (
	"unsafe"

	"github.com/bytedance/sonic"
)

// https://tools.ietf.org/html/rfc7519
type Audience struct {
	aud    unsafe.Pointer // Pointer to the original slice
	lenAud int            // Number of elements in the slice
}

func NewAudience(aud []string) *Audience {
	// Store reference to the string array as unsafe.Pointer
	return &Audience{
		aud:    unsafe.Pointer(&aud),
		lenAud: len(aud),
	}
}

func (ap *Audience) Get() []string {
	if ap.aud == nil || ap.lenAud == 0 {
		return nil
	}

	// Directly access the string array via unsafe.Pointer
	audArray := *(*[]string)(ap.aud)

	// result := make([]string, ap.lenAud)
	//
	// copy(result, *audArray)

	return audArray
}

func (ap *Audience) MarshalJSON() ([]byte, error) {
	switch ap.lenAud {
	case 0:
		return []byte("[]"), nil
	case 1:

		return sonic.ConfigFastest.Marshal(ap.Get()[0])
	default:

		return sonic.ConfigFastest.Marshal(ap.Get())

	}
}

func (ap *Audience) UnmarshalJSON(data []byte) error {

	var raw interface{}
	if err := sonic.ConfigFastest.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch v := raw.(type) {
	case string: // Single string
		ap.lenAud = 1
		ap.aud = unsafe.Pointer(&[]string{v})
		return nil
	case []string: // Array of strings
		ap.lenAud = len(v)
		ap.aud = unsafe.Pointer(&v)
		return nil
	case []interface{}:
		tempAud := make([]string, len(v))
		for i := range v {
			str, ok := v[i].(string)
			if !ok {
				return ErrInvalid
			}
			tempAud[i] = str
		}
		ap.lenAud = len(tempAud)
		ap.aud = unsafe.Pointer(&tempAud)
		return nil
	default:
		return ErrInvalid
	}

}
